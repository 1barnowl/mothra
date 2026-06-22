"""
healing_core.itsm
──────────────────
ITSMDispatcher — guide mandate:
  "optional human-in-the-loop escalation produces an ITSM ticket or
   a signed attestation before high-risk changes"

Supported backends (all optional, configured via HealingPolicy YAML):

  webhook     — generic HTTP POST (JSON payload)
  jira        — Jira REST API v3 issue creation
  slack       — Slack Incoming Webhook notification
  pagerduty   — PagerDuty Events API v2 trigger

Signed attestation:
  High-risk fixes (impact > threshold) can be gated behind a
  SignedAttestation: a HMAC-SHA256 record that a human approver
  reviewed and approved the action.  The attestation is appended to
  the append-only audit trail before the fix is applied.

Policy YAML keys (all optional):
  itsm:
    webhook_url:       "https://hooks.example.com/healing"
    jira_url:          "https://myco.atlassian.net"
    jira_project:      "OPS"
    jira_token:        "ATATT3…"
    jira_email:        "bot@myco.com"
    slack_webhook_url: "https://hooks.slack.com/services/…"
    pagerduty_key:     "r1z9…"        # routing key
    attestation_secret:"change-me"    # HMAC secret
    attestation_threshold: 0.80       # impact score requiring attestation

Usage (wired in EscalationManager):
    itsm = ITSMDispatcher.from_policy(policy)
    results = itsm.dispatch(incident, snapshot, "heal_failed")
    attes   = itsm.request_attestation(incident, fix)
    ok      = itsm.verify_attestation(attes, approver="alice", secret=secret)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import urllib.request
import urllib.error
import base64
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models   import Incident, RemediationFix, Snapshot
    from .policy   import HealingPolicy

log = logging.getLogger("healing_core.itsm")


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class EscalationResult:
    backend:   str
    success:   bool
    ticket_id: str  = ""
    url:       str  = ""
    detail:    str  = ""


@dataclass
class AttestationRequest:
    id:          str   = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str   = ""
    fix_name:    str   = ""
    impact:      float = 0.0
    risk_score:  float = 0.0
    summary:     str   = ""
    created_at:  float = field(default_factory=time.time)
    approved:    bool  = False
    approver:    str   = ""
    approved_at: float = 0.0
    signature:   str   = ""   # HMAC-SHA256 hex


# ── Abstract backend ──────────────────────────────────────────────────────────

class ITSMBackend(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def create_ticket(
        self,
        incident: "Incident",
        snapshot: "Snapshot",
        reason:   str,
    ) -> EscalationResult: ...

    @staticmethod
    def _post(url: str, payload: bytes,
              headers: Optional[Dict] = None) -> tuple:
        """HTTP POST → (status_code, response_text)."""
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        req  = urllib.request.Request(url, data=payload, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
        except Exception as exc:
            return 0, str(exc)


# ── Webhook backend ───────────────────────────────────────────────────────────

class WebhookBackend(ITSMBackend):
    """Generic HTTP POST webhook — sends JSON payload."""

    def __init__(self, url: str,
                 extra_headers: Optional[Dict] = None) -> None:
        self._url     = url
        self._headers = extra_headers or {}

    @property
    def name(self) -> str:
        return "webhook"

    def create_ticket(self, incident, snapshot, reason) -> EscalationResult:
        payload = json.dumps({
            "source":      "HealingCore",
            "incident_id": incident.id,
            "category":    incident.category.name,
            "severity":    incident.severity.name,
            "risk_score":  incident.risk_score,
            "actor":       incident.event.actor,
            "message":     incident.event.message[:200],
            "reason":      reason,
            "snapshot_id": snapshot.id,
            "timestamp":   time.time(),
        }).encode()
        status, body = self._post(self._url, payload, self._headers)
        ok = 200 <= status < 300
        log.info("itsm.webhook | status=%d  ok=%s", status, ok)
        return EscalationResult(backend="webhook", success=ok,
                                ticket_id="", url=self._url,
                                detail=body[:120] if not ok else "ok")


# ── Jira backend ──────────────────────────────────────────────────────────────

class JiraBackend(ITSMBackend):
    """Creates Jira issues via REST API v3."""

    def __init__(self, base_url: str, project_key: str,
                 api_token: str, email: str,
                 issue_type: str = "Bug",
                 priority_map: Optional[Dict] = None) -> None:
        self._url     = base_url.rstrip("/")
        self._project = project_key
        self._token   = api_token
        self._email   = email
        self._itype   = issue_type
        self._pmap    = priority_map or {
            "CRITICAL": "Highest", "HIGH": "High",
            "MEDIUM":   "Medium",  "LOW":  "Low",
        }

    @property
    def name(self) -> str:
        return "jira"

    def _auth_header(self) -> str:
        creds = base64.b64encode(
            f"{self._email}:{self._token}".encode()).decode()
        return f"Basic {creds}"

    def create_ticket(self, incident, snapshot, reason) -> EscalationResult:
        priority = self._pmap.get(incident.severity.name, "Medium")
        summary  = (f"[HealingCore] {incident.category.name} — "
                    f"{incident.event.actor}: "
                    f"{incident.event.message[:80]}")
        desc     = (
            f"*Incident:* {incident.id}\n"
            f"*Category:* {incident.category.name}\n"
            f"*Severity:* {incident.severity.name}\n"
            f"*Risk Score:* {incident.risk_score}\n"
            f"*Actor:* {incident.event.actor}\n"
            f"*Message:* {incident.event.message[:400]}\n"
            f"*Reason:* {reason}\n"
            f"*Snapshot:* {snapshot.id}\n"
        )
        payload = json.dumps({
            "fields": {
                "project":     {"key": self._project},
                "summary":     summary,
                "description": {
                    "type":    "doc",
                    "version": 1,
                    "content": [{"type": "paragraph", "content": [
                        {"type": "text", "text": desc}
                    ]}],
                },
                "issuetype": {"name": self._itype},
                "priority":  {"name": priority},
                "labels":    ["healing-core", "automated"],
            }
        }).encode()
        url = f"{self._url}/rest/api/3/issue"
        status, body = self._post(
            url, payload,
            {"Authorization": self._auth_header(),
             "Accept": "application/json"})
        ok = status in (200, 201)
        ticket_id, ticket_url = "", ""
        if ok:
            try:
                data      = json.loads(body)
                ticket_id = data.get("key", "")
                ticket_url= f"{self._url}/browse/{ticket_id}"
            except Exception:
                pass
        log.info("itsm.jira | status=%d  key=%s", status, ticket_id)
        return EscalationResult(backend="jira", success=ok,
                                ticket_id=ticket_id, url=ticket_url,
                                detail=body[:120] if not ok else ticket_id)


# ── Slack backend ─────────────────────────────────────────────────────────────

class SlackBackend(ITSMBackend):
    """Slack Incoming Webhook notification."""

    _COLOUR = {
        "CRITICAL": "#FF0000", "HIGH": "#FF8800",
        "MEDIUM":   "#FFCC00", "LOW":  "#00AA00",
    }

    def __init__(self, webhook_url: str) -> None:
        self._url = webhook_url

    @property
    def name(self) -> str:
        return "slack"

    def create_ticket(self, incident, snapshot, reason) -> EscalationResult:
        colour = self._COLOUR.get(incident.severity.name, "#888888")
        payload = json.dumps({
            "attachments": [{
                "color":    colour,
                "title":    f"HealingCore Escalation — {incident.category.name}",
                "text":     (
                    f"*Actor:* `{incident.event.actor}`\n"
                    f"*Message:* {incident.event.message[:200]}\n"
                    f"*Risk:* {incident.risk_score}   "
                    f"*Severity:* {incident.severity.name}\n"
                    f"*Reason:* {reason}"
                ),
                "footer":   f"incident: {incident.id[:8]}  "
                            f"snap: {snapshot.id[:8]}",
                "ts":       int(time.time()),
            }]
        }).encode()
        status, body = self._post(self._url, payload)
        ok = status == 200
        log.info("itsm.slack | status=%d  ok=%s", status, ok)
        return EscalationResult(backend="slack", success=ok,
                                detail=body[:80] if not ok else "ok")


# ── PagerDuty backend ─────────────────────────────────────────────────────────

class PagerDutyBackend(ITSMBackend):
    """PagerDuty Events API v2."""

    _SEV = {"CRITICAL":"critical","HIGH":"error","MEDIUM":"warning","LOW":"info"}
    _URL  = "https://events.pagerduty.com/v2/enqueue"

    def __init__(self, routing_key: str) -> None:
        self._key = routing_key

    @property
    def name(self) -> str:
        return "pagerduty"

    def create_ticket(self, incident, snapshot, reason) -> EscalationResult:
        sev = self._SEV.get(incident.severity.name, "warning")
        payload = json.dumps({
            "routing_key":  self._key,
            "event_action": "trigger",
            "dedup_key":    incident.id,
            "payload": {
                "summary":   (f"[HealingCore] {incident.category.name} on "
                              f"{incident.event.actor}: "
                              f"{incident.event.message[:80]}"),
                "source":    "HealingCore",
                "severity":  sev,
                "custom_details": {
                    "incident_id": incident.id,
                    "snapshot_id": snapshot.id,
                    "risk_score":  incident.risk_score,
                    "reason":      reason,
                    "message":     incident.event.message[:300],
                },
            },
        }).encode()
        status, body = self._post(self._URL, payload)
        ok   = status == 202
        data = {}
        try:
            data = json.loads(body)
        except Exception:
            pass
        dedupe_key = data.get("dedup_key", "")
        log.info("itsm.pagerduty | status=%d  ok=%s", status, ok)
        return EscalationResult(backend="pagerduty", success=ok,
                                ticket_id=dedupe_key,
                                detail=body[:120] if not ok else "ok")


# ── Signed Attestation ────────────────────────────────────────────────────────

class SignedAttestation:
    """
    Human-in-the-loop approval gate for high-risk fixes.

    Flow:
      1. core calls itsm.request_attestation(incident, fix)
         → returns AttestationRequest with a pending ID
      2. Operator receives the request (via ITSM ticket / Slack) and calls
         itsm.approve_attestation(request_id, approver, secret)
         → returns signed Attestation
      3. core calls itsm.verify_attestation(attestation)
         → returns True if HMAC valid + not expired
      4. Attestation dict appended to audit trail before fix applies

    The HMAC-SHA256 signature covers:
        request.id | incident_id | fix_name | approver | approved_at
    """

    DEFAULT_EXPIRY_SECONDS = 300   # attestation valid for 5 minutes

    def __init__(self, secret: str,
                 expiry_seconds: int = DEFAULT_EXPIRY_SECONDS) -> None:
        self._secret  = secret.encode("utf-8")
        self._expiry  = expiry_seconds
        self._pending: Dict[str, AttestationRequest] = {}

    def request(self, incident: "Incident",
                fix: "RemediationFix") -> AttestationRequest:
        req = AttestationRequest(
            incident_id = incident.id,
            fix_name    = fix.name,
            impact      = fix.impact,
            risk_score  = incident.risk_score,
            summary     = (f"{incident.category.name} / "
                           f"{incident.severity.name} — "
                           f"{incident.event.actor}: "
                           f"{incident.event.message[:120]}"),
        )
        self._pending[req.id] = req
        log.info("itsm.attest | requested  id=%s  fix=%s  risk=%.2f",
                 req.id[:8], fix.name, incident.risk_score)
        return req

    def approve(self, request_id: str, approver: str,
                secret: Optional[str] = None) -> Optional[AttestationRequest]:
        req = self._pending.get(request_id)
        if req is None:
            log.warning("itsm.attest | unknown request_id=%s", request_id[:8])
            return None
        if secret and secret.encode("utf-8") != self._secret:
            log.warning("itsm.attest | bad secret for request_id=%s", request_id[:8])
            return None
        req.approved    = True
        req.approver    = approver
        req.approved_at = time.time()
        req.signature   = self._sign(req)
        del self._pending[request_id]
        log.info("itsm.attest | approved  id=%s  approver=%s",
                 request_id[:8], approver)
        return req

    def verify(self, req: AttestationRequest) -> bool:
        if not req.approved or not req.signature:
            return False
        if time.time() - req.approved_at > self._expiry:
            log.warning("itsm.attest | expired  id=%s", req.id[:8])
            return False
        expected = self._sign(req)
        return hmac.compare_digest(req.signature, expected)

    def to_audit_dict(self, req: AttestationRequest) -> dict:
        return {
            "attestation_id":  req.id,
            "incident_id":     req.incident_id,
            "fix_name":        req.fix_name,
            "impact":          req.impact,
            "approver":        req.approver,
            "approved_at":     req.approved_at,
            "signature":       req.signature[:16] + "…",  # truncated for safety
            "valid":           self.verify(req),
        }

    def _sign(self, req: AttestationRequest) -> str:
        msg = "|".join([
            req.id, req.incident_id, req.fix_name,
            req.approver, str(req.approved_at),
        ]).encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()


# ── Dispatcher ────────────────────────────────────────────────────────────────

class ITSMDispatcher:
    """Routes escalations to all configured backends."""

    def __init__(self, backends: Optional[List[ITSMBackend]] = None,
                 attestation: Optional[SignedAttestation] = None,
                 attestation_threshold: float = 0.80) -> None:
        self._backends   = backends or []
        self._attest     = attestation
        self._attest_thr = attestation_threshold
        self._dispatched = 0
        self._failed     = 0

    @classmethod
    def from_policy(cls, policy: "HealingPolicy") -> "ITSMDispatcher":
        """Build dispatcher from HealingPolicy YAML settings."""
        cfg = getattr(policy, "itsm", {}) or {}
        backends: List[ITSMBackend] = []

        if cfg.get("webhook_url"):
            backends.append(WebhookBackend(cfg["webhook_url"]))
        if cfg.get("jira_url") and cfg.get("jira_token"):
            backends.append(JiraBackend(
                base_url    = cfg["jira_url"],
                project_key = cfg.get("jira_project", "OPS"),
                api_token   = cfg["jira_token"],
                email       = cfg.get("jira_email", ""),
            ))
        if cfg.get("slack_webhook_url"):
            backends.append(SlackBackend(cfg["slack_webhook_url"]))
        if cfg.get("pagerduty_key"):
            backends.append(PagerDutyBackend(cfg["pagerduty_key"]))

        attest = None
        if cfg.get("attestation_secret"):
            attest = SignedAttestation(
                secret=cfg["attestation_secret"],
                expiry_seconds=int(cfg.get("attestation_expiry", 300)),
            )

        return cls(
            backends              = backends,
            attestation           = attest,
            attestation_threshold = float(cfg.get("attestation_threshold", 0.80)),
        )

    def dispatch(self, incident: "Incident", snapshot: "Snapshot",
                 reason: str = "") -> List[EscalationResult]:
        """Fire all backends. Returns list of results."""
        if not self._backends:
            log.debug("itsm | no backends configured")
            return []
        results = []
        for backend in self._backends:
            try:
                r = backend.create_ticket(incident, snapshot, reason)
                results.append(r)
                if r.success:
                    self._dispatched += 1
                else:
                    self._failed += 1
            except Exception as exc:
                log.warning("itsm.%s | dispatch error: %s", backend.name, exc)
                self._failed += 1
                results.append(EscalationResult(
                    backend=backend.name, success=False, detail=str(exc)))
        return results

    def needs_attestation(self, fix: "RemediationFix",
                          incident: "Incident") -> bool:
        """Returns True if this fix+incident requires human attestation."""
        if self._attest is None:
            return False
        return fix.impact >= self._attest_thr or incident.risk_score >= self._attest_thr

    def request_attestation(self, incident: "Incident",
                            fix: "RemediationFix") -> Optional[AttestationRequest]:
        if self._attest is None:
            return None
        return self._attest.request(incident, fix)

    def approve_attestation(self, request_id: str, approver: str,
                            secret: str = "") -> Optional[AttestationRequest]:
        if self._attest is None:
            return None
        return self._attest.approve(request_id, approver, secret)

    def verify_attestation(self, req: AttestationRequest) -> bool:
        if self._attest is None:
            return True   # no attestation configured → auto-approve
        return self._attest.verify(req)

    def stats(self) -> dict:
        return {
            "backends":              [b.name for b in self._backends],
            "dispatched":            self._dispatched,
            "failed":                self._failed,
            "attestation_enabled":   self._attest is not None,
            "attestation_threshold": self._attest_thr,
            "pending_attestations":  len(self._attest._pending) if self._attest else 0,
        }
