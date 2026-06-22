"""healing_core.escalation — PagerDuty Events v2 + Slack webhook."""
from __future__ import annotations
import json, logging, urllib.request
from typing import TYPE_CHECKING, List
from .models import Incident, Snapshot

if TYPE_CHECKING:
    from .policy    import HealingPolicy
    from .audit     import AuditTrail
    from .primitives import PrimitivesRegistry

log = logging.getLogger("healing_core.escalation")

class EscalationManager:
    def __init__(self, policy: "HealingPolicy"):
        self._policy = policy

    def escalate(self, incident: Incident, snapshot: Snapshot,
                 candidates: List, audit: "AuditTrail",
                 primitives: "PrimitivesRegistry") -> None:
        summary = (
            f"[{incident.severity.name}] {incident.category.name} incident "
            f"on {incident.event.actor} — {incident.event.message[:120]}"
        )
        log.warning("ESCALATION | %s", summary)
        audit.append("escalated", incident.id, snapshot.id,
                     {"reason": summary, "candidates": [c.name for c in candidates[:3]]})
        self._pagerduty(incident, summary)
        self._slack(incident, summary)

    def _pagerduty(self, incident: Incident, summary: str) -> None:
        key = getattr(self._policy, "pagerduty_key", "") or ""
        if not key:
            log.debug("escalation | PagerDuty key not set, skipping")
            return
        payload = json.dumps({
            "routing_key":  key,
            "event_action": "trigger",
            "dedup_key":    incident.id,
            "payload": {
                "summary":   summary,
                "severity":  incident.severity.name.lower(),
                "source":    "healing_core_v0.4",
                "custom_details": {
                    "category":    incident.category.name,
                    "risk_score":  incident.risk_score,
                    "correlation": incident.correlation_id,
                },
            },
        }).encode()
        self._post("https://events.pagerduty.com/v2/enqueue", payload)

    def _slack(self, incident: Incident, summary: str) -> None:
        url = getattr(self._policy, "slack_webhook", "") or ""
        if not url:
            log.debug("escalation | Slack webhook not set, skipping")
            return
        payload = json.dumps({
            "text": f":rotating_light: *HealingCore Escalation*\n{summary}",
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"*Category:* {incident.category.name}\n"
                                 f"*Severity:* {incident.severity.name}\n"
                                 f"*Risk:* {incident.risk_score:.2f}\n"
                                 f"*Actor:* `{incident.event.actor}`\n"
                                 f"*Message:* {incident.event.message[:200]}"}
            }],
        }).encode()
        self._post(url, payload)

    @staticmethod
    def _post(url: str, payload: bytes) -> None:
        try:
            req = urllib.request.Request(url, data=payload,
                                          headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                log.debug("escalation | POST %s → %d", url[:40], resp.status)
        except Exception as e:
            log.warning("escalation | POST failed: %s", e)
