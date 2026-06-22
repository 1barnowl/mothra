"""
healing_core.alertmanager
─────────────────────────
AlertmanagerBridge — receives Prometheus Alertmanager webhooks and
translates them into HealingCore Events.

Guide mandate:
  "pluggable telemetry hooks so external controllers can observe healing
   actions without exposing internal memory"
  (production integration with the standard Prometheus/Alertmanager stack)

Setup in alertmanager.yml:
  receivers:
    - name: healing_core
      webhook_configs:
        - url: http://healing-core:9094/api/v1/alerts
          send_resolved: true

Alertmanager POST body (simplified):
  {
    "version": "4",
    "groupKey": "{}:{alertname=\"DiskFull\"}",
    "status": "firing",  # or "resolved"
    "alerts": [
      {
        "status": "firing",
        "labels": {"alertname": "DiskFull", "instance": "server1", "severity": "critical"},
        "annotations": {"summary": "Disk at 95%", "description": "..."},
        "startsAt": "2024-01-01T12:00:00Z",
        "endsAt":   "0001-01-01T00:00:00Z"
      }
    ]
  }

Label → Event field mapping:
  alertname        → error_type  (snake_cased)
  instance / host  → actor
  job / service    → subsystem
  namespace        → subsystem (K8s)
  severity         → mapped to Severity enum
  annotations.summary / description → message
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

log = logging.getLogger("healing_core.alertmanager")


# ── Label → Severity mapping ──────────────────────────────────────────────────

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "warning":  "MEDIUM",
    "warn":     "MEDIUM",
    "info":     "LOW",
    "low":      "LOW",
    "page":     "CRITICAL",
    "ticket":   "MEDIUM",
}

# alertnames that map to specific error_types
_ALERTNAME_REMAP = {
    "HighCPU":              "cpu_overload",
    "CPUThrottling":        "cpu_overload",
    "HighMemory":           "memory_depletion",
    "OOMKill":              "memory_depletion",
    "DiskFull":             "disk_full",
    "DiskSpaceLow":         "disk_full",
    "ServiceDown":          "service_crash",
    "ServiceUnhealthy":     "service_hung",
    "PodCrashLooping":      "service_crash",
    "DNSFailure":           "dns_failure",
    "NetworkErrors":        "network_errors",
    "HighLatency":          "high_latency",
    "CertExpiring":         "cert_expiry",
    "CertExpired":          "cert_expiry",
    "AuthFailures":         "auth_failure",
    "SuspiciousLogin":      "auth_failure",
    "MalwareDetected":      "malware_detected",
    "UnauthorizedAccess":   "unauthorized_access",
    "APIDown":              "api_down",
    "EndpointDown":         "api_down",
    "DatabaseDown":         "service_crash",
    "SlowQuery":            "high_latency",
    "ReplicationLag":       "high_latency",
    "RAIDDegraded":         "disk_failure",
    "NTPDrift":             "time_sync_failure",
    "KubernodeNotReady":    "service_crash",
    "PodOOMKilled":         "memory_depletion",
}


# ── Alert parser ──────────────────────────────────────────────────────────────

class AlertParser:
    @staticmethod
    def parse(alert_dict: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Parse a single Alertmanager alert object into an Event-compatible dict.
        Returns None for resolved alerts (we suppress further matching).
        """
        status = alert_dict.get("status", "firing")
        if status == "resolved":
            return None   # caller handles resolved suppression

        labels      = alert_dict.get("labels", {})
        annotations = alert_dict.get("annotations", {})

        alertname = labels.get("alertname", "unknown_alert")
        error_type = _ALERTNAME_REMAP.get(alertname) or _snake(alertname)

        actor = (labels.get("instance") or labels.get("host") or
                 labels.get("pod")      or labels.get("node") or
                 alertname)

        subsystem = (labels.get("job")       or labels.get("service") or
                     labels.get("namespace") or labels.get("app") or
                     "prometheus")

        message = (annotations.get("description") or
                   annotations.get("summary")     or
                   f"{alertname} on {actor}")

        # Build extra metadata string from all labels
        meta = " ".join(f"{k}={v}" for k, v in sorted(labels.items())
                        if k not in ("alertname", "instance", "job", "severity"))

        return {
            "actor":      actor[:200],
            "subsystem":  subsystem[:200],
            "error_type": error_type[:200],
            "message":    f"{message[:400]} [{meta[:200]}]",
            "severity":   _SEVERITY_MAP.get(labels.get("severity", "").lower(), "MEDIUM"),
            "alertname":  alertname,
            "fingerprint": alert_dict.get("fingerprint", ""),
        }


def _snake(s: str) -> str:
    """CamelCase → snake_case."""
    return re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', s).lower()


# ── HTTP handler ──────────────────────────────────────────────────────────────

class _AlertHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug("alertmanager | " + fmt, *args)

    def do_POST(self):
        if self.path.rstrip("/") not in ("/api/v1/alerts", "/alerts", "/-/webhook"):
            self.send_response(404); self.end_headers(); return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
        except Exception as e:
            log.warning("alertmanager | bad payload: %s", e)
            self.send_response(400); self.end_headers()
            self.wfile.write(b'{"error":"bad json"}')
            return

        bridge: AlertmanagerBridge = self.server._bridge
        ingested, suppressed = bridge._process_payload(body)

        resp = json.dumps({"ingested": ingested, "suppressed": suppressed}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self):
        if self.path.rstrip("/") in ("/-/healthy", "/health"):
            self.send_response(200); self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404); self.end_headers()


# ── AlertmanagerBridge ────────────────────────────────────────────────────────

class AlertmanagerBridge:
    """
    Listens for Alertmanager webhook POSTs and injects Events into HealingCore.
    """

    def __init__(
        self,
        core: "HealingCore",
        port: int = 9094,
        on_resolved: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._core       = core
        self._port       = port
        self._on_resolved = on_resolved
        self._parser     = AlertParser()
        self._resolved:  set = set()    # suppressed fingerprints
        self._stats: Dict[str, int] = {"received": 0, "ingested": 0,
                                        "suppressed": 0, "resolved": 0}

        class _Srv(ThreadingHTTPServer):
            pass
        srv = _Srv(("", port), _AlertHandler)
        srv._bridge = self
        self._server = srv

    def start(self) -> None:
        t = threading.Thread(target=self._server.serve_forever,
                             daemon=True, name="hc-alertmanager")
        t.start()
        log.info("alertmanager | bridge listening on :%d/api/v1/alerts", self._port)

    def stop(self) -> None:
        self._server.shutdown()

    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _process_payload(self, body: Dict) -> tuple:
        from .models import Event

        alerts    = body.get("alerts", [])
        ingested  = 0
        suppressed = 0
        self._stats["received"] += len(alerts)

        for alert in alerts:
            fp     = alert.get("fingerprint", "")
            status = alert.get("status", "firing")

            # Handle resolved
            if status == "resolved":
                self._resolved.add(fp)
                self._stats["resolved"] += 1
                if self._on_resolved:
                    self._on_resolved(fp)
                log.debug("alertmanager | resolved fp=%s", fp[:16])
                continue

            # Skip previously resolved alerts (re-firing check)
            if fp in self._resolved:
                self._resolved.discard(fp)   # allow re-trigger

            parsed = AlertParser.parse(alert)
            if parsed is None:
                suppressed += 1
                self._stats["suppressed"] += 1
                continue

            ev = Event(
                actor      = parsed["actor"],
                subsystem  = parsed["subsystem"],
                error_type = parsed["error_type"],
                message    = parsed["message"],
            )
            ev.fingerprint = fp or ev.compute_fingerprint()

            try:
                self._core.ingest(ev)
                ingested += 1
                self._stats["ingested"] += 1
                log.info("alertmanager | ingested alert=%s  actor=%s",
                         parsed["alertname"], parsed["actor"])
            except Exception as e:
                log.error("alertmanager | ingest error: %s", e)
                suppressed += 1

        return ingested, suppressed
