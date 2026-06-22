"""
healing_core.api
────────────────
Lightweight REST API over stdlib http.server — no external web framework needed.

Endpoints (all under /api/v1/):
  GET  /health                  — liveness probe
  POST /events                  — ingest an event  {actor, subsystem, error_type, message}
  GET  /incidents               — list recent incidents  ?limit=50&status=COMMITTED
  GET  /incidents/{id}          — single incident detail
  GET  /primitives              — list registered healing primitives
  GET  /primitives/{name}       — single primitive detail
  GET  /audit                   — last N audit entries  ?limit=100
  GET  /metrics                 — Prometheus text format (mirrors /metrics endpoint)
  POST /policy/reload           — trigger hot-reload of YAML policy
  GET  /correlation/summary     — event correlator stats
  GET  /correlation/blast       — blast radius breakdown
  GET  /plugins                 — list loaded plugins

Authentication: X-API-Key header (configurable; None = disabled).
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from .core import HealingCore

log = logging.getLogger("healing_core.api")


class _Handler(BaseHTTPRequestHandler):
    """HTTP handler — receives reference to HealingCore via server attribute."""

    core: "HealingCore"
    api_key: Optional[str]

    def log_message(self, fmt, *args):
        log.debug("api | " + fmt, *args)

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _authorized(self) -> bool:
        if not self.api_key:
            return True
        return self.headers.get("X-API-Key") == self.api_key

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        qs     = parse_qs(parsed.query)

        routes = {
            "/api/v1/health":                self._health,
            "/api/v1/incidents":             lambda: self._incidents(qs),
            "/api/v1/primitives":            self._primitives,
            "/api/v1/audit":                 lambda: self._audit(qs),
            "/api/v1/metrics":               self._metrics,
            "/api/v1/correlation/summary":   self._correlation_summary,
            "/api/v1/correlation/blast":     self._correlation_blast,
            "/api/v1/plugins":               self._plugins,
        }

        # Dynamic route matching
        if path.startswith("/api/v1/incidents/"):
            inc_id = path.split("/api/v1/incidents/")[-1]
            return self._incident_detail(inc_id)
        if path.startswith("/api/v1/primitives/"):
            name = path.split("/api/v1/primitives/")[-1]
            return self._primitive_detail(name)

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send(404, {"error": f"no route for {path}"})

    def do_POST(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")

        routes = {
            "/api/v1/events":        self._ingest_event,
            "/api/v1/policy/reload": self._policy_reload,
        }
        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send(404, {"error": f"no route for {path}"})

    # ── Endpoint handlers ─────────────────────────────────────────────────────

    def _health(self):
        core = self.server.core
        self._send(200, {
            "status":    "ok",
            "version":   "0.4.0",
            "uptime_s":  round(time.time() - core._start_time, 1),
            "incidents": core._stats.get("total_incidents", 0),
            "healed":    core._stats.get("total_healed", 0),
        })

    def _ingest_event(self):
        body = self._read_body()
        if body is None:
            return self._send(400, {"error": "invalid JSON body"})

        required = {"actor", "error_type", "message"}
        missing  = required - set(body.keys())
        if missing:
            return self._send(400, {"error": f"missing fields: {missing}"})

        from .models import Event
        ev = Event(
            actor      = str(body.get("actor", "")),
            subsystem  = str(body.get("subsystem", "")),
            error_type = str(body.get("error_type", "")),
            message    = str(body.get("message", "")),
        )
        incident = self.server.core.ingest(ev)
        if incident is None:
            return self._send(200, {"status": "suppressed", "event_id": ev.id})

        self._send(201, {
            "status":      "created",
            "event_id":    ev.id,
            "incident_id": incident.id,
            "category":    incident.category.name,
            "severity":    incident.severity.name,
            "risk_score":  round(incident.risk_score, 3),
            "inc_status":  incident.status.name,
        })

    def _incidents(self, qs: Dict):
        limit  = int((qs.get("limit",  ["50"]))[0])
        status = (qs.get("status", [None]))[0]
        core   = self.server.core

        # Retrieve from audit trail
        rows = core.audit.last_n(limit * 2)
        seen_ids = set()
        out = []
        for row in rows:
            iid = row.get("incident_id", "")
            if not iid or iid in seen_ids:
                continue
            seen_ids.add(iid)
            # We don't store full Incident objects, so reconstruct summary from audit
            if status and row.get("event_type", "").find(status.lower()) == -1:
                pass   # filter skipped for now; full filtering requires incident store
            out.append({
                "incident_id": iid,
                "event_type":  row.get("event_type"),
                "timestamp":   row.get("timestamp"),
                "detail":      row.get("detail", {}),
            })
        self._send(200, {"incidents": out[:limit], "count": len(out[:limit])})

    def _incident_detail(self, inc_id: str):
        core = self.server.core
        rows = [r for r in core.audit.last_n(500) if r.get("incident_id") == inc_id]
        if not rows:
            return self._send(404, {"error": f"incident {inc_id!r} not found"})
        self._send(200, {"incident_id": inc_id, "audit_trail": rows})

    def _primitives(self):
        core = self.server.core
        out  = []
        for cat, fixes in core.primitives._store.items():
            for fix in fixes:
                out.append({
                    "name":         fix.name,
                    "category":     cat,
                    "description":  fix.description,
                    "cost":         fix.cost,
                    "impact":       fix.impact,
                    "version":      fix.version,
                    "source":       fix.source,
                    "success_rate": round(fix.success_rate, 3),
                    "promoted_at":  fix.promoted_at,
                })
        self._send(200, {"primitives": out, "count": len(out)})

    def _primitive_detail(self, name: str):
        core = self.server.core
        for fixes in core.primitives._store.values():
            for fix in fixes:
                if fix.name == name:
                    return self._send(200, {
                        "name":         fix.name,
                        "description":  fix.description,
                        "cost":         fix.cost,
                        "impact":       fix.impact,
                        "version":      fix.version,
                        "source":       fix.source,
                        "success_count":fix.success_count,
                        "failure_count":fix.failure_count,
                        "success_rate": round(fix.success_rate, 3),
                    })
        self._send(404, {"error": f"primitive {name!r} not found"})

    def _audit(self, qs: Dict):
        limit = int((qs.get("limit", ["100"]))[0])
        rows  = self.server.core.audit.last_n(limit)
        self._send(200, {"entries": rows, "count": len(rows)})

    def _metrics(self):
        text = self.server.core._prometheus_metrics()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode())

    def _policy_reload(self):
        try:
            self.server.core.policy.load()
            self._send(200, {"status": "reloaded"})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def _correlation_summary(self):
        self._send(200, self.server.core.correlator.summary())

    def _correlation_blast(self):
        self._send(200, self.server.core.correlator.blast_radius())

    def _plugins(self):
        manifests = [
            {
                "name":    m.name,
                "version": m.version,
                "description": m.description,
                "author":  m.author,
                "loaded":  m.loaded,
                "error":   m.error,
            }
            for m in self.server.core.plugin_loader.manifests
        ]
        self._send(200, {"plugins": manifests, "count": len(manifests)})

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _send(self, code: int, body: Any):
        payload = json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> Optional[Dict]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw    = self.rfile.read(length)
            return json.loads(raw)
        except Exception:
            return None


class APIServer:
    """Wraps ThreadingHTTPServer, runs in a daemon thread."""

    def __init__(self, core: "HealingCore", port: int = 8740, api_key: Optional[str] = None):
        self._port = port
        self._core = core

        class _Server(ThreadingHTTPServer):
            pass

        server = _Server(("", port), _Handler)
        server.core    = core        # type: ignore[attr-defined]
        server.api_key = api_key     # type: ignore[attr-defined]
        self._server   = server

    def start(self) -> None:
        t = threading.Thread(target=self._server.serve_forever, daemon=True, name="hc-api")
        t.start()
        log.info("api | listening on http://0.0.0.0:%d/api/v1/", self._port)

    def stop(self) -> None:
        self._server.shutdown()
