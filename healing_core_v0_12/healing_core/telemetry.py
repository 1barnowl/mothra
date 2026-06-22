"""healing_core.telemetry — TelemetryOutlet + PrometheusExporter."""
from __future__ import annotations
import http.server, logging, threading
from collections import deque
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

log = logging.getLogger("healing_core.telemetry")

class TelemetryOutlet:
    def __init__(self, max_log: int = 500):
        self._log: deque = deque(maxlen=max_log)

    def publish(self, event_type: str, incident_id: str, success: bool,
                meta: Dict[str, Any] = None) -> None:
        entry = {"type": event_type, "incident": incident_id[:8],
                 "success": success, "meta": meta or {}}
        self._log.append(entry)
        log.debug("telemetry | %s", entry)


class _MetricsHandler(http.server.BaseHTTPRequestHandler):
    core: "HealingCore"
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path not in ("/metrics", "/metrics/"):
            self.send_response(404); self.end_headers(); return
        body = self.server.core._prometheus_metrics().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PrometheusExporter:
    def __init__(self, port: int = 9091):
        self._port   = port
        self._server = None

    def start(self, core: "HealingCore") -> None:
        class _Srv(http.server.ThreadingHTTPServer): pass
        srv = _Srv(("", self._port), _MetricsHandler)
        srv.core = core
        self._server = srv
        t = threading.Thread(target=srv.serve_forever, daemon=True, name="hc-prom")
        t.start()
        log.info("prometheus | http://localhost:%d/metrics", self._port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
