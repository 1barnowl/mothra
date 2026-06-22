"""
healing_core.tracing
────────────────────
Lightweight OTLP-compatible distributed tracing — zero external dependencies.

Guide mandate:
  "Distributed tracing (OpenTelemetry) for end-to-end incident lifecycle"
  "who/what/why/seed/replay-id" granular audit trail

Architecture:
  Every incident gets a trace_id.  Each pipeline stage produces a child span:
    incident_detected → [classify, triage, correlate, contain, snapshot,
                         verify, ratchet, remediate, escalate]

  Spans are stored in-memory (ring buffer) and optionally exported to an
  OTLP HTTP endpoint (Jaeger, Tempo, Zipkin via collector).

  trace_id is attached to every AuditEntry so logs correlate with traces.

  The exporter speaks OTLP JSON (not protobuf) so it works with any modern
  collector that accepts OTLP/HTTP without needing the OTel SDK.

Usage:
  tracer = Tracer(export_endpoint="http://tempo:4318/v1/traces")
  with tracer.span("classify", trace_id=inc.trace_id) as span:
      span.set("category", category.name)
      category = classify(event)
"""
from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
import urllib.request
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Generator, List, Optional

log = logging.getLogger("healing_core.tracing")


# ── Span ──────────────────────────────────────────────────────────────────────

@dataclass
class Span:
    trace_id:   str
    span_id:    str
    parent_id:  str = ""
    name:       str = ""
    start_ns:   int = field(default_factory=lambda: time.time_ns())
    end_ns:     int = 0
    status:     str = "OK"   # OK | ERROR
    attributes: Dict[str, Any] = field(default_factory=dict)
    events:     List[Dict]     = field(default_factory=list)

    def set(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def add_event(self, name: str, **attrs) -> None:
        self.events.append({"name": name, "time_unix_nano": time.time_ns(), **attrs})

    def finish(self, status: str = "OK") -> None:
        self.end_ns = time.time_ns()
        self.status = status

    @property
    def duration_ms(self) -> float:
        if self.end_ns == 0:
            return 0.0
        return (self.end_ns - self.start_ns) / 1_000_000

    def to_otlp(self) -> Dict:
        """Serialize to OTLP JSON span format."""
        return {
            "traceId":           self.trace_id,
            "spanId":            self.span_id,
            "parentSpanId":      self.parent_id,
            "name":              self.name,
            "kind":              1,  # INTERNAL
            "startTimeUnixNano": str(self.start_ns),
            "endTimeUnixNano":   str(self.end_ns or time.time_ns()),
            "status":            {"code": 1 if self.status == "OK" else 2},
            "attributes":        [
                {"key": k, "value": {"stringValue": str(v)}}
                for k, v in self.attributes.items()
            ],
            "events": [
                {"name": e["name"], "timeUnixNano": str(e["time_unix_nano"])}
                for e in self.events
            ],
        }


# ── Tracer ────────────────────────────────────────────────────────────────────

class Tracer:
    """
    Creates and manages spans for the incident lifecycle.
    Exports completed spans to OTLP HTTP endpoint in background batches.
    """

    SERVICE_NAME = "healing_core"
    BUFFER_SIZE  = 2000
    EXPORT_BATCH = 50
    EXPORT_INTERVAL_S = 5.0

    def __init__(
        self,
        export_endpoint: str = "",  # e.g. "http://localhost:4318/v1/traces"
        service_name:    str = "",
    ) -> None:
        self._endpoint    = export_endpoint.rstrip("/")
        self._service     = service_name or self.SERVICE_NAME
        self._buffer: Deque[Span] = deque(maxlen=self.BUFFER_SIZE)
        self._pending: List[Span] = []
        self._lock = threading.Lock()
        self._active: Dict[str, Span] = {}   # span_id → active span

        if self._endpoint:
            self._start_exporter()

    # ── Public API ────────────────────────────────────────────────────────────

    def new_trace_id(self) -> str:
        return "%032x" % random.getrandbits(128)

    def new_span_id(self) -> str:
        return "%016x" % random.getrandbits(64)

    def start_span(self, name: str, trace_id: str,
                   parent_id: str = "") -> Span:
        span = Span(
            trace_id  = trace_id,
            span_id   = self.new_span_id(),
            parent_id = parent_id,
            name      = name,
        )
        with self._lock:
            self._active[span.span_id] = span
        return span

    def finish_span(self, span: Span, status: str = "OK") -> None:
        span.finish(status)
        with self._lock:
            self._active.pop(span.span_id, None)
            self._buffer.append(span)
            self._pending.append(span)

    @contextmanager
    def span(self, name: str, trace_id: str,
             parent_id: str = "") -> Generator[Span, None, None]:
        """Context manager for automatic span start/finish."""
        s = self.start_span(name, trace_id, parent_id)
        try:
            yield s
            self.finish_span(s, "OK")
        except Exception as exc:
            s.set("error", str(exc))
            self.finish_span(s, "ERROR")
            raise

    def instrument_incident(self, incident_id: str,
                             trace_id: str) -> Span:
        """Create the root span for an incident."""
        span = self.start_span("incident", trace_id)
        span.set("incident_id", incident_id)
        span.set("service.name", self._service)
        return span

    def recent_traces(self, n: int = 20) -> List[Dict]:
        """Return last N completed spans as dicts for the API."""
        with self._lock:
            spans = list(self._buffer)[-n:]
        return [
            {"trace_id":   s.trace_id[:16],
             "span_id":    s.span_id[:8],
             "name":       s.name,
             "duration_ms":round(s.duration_ms, 2),
             "status":     s.status,
             "attributes": s.attributes}
            for s in reversed(spans)
        ]

    def stats(self) -> Dict:
        with self._lock:
            return {
                "buffered_spans":  len(self._buffer),
                "active_spans":    len(self._active),
                "export_endpoint": self._endpoint or "disabled",
                "service":         self._service,
            }

    # ── OTLP export ───────────────────────────────────────────────────────────

    def _start_exporter(self) -> None:
        t = threading.Thread(target=self._export_loop,
                             daemon=True, name="hc-tracer")
        t.start()
        log.info("tracing | OTLP exporter → %s", self._endpoint)

    def _export_loop(self) -> None:
        while True:
            time.sleep(self.EXPORT_INTERVAL_S)
            try:
                self._flush()
            except Exception as e:
                log.debug("tracing | export error: %s", e)

    def _flush(self) -> None:
        with self._lock:
            if not self._pending:
                return
            batch = self._pending[:self.EXPORT_BATCH]
            self._pending = self._pending[self.EXPORT_BATCH:]

        payload = json.dumps({
            "resourceSpans": [{
                "resource": {
                    "attributes": [{"key": "service.name",
                                    "value": {"stringValue": self._service}}]
                },
                "scopeSpans": [{
                    "scope": {"name": "healing_core", "version": "0.6.0"},
                    "spans": [s.to_otlp() for s in batch],
                }],
            }]
        }).encode()

        req = urllib.request.Request(
            self._endpoint + "/v1/traces",
            data    = payload,
            headers = {"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                log.debug("tracing | exported %d spans → %d", len(batch), resp.status)
        except Exception as e:
            log.debug("tracing | export failed: %s  (re-queueing)", e)
            with self._lock:
                self._pending = batch + self._pending


# ── Trace context propagation helper ─────────────────────────────────────────

_local = threading.local()

def current_trace_id() -> str:
    return getattr(_local, "trace_id", "")

def set_trace_id(tid: str) -> None:
    _local.trace_id = tid
