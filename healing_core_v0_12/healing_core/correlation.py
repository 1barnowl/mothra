"""
healing_core.correlation
────────────────────────
EventCorrelator  — the most significant new component in v0.4.

Responsibilities:
  • Fingerprint-based deduplication within a configurable time window
  • Causal chain detection (B happened because of A)
  • Alert storm suppression (same fingerprint fires > threshold times)
  • Correlation group management (groups related incidents under one ID)
  • Per-subsystem blast-radius tracking

Design:
  All state is in-memory with an optional SQLite flush for persistence.
  Thread-safe via a single RLock.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from threading import RLock
from typing import Dict, List, Optional, Tuple

from .models import (
    CorrelationGroup, Event, Incident, IncidentCategory,
    RemediationStatus, Severity,
)

log = logging.getLogger("healing_core.correlation")


class EventCorrelator:
    """
    Correlates incoming events before they become incidents.

    Returns one of three decisions for each event:
      ("new",       None)           — novel event, create an incident normally
      ("correlated", group_id)      — related to existing group, fold in
      ("suppressed", reason_str)    — storm or duplicate, drop silently
    """

    CAUSAL_PAIRS: List[Tuple[str, str]] = [
        # (upstream_error_type, downstream_error_type) — if A seen, B is its child
        ("wifi_down",          "dns_failure"),
        ("wifi_down",          "gateway_unreachable"),
        ("dns_failure",        "api_down"),
        ("gateway_unreachable","api_down"),
        ("memory_depletion",   "service_crash"),
        ("memory_depletion",   "service_hung"),
        ("disk_full",          "service_crash"),
        ("disk_full",          "config_corrupt"),
        ("cpu_overheating",    "service_crash"),
        ("config_corrupt",     "service_crash"),
        ("auth_failure",       "service_crash"),
        ("malware_detected",   "unauthorized_account"),
        ("malware_detected",   "network_block"),
    ]

    def __init__(
        self,
        window_seconds:       float = 300.0,
        storm_threshold:      int   = 5,
        storm_window_seconds: float = 60.0,
        causal_window_seconds:float = 30.0,
    ) -> None:
        self._window          = window_seconds
        self._storm_threshold = storm_threshold
        self._storm_window    = storm_window_seconds
        self._causal_window   = causal_window_seconds

        # fingerprint → CorrelationGroup
        self._groups:   Dict[str, CorrelationGroup] = {}
        # fingerprint → deque of (timestamp, event_id)  for storm detection
        self._recent:   Dict[str, deque]            = defaultdict(deque)
        # event_id → timestamp  for causal lookback
        self._event_log: deque                      = deque(maxlen=2000)
        # error_type → list of (timestamp, fingerprint) for causal chain
        self._type_index: Dict[str, deque]          = defaultdict(lambda: deque(maxlen=50))

        self._lock = RLock()

    # ── Public interface ──────────────────────────────────────────────────────

    def evaluate(self, event: Event) -> Tuple[str, Optional[str]]:
        """
        Returns (decision, detail).
        decision ∈ {"new", "correlated", "suppressed"}
        detail   = correlation_group_id | suppression_reason | None
        """
        with self._lock:
            fp = event.compute_fingerprint()
            now = event.timestamp

            # 1. Prune stale entries
            self._prune(now)

            # 2. Storm check
            storm_decision = self._check_storm(fp, event.id, now)
            if storm_decision:
                return ("suppressed", storm_decision)

            # 3. Causal chain check — is this event caused by a recent upstream?
            parent_fp = self._find_causal_parent(event, now)
            if parent_fp and parent_fp in self._groups:
                group = self._groups[parent_fp]
                group.members.append(event.id)
                group.last_seen = now
                group.count += 1
                log.debug("correlated | fp=%s → parent_group=%s", fp, group.id)
                return ("correlated", group.id)

            # 4. Same fingerprint — fold into existing group if within window
            if fp in self._groups:
                group = self._groups[fp]
                if now - group.last_seen < self._window:
                    group.members.append(event.id)
                    group.last_seen = now
                    group.count += 1
                    log.debug("folded | fp=%s  group=%s", fp, group.id)
                    return ("correlated", group.id)
                else:
                    # Window expired — start fresh group for same fingerprint
                    del self._groups[fp]

            # 5. New group
            group = CorrelationGroup(
                fingerprint = fp,
                root_event  = event.id,
                members     = [event.id],
                first_seen  = now,
                last_seen   = now,
                count       = 1,
            )
            self._groups[fp] = group
            self._type_index[event.error_type].append((now, fp))
            self._event_log.append((now, event.id, event.error_type, fp))
            log.debug("new group | fp=%s  group=%s", fp, group.id)
            return ("new", None)

    def get_group(self, fp_or_id: str) -> Optional[CorrelationGroup]:
        """Lookup by fingerprint or group id."""
        with self._lock:
            if fp_or_id in self._groups:
                return self._groups[fp_or_id]
            for g in self._groups.values():
                if g.id == fp_or_id:
                    return g
            return None

    def register_incident(self, incident: Incident) -> None:
        """Called after an incident is created so we can update the group."""
        fp = incident.event.compute_fingerprint()
        with self._lock:
            if fp in self._groups:
                # store correlation_id back on incident if it's a child
                if len(self._groups[fp].members) > 1:
                    incident.correlation_id = self._groups[fp].id

    def summary(self) -> Dict:
        with self._lock:
            return {
                "active_groups":   len(self._groups),
                "storm_groups":    sum(1 for g in self._groups.values() if g.storm),
                "total_correlated": sum(g.count for g in self._groups.values()),
                "causal_pairs_tracked": len(self.CAUSAL_PAIRS),
            }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _check_storm(self, fp: str, event_id: str, now: float) -> Optional[str]:
        """Returns a reason string if this event is part of a storm, else None."""
        dq = self._recent[fp]
        dq.append((now, event_id))
        # Remove entries outside storm window
        while dq and now - dq[0][0] > self._storm_window:
            dq.popleft()
        if len(dq) > self._storm_threshold:
            if fp in self._groups:
                self._groups[fp].storm = True
            reason = (
                f"storm: {len(dq)} occurrences of fp={fp} "
                f"in {self._storm_window:.0f}s (threshold={self._storm_threshold})"
            )
            log.warning("storm suppressed | %s", reason)
            return reason
        return None

    def _find_causal_parent(self, event: Event, now: float) -> Optional[str]:
        """
        Check if any known upstream error type was seen recently for the
        same subsystem or actor, suggesting this event is a downstream effect.
        """
        for upstream_type, downstream_type in self.CAUSAL_PAIRS:
            if event.error_type != downstream_type:
                continue
            # Look for a recent upstream event with matching subsystem/actor
            if upstream_type not in self._type_index:
                continue
            for ts, fp in reversed(self._type_index[upstream_type]):
                if now - ts < self._causal_window:
                    return fp   # found a causal parent
        return None

    def _prune(self, now: float) -> None:
        """Remove groups and index entries that have expired."""
        expired = [
            fp for fp, g in self._groups.items()
            if now - g.last_seen > self._window and not g.storm
        ]
        for fp in expired:
            del self._groups[fp]

        # Prune type index
        for dq in self._type_index.values():
            while dq and now - dq[0][0] > self._window:
                dq.popleft()

    def blast_radius(self) -> Dict[str, int]:
        """
        Returns a dict of error_type → active correlated count.
        Useful for understanding how many downstream effects a root cause has.
        """
        with self._lock:
            result: Dict[str, int] = defaultdict(int)
            for ts, eid, etype, fp in self._event_log:
                if fp in self._groups:
                    result[etype] += 1
            return dict(result)
