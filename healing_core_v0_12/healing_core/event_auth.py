"""
healing_core.event_auth
───────────────────────
EventAuthenticator — telemetry integrity layer.

Guide mandate:
  "Treat telemetry integrity as first-class — authenticate, sign and
   validate sources, apply provenance checks and majority/consensus
   when possible — because bad inputs make bad diagnoses"

Features:
  • HMAC-SHA256 event signing (any secret key, rotatable)
  • Replay-attack prevention — seen event IDs rejected within TTL window
  • Source allowlist/denylist enforcement
  • Consensus voting — if multiple sources report the same fingerprint,
    confidence is boosted; single-source anomalies are held for confirmation
  • Confidence scoring — unsigned events get lower weight; forged events rejected
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import RLock
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("healing_core.event_auth")


@dataclass
class AuthPolicy:
    signing_key:          str   = "change-me-in-production"
    require_signature:    bool  = False    # False = unsigned accepted but scored lower
    allowed_sources:      List[str] = field(default_factory=list)    # empty = all
    denied_sources:       List[str] = field(default_factory=list)
    replay_ttl_seconds:   float = 300.0   # how long to remember event IDs
    consensus_threshold:  int   = 2       # reports needed to boost confidence
    single_source_weight: float = 0.7     # confidence multiplier for lone reporters
    unsigned_weight:      float = 0.6     # confidence multiplier for unsigned events


@dataclass
class AuthResult:
    accepted:    bool
    confidence:  float   # 0.0–1.0  — fed into triage risk scoring
    reason:      str
    source:      str
    signed:      bool = False


class EventAuthenticator:
    """
    Wraps event ingestion: signs outgoing events, verifies incoming ones,
    tracks sources for consensus, and blocks replays.
    """

    def __init__(self, policy: Optional[AuthPolicy] = None) -> None:
        self._policy  = policy or AuthPolicy()
        self._seen:   deque         = deque()    # (timestamp, event_id)
        self._seen_set: Set[str]    = set()
        self._votes:  Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._lock    = RLock()

    # ── Signing (for events we generate) ─────────────────────────────────────

    def sign_event(self, event_dict: dict) -> str:
        """Return HMAC-SHA256 signature for an event dict."""
        payload = json.dumps(
            {k: v for k, v in sorted(event_dict.items()) if k != "signature"},
            default=str
        ).encode()
        return hmac.new(
            self._policy.signing_key.encode(), payload, hashlib.sha256
        ).hexdigest()

    def attach_signature(self, event_dict: dict) -> dict:
        """Add 'signature' field to event dict in-place, return it."""
        event_dict["signature"] = self.sign_event(event_dict)
        return event_dict

    # ── Verification (for received events) ────────────────────────────────────

    def verify(self, event_dict: dict, source: str = "unknown") -> AuthResult:
        """
        Full verification pipeline.  Returns AuthResult with
        accepted flag and confidence score.
        """
        with self._lock:
            self._prune_replay_window()

            # 1. Source check
            if self._policy.denied_sources and source in self._policy.denied_sources:
                return AuthResult(False, 0.0, f"source {source!r} is denied", source)

            if self._policy.allowed_sources and source not in self._policy.allowed_sources:
                return AuthResult(False, 0.0, f"source {source!r} not in allowlist", source)

            # 2. Replay check
            eid = event_dict.get("id", "")
            if eid and eid in self._seen_set:
                return AuthResult(False, 0.0, f"replay detected: event_id={eid}", source)

            # 3. Signature check
            sig = event_dict.get("signature", "")
            signed = False
            if sig:
                expected = self.sign_event(event_dict)
                if not hmac.compare_digest(sig, expected):
                    return AuthResult(False, 0.0, "invalid signature", source, signed=False)
                signed = True
            elif self._policy.require_signature:
                return AuthResult(False, 0.0, "signature required but missing", source)

            # 4. Record event ID to prevent replay
            if eid:
                self._seen.append((time.time(), eid))
                self._seen_set.add(eid)

            # 5. Consensus voting
            fp = event_dict.get("fingerprint", "") or event_dict.get("error_type", "")
            confidence = self._consensus_confidence(fp, source, signed)

            return AuthResult(True, confidence, "accepted", source, signed=signed)

    def inject_vote(self, fingerprint: str, source: str) -> None:
        """External systems can manually inject consensus votes."""
        with self._lock:
            self._votes[fingerprint].append((time.time(), source))

    def consensus_level(self, fingerprint: str) -> int:
        """How many distinct sources have reported this fingerprint recently."""
        with self._lock:
            cutoff = time.time() - self._policy.replay_ttl_seconds
            entries = [(ts, src) for ts, src in self._votes.get(fingerprint, [])
                       if ts > cutoff]
            return len(set(src for _, src in entries))

    # ── Internal ──────────────────────────────────────────────────────────────

    def _consensus_confidence(self, fingerprint: str, source: str, signed: bool) -> float:
        """Compute confidence score based on consensus and signature."""
        # Record this vote
        self._votes[fingerprint].append((time.time(), source))

        distinct = self.consensus_level(fingerprint)
        base = 1.0

        if distinct < self._policy.consensus_threshold:
            base *= self._policy.single_source_weight

        if not signed:
            base *= self._policy.unsigned_weight

        return round(min(1.0, base), 3)

    def _prune_replay_window(self) -> None:
        cutoff = time.time() - self._policy.replay_ttl_seconds
        while self._seen and self._seen[0][0] < cutoff:
            _, eid = self._seen.popleft()
            self._seen_set.discard(eid)
        # Prune vote history
        for fp in list(self._votes):
            self._votes[fp] = [(ts, s) for ts, s in self._votes[fp] if ts > cutoff]
            if not self._votes[fp]:
                del self._votes[fp]

    def stats(self) -> Dict:
        with self._lock:
            return {
                "replay_window_size": len(self._seen_set),
                "active_fingerprints": len(self._votes),
                "signing_key_set": self._policy.signing_key != "change-me-in-production",
                "require_signature": self._policy.require_signature,
            }
