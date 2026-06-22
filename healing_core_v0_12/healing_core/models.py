"""
healing_core.models
───────────────────
All shared dataclasses, enums, and type aliases.
Nothing in this module imports from other healing_core submodules.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional


# ── Enums ────────────────────────────────────────────────────────────────────

class IncidentCategory(Enum):
    TRANSIENT      = auto()
    SYSTEMIC       = auto()
    RESOURCE       = auto()
    SEMANTIC       = auto()
    SECURITY       = auto()
    NETWORK        = auto()
    SERVICE        = auto()
    HARDWARE       = auto()
    AUTHENTICATION = auto()
    DEPENDENCY     = auto()
    CONFIGURATION  = auto()
    MALWARE        = auto()
    DRIVER         = auto()
    UNKNOWN        = auto()

class Scope(Enum):
    MODULE    = auto()
    SUBSYSTEM = auto()
    GLOBAL    = auto()

class RemediationStatus(Enum):
    PENDING     = auto()
    STAGED      = auto()
    VERIFIED    = auto()
    COMMITTED   = auto()
    ROLLED_BACK = auto()
    ESCALATED   = auto()
    SUPPRESSED  = auto()   # new: storm suppression
    CORRELATED  = auto()   # new: folded into a parent incident

class Severity(Enum):
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


# ── Core dataclasses ─────────────────────────────────────────────────────────

@dataclass
class HealthSignal:
    source:    str
    metric:    str
    value:     float
    unit:      str   = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class Event:
    id:               str   = field(default_factory=lambda: str(uuid.uuid4()))
    actor:            str   = ""
    subsystem:        str   = ""
    error_type:       str   = ""
    message:          str   = ""
    raw:              Any   = None
    timestamp:        float = field(default_factory=time.time)
    is_health_signal: bool  = False
    fingerprint:      str   = ""

    def compute_fingerprint(self) -> str:
        """Stable hash of actor + error_type for dedup / correlation."""
        key = f"{self.actor}:{self.error_type}"
        return hashlib.md5(key.encode()).hexdigest()[:16]


@dataclass
class Incident:
    id:             str               = field(default_factory=lambda: str(uuid.uuid4()))
    event:          Event             = field(default_factory=Event)
    category:       IncidentCategory  = IncidentCategory.UNKNOWN
    scope:          Scope             = Scope.MODULE
    severity:       Severity          = Severity.MEDIUM
    risk_score:     float             = 0.0
    status:         RemediationStatus = RemediationStatus.PENDING
    timestamp:      float             = field(default_factory=time.time)
    correlation_id: str               = ""    # parent incident id if this is a child
    causal_chain:   List[str]         = field(default_factory=list)   # ordered event ids
    suppression_reason: str           = ""


@dataclass
class Snapshot:
    id:          str            = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str            = ""
    tag:         str            = ""
    state:       Dict[str, Any] = field(default_factory=dict)
    checksum:    str            = ""
    timestamp:   float          = field(default_factory=time.time)
    # v0.11: signed-checkpoint fields for deterministic replay
    signature:   str            = ""   # HMAC-SHA256 hex (cryptographic)
    replay_id:   str            = ""   # links snapshot to an audit-chain replay
    seed:        int            = 0    # deterministic RNG seed for this replay

    def sign(self) -> None:
        """Legacy self-checksum (SHA256, no secret). Kept for backward compat."""
        payload = json.dumps(self.state, sort_keys=True, default=str)
        self.checksum = hashlib.sha256(payload.encode()).hexdigest()

    def verify(self) -> bool:
        """Legacy self-checksum verification (SHA256, no secret)."""
        payload = json.dumps(self.state, sort_keys=True, default=str)
        return self.checksum == hashlib.sha256(payload.encode()).hexdigest()

    # ── v0.11: signed checkpoints (cryptographic, HMAC-SHA256) ───────────────

    def _hmac_payload(self) -> bytes:
        return json.dumps({
            "id":          self.id,
            "incident_id": self.incident_id,
            "tag":         self.tag,
            "state":       self.state,
            "timestamp":   self.timestamp,
            "replay_id":   self.replay_id,
            "seed":        self.seed,
        }, sort_keys=True, default=str).encode("utf-8")

    def sign_hmac(self, secret: bytes) -> None:
        """Sign this checkpoint with HMAC-SHA256 so it cannot be forged
        without the audit-trail secret. Required for deterministic,
        tamper-evident replay per the HealingCore guideline."""
        self.signature = hmac.new(secret, self._hmac_payload(),
                                  hashlib.sha256).hexdigest()

    def verify_hmac(self, secret: bytes) -> bool:
        """Verify this checkpoint's HMAC signature."""
        if not self.signature:
            return False
        expected = hmac.new(secret, self._hmac_payload(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass
class RemediationFix:
    id:            str              = field(default_factory=lambda: str(uuid.uuid4()))
    name:          str              = ""
    category:      IncidentCategory = IncidentCategory.UNKNOWN
    description:   str              = ""
    steps:         List[Callable]   = field(default_factory=list)
    cost:          float            = 0.0
    impact:        float            = 0.0
    version:       str              = "0.4.0"
    source:        str              = "builtin"   # builtin | plugin | ai_suggested | learned
    promoted_at:   Optional[float]  = None
    success_count: int              = 0
    failure_count: int              = 0

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total else 0.0


@dataclass
class AuditEntry:
    id:          str            = field(default_factory=lambda: str(uuid.uuid4()))
    event_type:  str            = ""
    incident_id: str            = ""
    snapshot_id: str            = ""
    actor:       str            = "healing_core"
    detail:      Dict[str, Any] = field(default_factory=dict)
    timestamp:   float          = field(default_factory=time.time)
    checksum:    str            = ""
    # v0.11: cryptographic provenance — "who/what/why/seed/replay-id"
    reason:      str            = ""   # WHY this entry was recorded
    seed:        int            = 0    # deterministic RNG seed for replay
    replay_id:   str            = ""   # groups entries for one replay/attempt
    prev_hash:   str            = ""   # hash-chain link to previous entry
    signature:   str            = ""   # HMAC-SHA256(prev_hash + payload)

    def sign(self) -> None:
        """Legacy self-checksum (SHA256, no secret). Kept for backward compat."""
        payload = json.dumps({
            "id": self.id, "event_type": self.event_type,
            "incident_id": self.incident_id, "snapshot_id": self.snapshot_id,
            "detail": self.detail, "timestamp": self.timestamp,
        }, sort_keys=True, default=str)
        self.checksum = hashlib.sha256(payload.encode()).hexdigest()

    def verify(self) -> bool:
        """Legacy self-checksum verification (SHA256, no secret)."""
        stored = self.checksum
        self.sign()
        ok = self.checksum == stored
        self.checksum = stored
        return ok

    # ── v0.11: hash-chained, HMAC-signed audit trail ─────────────────────────

    def _chain_payload(self) -> bytes:
        return json.dumps({
            "id":          self.id,
            "event_type":  self.event_type,
            "incident_id": self.incident_id,
            "snapshot_id": self.snapshot_id,
            "actor":       self.actor,
            "detail":      self.detail,
            "timestamp":   self.timestamp,
            "reason":      self.reason,
            "seed":        self.seed,
            "replay_id":   self.replay_id,
            "prev_hash":   self.prev_hash,
        }, sort_keys=True, default=str).encode("utf-8")

    def sign_chained(self, prev_hash: str, secret: bytes) -> None:
        """Link this entry to the previous entry's signature and sign with
        HMAC-SHA256. Tampering with this entry, or any entry before it,
        invalidates every signature from that point forward."""
        self.prev_hash = prev_hash
        self.signature = hmac.new(secret, self._chain_payload(),
                                  hashlib.sha256).hexdigest()

    def verify_chained(self, secret: bytes) -> bool:
        """Verify this entry's HMAC signature against its stored prev_hash."""
        if not self.signature:
            return False
        expected = hmac.new(secret, self._chain_payload(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


@dataclass
class LearningRecord:
    id:             str              = field(default_factory=lambda: str(uuid.uuid4()))
    category:       IncidentCategory = IncidentCategory.UNKNOWN
    fix_name:       str              = ""
    outcome:        str              = ""   # success | failure | verifier_failure
    detail:         str              = ""
    fingerprint:    str              = ""
    timestamp:      float            = field(default_factory=time.time)


@dataclass
class CorrelationGroup:
    """Represents a group of causally-related incidents."""
    id:          str         = field(default_factory=lambda: str(uuid.uuid4()))
    fingerprint: str         = ""
    root_event:  str         = ""        # event id that started the chain
    members:     List[str]   = field(default_factory=list)   # incident ids
    storm:       bool        = False     # True if suppressed as storm
    first_seen:  float       = field(default_factory=time.time)
    last_seen:   float       = field(default_factory=time.time)
    count:       int         = 0


# ── Plugin manifest ───────────────────────────────────────────────────────────

@dataclass
class PluginManifest:
    name:        str
    version:     str
    description: str = ""
    author:      str = ""
    path:        str = ""
    loaded:      bool = False
    error:       str  = ""
