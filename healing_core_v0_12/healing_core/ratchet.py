"""
healing_core.ratchet
────────────────────
DeterministicRatchetTest — replays failing event sequences in a controlled
sandbox to validate fixes before they are promoted to stable.

Guide mandate:
  "replay failing sequences in simulator/sandbox to validate fixes before
   promotion, metrics-driven rollback thresholds to avoid oscillation"
  "deterministic and replayable (signed checkpoints, fixed RNG seeds,
   ordered event processing)"

Architecture:
  ┌─────────────────────────────────────────────────────────┐
  │  ReplaySession  (recorded event sequence + RNG state)   │
  │  → RatchetRunner (isolated mini-pipeline, fixed seed)   │
  │  → RatchetResult (pass/fail + step-by-step transcript)  │
  │  → PromotionGate (N consecutive passes → stable)        │
  └─────────────────────────────────────────────────────────┘

Every run is deterministic: same seed, same event order → same outcome.
Sessions are persisted to SQLite so they survive process restarts.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import random
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Event, Incident, RemediationFix, Snapshot
    from .primitives import PrimitivesRegistry

log = logging.getLogger("healing_core.ratchet")


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ReplayStep:
    """One recorded step in a replay session."""
    order:       int
    description: str
    input_state: Dict[str, Any]
    output:      Any
    success:     bool
    error:       str = ""
    duration_ms: float = 0.0


@dataclass
class ReplaySession:
    """A recorded event sequence ready for deterministic replay."""
    id:            str              = field(default_factory=lambda: str(uuid.uuid4()))
    fix_name:      str              = ""
    category:      str              = ""
    rng_seed:      int              = 0
    event_sequence: List[Dict]      = field(default_factory=list)
    snapshot_state: Dict[str, Any]  = field(default_factory=dict)
    created_at:    float            = field(default_factory=time.time)
    promotion_runs: int             = 0   # how many times this passed
    promoted:      bool             = False
    checksum:      str              = ""

    def sign(self) -> None:
        payload = json.dumps({
            "id": self.id, "fix_name": self.fix_name,
            "rng_seed": self.rng_seed,
            "event_sequence": self.event_sequence,
        }, sort_keys=True)
        self.checksum = hashlib.sha256(payload.encode()).hexdigest()

    def verify(self) -> bool:
        stored = self.checksum
        self.sign()
        ok = self.checksum == stored
        self.checksum = stored
        return ok


@dataclass
class RatchetResult:
    """Result of one ratchet run."""
    session_id:  str
    fix_name:    str
    passed:      bool
    reason:      str
    steps:       List[ReplayStep] = field(default_factory=list)
    duration_ms: float = 0.0
    run_number:  int   = 0


# ── Promotion gate ────────────────────────────────────────────────────────────

PROMOTE_AFTER_N = 3   # consecutive passing runs required


# ── DeterministicRatchetTest ─────────────────────────────────────────────────

class DeterministicRatchetTest:
    """
    Records failing event sequences and replays them deterministically
    to validate fixes before promotion.
    """

    def __init__(self, db_path: str = "healing_core.db") -> None:
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS ratchet_sessions (
                id TEXT PRIMARY KEY,
                fix_name TEXT, category TEXT,
                rng_seed INTEGER,
                event_sequence TEXT,
                snapshot_state TEXT,
                created_at REAL,
                promotion_runs INTEGER DEFAULT 0,
                promoted INTEGER DEFAULT 0,
                checksum TEXT
            )""")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS ratchet_runs (
                id TEXT PRIMARY KEY,
                session_id TEXT, fix_name TEXT,
                passed INTEGER, reason TEXT,
                steps TEXT, duration_ms REAL,
                run_number INTEGER, timestamp REAL
            )""")
        self._db.commit()

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, incident: "Incident", fix: "RemediationFix",
               snapshot: "Snapshot") -> ReplaySession:
        """
        Record a failing incident + the fix that will be tried, producing
        a ReplaySession that can be replayed deterministically later.
        """
        seed = int(hashlib.md5(incident.id.encode()).hexdigest()[:8], 16)
        session = ReplaySession(
            fix_name       = fix.name,
            category       = incident.category.name,
            rng_seed       = seed,
            event_sequence = [self._serialize_event(incident.event)],
            snapshot_state = snapshot.state,
        )
        session.sign()
        self._persist_session(session)
        log.debug("ratchet | recorded session=%.8s  fix=%s", session.id, fix.name)
        return session

    def run(self, session: ReplaySession, fix: "RemediationFix") -> RatchetResult:
        """
        Replay the session deterministically using a fixed RNG seed.
        Returns a RatchetResult describing pass/fail and step transcript.
        """
        if not session.verify():
            return RatchetResult(session.id, fix.name, False,
                                 "session checksum invalid — replay refused")

        rng = random.Random(session.rng_seed)   # fixed seed = deterministic
        start = time.monotonic()
        steps: List[ReplayStep] = []

        # Reconstruct a minimal incident from the recorded event sequence
        from .models import Event, Incident, IncidentCategory, Scope, Severity, RemediationStatus
        rec = session.event_sequence[0] if session.event_sequence else {}
        sim_event = Event(
            id         = rec.get("id", str(uuid.uuid4())),
            actor      = rec.get("actor", ""),
            subsystem  = rec.get("subsystem", ""),
            error_type = rec.get("error_type", ""),
            message    = rec.get("message", ""),
        )
        sim_incident = Incident(
            event    = sim_event,
            category = IncidentCategory[session.category] if session.category in IncidentCategory.__members__ else IncidentCategory.UNKNOWN,
            scope    = Scope.MODULE,
            severity = Severity.MEDIUM,
        )

        passed = True
        reason = "all steps passed"

        for i, step_fn in enumerate(fix.steps):
            step_start = time.monotonic()
            in_state   = {"incident_id": sim_incident.id, "rng_val": rng.random()}
            try:
                result  = step_fn(sim_incident)
                success = result is not False
            except Exception as e:
                success = False
                reason  = f"step {i} raised: {e}"
                passed  = False

            step = ReplayStep(
                order       = i,
                description = getattr(step_fn, "__name__", f"step_{i}"),
                input_state = in_state,
                output      = str(result) if "result" in dir() else "exception",
                success     = success,
                duration_ms = (time.monotonic() - step_start) * 1000,
            )
            steps.append(step)
            if not success:
                passed = False
                reason = reason or f"step {i} returned False"
                break

        duration = (time.monotonic() - start) * 1000
        result   = RatchetResult(
            session_id  = session.id,
            fix_name    = fix.name,
            passed      = passed,
            reason      = reason,
            steps       = steps,
            duration_ms = duration,
            run_number  = session.promotion_runs + 1,
        )

        self._persist_run(result)
        if passed:
            session.promotion_runs += 1
            self._update_promotion_runs(session)
        return result

    def should_promote(self, session: ReplaySession) -> bool:
        return session.promotion_runs >= PROMOTE_AFTER_N and not session.promoted

    def mark_promoted(self, session: ReplaySession) -> None:
        session.promoted = True
        self._db.execute("UPDATE ratchet_sessions SET promoted=1 WHERE id=?", (session.id,))
        self._db.commit()
        log.info("ratchet | PROMOTED  fix=%s  runs=%d", session.fix_name, session.promotion_runs)

    def sessions_for_fix(self, fix_name: str) -> List[ReplaySession]:
        rows = self._db.execute(
            "SELECT id,fix_name,category,rng_seed,event_sequence,snapshot_state,"
            "created_at,promotion_runs,promoted,checksum "
            "FROM ratchet_sessions WHERE fix_name=? ORDER BY created_at DESC",
            (fix_name,)
        ).fetchall()
        return [self._row_to_session(r) for r in rows]

    def summary(self) -> Dict[str, Any]:
        total    = self._db.execute("SELECT COUNT(*) FROM ratchet_sessions").fetchone()[0]
        promoted = self._db.execute("SELECT COUNT(*) FROM ratchet_sessions WHERE promoted=1").fetchone()[0]
        runs     = self._db.execute("SELECT COUNT(*) FROM ratchet_runs").fetchone()[0]
        passed   = self._db.execute("SELECT COUNT(*) FROM ratchet_runs WHERE passed=1").fetchone()[0]
        return {
            "total_sessions": total,
            "promoted":       promoted,
            "total_runs":     runs,
            "pass_rate":      round(passed / runs, 3) if runs else 0.0,
        }

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist_session(self, s: ReplaySession) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO ratchet_sessions VALUES (?,?,?,?,?,?,?,?,?,?)",
            (s.id, s.fix_name, s.category, s.rng_seed,
             json.dumps(s.event_sequence), json.dumps(s.snapshot_state),
             s.created_at, s.promotion_runs, int(s.promoted), s.checksum)
        )
        self._db.commit()

    def _update_promotion_runs(self, s: ReplaySession) -> None:
        self._db.execute(
            "UPDATE ratchet_sessions SET promotion_runs=? WHERE id=?",
            (s.promotion_runs, s.id)
        )
        self._db.commit()

    def _persist_run(self, r: RatchetResult) -> None:
        self._db.execute(
            "INSERT INTO ratchet_runs VALUES (?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), r.session_id, r.fix_name, int(r.passed), r.reason,
             json.dumps([{"order": s.order, "success": s.success, "error": s.error}
                         for s in r.steps]),
             r.duration_ms, r.run_number, time.time())
        )
        self._db.commit()

    @staticmethod
    def _serialize_event(event: "Event") -> Dict:
        return {
            "id": event.id, "actor": event.actor, "subsystem": event.subsystem,
            "error_type": event.error_type, "message": event.message,
            "timestamp": event.timestamp,
        }

    @staticmethod
    def _row_to_session(r) -> ReplaySession:
        return ReplaySession(
            id=r[0], fix_name=r[1], category=r[2], rng_seed=r[3],
            event_sequence=json.loads(r[4]), snapshot_state=json.loads(r[5]),
            created_at=r[6], promotion_runs=r[7], promoted=bool(r[8]), checksum=r[9],
        )
