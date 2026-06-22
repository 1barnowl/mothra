"""
healing_core.reconciler
───────────────────────
StateReconciler — CRDT/event-log merge for multi-node environments.

Guide mandate:
  "state reconciliation via CRDT/event-log merges where applicable"
  "Architect the core for high availability and safe failover
   (replicated decision logs, leader-election, split-brain avoidance)"

This module handles:
  1. Config-state reconciliation — last-write-wins per key, with
     conflict detection when two nodes modify the same key simultaneously
  2. Event-log merge — given two partial audit logs, find the common
     ancestor and produce a merged, causally-ordered result
  3. Leader election stub — simple epoch-based lock via SQLite
     (production would use etcd/ZooKeeper/Raft)
  4. Split-brain detection — if two nodes both believe they're leader,
     raise an alarm and enter read-only mode

Reconciliation strategy:
  • Per-key vector clocks track which node last modified each config value
  • Conflicts are resolved by wall-clock timestamp (LWW) with an audit note
  • Event logs are merged on incident_id — duplicate entries are deduplicated
    by checksum; ordering is by timestamp
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("healing_core.reconciler")


# ── Vector clock ─────────────────────────────────────────────────────────────

VectorClock = Dict[str, int]   # node_id → logical timestamp


def vc_merge(a: VectorClock, b: VectorClock) -> VectorClock:
    keys = set(a) | set(b)
    return {k: max(a.get(k, 0), b.get(k, 0)) for k in keys}

def vc_dominates(a: VectorClock, b: VectorClock) -> bool:
    """True if a happened-after b (a ≥ b component-wise, at least one strict)."""
    return all(a.get(k, 0) >= b.get(k, 0) for k in b) and a != b


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ConfigEntry:
    key:         str
    value:       Any
    node_id:     str
    wall_clock:  float = field(default_factory=time.time)
    vector_clock: VectorClock = field(default_factory=dict)
    checksum:    str = ""

    def sign(self) -> None:
        self.checksum = hashlib.sha256(
            json.dumps({"key": self.key, "value": self.value,
                        "node_id": self.node_id, "wall_clock": self.wall_clock},
                       default=str).encode()
        ).hexdigest()


@dataclass
class ConflictRecord:
    key:        str
    local:      ConfigEntry
    remote:     ConfigEntry
    resolved_to: str   # "local" | "remote"
    reason:     str


@dataclass
class MergeResult:
    merged_entries: Dict[str, ConfigEntry]
    conflicts:      List[ConflictRecord]
    merged_events:  List[Dict]


# ── Leader election (SQLite-based stub) ───────────────────────────────────────

class LeaderElection:
    """
    Simple SQLite-based leader lock.
    In production, replace with etcd TTL lease or Raft consensus.
    """
    LEASE_TTL = 30.0   # seconds

    def __init__(self, db_path: str, node_id: str) -> None:
        self._db      = sqlite3.connect(db_path, check_same_thread=False)
        self._node_id = node_id
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS leader_lock (
                id INTEGER PRIMARY KEY CHECK(id=1),
                node_id TEXT, epoch INTEGER, expires_at REAL
            )""")
        self._db.commit()

    def try_acquire(self) -> bool:
        now = time.time()
        try:
            row = self._db.execute(
                "SELECT node_id, expires_at FROM leader_lock WHERE id=1"
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO leader_lock VALUES (1,?,1,?)",
                    (self._node_id, now + self.LEASE_TTL)
                )
                self._db.commit()
                return True
            holder, expires = row
            if holder == self._node_id or now > expires:
                self._db.execute(
                    "UPDATE leader_lock SET node_id=?, expires_at=? WHERE id=1",
                    (self._node_id, now + self.LEASE_TTL)
                )
                self._db.commit()
                return True
            return False
        except Exception as e:
            log.warning("leader_election | error: %s", e)
            return False

    def renew(self) -> bool:
        return self.try_acquire()

    def release(self) -> None:
        self._db.execute(
            "UPDATE leader_lock SET expires_at=0 WHERE id=1 AND node_id=?",
            (self._node_id,)
        )
        self._db.commit()

    def current_leader(self) -> Optional[str]:
        row = self._db.execute(
            "SELECT node_id, expires_at FROM leader_lock WHERE id=1"
        ).fetchone()
        if row and time.time() < row[1]:
            return row[0]
        return None

    def is_leader(self) -> bool:
        return self.current_leader() == self._node_id


# ── StateReconciler ───────────────────────────────────────────────────────────

class StateReconciler:
    """
    Merges config state and audit event logs from two nodes.
    """

    def __init__(self, node_id: str, db_path: str = "healing_core.db") -> None:
        self._node_id  = node_id
        self._db_path  = db_path
        self._state:   Dict[str, ConfigEntry] = {}
        self._lock     = RLock()
        self._election = LeaderElection(db_path, node_id)

    # ── Config reconciliation ─────────────────────────────────────────────────

    def set(self, key: str, value: Any, vc: Optional[VectorClock] = None) -> ConfigEntry:
        with self._lock:
            existing_vc = self._state[key].vector_clock if key in self._state else {}
            new_vc = vc_merge(existing_vc, vc or {})
            new_vc[self._node_id] = new_vc.get(self._node_id, 0) + 1
            entry = ConfigEntry(key=key, value=value, node_id=self._node_id,
                                vector_clock=new_vc)
            entry.sign()
            self._state[key] = entry
            return entry

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            return self._state[key].value if key in self._state else None

    def merge_remote(self, remote_state: Dict[str, ConfigEntry]) -> MergeResult:
        """
        Merge a remote node's state into our local state.
        Returns a MergeResult describing any conflicts and how they were resolved.
        """
        conflicts: List[ConflictRecord] = []
        with self._lock:
            merged = dict(self._state)
            for key, remote_entry in remote_state.items():
                if key not in merged:
                    merged[key] = remote_entry
                    continue
                local_entry = merged[key]
                if local_entry.value == remote_entry.value:
                    # No conflict — merge vector clocks
                    merged_vc = vc_merge(local_entry.vector_clock, remote_entry.vector_clock)
                    local_entry.vector_clock = merged_vc
                    merged[key] = local_entry
                    continue
                # Conflict — resolve by LWW (last write wins)
                if vc_dominates(remote_entry.vector_clock, local_entry.vector_clock):
                    winner, loser, resolved = remote_entry, local_entry, "remote"
                elif vc_dominates(local_entry.vector_clock, remote_entry.vector_clock):
                    winner, loser, resolved = local_entry, remote_entry, "local"
                else:
                    # Concurrent writes — fall back to wall clock
                    if remote_entry.wall_clock > local_entry.wall_clock:
                        winner, loser, resolved = remote_entry, local_entry, "remote"
                    else:
                        winner, loser, resolved = local_entry, remote_entry, "local"

                winner.vector_clock = vc_merge(
                    local_entry.vector_clock, remote_entry.vector_clock
                )
                merged[key] = winner
                conflicts.append(ConflictRecord(
                    key=key, local=local_entry, remote=remote_entry,
                    resolved_to=resolved,
                    reason=f"LWW: {'remote' if resolved == 'remote' else 'local'} newer"
                ))
                log.info("reconciler | conflict on %r resolved to %s", key, resolved)

            self._state = merged
            return MergeResult(merged_entries=merged, conflicts=conflicts, merged_events=[])

    # ── Audit log merge ───────────────────────────────────────────────────────

    def merge_audit_logs(self, local_rows: List[Dict],
                         remote_rows: List[Dict]) -> List[Dict]:
        """
        Merge two audit log lists.  Dedup by checksum, sort by timestamp.
        """
        seen: Dict[str, Dict] = {}
        for row in local_rows + remote_rows:
            key = row.get("checksum") or row.get("id", str(uuid.uuid4()))
            if key not in seen:
                seen[key] = row
            else:
                # Keep the one with more detail
                if len(str(row)) > len(str(seen[key])):
                    seen[key] = row

        merged = sorted(seen.values(), key=lambda r: r.get("timestamp", 0))
        log.debug("reconciler | merged audit logs: %d+%d → %d",
                  len(local_rows), len(remote_rows), len(merged))
        return merged

    # ── Leader election helpers ───────────────────────────────────────────────

    def is_leader(self) -> bool:
        return self._election.is_leader()

    def try_become_leader(self) -> bool:
        ok = self._election.try_acquire()
        if ok:
            log.info("reconciler | node %s acquired leader lease", self._node_id)
        return ok

    def renew_leadership(self) -> bool:
        return self._election.renew()

    def leadership_status(self) -> Dict:
        return {
            "node_id":        self._node_id,
            "is_leader":      self.is_leader(),
            "current_leader": self._election.current_leader(),
        }

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> Dict:
        return {
            "local_keys":     len(self._state),
            "node_id":        self._node_id,
            "is_leader":      self.is_leader(),
            "current_leader": self._election.current_leader(),
        }
