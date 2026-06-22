"""
healing_core.audit — AuditTrail  (v0.11: hash-chained + HMAC-signed)

Per the HealingCore guideline, the audit trail must be:
  "tamper-evident and very granular (who/what/why/seed/replay-id)"
  "cryptographic provenance"

Implementation:
  • Every entry is HMAC-SHA256 signed using a secret key
  • Each entry's signature covers its own fields PLUS the previous
    entry's signature (prev_hash) — a hash chain
  • Tampering with any entry, or deleting/reordering entries, breaks
    the chain from that point forward — detectable via verify_chain()
  • "who"  = entry.actor
    "what" = entry.event_type + entry.detail
    "why"  = entry.reason
    "seed" = entry.seed              (deterministic RNG seed for replay)
    "replay-id" = entry.replay_id    (groups entries for one attempt)

Key management:
  • If `hmac_secret` is passed explicitly, it is used directly.
  • Else if `key_path` exists, the key is loaded from that file.
  • Else if `key_path` is given but missing, a new 32-byte key is
    generated and written with mode 0600.
  • Else (no key_path, e.g. ":memory:" DBs in tests), an ephemeral
    random key is generated — the chain is internally consistent for
    the life of this process but cannot be re-verified after restart.
    A warning is logged so this is never silently relied upon in prod.
"""
from __future__ import annotations

import base64
import logging
import os
import sqlite3
import time
from typing import Dict, List, Optional, Tuple

from .models import AuditEntry

log = logging.getLogger("healing_core.audit")

GENESIS_HASH = "0" * 64


class AuditTrail:
    def __init__(self, db_path: str = "healing_core.db",
                 hmac_secret: Optional[bytes | str] = None,
                 key_path: Optional[str] = None) -> None:
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._secret = self._load_or_create_secret(hmac_secret, key_path)
        self._ensure_schema()
        self._last_signature = self._load_last_signature()

    # ── Key management ────────────────────────────────────────────────────

    @staticmethod
    def _load_or_create_secret(hmac_secret, key_path) -> bytes:
        if hmac_secret:
            if isinstance(hmac_secret, str):
                return hmac_secret.encode("utf-8")
            return hmac_secret

        if key_path:
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    raw = f.read().strip()
                try:
                    return base64.b64decode(raw)
                except Exception:
                    return raw
            # Generate + persist
            secret = os.urandom(32)
            try:
                with open(key_path, "wb") as f:
                    f.write(base64.b64encode(secret))
                os.chmod(key_path, 0o600)
                log.info("audit | generated new HMAC key → %s (mode 0600)",
                         key_path)
            except OSError as exc:
                log.warning("audit | could not persist HMAC key to %s: %s",
                            key_path, exc)
            return secret

        # No key path — ephemeral key for this process only
        log.warning(
            "audit | no hmac_secret or key_path provided — using an "
            "ephemeral in-memory key. The audit chain will be internally "
            "consistent for this process but CANNOT be re-verified after "
            "restart. Pass key_path= to persist a key.")
        return os.urandom(32)

    @property
    def secret(self) -> bytes:
        """The HMAC secret used to sign this audit chain.

        Shared with SnapshotStore so checkpoint signatures are
        verifiable against the same key material.
        """
        return self._secret

    # ── Schema ─────────────────────────────────────────────────────────────

    def _ensure_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
                id          TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                incident_id TEXT,
                snapshot_id TEXT,
                actor       TEXT,
                detail      TEXT,
                timestamp   REAL,
                checksum    TEXT,
                reason      TEXT DEFAULT '',
                seed        INTEGER DEFAULT 0,
                replay_id   TEXT DEFAULT '',
                prev_hash   TEXT DEFAULT '',
                signature   TEXT DEFAULT ''
            )
        """)
        self._conn.commit()

    def _load_last_signature(self) -> str:
        cur = self._conn.execute(
            "SELECT signature FROM audit_log ORDER BY rowid DESC LIMIT 1")
        row = cur.fetchone()
        if row and row[0]:
            return row[0]
        return GENESIS_HASH

    # ── Append (hash-chained) ─────────────────────────────────────────────

    def append(self, event_type: str, incident_id: str = "",
               snapshot_id: str = "", detail: Optional[Dict] = None, *,
               actor: str = "healing_core", reason: str = "",
               seed: int = 0, replay_id: str = "") -> AuditEntry:
        """Append a new entry to the hash-chained audit trail.

        All v0.11 kwargs (actor, reason, seed, replay_id) are optional
        and keyword-only so existing positional call sites
        (`audit.append("incident_detected", inc.id, snap.id, {...})`)
        continue to work unchanged.
        """
        import json as _json
        entry = AuditEntry(
            event_type  = event_type,
            incident_id = incident_id,
            snapshot_id = snapshot_id,
            actor       = actor,
            detail      = detail or {},
            reason      = reason,
            seed        = seed,
            replay_id   = replay_id,
        )
        # Legacy self-checksum (kept for backward compat / verify_integrity)
        entry.sign()
        # Hash-chain: link to previous signature, HMAC-sign
        entry.sign_chained(self._last_signature, self._secret)

        self._conn.execute(
            "INSERT INTO audit_log "
            "(id, event_type, incident_id, snapshot_id, actor, detail, "
            " timestamp, checksum, reason, seed, replay_id, prev_hash, signature) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (entry.id, entry.event_type, entry.incident_id, entry.snapshot_id,
             entry.actor, _json.dumps(entry.detail, default=str), entry.timestamp,
             entry.checksum, entry.reason, entry.seed, entry.replay_id,
             entry.prev_hash, entry.signature),
        )
        self._conn.commit()
        self._last_signature = entry.signature
        return entry

    # ── Queries ────────────────────────────────────────────────────────────

    def last_n(self, n: int = 20) -> List[Dict]:
        cur = self._conn.execute(
            "SELECT id, event_type, incident_id, snapshot_id, actor, detail, "
            "timestamp, checksum, reason, seed, replay_id, prev_hash, signature "
            "FROM audit_log ORDER BY rowid DESC LIMIT ?", (n,))
        return [self._row_to_dict(r) for r in cur.fetchall()]

    def by_replay_id(self, replay_id: str) -> List[Dict]:
        """All entries belonging to one replay/attempt, in chain order."""
        cur = self._conn.execute(
            "SELECT id, event_type, incident_id, snapshot_id, actor, detail, "
            "timestamp, checksum, reason, seed, replay_id, prev_hash, signature "
            "FROM audit_log WHERE replay_id = ? ORDER BY rowid ASC", (replay_id,))
        return [self._row_to_dict(r) for r in cur.fetchall()]

    def by_incident(self, incident_id: str) -> List[Dict]:
        cur = self._conn.execute(
            "SELECT id, event_type, incident_id, snapshot_id, actor, detail, "
            "timestamp, checksum, reason, seed, replay_id, prev_hash, signature "
            "FROM audit_log WHERE incident_id = ? ORDER BY rowid ASC", (incident_id,))
        return [self._row_to_dict(r) for r in cur.fetchall()]

    @staticmethod
    def _row_to_dict(row) -> Dict:
        import json as _json
        try:
            detail = _json.loads(row[5]) if row[5] else {}
        except Exception:
            detail = {}
        return {
            "id": row[0], "event_type": row[1], "incident_id": row[2],
            "snapshot_id": row[3], "actor": row[4], "detail": detail,
            "timestamp": row[6], "checksum": row[7], "reason": row[8],
            "seed": row[9], "replay_id": row[10],
            "prev_hash": row[11], "signature": row[12],
        }

    # ── Integrity verification ────────────────────────────────────────────

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """Legacy per-entry SHA256 self-checksum verification.

        Detects accidental field corruption but NOT malicious tampering
        (no secret involved). Kept for backward compatibility — use
        verify_chain() for cryptographic tamper-evidence.
        """
        bad: List[str] = []
        for row in self.last_n(10_000):
            entry = AuditEntry(
                id=row["id"], event_type=row["event_type"],
                incident_id=row["incident_id"], snapshot_id=row["snapshot_id"],
                actor=row["actor"], detail=row["detail"],
                timestamp=row["timestamp"], checksum=row["checksum"],
            )
            if not entry.verify():
                bad.append(entry.id)
        return (len(bad) == 0, bad)

    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Cryptographic tamper-evidence check (v0.11).

        Walks the entire audit log in insertion order, re-deriving each
        entry's HMAC-SHA256 signature from (prev_hash + fields) using the
        audit secret, and confirms:
          1. entry.signature matches the re-derived HMAC  (no field tampered)
          2. entry.prev_hash matches the prior entry's signature
             (no entry inserted, deleted, or reordered)

        Returns (ok, [bad_entry_ids]).  An empty list of bad IDs but
        ok=False can occur only if the chain length itself looks wrong
        (handled by returning entry IDs for any break).
        """
        cur = self._conn.execute(
            "SELECT id, event_type, incident_id, snapshot_id, actor, detail, "
            "timestamp, checksum, reason, seed, replay_id, prev_hash, signature "
            "FROM audit_log ORDER BY rowid ASC")
        rows = [self._row_to_dict(r) for r in cur.fetchall()]

        bad: List[str] = []
        expected_prev = GENESIS_HASH
        for row in rows:
            entry = AuditEntry(
                id=row["id"], event_type=row["event_type"],
                incident_id=row["incident_id"], snapshot_id=row["snapshot_id"],
                actor=row["actor"], detail=row["detail"],
                timestamp=row["timestamp"], checksum=row["checksum"],
                reason=row["reason"], seed=row["seed"],
                replay_id=row["replay_id"], prev_hash=row["prev_hash"],
                signature=row["signature"],
            )
            link_ok = (entry.prev_hash == expected_prev)
            sig_ok  = entry.verify_chained(self._secret)
            if not (link_ok and sig_ok):
                bad.append(entry.id)
            expected_prev = entry.signature
        return (len(bad) == 0, bad)

    def chain_summary(self) -> Dict:
        ok, bad = self.verify_chain()
        total = self._conn.execute(
            "SELECT COUNT(*) FROM audit_log").fetchone()[0]
        return {
            "total_entries":     total,
            "chain_valid":       ok,
            "tampered_entries":  len(bad),
            "tampered_ids":      bad[:10],   # cap for display
            "last_signature":    self._last_signature[:16] + "…"
                                  if self._last_signature != GENESIS_HASH else "(genesis)",
        }
