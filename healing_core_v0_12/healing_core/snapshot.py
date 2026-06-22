"""
healing_core.snapshot — SnapshotStore with real rollback + signed checkpoints.

v0.11: Snapshots can be HMAC-signed with the same secret used by the
audit trail, turning them into "signed checkpoints" per the guideline:

  "deterministic and replayable (signed checkpoints, fixed RNG seeds,
   ordered event processing, deterministic simulator/ratchet-test harness)"

If a `secret` is supplied to SnapshotStore, every captured snapshot is
HMAC-signed (in addition to the legacy SHA256 self-checksum) and tagged
with a `replay_id` + `seed` so the exact pre-heal state can be
cryptographically verified before restore — proving the checkpoint
hasn't been tampered with since capture, independent of the audit log.

restore() prefers HMAC verification when a signature is present,
falling back to the legacy self-checksum for older / unsigned
snapshots so existing callers keep working unchanged.
"""
from __future__ import annotations
import logging, os, json, time
from typing import Optional
from .models import Incident, Snapshot

log = logging.getLogger("healing_core.snapshot")


class SnapshotStore:
    def __init__(self, secret: Optional[bytes] = None):
        self._store: dict = {}
        self._secret = secret   # shared with AuditTrail.secret when wired by core

    def capture(self, incident: Incident, *,
                replay_id: str = "", seed: int = 0) -> Snapshot:
        """Capture pre-heal state as a Snapshot.

        v0.11: if this store has a secret (shared with AuditTrail), the
        snapshot is also HMAC-signed and stamped with replay_id/seed so
        it forms part of the cryptographically-verifiable replay record
        for this remediation attempt.
        """
        state = self._collect_state(incident)
        snap = Snapshot(incident_id=incident.id, tag="pre-heal", state=state,
                        timestamp=time.time(), replay_id=replay_id, seed=seed)
        snap.sign()   # legacy self-checksum, always set for backward compat
        if self._secret:
            snap.sign_hmac(self._secret)
        self._store[snap.id] = snap
        log.debug("snapshot | captured snap=%.8s  inc=%.8s  signed=%s",
                 snap.id, incident.id, bool(snap.signature))
        return snap

    def restore(self, snap: Snapshot) -> tuple:
        """Restore config files from a snapshot.

        v0.11: if the snapshot carries an HMAC signature, it is verified
        against the store's secret (cryptographic, tamper-evident).
        Otherwise falls back to the legacy SHA256 self-checksum.
        """
        if snap.signature:
            if self._secret is None:
                return False, "signed snapshot but no secret configured to verify"
            if not snap.verify_hmac(self._secret):
                return False, "HMAC signature mismatch — checkpoint tampered"
        else:
            if not snap.verify():
                return False, "checksum mismatch — snapshot tampered"

        restored = []
        failed   = []
        for path, content in snap.state.get("config_files", {}).items():
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(content)
                restored.append(path)
            except Exception as e:
                failed.append(f"{path}: {e}")
        if failed:
            return False, f"partial restore — failed: {failed}"
        log.info("snapshot | restored %d config file(s)", len(restored))
        return True, f"restored {len(restored)} files"

    def verify(self, snap: Snapshot) -> bool:
        """Verify a snapshot's integrity using whichever signature it has."""
        if snap.signature:
            return self._secret is not None and snap.verify_hmac(self._secret)
        return snap.verify()

    def _collect_state(self, incident: Incident) -> dict:
        state: dict = {
            "event_actor":    incident.event.actor,
            "event_type":     incident.event.error_type,
            "config_files":   {},
            "env_vars":       {},
            "timestamp":      time.time(),
        }
        # Capture relevant config files based on actor/subsystem
        candidates = self._config_candidates(incident.event.actor, incident.event.subsystem)
        for path in candidates:
            try:
                if os.path.isfile(path):
                    with open(path) as f:
                        state["config_files"][path] = f.read()
            except Exception:
                pass
        # Capture relevant environment variables
        for key in ["PATH", "HOME", "PYTHONPATH", "NODE_ENV", "APP_ENV"]:
            if key in os.environ:
                state["env_vars"][key] = os.environ[key]
        return state

    def _config_candidates(self, actor: str, subsystem: str) -> list:
        candidates = []
        mapping = {
            "nginx":    ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"],
            "db":       ["/etc/mysql/my.cnf", "/etc/postgresql/postgresql.conf"],
            "network":  ["/etc/resolv.conf", "/etc/hosts", "/etc/network/interfaces"],
            "system":   ["/etc/hosts", "/etc/fstab"],
        }
        for key, paths in mapping.items():
            if key in actor.lower() or key in subsystem.lower():
                candidates.extend(paths)
        return candidates
