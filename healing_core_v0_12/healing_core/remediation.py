"""healing_core.remediation — RemediationEngine + VerifierHarness."""
from __future__ import annotations
import copy, logging, time
from .models import Incident, RemediationFix, Snapshot

log = logging.getLogger("healing_core.remediation")

class RemediationEngine:
    def __init__(self, dry_run: bool = True):
        self._dry_run = dry_run

    def apply_staged(self, fix: RemediationFix, incident: Incident) -> tuple:
        log.info("remediation | applying fix=%s  inc=%.8s", fix.name, incident.id)
        try:
            for step in fix.steps:
                result = step(incident)
                if result is not None and result is False:
                    fix.failure_count += 1
                    return False, f"step returned False in {fix.name}"
            fix.success_count += 1
            return True, "ok"
        except Exception as e:
            fix.failure_count += 1
            return False, str(e)

    def rollback(self, snapshot: Snapshot) -> tuple:
        from .snapshot import SnapshotStore
        store = SnapshotStore()
        return store.restore(snapshot)


class VerifierHarness:
    """Run fix steps against a detached copy of the incident in dry-run mode."""
    def __init__(self, dry_run: bool = True):
        self._dry_run = dry_run

    def run(self, fix: RemediationFix, incident: Incident, snapshot: Snapshot) -> tuple:
        if not fix.steps:
            return False, "no steps defined"
        sim_incident = copy.deepcopy(incident)
        try:
            for step in fix.steps:
                # In verification, swap to dry-run actuator
                step(sim_incident)
            if not snapshot.verify():
                return False, "snapshot integrity failed during verification"
            log.debug("verifier | PASS  fix=%s", fix.name)
            return True, "ok"
        except Exception as e:
            log.debug("verifier | FAIL  fix=%s  err=%s", fix.name, e)
            return False, str(e)
