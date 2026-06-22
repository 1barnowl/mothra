"""healing_core.containment — cross-platform ContainmentEngine."""
from __future__ import annotations
import logging, platform
from .models import Incident, Scope

log = logging.getLogger("healing_core.containment")
OS = platform.system()

class ContainmentEngine:
    def __init__(self, dry_run: bool = True):
        self._dry_run = dry_run
        self._active: dict = {}

    def apply(self, incident: Incident) -> None:
        actor = incident.event.actor
        if actor in self._active:
            return
        if incident.scope == Scope.MODULE:
            self._quarantine(actor, incident)
        elif incident.scope == Scope.SUBSYSTEM:
            self._throttle(actor, incident)
        else:
            self._degraded(incident)
        self._active[actor] = incident.scope

    def release(self, actor: str) -> None:
        if actor not in self._active:
            return
        log.info("containment | released actor=%s", actor)
        if OS == "Linux":
            try:
                from drivers.linux import release_cgroup
                release_cgroup(actor)
            except Exception: pass
        del self._active[actor]

    def _quarantine(self, actor: str, incident: Incident) -> None:
        log.info("containment | quarantine actor=%s", actor)
        if OS == "Linux":
            try:
                from drivers.linux import apply_cgroup_limits
                apply_cgroup_limits(actor, cpu_pct=10, mem_mb=128)
            except Exception as e:
                log.debug("cgroup error: %s", e)
        elif OS == "Windows":
            try:
                from drivers.windows import lower_process_priority
                lower_process_priority(actor)
            except Exception as e:
                log.debug("priority error: %s", e)

    def _throttle(self, actor: str, incident: Incident) -> None:
        log.info("containment | throttle subsystem=%s", incident.event.subsystem)
        if OS == "Linux":
            try:
                from drivers.linux import apply_cgroup_limits
                apply_cgroup_limits(actor, cpu_pct=30, mem_mb=512)
            except Exception: pass

    def _degraded(self, incident: Incident) -> None:
        log.warning("containment | GLOBAL degraded mode — subsystem=%s", incident.event.subsystem)
