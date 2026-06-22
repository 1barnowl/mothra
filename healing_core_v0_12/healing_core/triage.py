"""healing_core.triage — risk scoring and scope determination."""
from __future__ import annotations
from .models import Event, Incident, IncidentCategory, Scope, Severity
from typing import Tuple

_SCOPE_KEYWORDS = {
    Scope.GLOBAL:    ["global", "all", "system", "entire", "widespread"],
    Scope.SUBSYSTEM: ["subsystem", "service", "cluster", "pool", "layer"],
}
_SEV_WEIGHTS = {
    IncidentCategory.MALWARE: 1.0, IncidentCategory.SECURITY: 0.95,
    IncidentCategory.HARDWARE: 0.85, IncidentCategory.RESOURCE: 0.75,
    IncidentCategory.SYSTEMIC: 0.80, IncidentCategory.AUTHENTICATION: 0.70,
    IncidentCategory.SERVICE: 0.65, IncidentCategory.DEPENDENCY: 0.60,
    IncidentCategory.NETWORK: 0.55, IncidentCategory.DRIVER: 0.65,
    IncidentCategory.CONFIGURATION: 0.50, IncidentCategory.TRANSIENT: 0.30,
    IncidentCategory.SEMANTIC: 0.45, IncidentCategory.UNKNOWN: 0.40,
}

class TriageEngine:
    def score(self, event: Event, category: IncidentCategory) -> Tuple[Scope, float, Severity]:
        scope = self._scope(event)
        base  = _SEV_WEIGHTS.get(category, 0.5)
        scope_mult = {Scope.MODULE: 1.0, Scope.SUBSYSTEM: 1.3, Scope.GLOBAL: 1.7}[scope]
        risk = min(1.0, base * scope_mult)
        if   risk >= 0.85: sev = Severity.CRITICAL
        elif risk >= 0.65: sev = Severity.HIGH
        elif risk >= 0.40: sev = Severity.MEDIUM
        else:              sev = Severity.LOW
        return scope, round(risk, 3), sev

    def _scope(self, event: Event) -> Scope:
        text = f"{event.message} {event.subsystem}".lower()
        for scope, words in _SCOPE_KEYWORDS.items():
            if any(w in text for w in words):
                return scope
        return Scope.MODULE
