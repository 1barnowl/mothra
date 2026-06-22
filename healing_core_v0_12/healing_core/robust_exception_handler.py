"""
healing_core.robust_exception_handler
───────────────────────────────────────
RobustExceptionHandler — guide mandate:
  "Robust exception handler"
  "web search for solution / redirect to related module"
  "exception tree — exception list and data on each Exception"
  "exception analysis for everything in list"
  "new patch/update handler"

This is the top-level dispatcher that bridges the exception/OS-fault
taxonomies with the AI oracle and program synthesizer.  It is called
by the remediation loop AFTER all registry lookups have failed.

Cascade order (guide: "layered fixes"):
  1. ExceptionCatalog lookup        — known Python exception → fix_primitive
  2. OsFaultCatalog lookup          — OS fault taxonomy → preferred primitives
  3. MultiAIOracle query            — all backends in parallel
  4. ProgramSynthesizer.synthesize  — validate + register AI command
  5. Web-search narrative logging   — even if no command, log the answer
  6. Operator escalation hint       — surface best suggestion to human

Each stage records its result to the AuditTrail so every dispatch
decision has full provenance.

The handler is stateless — all state lives in the injected subsystems.
"""
from __future__ import annotations

import logging
import time
from typing import List, Optional, TYPE_CHECKING

from .models import RemediationFix

if TYPE_CHECKING:
    from .models import Incident
    from .audit import AuditTrail
    from .exception_catalog import ExceptionCatalog
    from .os_fault_catalog import OsFaultCatalog
    from .multi_ai_oracle import MultiAIOracle, CandidateFix
    from .program_synthesizer import ProgramSynthesizer
    from .primitives import PrimitivesRegistry
    from .knowledge import KnowledgeCore

log = logging.getLogger("healing_core.robust_exception_handler")


class RobustExceptionHandler:
    """
    Cascading exception/fault dispatcher.

    Usage (called from core._remediation_loop after registry exhausted):

        fix = self.exception_handler.handle(incident)
        if fix:
            # treat like any other RemediationFix

    Guide flow:
        "if still stuck, search for already existing program that fits needs"
        "if still stuck, build program autonomously"
    """

    def __init__(
        self,
        *,
        exception_catalog:  Optional["ExceptionCatalog"]  = None,
        os_fault_catalog:   Optional["OsFaultCatalog"]    = None,
        multi_ai_oracle:    Optional["MultiAIOracle"]      = None,
        program_synthesizer: Optional["ProgramSynthesizer"] = None,
        audit:              Optional["AuditTrail"]          = None,
        primitives:         Optional["PrimitivesRegistry"]  = None,
        knowledge:          Optional["KnowledgeCore"]       = None,
        min_confidence_to_synthesize: float = 0.55,
    ) -> None:
        self._exc_catalog  = exception_catalog
        self._os_catalog   = os_fault_catalog
        self._oracle       = multi_ai_oracle
        self._synthesizer  = program_synthesizer
        self._audit        = audit
        self._primitives   = primitives
        self._knowledge    = knowledge
        self._min_conf     = min_confidence_to_synthesize

        self._dispatch_count  = 0
        self._resolved_count  = 0
        self._escalated_count = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def handle(self, incident: "Incident") -> Optional[RemediationFix]:
        """
        Main entry point.  Returns a RemediationFix or None if all stages
        exhausted.  Records every stage result to audit.
        """
        self._dispatch_count += 1
        t0 = time.monotonic()

        log.info(
            "robust_handler | dispatching inc=%.8s  etype=%s  cat=%s",
            incident.id, incident.event.error_type, incident.category.name,
        )

        # ── Stage 1: ExceptionCatalog ─────────────────────────────────────
        fix = self._stage_exception_catalog(incident)
        if fix:
            self._resolved_count += 1
            self._record("exception_catalog", incident, fix, t0)
            return fix

        # ── Stage 2: OsFaultCatalog ───────────────────────────────────────
        fix = self._stage_os_fault_catalog(incident)
        if fix:
            self._resolved_count += 1
            self._record("os_fault_catalog", incident, fix, t0)
            return fix

        # ── Stage 3: MultiAIOracle ────────────────────────────────────────
        candidates: List["CandidateFix"] = []
        if self._oracle:
            candidates = self._oracle.query(incident)

        # ── Stage 4: ProgramSynthesizer ───────────────────────────────────
        for candidate in candidates:
            if candidate.command and candidate.confidence >= self._min_conf:
                fix = self._stage_synthesize(incident, candidate)
                if fix:
                    self._resolved_count += 1
                    self._record("synthesized", incident, fix, t0)
                    return fix

        # ── Stage 5: Fallback — return top non-command AI result as hint ──
        # Even if we cannot synthesize, wrap the best description as a
        # read-only info fix (command="") so the escalation message is richer.
        if candidates:
            top = candidates[0]
            fix = RemediationFix(
                name        = top.name or f"hint_{incident.event.error_type}",
                category    = incident.category,
                description = top.description[:500],
                steps       = [lambda inc, d=top.description:
                                log.info("[oracle-hint] %s", d[:200])],
                cost        = 0.0,
                impact      = 0.0,
                source      = f"oracle_hint:{top.source}",
            )
            self._resolved_count += 1
            self._record("oracle_hint", incident, fix, t0)
            return fix

        # ── Stage 6: Total escalation ─────────────────────────────────────
        self._escalated_count += 1
        self._record("all_stages_exhausted", incident, None, t0)
        log.warning(
            "robust_handler | all stages exhausted for inc=%.8s  etype=%s",
            incident.id, incident.event.error_type,
        )
        return None

    def stats(self) -> dict:
        oracle_stats = self._oracle.stats() if self._oracle else {}
        synth_stats  = self._synthesizer.stats() if self._synthesizer else {}
        return {
            "dispatched":     self._dispatch_count,
            "resolved":       self._resolved_count,
            "escalated":      self._escalated_count,
            "resolve_rate":   round(
                self._resolved_count / max(1, self._dispatch_count), 3
            ),
            "oracle":         oracle_stats,
            "synthesizer":    synth_stats,
        }

    # ── Stage implementations ──────────────────────────────────────────────

    def _stage_exception_catalog(self, incident: "Incident") -> Optional[RemediationFix]:
        if not self._exc_catalog or not self._primitives:
            return None
        text  = f"{incident.event.error_type} {incident.event.message}"
        entry = self._exc_catalog.lookup(text)
        if not entry:
            return None
        prim_name = entry.fix_primitive
        # Find matching primitive in registry
        fix = self._find_primitive(prim_name, incident)
        if fix:
            log.info("robust_handler | exc_catalog → %s  (entry=%s)",
                     fix.name, entry.exception_class)
        return fix

    def _stage_os_fault_catalog(self, incident: "Incident") -> Optional[RemediationFix]:
        if not self._os_catalog or not self._primitives:
            return None
        import platform
        plat  = "windows" if platform.system() == "Windows" else "linux"
        text  = f"{incident.event.error_type} {incident.event.message}"
        entry = self._os_catalog.lookup(text, platform=plat)
        if not entry:
            return None
        # Try primitives in order
        for prim_name in entry.fix_primitives:
            fix = self._find_primitive(prim_name, incident)
            if fix:
                log.info("robust_handler | os_catalog → %s  (fault=%s)",
                         fix.name, entry.fault_id)
                return fix
        return None

    def _stage_synthesize(
        self,
        incident:  "Incident",
        candidate: "CandidateFix",
    ) -> Optional[RemediationFix]:
        if not self._synthesizer or not self._primitives:
            return None
        result = self._synthesizer.synthesize(
            candidate, incident, self._primitives, self._knowledge
        )
        if result.success and result.fix:
            log.info(
                "robust_handler | synthesized fix=%s  from=%s  conf=%.2f",
                result.fix.name, candidate.source, candidate.confidence,
            )
            return result.fix
        log.debug(
            "robust_handler | synthesis failed: %s  candidate=%s",
            result.reason, candidate.name,
        )
        return None

    def _find_primitive(self, name: str,
                        incident: "Incident") -> Optional[RemediationFix]:
        """Search the primitives registry for a fix by name."""
        if not self._primitives:
            return None
        # Search all categories
        for fixes in self._primitives._store.values():
            for fix in fixes:
                if fix.name == name or fix.name.endswith(f"_{name}"):
                    return fix
        # Fuzzy: substring match
        for fixes in self._primitives._store.values():
            for fix in fixes:
                if name in fix.name or fix.name in name:
                    return fix
        return None

    def _record(self, stage: str, incident: "Incident",
                fix: Optional[RemediationFix], t0: float) -> None:
        if not self._audit:
            return
        try:
            self._audit.append(
                "robust_handler_dispatch",
                incident.id,
                "",
                {
                    "stage":     stage,
                    "fix_name":  fix.name if fix else "",
                    "fix_source": fix.source if fix else "",
                    "etype":     incident.event.error_type,
                    "latency_ms": round((time.monotonic() - t0) * 1000, 1),
                },
            )
        except Exception:
            pass
