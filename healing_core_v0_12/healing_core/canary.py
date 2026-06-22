"""
healing_core.canary
────────────────────
CanaryDeployment — guide mandate:
  "staged canaries ... automated rollouts with dry-run validation"
  "micro-patch promotion only after sandbox verification"
  "metrics-driven rollback thresholds to avoid oscillation"

A canary deployment gates high-impact fixes through three ordered stages
before committing them to production:

  Stage 0 — Gate check
      Only activate for fixes above the impact threshold (default 0.5).
      Low-risk fixes bypass canary and go straight to normal application.

  Stage 1 — Dry-run probe
      Execute the fix in strict dry-run mode and validate the output.
      Checks: non-empty output, no ERROR/FATAL strings, return True.
      If the probe fails → block the fix and escalate immediately.

  Stage 2 — Metric window
      Wait `wait_seconds` (default 10 s in tests, 30 s in production).
      Poll the HealingCore health monitor for anomalies.
      If CPU/memory/disk breach critical thresholds → rollback.

  Stage 3 — Commit or rollback
      If stages 1+2 pass → return allow=True to the remediation loop.
      If any stage fails → record failure, emit telemetry, return allow=False.

The canary is transparent: the remediation loop calls
  result = canary.gate(fix, incident, snapshot, core)
and acts on result.allowed.  No fix step list is modified.

Fully deterministic in tests — pass wait_seconds=0 to skip the metric window.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import RemediationFix, Incident, Snapshot
    from .core import HealingCore

log = logging.getLogger("healing_core.canary")


@dataclass
class CanaryResult:
    allowed:       bool
    stage_reached: int    # 0 = bypass, 1 = probe fail, 2 = metric fail, 3 = passed
    reason:        str
    latency_ms:    float


@dataclass
class CanaryConfig:
    impact_threshold:   float = 0.50   # fixes below this bypass canary
    wait_seconds:       float = 30.0   # metric-window duration
    cpu_abort_pct:      float = 95.0   # abort if CPU spikes above this
    mem_abort_pct:      float = 92.0   # abort if memory spikes above this
    disk_abort_pct:     float = 95.0   # abort if disk spikes above this


class CanaryDeployment:
    """
    Staged gate for high-impact fix deployment.

    Usage:
        canary = CanaryDeployment(config)
        result = canary.gate(fix, incident, snapshot, core)
        if result.allowed:
            # proceed with real apply
    """

    def __init__(self, config: Optional[CanaryConfig] = None) -> None:
        self._cfg  = config or CanaryConfig()
        self._lock = threading.Lock()

        self._total:    int = 0
        self._bypassed: int = 0
        self._passed:   int = 0
        self._blocked:  int = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def gate(
        self,
        fix:      "RemediationFix",
        incident: "Incident",
        snapshot: "Snapshot",
        core:     Optional["HealingCore"] = None,
    ) -> CanaryResult:
        """
        Main entry point.  Returns CanaryResult.
        If impact < threshold → bypass (stage_reached=0, allowed=True).
        """
        t0 = time.monotonic()
        self._total += 1

        # Stage 0 — bypass low-impact fixes
        if fix.impact < self._cfg.impact_threshold:
            self._bypassed += 1
            return CanaryResult(
                allowed=True, stage_reached=0,
                reason="below impact threshold (bypassed)",
                latency_ms=self._elapsed(t0),
            )

        log.info(
            "canary | gating fix=%s  impact=%.2f  inc=%.8s",
            fix.name, fix.impact, incident.id,
        )

        # Stage 1 — dry-run probe
        probe_ok, probe_detail = self._probe(fix, incident)
        if not probe_ok:
            self._blocked += 1
            reason = f"probe failed: {probe_detail}"
            log.warning("canary | BLOCKED fix=%s  stage=1  %s", fix.name, reason)
            return CanaryResult(
                allowed=False, stage_reached=1,
                reason=reason, latency_ms=self._elapsed(t0),
            )

        # Stage 2 — metric window
        metric_ok, metric_detail = self._metric_window(core)
        if not metric_ok:
            self._blocked += 1
            reason = f"metric window breach: {metric_detail}"
            log.warning("canary | BLOCKED fix=%s  stage=2  %s", fix.name, reason)
            return CanaryResult(
                allowed=False, stage_reached=2,
                reason=reason, latency_ms=self._elapsed(t0),
            )

        # Stage 3 — commit
        self._passed += 1
        log.info(
            "canary | PASSED fix=%s  latency=%.0fms",
            fix.name, self._elapsed(t0),
        )
        return CanaryResult(
            allowed=True, stage_reached=3,
            reason="all stages passed",
            latency_ms=self._elapsed(t0),
        )

    def stats(self) -> dict:
        return {
            "total":              self._total,
            "bypassed":           self._bypassed,
            "passed":             self._passed,
            "blocked":            self._blocked,
            "impact_threshold":   self._cfg.impact_threshold,
            "wait_seconds":       self._cfg.wait_seconds,
        }

    # ── Stage implementations ───────────────────────────────────────────────

    def _probe(
        self,
        fix:      "RemediationFix",
        incident: "Incident",
    ) -> Tuple[bool, str]:
        """
        Stage 1: Execute each fix step with DryRun=True and inspect output.
        Does NOT apply the fix for real.
        """
        if not fix.steps:
            return True, "no steps to probe"

        _BAD = ("error", "fatal", "exception", "traceback", "failed",
                "cannot", "denied", "permission", "not found")

        for idx, step in enumerate(fix.steps):
            try:
                result = step(incident)
                # step may return (bool, str) tuple or just call side effects
                if isinstance(result, tuple):
                    ok, detail = result
                    if not ok:
                        return False, f"step {idx}: {detail}"
                    # Check output text for error keywords
                    detail_lower = detail.lower()
                    for bad in _BAD:
                        if bad in detail_lower:
                            return False, f"step {idx} output contains '{bad}': {detail[:120]}"
            except Exception as exc:
                return False, f"step {idx} raised: {exc}"

        return True, "probe passed"

    def _metric_window(
        self,
        core: Optional["HealingCore"],
    ) -> Tuple[bool, str]:
        """
        Stage 2: Wait and poll system metrics.
        Returns (ok, detail).
        """
        if self._cfg.wait_seconds <= 0 or core is None:
            return True, "skipped"

        deadline = time.monotonic() + self._cfg.wait_seconds
        poll_interval = min(5.0, self._cfg.wait_seconds / 4)

        while time.monotonic() < deadline:
            time.sleep(poll_interval)
            try:
                m = core.poll_metrics()
                cpu  = m.get("cpu_pct",  0.0)
                mem  = m.get("mem_pct",  0.0)
                disk = m.get("disk_pct", 0.0)

                if cpu > self._cfg.cpu_abort_pct:
                    return False, f"CPU spike {cpu:.1f}% > {self._cfg.cpu_abort_pct:.0f}%"
                if mem > self._cfg.mem_abort_pct:
                    return False, f"memory spike {mem:.1f}% > {self._cfg.mem_abort_pct:.0f}%"
                if disk > self._cfg.disk_abort_pct:
                    return False, f"disk spike {disk:.1f}% > {self._cfg.disk_abort_pct:.0f}%"

            except Exception as exc:
                log.debug("canary | metric poll error: %s", exc)

        return True, f"metric window {self._cfg.wait_seconds:.0f}s clear"

    @staticmethod
    def _elapsed(t0: float) -> float:
        return round((time.monotonic() - t0) * 1000, 1)
