"""
healing_core.budget_tracker
────────────────────────────
BudgetTracker — guide mandate:
  "instrument fine-grained resource/accounting & throttles
   (CPU/memory/I/O budgets, rate-limited remediation commands)"
  "resource budgets, operator escalation rules"
  "fixes can't starve production"

The tracker maintains a sliding-window ledger of remediation cost and
impact spend.  Before each fix is applied the core calls check(fix):
  - Returns (allowed=True, reason) if budget headroom exists
  - Returns (allowed=False, reason) if either cost OR impact ceiling
    would be breached; the fix is blocked and an escalation hint logged

Separate per-category sub-budgets are enforced so a flood of RESOURCE
fixes cannot crowd out SECURITY fixes.

Design choices:
  • Pure stdlib — no external deps
  • Thread-safe (RLock)
  • Configurable via HealingPolicy YAML (budget_* keys)
  • Emits Prometheus-style counter strings via metrics()
  • Persists nothing — in-memory sliding window only
    (restart resets the window, which is intentional for safety)
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Deque, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import RemediationFix

log = logging.getLogger("healing_core.budget_tracker")


@dataclass
class _Spend:
    """One remediation cost/impact entry in the ledger."""
    fix_name:  str
    category:  str
    cost:      float
    impact:    float
    timestamp: float = field(default_factory=time.time)


@dataclass
class BudgetConfig:
    window_seconds:    float = 3600.0   # 1-hour sliding window
    max_cost:          float = 5.0      # total cost units per window
    max_impact:        float = 3.0      # total impact units per window
    max_cost_per_cat:  float = 2.0      # per-category cost ceiling
    max_impact_per_cat:float = 1.5      # per-category impact ceiling
    warn_at_pct:       float = 0.80     # warn when spend > 80% of ceiling


class BudgetTracker:
    """Sliding-window cost/impact ledger with per-category sub-budgets."""

    def __init__(self, config: Optional[BudgetConfig] = None) -> None:
        self._cfg     = config or BudgetConfig()
        self._ledger: Deque[_Spend] = deque()
        self._lock    = threading.RLock()

        # Cumulative lifetime stats
        self._total_blocked: int = 0
        self._total_allowed: int = 0
        self._total_warned:  int = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def check(self, fix: "RemediationFix") -> Tuple[bool, str]:
        """
        Returns (allowed, reason).
        Call BEFORE applying a fix.  Does NOT record the spend — call
        record() after successful application.
        """
        with self._lock:
            self._evict()
            total_cost, total_impact = self._window_totals()
            cat = fix.category.name

            # Global ceiling checks
            if total_cost + fix.cost > self._cfg.max_cost:
                self._total_blocked += 1
                reason = (
                    f"global cost budget exhausted "
                    f"(window={total_cost:.2f}+{fix.cost:.2f} > {self._cfg.max_cost:.2f})"
                )
                log.warning("budget | BLOCKED %s — %s", fix.name, reason)
                return False, reason

            if total_impact + fix.impact > self._cfg.max_impact:
                self._total_blocked += 1
                reason = (
                    f"global impact budget exhausted "
                    f"(window={total_impact:.2f}+{fix.impact:.2f} > {self._cfg.max_impact:.2f})"
                )
                log.warning("budget | BLOCKED %s — %s", fix.name, reason)
                return False, reason

            # Per-category ceiling checks
            cat_cost, cat_impact = self._category_totals(cat)
            if cat_cost + fix.cost > self._cfg.max_cost_per_cat:
                self._total_blocked += 1
                reason = (
                    f"category[{cat}] cost budget exhausted "
                    f"({cat_cost:.2f}+{fix.cost:.2f} > {self._cfg.max_cost_per_cat:.2f})"
                )
                log.warning("budget | BLOCKED %s — %s", fix.name, reason)
                return False, reason

            if cat_impact + fix.impact > self._cfg.max_impact_per_cat:
                self._total_blocked += 1
                reason = (
                    f"category[{cat}] impact budget exhausted "
                    f"({cat_impact:.2f}+{fix.impact:.2f} > {self._cfg.max_impact_per_cat:.2f})"
                )
                log.warning("budget | BLOCKED %s — %s", fix.name, reason)
                return False, reason

            # Warn when nearing limits
            warn_ratio = self._cfg.warn_at_pct
            if total_cost / self._cfg.max_cost >= warn_ratio:
                self._total_warned += 1
                log.warning("budget | WARN global cost at %.0f%%",
                            100 * total_cost / self._cfg.max_cost)
            if total_impact / self._cfg.max_impact >= warn_ratio:
                self._total_warned += 1
                log.warning("budget | WARN global impact at %.0f%%",
                            100 * total_impact / self._cfg.max_impact)

            self._total_allowed += 1
            return True, "ok"

    def record(self, fix: "RemediationFix") -> None:
        """Record a fix that was successfully applied."""
        with self._lock:
            self._ledger.append(_Spend(
                fix_name  = fix.name,
                category  = fix.category.name,
                cost      = fix.cost,
                impact    = fix.impact,
            ))
            log.debug("budget | recorded %s  cost=%.2f  impact=%.2f",
                      fix.name, fix.cost, fix.impact)

    def summary(self) -> dict:
        """Current window totals + lifetime stats."""
        with self._lock:
            self._evict()
            cost, impact = self._window_totals()
            return {
                "window_seconds":  self._cfg.window_seconds,
                "window_cost":     round(cost, 3),
                "window_impact":   round(impact, 3),
                "max_cost":        self._cfg.max_cost,
                "max_impact":      self._cfg.max_impact,
                "cost_pct":        round(cost / self._cfg.max_cost * 100, 1),
                "impact_pct":      round(impact / self._cfg.max_impact * 100, 1),
                "ledger_entries":  len(self._ledger),
                "total_allowed":   self._total_allowed,
                "total_blocked":   self._total_blocked,
                "total_warned":    self._total_warned,
            }

    def metrics(self) -> str:
        """Prometheus-style metric lines."""
        s = self.summary()
        return (
            f"hc_budget_cost_window {s['window_cost']}\n"
            f"hc_budget_impact_window {s['window_impact']}\n"
            f"hc_budget_allowed_total {s['total_allowed']}\n"
            f"hc_budget_blocked_total {s['total_blocked']}\n"
        )

    # ── Internals ──────────────────────────────────────────────────────────

    def _evict(self) -> None:
        """Remove entries older than the sliding window."""
        cutoff = time.time() - self._cfg.window_seconds
        while self._ledger and self._ledger[0].timestamp < cutoff:
            self._ledger.popleft()

    def _window_totals(self) -> Tuple[float, float]:
        total_cost   = sum(s.cost   for s in self._ledger)
        total_impact = sum(s.impact for s in self._ledger)
        return total_cost, total_impact

    def _category_totals(self, category: str) -> Tuple[float, float]:
        entries = [s for s in self._ledger if s.category == category]
        return sum(s.cost for s in entries), sum(s.impact for s in entries)
