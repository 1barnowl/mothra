"""
healing_core.dsl
────────────────
PolicyDSL — a compact, auditable rule language for healing policy.

Guide mandate:
  "a compact DSL for policy and remediation recipes so rules are
   auditable, versioned, and easy to formally reason about"

Rule syntax (YAML):
  rules:
    - id: rule_001
      when:
        category: SECURITY
        risk_above: 0.8
      then:
        action: escalate_immediately
      priority: 100

    - id: rule_002
      when:
        error_type_matches: "wifi_*"
        scope: MODULE
      then:
        action: run_primitive
        primitive: restart_wifi
        max_attempts: 5
      priority: 50

    - id: rule_003
      when:
        actor_matches: "nginx"
        category: CONFIGURATION
      then:
        action: run_primitive
        primitive: reload_config_nginx

    - id: rule_004
      when:
        severity: CRITICAL
        category: MALWARE
      then:
        action: quarantine_and_escalate

Actions:
  escalate_immediately   — skip auto-remediation, page immediately
  allow_auto             — force allow despite policy.allows_auto check
  deny_auto              — block auto-remediation regardless
  run_primitive <name>   — run a specific primitive by name
  quarantine_and_escalate— containment + escalation
  suppress               — silently drop (useful for known-noisy signals)
  notify_only            — audit + telemetry, no remediation
"""
from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Incident

log = logging.getLogger("healing_core.dsl")


# ── DSL Rule structures ───────────────────────────────────────────────────────

@dataclass
class DSLCondition:
    category:       Optional[str]   = None   # exact category name
    categories:     List[str]       = field(default_factory=list)
    error_type_matches: Optional[str] = None  # glob pattern
    actor_matches:  Optional[str]   = None
    scope:          Optional[str]   = None
    severity:       Optional[str]   = None
    risk_above:     Optional[float] = None
    risk_below:     Optional[float] = None
    subsystem_matches: Optional[str] = None

    def matches(self, incident: "Incident") -> bool:
        inc = incident

        if self.category and inc.category.name != self.category:
            return False
        if self.categories and inc.category.name not in self.categories:
            return False
        if self.error_type_matches:
            if not fnmatch.fnmatch(inc.event.error_type, self.error_type_matches):
                return False
        if self.actor_matches:
            if not fnmatch.fnmatch(inc.event.actor, self.actor_matches):
                return False
        if self.scope and inc.scope.name != self.scope:
            return False
        if self.severity and inc.severity.name != self.severity:
            return False
        if self.risk_above is not None and inc.risk_score <= self.risk_above:
            return False
        if self.risk_below is not None and inc.risk_score >= self.risk_below:
            return False
        if self.subsystem_matches:
            if not fnmatch.fnmatch(inc.event.subsystem, self.subsystem_matches):
                return False
        return True


@dataclass
class DSLAction:
    action:       str            # see Actions list above
    primitive:    Optional[str]  = None
    max_attempts: Optional[int]  = None
    escalation_msg: str          = ""


@dataclass
class DSLRule:
    id:       str
    when:     DSLCondition
    then:     DSLAction
    priority: int  = 50
    enabled:  bool = True
    hit_count: int = 0


# ── DSL evaluation result ─────────────────────────────────────────────────────

@dataclass
class DSLDecision:
    matched_rule: Optional[str]  = None   # rule id
    action:       Optional[str]  = None
    primitive:    Optional[str]  = None
    max_attempts: Optional[int]  = None
    override_auto: Optional[bool] = None  # True=force allow, False=force deny, None=no override


# ── PolicyDSL ─────────────────────────────────────────────────────────────────

class PolicyDSL:
    """
    Loads and evaluates DSL rules.  The DSL is a layer ABOVE the
    HealingPolicy defaults — rules with higher priority fire first.
    """

    def __init__(self, rules_yaml_path: str = "healing_policy.yaml") -> None:
        self._path  = rules_yaml_path
        self._rules: List[DSLRule] = []
        self.load()

    def load(self) -> None:
        """(Re)load rules from YAML file."""
        if not os.path.exists(self._path):
            self._rules = self._builtin_rules()
            return
        try:
            import yaml as _yaml
            with open(self._path) as f:
                data = _yaml.safe_load(f) or {}
            raw_rules = data.get("rules", [])
            self._rules = [self._parse_rule(r) for r in raw_rules]
            log.info("dsl | loaded %d rule(s) from %s", len(self._rules), self._path)
        except ImportError:
            log.debug("dsl | PyYAML not installed, using built-in rules")
            self._rules = self._builtin_rules()
        except Exception as e:
            log.warning("dsl | load error: %s — using built-ins", e)
            self._rules = self._builtin_rules()

    def evaluate(self, incident: "Incident") -> DSLDecision:
        """
        Evaluate rules in priority order.  Returns the first match.
        """
        # Sort descending by priority so highest priority fires first
        for rule in sorted(self._rules, key=lambda r: r.priority, reverse=True):
            if not rule.enabled:
                continue
            if rule.when.matches(incident):
                rule.hit_count += 1
                log.debug("dsl | rule %s matched  action=%s", rule.id, rule.then.action)
                return self._to_decision(rule)
        return DSLDecision()  # no match — use default policy

    def simulate(self, incident: "Incident") -> "DSLDecision":
        """Dry-run policy evaluation — does NOT increment hit_count on any rule."""
        for rule in sorted(self._rules, key=lambda r: r.priority, reverse=True):
            if not rule.enabled:
                continue
            if rule.when.matches(incident):
                # Return decision without touching rule.hit_count
                return self._to_decision(rule)
        return DSLDecision()

    def detect_conflicts(self) -> List[Dict]:
        """Return list of conflicting rule pairs.

        A conflict is two rules whose *when* conditions overlap
        (identical category/error_type/actor match) but whose
        *then* actions differ in a meaningful way.
        """
        conflicts = []
        rules = self._rules
        for i, a in enumerate(rules):
            for b in rules[i+1:]:
                if self._conditions_overlap(a, b):
                    action_a = self._rule_action(a)
                    action_b = self._rule_action(b)
                    if action_a != action_b:
                        id_a = a.id if hasattr(a, "id") else a.get("id","?")
                        id_b = b.id if hasattr(b, "id") else b.get("id","?")
                        conflicts.append({
                            "rule_a":      id_a,
                            "rule_b":      id_b,
                            "action_a":    action_a,
                            "action_b":    action_b,
                            "conflict":    "overlapping_conditions_different_actions",
                            "description": (
                                f"Rules '{id_a}' ({action_a}) and "
                                f"'{id_b}' ({action_b}) match the same "
                                f"incidents but prescribe different actions."
                            ),
                        })
        return conflicts

    @staticmethod
    def _rule_action(rule) -> str:
        then = rule.then if hasattr(rule, "then") else rule.get("then", {})
        if hasattr(then, "action"):
            return then.action or "allow"
        return then.get("action", "allow") if isinstance(then, dict) else "allow"

    @staticmethod
    def _conditions_overlap(rule_a, rule_b) -> bool:
        """Heuristic: rules overlap if they share a category or error_type condition."""
        def _get(rule, field):
            when = rule.when if hasattr(rule, "when") else rule.get("when", {})
            if hasattr(when, field):
                return getattr(when, field)
            if isinstance(when, dict):
                return when.get(field)
            return None

        # Overlap on single category
        ca = _get(rule_a, "category")
        cb = _get(rule_b, "category")
        if ca and ca == cb:
            return True

        # Overlap on categories list intersection
        cats_a = _get(rule_a, "categories") or ([] if not ca else [ca])
        cats_b = _get(rule_b, "categories") or ([] if not cb else [cb])
        if cats_a and cats_b:
            if set(cats_a) & set(cats_b):
                return True

        # Overlap on error_type_matches
        ea = _get(rule_a, "error_type_matches")
        eb = _get(rule_b, "error_type_matches")
        if ea and ea == eb:
            return True

        # Overlap on actor_matches
        aa = _get(rule_a, "actor_matches")
        ab = _get(rule_b, "actor_matches")
        if aa and aa == ab:
            return True

        return False

    def rule_stats(self) -> List[Dict]:
        return [{"id": r.id, "action": r.then.action,
                 "priority": r.priority, "hits": r.hit_count, "enabled": r.enabled}
                for r in self._rules]

    # ── Parsing ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_rule(raw: Dict) -> DSLRule:
        when_raw = raw.get("when", {})
        then_raw = raw.get("then", {})
        cond = DSLCondition(
            category          = when_raw.get("category"),
            categories        = when_raw.get("categories", []),
            error_type_matches= when_raw.get("error_type_matches"),
            actor_matches     = when_raw.get("actor_matches"),
            scope             = when_raw.get("scope"),
            severity          = when_raw.get("severity"),
            risk_above        = when_raw.get("risk_above"),
            risk_below        = when_raw.get("risk_below"),
            subsystem_matches = when_raw.get("subsystem_matches"),
        )
        action = DSLAction(
            action       = then_raw.get("action", "allow_auto"),
            primitive    = then_raw.get("primitive"),
            max_attempts = then_raw.get("max_attempts"),
            escalation_msg = then_raw.get("escalation_msg", ""),
        )
        return DSLRule(
            id       = str(raw.get("id", f"rule_{id(raw)}")),
            when     = cond,
            then     = action,
            priority = int(raw.get("priority", 50)),
            enabled  = bool(raw.get("enabled", True)),
        )

    @staticmethod
    def _to_decision(rule: DSLRule) -> DSLDecision:
        action = rule.then.action
        override = None
        if action in ("allow_auto",):
            override = True
        elif action in ("deny_auto", "escalate_immediately",
                        "quarantine_and_escalate", "suppress", "notify_only"):
            override = False
        return DSLDecision(
            matched_rule  = rule.id,
            action        = action,
            primitive     = rule.then.primitive,
            max_attempts  = rule.then.max_attempts,
            override_auto = override,
        )

    # ── Built-in rules (loaded when YAML is absent / has no 'rules' key) ─────

    @staticmethod
    def _builtin_rules() -> List[DSLRule]:
        return [
            DSLRule("builtin_security_escalate",
                    DSLCondition(categories=["SECURITY", "MALWARE"], risk_above=0.5),
                    DSLAction("escalate_immediately"), priority=100),

            DSLRule("builtin_critical_hardware",
                    DSLCondition(category="HARDWARE", severity="CRITICAL"),
                    DSLAction("escalate_immediately"), priority=95),

            DSLRule("builtin_suppress_test_actors",
                    DSLCondition(actor_matches="test_*"),
                    DSLAction("suppress"), priority=90),

            DSLRule("builtin_auto_network_transient",
                    DSLCondition(categories=["NETWORK", "TRANSIENT"]),
                    DSLAction("allow_auto", max_attempts=5), priority=40),

            DSLRule("builtin_notify_unknown",
                    DSLCondition(category="UNKNOWN"),
                    DSLAction("notify_only"), priority=30),
        ]
