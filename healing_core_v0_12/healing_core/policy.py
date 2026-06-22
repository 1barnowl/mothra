"""healing_core.policy — HealingPolicy with YAML loading + hot-reload."""
from __future__ import annotations
import logging, os
from dataclasses import dataclass, field
from typing import List
from .models import Incident, IncidentCategory

log = logging.getLogger("healing_core.policy")

@dataclass
class HealingPolicy:
    yaml_path:                          str   = "healing_policy.yaml"
    max_automated_attempts:             int   = 3
    max_cost_per_fix:                   float = 0.6
    max_impact_per_fix:                 float = 0.4
    human_approval_required_above_impact:float= 0.7
    cooldown_seconds:                   float = 30.0
    storm_threshold:                    int   = 5
    escalate_on_categories:             List[str] = field(default_factory=lambda: ["SECURITY","MALWARE"])
    auto_retry_on_categories:           List[str] = field(default_factory=lambda: ["TRANSIENT","NETWORK","SERVICE"])

    def __post_init__(self):
        self.load()

    def load(self) -> None:
        if not os.path.exists(self.yaml_path):
            log.debug("policy | yaml not found, using defaults")
            return
        try:
            import yaml as _yaml
            with open(self.yaml_path) as f:
                data = _yaml.safe_load(f) or {}
            for k, v in data.items():
                if hasattr(self, k):
                    setattr(self, k, v)
            log.info("policy | loaded from %s", self.yaml_path)
        except ImportError:
            log.debug("policy | PyYAML not installed, using defaults")
        except Exception as e:
            log.warning("policy | load error: %s", e)

    def allows_auto_remediation(self, incident: Incident) -> bool:
        if incident.category.name in self.escalate_on_categories:
            return False
        if incident.risk_score > self.human_approval_required_above_impact:
            log.info("policy | human approval required (risk=%.2f)", incident.risk_score)
            return False
        return True
