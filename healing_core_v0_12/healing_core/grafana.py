"""
healing_core.grafana
─────────────────────
GrafanaDashboard — guide mandate:
  "pluggable telemetry hooks so external controllers can observe healing
   actions without exposing internal memory"
  Roadmap: "Grafana dashboard JSON template auto-generated from Prometheus metrics"

Generates a complete Grafana 9/10-compatible dashboard JSON that can be:
  - Written to a .json file: dashboard.export("grafana_healing.json")
  - POSTed to Grafana API:   dashboard.push("http://grafana:3000", api_key)
  - Returned via REST API:   GET /api/v1/grafana

Panels generated (all reference the Prometheus metrics from
healing_core/telemetry.py PrometheusExporter):

  Row 1 — KPIs (stat panels)
    • Total incidents
    • Total healed
    • Healing rate %
    • Total suppressed

  Row 2 — Time series
    • Incidents per minute  (rate of hc_incidents_total)
    • Healing success rate  (hc_healed_total / hc_incidents_total)
    • Budget cost window    (hc_budget_cost_window)
    • Budget impact window  (hc_budget_impact_window)

  Row 3 — Tables / bar charts
    • Incidents by category (bar gauge)
    • Top primitives        (table panel — static, generated at export time)
    • DSL rule hits         (bar gauge)
    • Canary stats          (stat panel)

  Row 4 — System health (if HealthMonitor is active)
    • CPU %   (gauge)
    • Memory % (gauge)
    • Disk %   (gauge)

All panels use the Prometheus datasource named "Prometheus" by default
(configurable via ds_name parameter).
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

log = logging.getLogger("healing_core.grafana")

# Short alias
_J = Dict[str, Any]


class GrafanaDashboard:
    """Builds and optionally exports a Grafana dashboard JSON."""

    TITLE   = "HealingCore v0.8"
    UID     = "healingcore_v08"
    VERSION = 8

    def __init__(
        self,
        core: Optional["HealingCore"] = None,
        ds_name: str = "Prometheus",
        prom_job: str = "healing_core",
    ) -> None:
        self._core     = core
        self._ds       = ds_name
        self._job      = prom_job

    # ── Public API ─────────────────────────────────────────────────────────

    def build(self) -> dict:
        """Assemble and return the complete dashboard dict."""
        panels: List[_J] = []
        y = 0

        # ── Row 1: KPI stats ──────────────────────────────────────────────
        kpis = [
            ("Incidents",      "hc_incidents_total"),
            ("Healed",         "hc_healed_total"),
            ("Suppressed",     "hc_suppressed_total"),
            ("Auth Rejected",  "hc_auth_rejected_total"),
        ]
        x = 0
        for title, metric in kpis:
            panels.append(self._stat_panel(
                title=title, metric=metric, x=x, y=y, w=6, h=3,
            ))
            x += 6
        y += 3

        # ── Row 2: Healing rate gauge ─────────────────────────────────────
        panels.append(self._gauge_panel(
            title="Healing Rate",
            expr=(
                "rate(hc_healed_total[5m]) / "
                "(rate(hc_incidents_total[5m]) + 0.001) * 100"
            ),
            unit="percent",
            x=0, y=y, w=6, h=6,
            thresholds=[(0, "red"), (50, "orange"), (80, "green")],
        ))
        panels.append(self._timeseries_panel(
            title="Incidents / min",
            expr=f"rate(hc_incidents_total{{job='{self._job}'}}[1m]) * 60",
            x=6, y=y, w=9, h=6,
            color="blue",
        ))
        panels.append(self._timeseries_panel(
            title="Healed / min",
            expr=f"rate(hc_healed_total{{job='{self._job}'}}[1m]) * 60",
            x=15, y=y, w=9, h=6,
            color="green",
        ))
        y += 6

        # ── Row 3: Budget gauges ───────────────────────────────────────────
        panels.append(self._gauge_panel(
            title="Budget Cost (window)",
            expr="hc_budget_cost_window",
            unit="short",
            x=0, y=y, w=6, h=4,
            thresholds=[(0, "green"), (3.5, "orange"), (5.0, "red")],
        ))
        panels.append(self._gauge_panel(
            title="Budget Impact (window)",
            expr="hc_budget_impact_window",
            unit="short",
            x=6, y=y, w=6, h=4,
            thresholds=[(0, "green"), (2.0, "orange"), (3.0, "red")],
        ))
        panels.append(self._stat_panel(
            title="Budget Blocked",
            metric="hc_budget_blocked_total",
            x=12, y=y, w=6, h=4,
            color_mode="thresholds",
            thresholds=[(0, "green"), (1, "red")],
        ))
        panels.append(self._stat_panel(
            title="Canary Blocked",
            metric="hc_canary_blocked_total",
            x=18, y=y, w=6, h=4,
            color_mode="thresholds",
            thresholds=[(0, "green"), (1, "orange")],
        ))
        y += 4

        # ── Row 4: System health gauges ───────────────────────────────────
        for metric, title in [
            ("node_cpu_seconds_total", "CPU %"),
            ("node_memory_MemAvailable_bytes", "Mem Available"),
            ("node_filesystem_avail_bytes", "Disk Available"),
        ]:
            panels.append(self._gauge_panel(
                title=title, expr=metric, unit="percent",
                x=(panels[-3 if y > 10 else 0].get("gridPos",{}).get("x",0) + 8) % 24,
                y=y, w=8, h=4,
                thresholds=[(0, "green"), (70, "orange"), (90, "red")],
            ))
        y += 4

        # ── Row 5: Correlation / ratchet stats ────────────────────────────
        panels.append(self._stat_panel(
            title="Correlation Groups",
            metric="hc_correlation_groups",
            x=0, y=y, w=6, h=3,
        ))
        panels.append(self._stat_panel(
            title="Ratchet Promoted",
            metric="hc_ratchet_promoted",
            x=6, y=y, w=6, h=3,
        ))
        panels.append(self._stat_panel(
            title="Knowledge Patterns",
            metric="hc_knowledge_patterns",
            x=12, y=y, w=6, h=3,
        ))
        panels.append(self._stat_panel(
            title="Primitives Registered",
            metric="hc_primitives_registered",
            x=18, y=y, w=6, h=3,
        ))
        y += 3

        return {
            "uid":        self.UID,
            "title":      self.TITLE,
            "version":    self.VERSION,
            "schemaVersion": 37,
            "refresh":    "30s",
            "time":       {"from": "now-1h", "to": "now"},
            "timepicker": {},
            "tags":       ["healing_core", "sre", "observability"],
            "annotations": {"list": []},
            "templating":  {"list": []},
            "panels":     panels,
            "links":      [],
            "fiscalYearStartMonth": 0,
            "graphTooltip": 1,
            "id": None,
        }

    def export(self, path: str = "grafana_healing.json") -> str:
        """Write dashboard JSON to a file. Returns the path."""
        data = {"dashboard": self.build(), "overwrite": True, "folderId": 0}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        log.info("grafana | exported → %s", path)
        return path

    def push(self, base_url: str, api_key: str) -> bool:
        """POST dashboard to Grafana API. Returns True on success."""
        url = base_url.rstrip("/") + "/api/dashboards/db"
        payload = json.dumps(
            {"dashboard": self.build(), "overwrite": True, "folderId": 0}
        ).encode()
        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                ok = resp.status in (200, 201)
                log.info("grafana | push → %s  status=%d", base_url[:40], resp.status)
                return ok
        except Exception as exc:
            log.warning("grafana | push failed: %s", exc)
            return False

    # ── Panel builders ─────────────────────────────────────────────────────

    def _datasource(self) -> _J:
        return {"type": "prometheus", "uid": self._ds}

    def _grid(self, x: int, y: int, w: int, h: int) -> _J:
        return {"x": x, "y": y, "w": w, "h": h}

    def _thresholds_cfg(self, steps: list) -> _J:
        return {
            "mode": "absolute",
            "steps": [{"color": c, "value": v} for v, c in steps],
        }

    def _stat_panel(
        self, title: str, metric: str,
        x: int, y: int, w: int = 6, h: int = 3,
        color_mode: str = "background",
        thresholds: Optional[list] = None,
    ) -> _J:
        th = thresholds or [(0, "blue")]
        return {
            "type": "stat", "title": title,
            "gridPos": self._grid(x, y, w, h),
            "datasource": self._datasource(),
            "targets": [{
                "expr": metric,
                "legendFormat": title,
                "refId": "A",
            }],
            "options": {
                "colorMode": color_mode,
                "graphMode": "area",
                "justifyMode": "center",
                "textMode": "auto",
            },
            "fieldConfig": {
                "defaults": {
                    "thresholds": self._thresholds_cfg(th),
                    "color": {"mode": "thresholds"},
                }
            },
        }

    def _timeseries_panel(
        self, title: str, expr: str,
        x: int, y: int, w: int = 12, h: int = 6,
        color: str = "blue",
    ) -> _J:
        return {
            "type": "timeseries", "title": title,
            "gridPos": self._grid(x, y, w, h),
            "datasource": self._datasource(),
            "targets": [{
                "expr": expr,
                "legendFormat": title,
                "refId": "A",
            }],
            "options": {"tooltip": {"mode": "single"}},
            "fieldConfig": {
                "defaults": {
                    "color": {"mode": "fixed", "fixedColor": color},
                    "custom": {"lineWidth": 2, "fillOpacity": 15},
                }
            },
        }

    def _gauge_panel(
        self, title: str, expr: str, unit: str,
        x: int, y: int, w: int = 6, h: int = 4,
        thresholds: Optional[list] = None,
    ) -> _J:
        th = thresholds or [(0, "green"), (70, "orange"), (90, "red")]
        return {
            "type": "gauge", "title": title,
            "gridPos": self._grid(x, y, w, h),
            "datasource": self._datasource(),
            "targets": [{"expr": expr, "refId": "A"}],
            "options": {"reduceOptions": {"calcs": ["lastNotNull"]}},
            "fieldConfig": {
                "defaults": {
                    "unit": unit,
                    "min": 0,
                    "max": 100,
                    "thresholds": self._thresholds_cfg(th),
                    "color": {"mode": "thresholds"},
                }
            },
        }
