"""
healing_core.reporter
─────────────────────
HealthReporter — generates a self-contained HTML report with SVG charts
showing incident trends, fix success rates, DSL rule hits, ratchet status,
knowledge base stats, and auth metrics.

No external dependencies — pure stdlib + inline SVG/CSS.

Usage:
    reporter = HealthReporter(core)
    html     = reporter.generate()
    reporter.write("healing_report.html")

Also served at GET /api/v1/report
"""
from __future__ import annotations

import html
import json
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore


# ── SVG chart helpers ─────────────────────────────────────────────────────────

def _bar_chart(data: List[Tuple[str, int]], width=480, height=160,
               color="#4f8ef7") -> str:
    if not data:
        return "<p style='color:#888'>No data</p>"
    max_v = max(v for _, v in data) or 1
    bar_w = max(8, (width - 40) // len(data) - 4)
    bars  = []
    labels = []
    for i, (label, val) in enumerate(data):
        x   = 20 + i * (bar_w + 4)
        bh  = int((val / max_v) * (height - 40))
        y   = height - 20 - bh
        tip = html.escape(f"{label}: {val}")
        bars.append(
            f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bh}" '
            f'fill="{color}" rx="2" opacity="0.85"><title>{tip}</title></rect>'
        )
        bars.append(
            f'<text x="{x + bar_w//2}" y="{height - 4}" text-anchor="middle" '
            f'font-size="9" fill="#666">{html.escape(label[:8])}</text>'
        )
        bars.append(
            f'<text x="{x + bar_w//2}" y="{y - 3}" text-anchor="middle" '
            f'font-size="9" fill="#333">{val}</text>'
        )
    return (f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">'
            + "".join(bars) + "</svg>")


def _gauge(value: float, label: str, width=120, height=90) -> str:
    pct  = max(0.0, min(1.0, value))
    color = "#28a745" if pct >= 0.7 else "#ffc107" if pct >= 0.4 else "#dc3545"
    r    = 36
    cx, cy = width // 2, height - 10
    # Arc math (semicircle, left→right)
    import math
    start_angle = math.pi
    end_angle   = start_angle + pct * math.pi
    sx = cx + r * math.cos(start_angle)
    sy = cy + r * math.sin(start_angle)
    ex = cx + r * math.cos(end_angle)
    ey = cy + r * math.sin(end_angle)
    large = 1 if pct > 0.5 else 0
    return (
        f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">'
        f'<path d="M {cx-r},{cy} A {r},{r} 0 0,1 {cx+r},{cy}" '
        f'fill="none" stroke="#e9ecef" stroke-width="8"/>'
        f'<path d="M {sx:.1f},{sy:.1f} A {r},{r} 0 {large},1 {ex:.1f},{ey:.1f}" '
        f'fill="none" stroke="{color}" stroke-width="8" stroke-linecap="round"/>'
        f'<text x="{cx}" y="{cy-8}" text-anchor="middle" font-size="14" '
        f'font-weight="bold" fill="{color}">{int(pct*100)}%</text>'
        f'<text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="9" '
        f'fill="#666">{html.escape(label)}</text>'
        f'</svg>'
    )


def _kv_table(rows: List[Tuple[str, Any]]) -> str:
    inner = "".join(
        f'<tr><td class="k">{html.escape(str(k))}</td>'
        f'<td class="v">{html.escape(str(v))}</td></tr>'
        for k, v in rows
    )
    return f'<table class="kv">{inner}</table>'


# ── HealthReporter ────────────────────────────────────────────────────────────

class HealthReporter:
    def __init__(self, core: "HealingCore") -> None:
        self._core = core

    def generate(self) -> str:
        core = self._core
        now  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        uptime_s = int(time.time() - core._start_time)
        h, m, s  = uptime_s//3600, (uptime_s%3600)//60, uptime_s%60

        # ── Data gathering ────────────────────────────────────────────────────

        audit_rows  = core.audit.last_n(500)
        stats       = dict(core._stats)
        prim_count  = sum(len(v) for v in core.primitives._store.values())
        corr_sum    = core.correlator.summary()
        ratch_sum   = core.ratchet.summary()
        dsl_stats   = core.dsl.rule_stats()
        auth_stats  = core.event_auth.stats()
        rec_sum     = core.reconciler.summary()

        # Incident counts by event_type
        etype_counts: Counter = Counter()
        status_counts: Counter = Counter()
        for row in audit_rows:
            et = row.get("event_type", "")
            etype_counts[et] += 1
            d = row.get("detail", {})
            if isinstance(d, dict) and "category" in d:
                status_counts[d.get("category", "UNKNOWN")] += 1

        top_etypes = etype_counts.most_common(8)
        top_cats   = status_counts.most_common(8)

        # Healing rate
        total = stats.get("total_incidents", 0)
        healed = stats.get("total_healed", 0)
        heal_rate = healed / total if total else 0.0

        # DSL hit chart data
        dsl_data = [(r["id"][:12], r["hits"]) for r in dsl_stats if r["hits"] > 0]

        # Primitive performance
        prim_rows: List[Tuple[str, int, int]] = []
        for cat, fixes in list(core.primitives._store.items())[:]:
            for f in fixes:
                if f.success_count + f.failure_count > 0:
                    prim_rows.append((f.name, f.success_count, f.failure_count))
        prim_rows.sort(key=lambda x: x[1], reverse=True)

        # Knowledge summary
        try:
            know_sum = core.knowledge.summary() if hasattr(core, "knowledge") else {}
        except Exception:
            know_sum = {}

        # Alertmanager stats
        try:
            am_stats = core.alertmanager_bridge.stats() if hasattr(core, "alertmanager_bridge") else {}
        except Exception:
            am_stats = {}

        # Tracing stats
        try:
            trace_stats = core.tracer.stats() if hasattr(core, "tracer") else {}
            recent_traces = core.tracer.recent_traces(5) if hasattr(core, "tracer") else []
        except Exception:
            trace_stats, recent_traces = {}, []

        # ── HTML assembly ─────────────────────────────────────────────────────

        sections = []

        # Header
        sections.append(f"""
        <div class="header">
            <h1>⚕ HealingCore v0.6 — Health Report</h1>
            <p class="ts">Generated {now} &nbsp;|&nbsp; Uptime {h}h {m}m {s}s
               &nbsp;|&nbsp; Node: {html.escape(rec_sum.get('node_id','?'))}</p>
        </div>""")

        # KPI row
        sections.append(f"""
        <div class="kpi-row">
            <div class="kpi">
                <div class="kpi-val">{total}</div>
                <div class="kpi-label">Total Incidents</div>
            </div>
            <div class="kpi">
                <div class="kpi-val" style="color:#28a745">{healed}</div>
                <div class="kpi-label">Auto-Healed</div>
            </div>
            <div class="kpi">
                <div class="kpi-val" style="color:#dc3545">{stats.get('suppressed',0)}</div>
                <div class="kpi-label">Storm-Suppressed</div>
            </div>
            <div class="kpi">
                <div class="kpi-val">{prim_count}</div>
                <div class="kpi-label">Primitives</div>
            </div>
            <div class="kpi">
                <div class="kpi-val">{ratch_sum.get('promoted',0)}</div>
                <div class="kpi-label">Promoted Fixes</div>
            </div>
            <div class="kpi">
                <div class="kpi-val" style="color:#fd7e14">{stats.get('auth_rejected',0)}</div>
                <div class="kpi-label">Auth Rejected</div>
            </div>
        </div>""")

        # Heal rate gauge + category chart
        gauge_html  = _gauge(heal_rate, "Heal Rate")
        ratch_rate  = _gauge(ratch_sum.get("pass_rate", 0.0), "Ratchet Pass")
        cat_chart   = _bar_chart(top_cats,   color="#4f8ef7")
        etype_chart = _bar_chart(top_etypes, color="#20c997")

        sections.append(f"""
        <div class="row">
            <div class="card" style="flex:0 0 260px">
                <h2>Healing Rates</h2>
                <div style="display:flex;gap:16px;align-items:center">
                    {gauge_html}{ratch_rate}
                </div>
                {_kv_table([
                    ("Total incidents", total),
                    ("Healed",          healed),
                    ("Escalated",       total - healed - stats.get('suppressed',0)),
                    ("Suppressed",      stats.get('suppressed',0)),
                    ("Auth rejected",   stats.get('auth_rejected',0)),
                ])}
            </div>
            <div class="card">
                <h2>Incidents by Category</h2>
                {cat_chart}
            </div>
            <div class="card">
                <h2>Top Audit Event Types</h2>
                {etype_chart}
            </div>
        </div>""")

        # Correlator + Ratchet
        sections.append(f"""
        <div class="row">
            <div class="card">
                <h2>EventCorrelator</h2>
                {_kv_table(list(corr_sum.items()))}
            </div>
            <div class="card">
                <h2>RatchetTest</h2>
                {_kv_table(list(ratch_sum.items()))}
            </div>
            <div class="card">
                <h2>Reconciler / HA</h2>
                {_kv_table(list(rec_sum.items()))}
            </div>
        </div>""")

        # DSL rules chart
        if dsl_data:
            sections.append(f"""
            <div class="card full">
                <h2>DSL Rule Hits</h2>
                {_bar_chart(dsl_data, width=780, color="#6f42c1")}
                <div class="table-wrap">
                <table>
                  <tr><th>Rule ID</th><th>Action</th><th>Priority</th><th>Hits</th><th>Enabled</th></tr>
                  {"".join(f'<tr><td>{html.escape(r["id"])}</td><td>{r["action"]}</td>'
                           f'<td>{r["priority"]}</td><td>{r["hits"]}</td>'
                           f'<td>{"✓" if r["enabled"] else "✗"}</td></tr>'
                           for r in dsl_stats)}
                </table></div>
            </div>""")

        # Top primitives
        if prim_rows:
            sections.append(f"""
            <div class="card full">
                <h2>Top Primitive Performance</h2>
                <div class="table-wrap">
                <table>
                  <tr><th>Name</th><th>Success</th><th>Failure</th><th>Rate</th></tr>
                  {"".join(
                      f'<tr><td>{html.escape(name)}</td><td class="num">{ok}</td>'
                      f'<td class="num">{fail}</td>'
                      f'<td class="num">{ok/(ok+fail)*100:.0f}%</td></tr>'
                      for name, ok, fail in prim_rows[:15]
                  )}
                </table></div>
            </div>""")

        # Knowledge base
        if know_sum:
            sections.append(f"""
            <div class="card">
                <h2>KnowledgeCore</h2>
                {_kv_table(list(know_sum.items()))}
            </div>""")

        # Alertmanager + Tracing
        if am_stats or trace_stats:
            cards = ""
            if am_stats:
                cards += f'<div class="card"><h2>Alertmanager Bridge</h2>{_kv_table(list(am_stats.items()))}</div>'
            if trace_stats:
                cards += f'<div class="card"><h2>Tracing</h2>{_kv_table(list(trace_stats.items()))}</div>'
            if recent_traces:
                rows_html = "".join(
                    f'<tr><td style="font-family:monospace;font-size:11px">{t["trace_id"]}</td>'
                    f'<td>{html.escape(t["name"])}</td><td>{t["duration_ms"]}ms</td>'
                    f'<td style="color:{"#28a745" if t["status"]==chr(79)+chr(75) else "#dc3545"}">{t["status"]}</td></tr>'
                    for t in recent_traces
                )
                cards += f"""
                <div class="card">
                    <h2>Recent Traces</h2>
                    <div class="table-wrap">
                    <table>
                      <tr><th>Trace ID</th><th>Span</th><th>Duration</th><th>Status</th></tr>
                      {rows_html}
                    </table></div>
                </div>"""
            sections.append(f'<div class="row">{cards}</div>')

        # Auth stats
        sections.append(f"""
        <div class="card">
            <h2>EventAuthenticator</h2>
            {_kv_table(list(auth_stats.items()))}
        </div>""")

        # Recent audit entries
        recent_audit = audit_rows[:10]
        if recent_audit:
            rows_html = "".join(
                f'<tr><td style="font-size:11px;color:#888">'
                f'{time.strftime("%H:%M:%S", time.gmtime(r.get("timestamp",0)))}</td>'
                f'<td>{html.escape(r.get("event_type",""))}</td>'
                f'<td style="font-family:monospace;font-size:11px">'
                f'{html.escape(str(r.get("incident_id",""))[:12])}</td></tr>'
                for r in recent_audit
            )
            sections.append(f"""
            <div class="card full">
                <h2>Recent Audit Entries</h2>
                <div class="table-wrap">
                <table>
                  <tr><th>Time</th><th>Event Type</th><th>Incident ID</th></tr>
                  {rows_html}
                </table></div>
            </div>""")

        body = "\n".join(sections)
        return _wrap_html(body, now)

    def write(self, path: str = "healing_report.html") -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.generate())


def _wrap_html(body: str, ts: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HealingCore Report — {ts}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #f8f9fa; color: #212529; padding: 20px; }}
  .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
             color: #fff; padding: 20px 28px; border-radius: 10px;
             margin-bottom: 20px; }}
  .header h1 {{ font-size: 22px; font-weight: 700; }}
  .ts {{ font-size: 12px; color: #adb5bd; margin-top: 6px; }}
  .kpi-row {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
  .kpi {{ background: #fff; border-radius: 8px; padding: 16px 20px; flex: 1 1 120px;
          box-shadow: 0 1px 4px rgba(0,0,0,.08); text-align: center; }}
  .kpi-val {{ font-size: 28px; font-weight: 700; }}
  .kpi-label {{ font-size: 12px; color: #6c757d; margin-top: 4px; }}
  .row {{ display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }}
  .card {{ background: #fff; border-radius: 8px; padding: 20px;
           box-shadow: 0 1px 4px rgba(0,0,0,.08); flex: 1 1 240px; }}
  .card.full {{ flex: 1 1 100%; }}
  .card h2 {{ font-size: 14px; font-weight: 600; color: #495057;
              border-bottom: 1px solid #dee2e6; padding-bottom: 8px;
              margin-bottom: 12px; text-transform: uppercase; letter-spacing: .5px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #f1f3f5; padding: 7px 10px; text-align: left;
       font-weight: 600; font-size: 12px; color: #495057; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #f1f3f5; }}
  td.num {{ text-align: right; font-family: monospace; }}
  .table-wrap {{ overflow-x: auto; }}
  table.kv {{ font-size: 12px; }}
  table.kv .k {{ color: #6c757d; width: 55%; }}
  table.kv .v {{ font-family: monospace; font-weight: 600; }}
  @media(max-width:600px){{ .row{{ flex-direction:column; }} }}
</style>
</head>
<body>
{body}
</body>
</html>"""
