"""
healing_core.primitive_registry — VersionedPrimitiveRegistry  (v0.11)

Per the HealingCore guideline:

  "...integrate it with versioned storage so every promoted healing
   primitive has provenance and test history"

  "...convert successful repairs into new, versioned healing
   primitives the seed can reuse autonomously"

This module is the versioned-storage half of that requirement. It is
SQLite-backed (shares the core db_path) and tracks two things per
named primitive (RemediationFix.name):

  1. **test_history** — every attempt (success / failure / ratchet
     result), with incident_id, replay_id, timestamp.

  2. **versions** — a new version row is created each time a
     primitive is *promoted* (RemediationFix.promoted_at transitions
     from None to a timestamp). Each version row captures:
       - version number (monotonically increasing per primitive name)
       - category / cost / impact / source at time of promotion
       - provenance: first_seen_incident, promoting_incident,
         ratchet_pass_count, ratchet_fail_count up to promotion
       - promoted_at timestamp

Nothing here executes remediation steps — it is a pure record-keeping
layer that core.py calls into alongside the existing
PrimitivesRegistry.promote() / LearningStore.record().
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Incident, RemediationFix

log = logging.getLogger("healing_core.primitive_registry")


@dataclass
class VersionRecord:
    name:            str
    version:         int
    category:        str
    cost:            float
    impact:          float
    source:          str
    promoted_at:     float
    first_incident:  str
    promoting_incident: str
    ratchet_pass:    int
    ratchet_fail:    int
    test_count:      int = 0


class VersionedPrimitiveRegistry:
    def __init__(self, db_path: str = "healing_core.db") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._ensure_schema()
        # in-memory: name → current version number
        self._versions: Dict[str, int] = {}
        self._load_versions()

    # ── Schema ─────────────────────────────────────────────────────────────

    def _ensure_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS primitive_test_history (
                rowid       INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                incident_id TEXT,
                replay_id   TEXT,
                outcome     TEXT,         -- success | failure | ratchet_failure
                ratchet_pass INTEGER,     -- 1/0
                timestamp   REAL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS primitive_versions (
                rowid           INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                version         INTEGER NOT NULL,
                category        TEXT,
                cost            REAL,
                impact          REAL,
                source          TEXT,
                promoted_at     REAL,
                first_incident  TEXT,
                promoting_incident TEXT,
                ratchet_pass    INTEGER,
                ratchet_fail    INTEGER,
                test_count      INTEGER,
                UNIQUE(name, version)
            )
        """)
        self._conn.commit()

    def _load_versions(self) -> None:
        cur = self._conn.execute(
            "SELECT name, MAX(version) FROM primitive_versions GROUP BY name")
        for name, ver in cur.fetchall():
            self._versions[name] = ver

    # ── Test history ──────────────────────────────────────────────────────

    def record_attempt(self, fix: "RemediationFix", incident: "Incident",
                       outcome: str, ratchet_passed: bool = False,
                       replay_id: str = "") -> None:
        """Record one remediation attempt for this primitive.

        outcome: "success" | "failure" | "ratchet_failure" | "verifier_failure"
        """
        self._conn.execute(
            "INSERT INTO primitive_test_history "
            "(name, incident_id, replay_id, outcome, ratchet_pass, timestamp) "
            "VALUES (?,?,?,?,?,?)",
            (fix.name, incident.id, replay_id, outcome,
             1 if ratchet_passed else 0, time.time()))
        self._conn.commit()

    def test_history(self, name: str, limit: int = 50) -> List[Dict]:
        cur = self._conn.execute(
            "SELECT incident_id, replay_id, outcome, ratchet_pass, timestamp "
            "FROM primitive_test_history WHERE name = ? "
            "ORDER BY rowid DESC LIMIT ?", (name, limit))
        return [
            {"incident_id": r[0], "replay_id": r[1], "outcome": r[2],
             "ratchet_pass": bool(r[3]), "timestamp": r[4]}
            for r in cur.fetchall()
        ]

    def _history_counts(self, name: str) -> Dict[str, int]:
        cur = self._conn.execute(
            "SELECT outcome, ratchet_pass, COUNT(*) FROM primitive_test_history "
            "WHERE name = ? GROUP BY outcome, ratchet_pass", (name,))
        success = failure = ratchet_pass = ratchet_fail = total = 0
        for outcome, rpass, cnt in cur.fetchall():
            total += cnt
            if outcome == "success":
                success += cnt
            else:
                failure += cnt
            if rpass:
                ratchet_pass += cnt
            else:
                ratchet_fail += cnt
        return {"success": success, "failure": failure, "total": total,
                "ratchet_pass": ratchet_pass, "ratchet_fail": ratchet_fail}

    # ── Versioning / promotion ───────────────────────────────────────────

    def promote(self, fix: "RemediationFix", incident: "Incident") -> VersionRecord:
        """Record a new version of this primitive at the moment of promotion.

        Called by core.py when RemediationFix.promoted_at transitions
        from None → timestamp (i.e. success_count just crossed the
        promotion threshold).
        """
        next_version = self._versions.get(fix.name, 0) + 1
        self._versions[fix.name] = next_version

        counts = self._history_counts(fix.name)
        first_incident = self._first_incident(fix.name) or incident.id

        rec = VersionRecord(
            name              = fix.name,
            version           = next_version,
            category          = fix.category.name,
            cost              = fix.cost,
            impact            = fix.impact,
            source            = fix.source,
            promoted_at       = fix.promoted_at or time.time(),
            first_incident    = first_incident,
            promoting_incident= incident.id,
            ratchet_pass      = counts["ratchet_pass"],
            ratchet_fail      = counts["ratchet_fail"],
            test_count        = counts["total"],
        )

        self._conn.execute(
            "INSERT OR REPLACE INTO primitive_versions "
            "(name, version, category, cost, impact, source, promoted_at, "
            " first_incident, promoting_incident, ratchet_pass, ratchet_fail, "
            " test_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (rec.name, rec.version, rec.category, rec.cost, rec.impact,
             rec.source, rec.promoted_at, rec.first_incident,
             rec.promoting_incident, rec.ratchet_pass, rec.ratchet_fail,
             rec.test_count))
        self._conn.commit()

        log.info("primitive_registry | %s promoted to v%d  "
                 "(tests=%d  ratchet_pass=%d  ratchet_fail=%d)",
                 fix.name, next_version, rec.test_count,
                 rec.ratchet_pass, rec.ratchet_fail)
        return rec

    def _first_incident(self, name: str) -> Optional[str]:
        cur = self._conn.execute(
            "SELECT incident_id FROM primitive_test_history "
            "WHERE name = ? ORDER BY rowid ASC LIMIT 1", (name,))
        row = cur.fetchone()
        return row[0] if row else None

    # ── Queries ────────────────────────────────────────────────────────────

    def current_version(self, name: str) -> int:
        return self._versions.get(name, 0)

    def version_history(self, name: str) -> List[VersionRecord]:
        cur = self._conn.execute(
            "SELECT name, version, category, cost, impact, source, promoted_at, "
            "first_incident, promoting_incident, ratchet_pass, ratchet_fail, "
            "test_count FROM primitive_versions "
            "WHERE name = ? ORDER BY version ASC", (name,))
        return [VersionRecord(*row) for row in cur.fetchall()]

    def all_versioned_primitives(self) -> List[str]:
        cur = self._conn.execute(
            "SELECT DISTINCT name FROM primitive_versions ORDER BY name")
        return [r[0] for r in cur.fetchall()]

    def provenance(self, name: str) -> Optional[Dict]:
        """Full provenance record for a primitive's current version,
        suitable for embedding in audit entries or API responses."""
        history = self.version_history(name)
        if not history:
            return None
        latest = history[-1]
        return {
            "name":               latest.name,
            "current_version":    latest.version,
            "total_versions":     len(history),
            "category":           latest.category,
            "source":             latest.source,
            "cost":               latest.cost,
            "impact":             latest.impact,
            "first_incident":     latest.first_incident,
            "promoting_incident": latest.promoting_incident,
            "promoted_at":        latest.promoted_at,
            "ratchet_pass":       latest.ratchet_pass,
            "ratchet_fail":       latest.ratchet_fail,
            "test_count":         latest.test_count,
            "test_history":       self.test_history(name, limit=10),
        }

    def summary(self) -> Dict:
        total_primitives = len(self.all_versioned_primitives())
        total_versions = self._conn.execute(
            "SELECT COUNT(*) FROM primitive_versions").fetchone()[0]
        total_tests = self._conn.execute(
            "SELECT COUNT(*) FROM primitive_test_history").fetchone()[0]
        return {
            "versioned_primitives": total_primitives,
            "total_versions":       total_versions,
            "total_test_records":   total_tests,
        }


# ── v0.12: Gated promotion ────────────────────────────────────────────────────

from dataclasses import dataclass as _dc2
from typing import Optional as _Opt

@_dc2
class PromotionGateConfig:
    min_ratchet_passes:  int   = 2
    min_success_rate:    float = 0.50
    min_total_attempts:  int   = 3
    chaos_seed:          int   = 42
    chaos_events:        int   = 60
    chaos_max_exceptions:int   = 0
    enabled:             bool  = True


class _GR:
    __slots__ = ("name","passed","detail")
    def __init__(self, n, p, d): self.name,self.passed,self.detail = n,p,d


class VersionedPrimitiveRegistryWithGate(VersionedPrimitiveRegistry):
    def gate_promote(self, fix, incident, core,
                     gate_cfg: "_Opt[PromotionGateConfig]" = None):
        cfg = gate_cfg or PromotionGateConfig()
        if not cfg.enabled:
            return self.promote(fix, incident)
        gates = self._eval_gates(fix, incident, core, cfg)
        passed = all(g.passed for g in gates)
        detail = {g.name: {"passed": g.passed, "detail": g.detail} for g in gates}
        audit  = getattr(core, "audit", None)
        if passed:
            rec = self.promote(fix, incident)
            if audit:
                audit.append("primitive_promoted", incident.id, "",
                             {"fix": fix.name, "version": rec.version,
                              "gate_results": {k: v["detail"] for k,v in detail.items()}},
                             reason=f"{fix.name} passed all {len(gates)} gate criteria → v{rec.version}")
            log.info("gate | %s PROMOTED to v%d", fix.name, rec.version)
            return rec
        else:
            failed = [g.name for g in gates if not g.passed]
            if audit:
                audit.append("primitive_promotion_blocked", incident.id, "",
                             {"fix": fix.name, "failed_gates": failed,
                              "gate_results": detail},
                             reason=f"{fix.name} blocked — failed: {failed}")
            log.warning("gate | %s BLOCKED — failed: %s", fix.name, failed)
            return None

    def _eval_gates(self, fix, incident, core, cfg):
        counts = self._history_counts(fix.name)
        total  = counts["total"]
        rpass  = counts["ratchet_pass"]
        ok_ct  = counts["success"]
        rate   = ok_ct / max(total, 1)
        return [
            _GR("min_attempts",      total >= cfg.min_total_attempts,
                f"{total}/{cfg.min_total_attempts} required"),
            _GR("min_ratchet_passes",rpass >= cfg.min_ratchet_passes,
                f"{rpass} ratchet passes/{cfg.min_ratchet_passes} required"),
            _GR("min_success_rate",  rate  >= cfg.min_success_rate,
                f"{rate:.1%}/{cfg.min_success_rate:.0%} ({ok_ct}/{total})"),
            self._chaos_gate(fix, core, cfg),
        ]

    def _chaos_gate(self, fix, core, cfg):
        try:
            from .chaos import ChaosHarness
            import types, uuid as _u, random as _r
            harness = ChaosHarness(seed=cfg.chaos_seed)
            cat_name = fix.category.name
            _SCENARIOS = {
                "SERVICE":        [{"error_type":"EventID_7034","message":"EventID 7034 service terminated","actor":"nginx","subsystem":"service"}],
                "RESOURCE":       [{"error_type":"oom_kill","message":"Out of memory kill nginx","actor":"nginx","subsystem":"kernel"}],
                "NETWORK":        [{"error_type":"dns_timeout","message":"DNS resolution failed","actor":"resolver","subsystem":"network"}],
                "AUTHENTICATION": [{"error_type":"EventID_4625","message":"EventID 4625 logon failure","actor":"sshd","subsystem":"auth"}],
                "CONFIGURATION":  [{"error_type":"configuration","message":"sfc scannow Windows Resource Protection found corrupt","actor":"sfc","subsystem":"system"}],
            }
            pool = _SCENARIOS.get(cat_name, [])
            def targeted(self_h, n):
                from .models import Event as _E
                rng = _r.Random(cfg.chaos_seed)
                evts = []
                for _ in range(n):
                    sc  = rng.choice(pool) if pool and rng.random() < 0.7 else None
                    if sc:
                        e = _E(**sc); e.id = str(_u.uuid4()); setattr(e,"_chaos_gen","targeted"); evts.append(e)
                    else:
                        e = self_h._gen_normal(); e.id = str(_u.uuid4()); evts.append(e)
                return evts
            harness.generate_sequence = types.MethodType(targeted, harness)
            rpt = harness.run(core, n_events=cfg.chaos_events, fast_canary=True)
            passed = rpt.exceptions <= cfg.chaos_max_exceptions and rpt.audit_chain_valid_after
            detail = f"seed={cfg.chaos_seed} events={rpt.total_events} exc={rpt.exceptions} chain={rpt.audit_chain_valid_after}"
            return _GR("chaos_drill", passed, detail)
        except Exception as exc:
            return _GR("chaos_drill", False, f"raised: {type(exc).__name__}: {exc}")
