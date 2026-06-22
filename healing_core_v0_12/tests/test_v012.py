"""tests/test_v012.py — v0.12: CI gate + gated primitive promotion"""
import os, sys, time, uuid, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest


# ── Helpers ─────────────────────────────────────────────────────────────────

def _core(**kw):
    from healing_core.core import HealingCore
    from healing_core.canary import CanaryConfig
    defaults = dict(
        dry_run=True, db_path=":memory:", api_port=0, prometheus_port=0,
        enable_monitor=False, knowledge_ai_enabled=False,
        enable_multi_ai=False, enable_ml_classifier=False,
        canary_config=CanaryConfig(impact_threshold=0.95, wait_seconds=0.0),
    )
    defaults.update(kw)
    return HealingCore(**defaults)

def _fix(name="restart_service", cat="SERVICE", promoted_at=None):
    from healing_core.models import RemediationFix, IncidentCategory
    f = RemediationFix(
        name=name,
        category=getattr(IncidentCategory, cat, IncidentCategory.SERVICE),
        description="test", steps=[lambda i: (True, "ok")],
        cost=0.3, impact=0.4, source="test")
    f.promoted_at = promoted_at
    return f

def _incident(cat="SERVICE", actor="nginx"):
    from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
    evt = Event(error_type="crash", message="test crash",
                actor=actor, subsystem="svc")
    return Incident(event=evt,
                    category=getattr(IncidentCategory, cat, IncidentCategory.SERVICE),
                    scope=Scope.MODULE, severity=Severity.HIGH, risk_score=0.5)


# ─── CIGate individual checks ─────────────────────────────────────────────────

class TestCIGateChecks:

    def _gate(self, **kw):
        from healing_core.ci_gate import CIGate
        return CIGate(chaos_seeds=[42], chaos_events=40, **kw)

    def test_required_primitives_passes_clean_core(self):
        core = _core()
        chk  = self._gate()._check_required_primitives(core)
        assert chk.passed, chk.detail
        core.shutdown()

    def test_required_primitives_fails_when_missing(self):
        core = _core()
        for cat in list(core.primitives._store.keys()):
            core.primitives._store[cat] = [
                f for f in core.primitives._store[cat]
                if f.name != "restart_service"
            ]
        chk = self._gate()._check_required_primitives(core)
        assert not chk.passed
        assert "restart_service" in chk.detail
        core.shutdown()

    def test_catalog_integrity_passes(self):
        core = _core()
        chk  = self._gate()._check_catalog_integrity(core)
        assert chk.passed, chk.detail
        core.shutdown()

    def test_classifier_coverage_passes(self):
        core = _core()
        chk  = self._gate()._check_classifier_coverage(core)
        assert chk.passed, chk.detail
        core.shutdown()

    def test_regression_scenarios_all_pass(self):
        core   = _core()
        gate   = self._gate()
        checks = gate._check_regression_scenarios(core)
        failed = [c for c in checks if not c.passed]
        assert not failed, [c.detail for c in failed]
        core.shutdown()

    def test_regression_scenario_count(self):
        from healing_core.ci_gate import REGRESSION_SCENARIOS
        assert len(REGRESSION_SCENARIOS) >= 12

    def test_chaos_seed_passes(self):
        core = _core()
        class _R:
            seed_reports = []
        gate   = self._gate()
        checks = gate._check_chaos_seeds(core, _R())
        assert checks[0].passed, checks[0].detail
        core.shutdown()

    def test_chaos_chain_valid_after(self):
        core = _core()
        class _R:
            seed_reports = []
        self._gate()._check_chaos_seeds(core, _R())
        ok, _ = core.audit.verify_chain()
        assert ok
        core.shutdown()

    def test_audit_chain_passes_on_clean_core(self):
        from healing_core.models import Event
        core = _core()
        core.ingest(Event(error_type="test", message="test",
                          actor="a", subsystem="s"))
        chk = self._gate()._check_audit_chain(core)
        assert chk.passed, chk.detail
        core.shutdown()

    def test_audit_chain_detects_tamper(self):
        from healing_core.models import Event
        core = _core()
        core.ingest(Event(error_type="test", message="test",
                          actor="a", subsystem="s"))
        core.audit._conn.execute(
            "UPDATE audit_log SET actor = 'attacker' WHERE rowid = 1")
        core.audit._conn.commit()
        chk = self._gate()._check_audit_chain(core)
        assert not chk.passed
        core.shutdown()


# ─── Full CI run ──────────────────────────────────────────────────────────────

class TestCIGateFull:

    def _gate(self, seeds=None, events=60):
        from healing_core.ci_gate import CIGate
        return CIGate(chaos_seeds=seeds or [42], chaos_events=events)

    def test_full_ci_passes(self):
        core   = _core()
        gate   = self._gate()
        result = gate.run(core)
        assert result.success, gate.format_report(result)
        core.shutdown()

    def test_exit_code_0_on_pass(self):
        core   = _core()
        result = self._gate().run(core)
        assert result.exit_code == 0
        core.shutdown()

    def test_exit_code_1_on_fail(self):
        core = _core()
        for cat in list(core.primitives._store.keys()):
            core.primitives._store[cat] = [
                f for f in core.primitives._store[cat]
                if f.name != "chkdsk"
            ]
        result = self._gate().run(core)
        assert result.exit_code == 1
        assert result.failed >= 1
        core.shutdown()

    def test_multiple_seeds_checked(self):
        core   = _core()
        gate   = self._gate(seeds=[42, 99], events=40)
        result = gate.run(core)
        chaos  = [c for c in result.checks if c.name.startswith("chaos/")]
        assert len(chaos) == 2
        assert all(c.passed for c in chaos)
        core.shutdown()

    def test_result_structure(self):
        core   = _core()
        result = self._gate().run(core)
        assert result.total >= 18
        assert result.passed + result.failed == result.total
        assert result.duration_s > 0
        core.shutdown()

    def test_format_report_has_key_strings(self):
        core = _core()
        gate = self._gate()
        rpt  = gate.format_report(gate.run(core))
        for kw in ("CI Gate", "required_primitives", "catalog_integrity",
                   "classifier_coverage", "audit_chain", "chaos/seed"):
            assert kw in rpt, f"missing '{kw}' in report"
        core.shutdown()

    def test_run_ci_via_core_method(self):
        core   = _core()
        result = core.run_ci(chaos_seeds=[42], chaos_events=40)
        assert result.success
        core.shutdown()

    def test_strict_mode_still_passes(self):
        from healing_core.ci_gate import CIGate
        core = _core()
        gate = CIGate(chaos_seeds=[42], chaos_events=40, strict=True)
        chk  = gate._check_classifier_coverage(core)
        assert chk.passed, chk.detail
        core.shutdown()

    def test_scenario_cooldowns_cleared(self):
        from healing_core.ci_gate import CIGate
        core   = _core()
        gate   = CIGate(chaos_seeds=[42], chaos_events=40)
        checks = gate._check_regression_scenarios(core)
        for c in checks:
            assert "EXCEPTION" not in c.detail, c.detail
        core.shutdown()


# ─── Classifier coverage for each scenario ────────────────────────────────────

class TestRegressionScenarioClassification:

    def test_svc_crash_7034(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="EventID_7034",
                    message="EventID 7034: nginx service terminated unexpectedly",
                    actor="nginx", subsystem="service")
        assert clf.classify(evt).name == "SERVICE"

    def test_oom_kill(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="oom_kill",
                    message="Out of memory: kill process 1234 (nginx) score 851",
                    actor="nginx", subsystem="kernel")
        assert clf.classify(evt).name == "RESOURCE"

    def test_disk_full(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="disk_full",
                    message="No space left on device /var/log — disk usage 100%",
                    actor="journald", subsystem="storage")
        assert clf.classify(evt).name == "RESOURCE"

    def test_dns_timeout(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="dns_timeout",
                    message="DNS resolution failed WSAEHOSTUNREACH for api.example.com",
                    actor="resolver", subsystem="network")
        assert clf.classify(evt).name == "NETWORK"

    def test_auth_failure_4625(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="EventID_4625",
                    message="EventID 4625: account logon failure Status 0xC000006D",
                    actor="sshd", subsystem="auth")
        assert clf.classify(evt).name == "AUTHENTICATION"

    def test_defender_threat(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="EventID_1116",
                    message="Windows Defender threat detected EventID 1116 Ransom.WannaCry",
                    actor="WinDefend", subsystem="security")
        assert clf.classify(evt).name == "MALWARE"

    def test_ransomware(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="malware",
                    message="ransomware vssadmin delete shadows encrypted files bitcoin",
                    actor="suspicious_proc", subsystem="security")
        assert clf.classify(evt).name == "MALWARE"

    def test_bsod(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="hardware",
                    message="STOP 0x0000007E kernel panic BugcheckCode BSOD system crashed",
                    actor="kernel", subsystem="system")
        assert clf.classify(evt).name == "HARDWARE"

    def test_driver_7026(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="EventID_7026",
                    message="EventID 7026: driver failed to load boot-start driver",
                    actor="nvlddmkm", subsystem="driver")
        assert clf.classify(evt).name == "DRIVER"

    def test_sfc_corrupt(self):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type="configuration",
                    message="Windows Resource Protection found corrupt files sfc scannow CBS.log",
                    actor="sfc", subsystem="system")
        assert clf.classify(evt).name == "CONFIGURATION"


# ─── PromotionGateConfig ──────────────────────────────────────────────────────

class TestPromotionGate:

    def _reg(self):
        from healing_core.primitive_registry import VersionedPrimitiveRegistryWithGate
        return VersionedPrimitiveRegistryWithGate(db_path=":memory:")

    def _cfg(self, **kw):
        from healing_core.primitive_registry import PromotionGateConfig
        defaults = dict(min_ratchet_passes=1, min_success_rate=0.5,
                        min_total_attempts=1, chaos_events=20, chaos_seed=42)
        defaults.update(kw)
        return PromotionGateConfig(**defaults)

    def test_gate_passes_all_criteria_met(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        rec = reg.gate_promote(fix, inc, core, self._cfg())
        assert rec is not None
        assert rec.version == 1
        core.shutdown()

    def test_gate_blocks_insufficient_ratchet(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        reg.record_attempt(fix, inc, "success", ratchet_passed=False)
        reg.record_attempt(fix, inc, "success", ratchet_passed=False)
        rec = reg.gate_promote(fix, inc, core,
                               self._cfg(min_ratchet_passes=2))
        assert rec is None
        core.shutdown()

    def test_gate_blocks_low_success_rate(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        for _ in range(4):
            reg.record_attempt(fix, inc, "failure", ratchet_passed=False)
        rec = reg.gate_promote(fix, inc, core,
                               self._cfg(min_success_rate=0.80))
        assert rec is None
        core.shutdown()

    def test_gate_blocks_insufficient_attempts(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        rec = reg.gate_promote(fix, inc, core,
                               self._cfg(min_total_attempts=5))
        assert rec is None
        core.shutdown()

    def test_gate_disabled_bypasses_all(self):
        from healing_core.primitive_registry import PromotionGateConfig
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        rec  = reg.gate_promote(fix, inc, core, PromotionGateConfig(enabled=False))
        assert rec is not None
        core.shutdown()

    def test_gate_success_writes_promoted_audit_entry(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        reg.gate_promote(fix, inc, core, self._cfg())
        entries  = core.audit.last_n(10)
        promoted = [e for e in entries
                    if e["event_type"] == "primitive_promoted"]
        assert len(promoted) >= 1
        assert promoted[0]["detail"]["version"] == 1
        core.shutdown()

    def test_gate_fail_writes_blocked_audit_entry(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        reg.record_attempt(fix, inc, "success", ratchet_passed=False)
        reg.gate_promote(fix, inc, core,
                         self._cfg(min_ratchet_passes=99))
        entries = core.audit.last_n(10)
        blocked = [e for e in entries
                   if e["event_type"] == "primitive_promotion_blocked"]
        assert len(blocked) >= 1
        assert fix.name in str(blocked[0]["detail"])
        core.shutdown()

    def test_gate_chaos_drill_runs_successfully(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        for _ in range(3):
            reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        rec = reg.gate_promote(fix, inc, core,
                               self._cfg(chaos_events=20))
        assert rec is not None
        core.shutdown()

    def test_default_gate_config(self):
        from healing_core.primitive_registry import PromotionGateConfig
        cfg = PromotionGateConfig()
        assert cfg.min_ratchet_passes  == 2
        assert cfg.min_success_rate    == 0.50
        assert cfg.min_total_attempts  == 3
        assert cfg.chaos_seed          == 42
        assert cfg.chaos_events        == 60
        assert cfg.enabled             is True

    def test_gate_increments_version_on_second_promotion(self):
        reg  = self._reg()
        fix  = _fix(promoted_at=time.time())
        inc  = _incident()
        core = _core()
        for _ in range(2):
            reg.record_attempt(fix, inc, "success", ratchet_passed=True)
        r1 = reg.gate_promote(fix, inc, core, self._cfg())
        r2 = reg.gate_promote(fix, inc, core, self._cfg())
        assert r1 is not None and r2 is not None
        assert r1.version == 1
        assert r2.version == 2
        core.shutdown()


# ─── Core with gated promotion ────────────────────────────────────────────────

class TestCoreGatedPromotion:

    def _gated_core(self, **kw):
        from healing_core.primitive_registry import PromotionGateConfig
        gate_cfg = PromotionGateConfig(
            min_ratchet_passes=1, min_success_rate=0.3,
            min_total_attempts=1, chaos_events=20, enabled=True)
        return _core(gate_config=gate_cfg, **kw)

    def test_gated_core_uses_gate_registry(self):
        from healing_core.primitive_registry import VersionedPrimitiveRegistryWithGate
        core = self._gated_core()
        assert isinstance(core.primitive_registry, VersionedPrimitiveRegistryWithGate)
        assert core._gate_config is not None
        core.shutdown()

    def test_ungated_core_uses_base_registry(self):
        from healing_core.primitive_registry import VersionedPrimitiveRegistry
        core = _core()
        assert type(core.primitive_registry) is VersionedPrimitiveRegistry
        core.shutdown()

    def test_gated_core_ingest_works(self):
        from healing_core.models import Event
        core = self._gated_core()
        evt  = Event(error_type="disk_full", message="No space left on device",
                     actor="journald", subsystem="storage")
        inc  = core.ingest(evt)
        assert inc is not None
        core.shutdown()

    def test_gated_core_ci_passes(self):
        core   = self._gated_core()
        result = core.run_ci(chaos_seeds=[42], chaos_events=40)
        assert result.success, result.checks
        core.shutdown()

    def test_gated_core_audit_chain_valid(self):
        from healing_core.models import Event
        core = self._gated_core()
        for _ in range(3):
            core.ingest(Event(error_type="disk_full",
                              message="No space left on device",
                              actor="journald", subsystem="storage"))
            core._cooldowns.clear()
        ok, bad = core.audit.verify_chain()
        assert ok, f"chain broken: {bad}"
        core.shutdown()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
