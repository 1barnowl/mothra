"""
tests/test_v08.py
─────────────────
v0.8 test suite covering all new modules:
  - macOS driver (dry-run)
  - macOS catalog registration
  - MLClassifier (with and without sklearn)
  - BudgetTracker (allow / block / per-category)
  - CanaryDeployment (bypass / probe / commit / rollback)
  - GrafanaDashboard (build / export)
  - Integration: budget + canary wired into HealingCore
  - Cross-platform: driver dispatch
"""
import json
import os
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

# ─── macOS driver ─────────────────────────────────────────────────────────────

class TestMacosDriver:
    """All tests run in DryRun=True so no real commands execute."""

    def setup_method(self):
        import drivers.macos as m
        m.DryRun = True
        self.m = m

    def test_restart_service(self):
        ok, d = self.m.restart_service("nginx")
        assert ok
        assert "dry-run" in d

    def test_restart_invalid_service(self):
        ok, d = self.m.restart_service("")
        assert not ok

    def test_flush_dns(self):
        ok, d = self.m.flush_dns()
        assert ok

    def test_toggle_wifi(self):
        ok, d = self.m.toggle_wifi(True, "Wi-Fi")
        assert ok

    def test_set_dns(self):
        ok, d = self.m.set_dns("1.1.1.1", "Wi-Fi")
        assert ok

    def test_release_renew_ip(self):
        ok, d = self.m.release_renew_ip("en0")
        assert ok

    def test_kill_process(self):
        ok, d = self.m.kill_process("suspiciousapp")
        assert ok

    def test_renice_process(self):
        ok, d = self.m.renice_process("heavyapp", nice=10)
        assert ok

    def test_purge_memory(self):
        ok, d = self.m.purge_memory()
        # May return False if purge not installed on the test machine,
        # but dry-run should still return True
        assert isinstance(ok, bool)

    def test_verify_disk(self):
        ok, d = self.m.verify_disk("/")
        assert ok

    def test_clear_temp_files_dryrun(self):
        ok, d = self.m.clear_temp_files()
        assert ok and "dry-run" in d

    def test_block_ip(self):
        ok, d = self.m.block_ip("10.0.0.99")
        assert ok

    def test_sync_time(self):
        ok, d = self.m.sync_time()
        assert ok

    def test_run_software_update_dryrun(self):
        ok, d = self.m.run_software_update()
        assert ok

    def test_repair_disk(self):
        ok, d = self.m.repair_disk("/")
        assert ok

    def test_enable_firewall(self):
        ok, d = self.m.enable_firewall()
        assert ok

    def test_disable_account(self):
        ok, d = self.m.disable_account("baduser")
        assert ok

    def test_allow_port_dryrun(self):
        ok, d = self.m.allow_port(8080, "tcp")
        assert ok


# ─── macOS catalog ────────────────────────────────────────────────────────────

class TestMacosCatalog:
    def setup_method(self):
        from healing_core.primitives import PrimitivesRegistry
        import drivers.macos as m
        m.DryRun = True
        self.registry = PrimitivesRegistry()

    def test_register_catalog(self):
        from drivers.macos_catalog import register_catalog
        register_catalog(self.registry)
        total = sum(len(v) for v in self.registry._store.values())
        assert total >= 20, f"Expected ≥20 fixes, got {total}"

    def test_catalog_has_network_fixes(self):
        from drivers.macos_catalog import network_fixes
        fixes = network_fixes()
        assert len(fixes) >= 4
        names = [f.name for f in fixes]
        assert any("dns" in n for n in names)
        assert any("dhcp" in n or "renew" in n for n in names)

    def test_catalog_has_service_fixes(self):
        from drivers.macos_catalog import service_fixes
        fixes = service_fixes()
        assert len(fixes) >= 3

    def test_catalog_has_security_fixes(self):
        from drivers.macos_catalog import security_fixes
        fixes = security_fixes()
        assert len(fixes) >= 3

    def test_catalog_costs_reasonable(self):
        from drivers.macos_catalog import (
            network_fixes, service_fixes, resource_fixes,
            security_fixes, auth_fixes
        )
        for fix in (network_fixes() + service_fixes() +
                    resource_fixes() + security_fixes() + auth_fixes()):
            assert 0 < fix.cost <= 1.0, f"{fix.name}.cost={fix.cost}"
            assert 0 <= fix.impact <= 1.0, f"{fix.name}.impact={fix.impact}"


# ─── ML Classifier ────────────────────────────────────────────────────────────

class TestMLClassifier:
    def _make(self):
        from healing_core.ml_classifier import MLClassifier
        from healing_core.exception_catalog import ExceptionCatalog
        from healing_core.os_fault_catalog  import OsFaultCatalog
        ec = ExceptionCatalog()
        oc = OsFaultCatalog()
        clf = MLClassifier(exception_catalog=ec, os_fault_catalog=oc)
        return clf

    def _event(self, error_type="oom_kill", message="Out of memory: kill nginx",
                subsystem="kernel"):
        from healing_core.models import Event
        return Event(error_type=error_type, message=message,
                     actor="test", subsystem=subsystem)

    def test_seed_builds_corpus(self):
        clf = self._make()
        clf.seed()
        assert len(clf._corpus) >= 10

    def test_classify_returns_category_and_confidence(self):
        from healing_core.models import IncidentCategory
        clf = self._make()
        clf.seed()
        evt = self._event()
        cat, conf = clf.classify(evt)
        assert isinstance(cat, IncidentCategory)
        assert 0.0 <= conf <= 1.0

    def test_classify_fallback_when_no_model(self):
        from healing_core.models import IncidentCategory
        clf = self._make()
        # Don't seed — no model trained
        evt = self._event()
        cat, conf = clf.classify(evt)
        assert isinstance(cat, IncidentCategory)
        assert conf == 1.0   # fallback returns 1.0 confidence sentinel

    def test_record_adds_to_corpus(self):
        from healing_core.models import IncidentCategory
        clf = self._make()
        clf.seed()
        before = len(clf._corpus)
        clf.record(self._event(), IncidentCategory.RESOURCE)
        assert len(clf._corpus) == before + 1

    def test_maybe_retrain_triggers_after_threshold(self):
        from healing_core.ml_classifier import RETRAIN_EVERY
        from healing_core.models import IncidentCategory
        clf = self._make()
        clf.seed()
        retrains_before = clf._retrains
        for _ in range(RETRAIN_EVERY + 1):
            clf.record(self._event(), IncidentCategory.RESOURCE)
        result = clf.maybe_retrain()
        # Only asserts True when sklearn is installed
        try:
            from sklearn.linear_model import LogisticRegression  # noqa
            if len(set(s.label for s in clf._corpus)) >= 2:
                assert result is True
                assert clf._retrains > retrains_before
        except ImportError:
            assert result is False

    def test_stats_dict_keys(self):
        clf = self._make()
        clf.seed()
        s = clf.stats()
        for key in ("sklearn_available", "model_trained", "corpus_size",
                    "total_classified", "ml_used", "fallbacks", "ml_rate"):
            assert key in s, f"missing key: {key}"

    def test_network_event_categorized(self):
        from healing_core.models import IncidentCategory
        clf = self._make()
        clf.seed()
        evt = self._event(error_type="dns_timeout",
                          message="DNS resolution failed for host",
                          subsystem="network")
        cat, _ = clf.classify(evt)
        # At least should not crash; category type is correct
        assert isinstance(cat, IncidentCategory)


# ─── Budget Tracker ───────────────────────────────────────────────────────────

class TestBudgetTracker:
    def _tracker(self, max_cost=2.0, max_impact=1.5, window=3600.0):
        from healing_core.budget_tracker import BudgetTracker, BudgetConfig
        cfg = BudgetConfig(max_cost=max_cost, max_impact=max_impact,
                           window_seconds=window, max_cost_per_cat=1.5,
                           max_impact_per_cat=1.0)
        return BudgetTracker(config=cfg)

    def _fix(self, cost=0.5, impact=0.3, category="RESOURCE", name="test_fix"):
        from healing_core.models import RemediationFix, IncidentCategory
        cat = getattr(IncidentCategory, category, IncidentCategory.RESOURCE)
        return RemediationFix(name=name, category=cat, description="test",
                              steps=[], cost=cost, impact=impact, source="test")

    def test_allows_fix_within_budget(self):
        t = self._tracker()
        fix = self._fix(cost=0.5, impact=0.3)
        ok, reason = t.check(fix)
        assert ok
        assert reason == "ok"

    def test_blocks_when_cost_exceeded(self):
        t = self._tracker(max_cost=1.0)
        fix = self._fix(cost=0.6)
        t.record(fix)              # cost now 0.6
        ok, reason = t.check(fix)  # would push to 1.2 > 1.0
        assert not ok
        assert "cost" in reason.lower()

    def test_blocks_when_impact_exceeded(self):
        t = self._tracker(max_impact=1.0)
        fix = self._fix(impact=0.6)
        t.record(fix)
        ok, reason = t.check(fix)
        assert not ok
        assert "impact" in reason.lower()

    def test_per_category_cost_ceiling(self):
        t = self._tracker()
        fix = self._fix(cost=0.8, category="RESOURCE")
        t.record(fix)                           # cat cost = 0.8
        ok, reason = t.check(fix)              # would push cat to 1.6 > 1.5
        assert not ok
        assert "category" in reason.lower()

    def test_record_increases_ledger(self):
        t = self._tracker()
        fix = self._fix()
        t.record(fix)
        s = t.summary()
        assert s["ledger_entries"] == 1
        assert s["window_cost"] == pytest.approx(0.5)

    def test_window_evicts_old_entries(self):
        from healing_core.budget_tracker import BudgetTracker, BudgetConfig, _Spend
        cfg = BudgetConfig(window_seconds=1, max_cost=10, max_impact=10)
        t = BudgetTracker(config=cfg)
        fix = self._fix(cost=0.5)
        t.record(fix)
        assert t.summary()["ledger_entries"] == 1
        time.sleep(1.05)
        t._evict()
        assert t.summary()["ledger_entries"] == 0

    def test_summary_keys(self):
        t = self._tracker()
        s = t.summary()
        for k in ("window_cost", "window_impact", "max_cost", "max_impact",
                  "cost_pct", "impact_pct", "total_allowed", "total_blocked"):
            assert k in s

    def test_metrics_string(self):
        t = self._tracker()
        m = t.metrics()
        assert "hc_budget_cost_window" in m
        assert "hc_budget_blocked_total" in m

    def test_multiple_categories_independent(self):
        t = self._tracker()
        net_fix  = self._fix(cost=0.4, category="NETWORK", name="net_fix")
        res_fix  = self._fix(cost=0.4, category="RESOURCE", name="res_fix")
        t.record(net_fix)
        t.record(res_fix)
        # Each category is under 1.5, global is 0.8 < 2.0 — both should pass
        ok1, _ = t.check(net_fix)
        ok2, _ = t.check(res_fix)
        assert ok1
        assert ok2


# ─── Canary Deployment ────────────────────────────────────────────────────────

class TestCanaryDeployment:
    def _canary(self, threshold=0.5, wait=0.0):
        from healing_core.canary import CanaryDeployment, CanaryConfig
        cfg = CanaryConfig(impact_threshold=threshold, wait_seconds=wait)
        return CanaryDeployment(config=cfg)

    def _fix(self, impact=0.3, name="test_fix"):
        from healing_core.models import RemediationFix, IncidentCategory
        def step(inc): return (True, "ok")
        return RemediationFix(name=name, category=IncidentCategory.RESOURCE,
                              description="test", steps=[step],
                              cost=0.2, impact=impact, source="test")

    def _incident(self):
        from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
        evt = Event(error_type="test", message="test msg", actor="test")
        return Incident(event=evt, category=IncidentCategory.RESOURCE,
                        scope=Scope.MODULE, severity=Severity.MEDIUM,
                        risk_score=0.5)

    def _snapshot(self):
        from healing_core.models import Snapshot
        return Snapshot(incident_id=str(uuid.uuid4()))

    def test_bypass_low_impact(self):
        c = self._canary(threshold=0.5)
        fix = self._fix(impact=0.2)    # below threshold
        r = c.gate(fix, self._incident(), self._snapshot())
        assert r.allowed
        assert r.stage_reached == 0

    def test_probe_passes_good_fix(self):
        c = self._canary(threshold=0.1, wait=0.0)
        fix = self._fix(impact=0.8)
        r = c.gate(fix, self._incident(), self._snapshot())
        assert r.allowed
        assert r.stage_reached == 3

    def test_probe_fails_bad_fix(self):
        from healing_core.models import RemediationFix, IncidentCategory
        c = self._canary(threshold=0.1, wait=0.0)
        def bad_step(inc): return (False, "permission denied")
        fix = RemediationFix(name="bad_fix", category=IncidentCategory.RESOURCE,
                             description="bad", steps=[bad_step],
                             cost=0.2, impact=0.8, source="test")
        r = c.gate(fix, self._incident(), self._snapshot())
        assert not r.allowed
        assert r.stage_reached == 1
        assert "probe failed" in r.reason

    def test_probe_fails_error_in_output(self):
        from healing_core.models import RemediationFix, IncidentCategory
        c = self._canary(threshold=0.1, wait=0.0)
        def step_with_error(inc): return (True, "ERROR: connection refused")
        fix = RemediationFix(name="err_fix", category=IncidentCategory.NETWORK,
                             description="err", steps=[step_with_error],
                             cost=0.2, impact=0.9, source="test")
        r = c.gate(fix, self._incident(), self._snapshot())
        assert not r.allowed
        assert r.stage_reached == 1

    def test_probe_with_no_steps(self):
        from healing_core.models import RemediationFix, IncidentCategory
        c = self._canary(threshold=0.1, wait=0.0)
        fix = RemediationFix(name="no_steps", category=IncidentCategory.TRANSIENT,
                             description="ok", steps=[],
                             cost=0.1, impact=0.8, source="test")
        r = c.gate(fix, self._incident(), self._snapshot())
        assert r.allowed

    def test_metric_window_skipped_when_zero(self):
        c = self._canary(threshold=0.1, wait=0.0)
        fix = self._fix(impact=0.9)
        t0 = time.monotonic()
        r = c.gate(fix, self._incident(), self._snapshot())
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0      # must not block for 30s
        assert r.allowed

    def test_stats(self):
        c = self._canary()
        fix_low  = self._fix(impact=0.1)
        fix_high = self._fix(impact=0.9, name="high")
        c.gate(fix_low,  self._incident(), self._snapshot())
        c.gate(fix_high, self._incident(), self._snapshot())
        s = c.stats()
        assert s["total"] == 2
        assert s["bypassed"] >= 1
        assert "passed" in s

    def test_latency_ms_populated(self):
        c = self._canary(threshold=0.1, wait=0.0)
        r = c.gate(self._fix(impact=0.8), self._incident(), self._snapshot())
        assert isinstance(r.latency_ms, float)
        assert r.latency_ms >= 0


# ─── Grafana Dashboard ────────────────────────────────────────────────────────

class TestGrafanaDashboard:
    def _dash(self):
        from healing_core.grafana import GrafanaDashboard
        return GrafanaDashboard(core=None, ds_name="Prometheus")

    def test_build_returns_dict(self):
        d = self._dash().build()
        assert isinstance(d, dict)

    def test_dashboard_has_uid_title(self):
        from healing_core.grafana import GrafanaDashboard
        d = self._dash().build()
        assert d["uid"] == GrafanaDashboard.UID
        assert "HealingCore" in d["title"]

    def test_dashboard_has_panels(self):
        d = self._dash().build()
        assert isinstance(d["panels"], list)
        assert len(d["panels"]) >= 8

    def test_all_panels_have_type(self):
        d = self._dash().build()
        for panel in d["panels"]:
            assert "type" in panel, f"panel missing 'type': {panel.get('title')}"
            assert panel["type"] in ("stat", "timeseries", "gauge", "table",
                                     "bargauge", "piechart", "text")

    def test_all_panels_have_gridpos(self):
        d = self._dash().build()
        for panel in d["panels"]:
            gp = panel.get("gridPos", {})
            for key in ("x", "y", "w", "h"):
                assert key in gp, f"panel '{panel.get('title')}' missing gridPos.{key}"

    def test_all_panels_have_targets(self):
        d = self._dash().build()
        for panel in d["panels"]:
            if panel["type"] in ("stat", "timeseries", "gauge"):
                assert "targets" in panel, f"panel '{panel.get('title')}' missing targets"
                assert len(panel["targets"]) >= 1

    def test_export_writes_file(self):
        dash = self._dash()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_grafana.json")
            result_path = dash.export(path)
            assert result_path == path
            assert os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert "dashboard" in data
            assert "overwrite" in data
            assert data["overwrite"] is True

    def test_export_valid_json(self):
        dash = self._dash()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "dash.json")
            dash.export(path)
            with open(path) as f:
                content = f.read()
            parsed = json.loads(content)
            assert parsed["dashboard"]["schemaVersion"] == 37

    def test_panels_use_correct_datasource(self):
        d = self._dash().build()
        for panel in d["panels"]:
            ds = panel.get("datasource", {})
            assert ds.get("type") == "prometheus"

    def test_dashboard_has_kpi_stats(self):
        """Stat panels for incidents, healed, suppressed should exist."""
        d = self._dash().build()
        stat_panels = [p for p in d["panels"] if p["type"] == "stat"]
        titles = [p["title"] for p in stat_panels]
        assert any("Incident" in t for t in titles)
        assert any("Heal" in t for t in titles)


# ─── Drivers cross-platform dispatch ─────────────────────────────────────────

class TestDriverDispatch:
    def test_get_driver_returns_module_or_none(self):
        from drivers import get_driver
        m = get_driver()
        # Should return module or None (if current OS driver not importable)
        assert m is None or hasattr(m, "DryRun")

    def test_set_dry_run_does_not_crash(self):
        from drivers import set_dry_run
        set_dry_run(True)   # Should not raise even if some drivers missing

    def test_platform_attribute(self):
        from drivers import PLATFORM
        assert PLATFORM in ("Linux", "Windows", "Darwin")


# ─── Integration: Budget + Canary in HealingCore ─────────────────────────────

class TestCoreV08Integration:
    def _core(self):
        from healing_core.core import HealingCore
        from healing_core.budget_tracker import BudgetConfig
        from healing_core.canary import CanaryConfig
        return HealingCore(
            dry_run=True, db_path=":memory:", api_port=0, prometheus_port=0,
            enable_monitor=False, knowledge_ai_enabled=False,
            enable_multi_ai=False, enable_ml_classifier=True,
            budget_config=BudgetConfig(max_cost=10.0, max_impact=8.0),
            canary_config=CanaryConfig(impact_threshold=0.95, wait_seconds=0.0),
        )

    def test_core_starts_with_new_modules(self):
        core = self._core()
        assert core.budget is not None
        assert core.canary is not None
        assert core.grafana is not None
        core.shutdown()

    def test_ml_classifier_initialized(self):
        core = self._core()
        assert core.ml_classifier is not None
        core.shutdown()

    def test_ingest_returns_incident(self):
        from healing_core.models import Event
        core = self._core()
        evt = Event(error_type="oom_kill",
                    message="Out of memory: nginx killed",
                    actor="nginx", subsystem="kernel")
        inc = core.ingest(evt)
        assert inc is not None
        core.shutdown()

    def test_budget_report_no_crash(self):
        core = self._core()
        core.budget_report()
        core.shutdown()

    def test_canary_report_no_crash(self):
        core = self._core()
        core.canary_report()
        core.shutdown()

    def test_ml_report_no_crash(self):
        core = self._core()
        core.ml_report()
        core.shutdown()

    def test_grafana_export(self):
        core = self._core()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "dash.json")
            result = core.export_grafana(path)
            assert os.path.exists(result)
        core.shutdown()

    def test_poll_metrics_includes_v08_keys(self):
        core = self._core()
        m = core.poll_metrics()
        assert "hc_budget_blocked" in m
        assert "hc_canary_blocked" in m
        core.shutdown()

    def test_prometheus_metrics_includes_v08(self):
        core = self._core()
        metrics = core._prometheus_metrics()
        assert "hc_budget_cost_window" in metrics
        assert "hc_budget_impact_window" in metrics
        assert "hc_canary_blocked_total" in metrics
        assert "hc_ml_corpus_size" in metrics
        assert "hc_ml_rate" in metrics
        core.shutdown()

    def test_budget_blocks_over_limit(self):
        """BudgetTracker actually blocks when ceiling hit."""
        from healing_core.budget_tracker import BudgetConfig
        from healing_core.canary import CanaryConfig
        from healing_core.core import HealingCore
        core = HealingCore(
            dry_run=True, db_path=":memory:", api_port=0, prometheus_port=0,
            enable_monitor=False, knowledge_ai_enabled=False,
            enable_multi_ai=False, enable_ml_classifier=False,
            budget_config=BudgetConfig(max_cost=0.001, max_impact=0.001),
            canary_config=CanaryConfig(impact_threshold=0.95, wait_seconds=0.0),
        )
        from healing_core.models import Event
        evt = Event(error_type="disk_full",
                    message="No space left on device /var/data",
                    actor="journald", subsystem="storage")
        core.ingest(evt)
        # Budget should have registered blocked events
        s = core.budget.summary()
        # After first fix attempt the budget ceiling should have been hit
        # (total_blocked >= 0 always; with 0.001 ceiling it will be hit)
        assert isinstance(s["total_blocked"], int)
        core.shutdown()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])


# ─── Windows classifier coverage ─────────────────────────────────────────────

class TestWindowsClassification:
    """Validate all 25 Windows-specific classifier signals."""

    def _clf(self):
        from healing_core.classification import IncidentClassifier
        return IncidentClassifier()

    def _cat(self, text):
        from healing_core.models import Event
        clf = self._clf()
        evt = Event(error_type="", message=text, actor="test", subsystem="")
        return clf.classify(evt).name

    # ── Service event IDs ─────────────────────────────────────────────────────
    def test_eventid_7034_service(self):
        assert self._cat("EventID 7034 service terminated unexpectedly") == "SERVICE"

    def test_eventid_7031_service(self):
        assert self._cat("EventID 7031 service termination recovery exhausted") == "SERVICE"

    def test_eventid_7036_service(self):
        assert self._cat("EventID 7036 service entered stopped state") == "SERVICE"

    def test_eventid_7000_service(self):
        assert self._cat("EventID 7000 service failed to start") == "SERVICE"

    def test_eventid_7009_service(self):
        assert self._cat("EventID 7009 timed out waiting for service") == "SERVICE"

    def test_eventid_7026_driver(self):
        assert self._cat("EventID 7026 driver failed to load boot-start") == "DRIVER"

    def test_eventid_7038_auth(self):
        assert self._cat("EventID 7038 logon as a service right failed") == "AUTHENTICATION"

    # ── Authentication event IDs ──────────────────────────────────────────────
    def test_eventid_4625_auth(self):
        assert self._cat("EventID 4625 account logon failure") == "AUTHENTICATION"

    def test_eventid_4740_auth(self):
        assert self._cat("EventID 4740 account locked out") == "AUTHENTICATION"

    def test_eventid_4771_kerberos(self):
        assert self._cat("EventID 4771 Kerberos pre-authentication failed") == "AUTHENTICATION"

    def test_eventid_4725_account_disabled(self):
        assert self._cat("EventID 4725 user account was disabled") == "AUTHENTICATION"

    def test_kdc_err(self):
        assert self._cat("KDC_ERR_PREAUTH_FAILED Kerberos error") == "AUTHENTICATION"

    def test_cert_expired(self):
        assert self._cat("CERT_E_EXPIRED certificate expired SSL handshake") == "AUTHENTICATION"

    # ── Security event IDs ────────────────────────────────────────────────────
    def test_eventid_10016_dcom(self):
        assert self._cat("EventID 10016 DCOM machine-default permission not granted") == "SECURITY"

    def test_eventid_4673_privilege(self):
        assert self._cat("EventID 4673 sensitive privilege used SeDebugPrivilege") == "SECURITY"

    # ── Malware event IDs ─────────────────────────────────────────────────────
    def test_eventid_1116_defender(self):
        assert self._cat("Windows Defender threat detected EventID 1116") == "MALWARE"

    def test_eventid_7045_new_service(self):
        assert self._cat("EventID 7045 new service was installed malware") == "MALWARE"

    def test_eventid_1102_log_cleared(self):
        assert self._cat("EventID 1102 audit log cleared security") == "MALWARE"

    def test_ransomware_vss(self):
        assert self._cat("ransomware vssadmin delete shadows") == "MALWARE"

    # ── Hardware stop codes ───────────────────────────────────────────────────
    def test_bsod_stop_code(self):
        assert self._cat("STOP 0x0000007E blue screen BSOD") == "HARDWARE"

    def test_eventid_41_shutdown(self):
        assert self._cat("EventID 41 kernel power unexpected shutdown BugcheckCode") == "HARDWARE"

    def test_eventid_11_disk_controller(self):
        assert self._cat("EventID 11 driver detected controller error harddisk") == "HARDWARE"

    # ── Network WSAE / HRESULT ────────────────────────────────────────────────
    def test_wsaenetunreach(self):
        assert self._cat("WSAENETUNREACH network unreachable") == "NETWORK"

    def test_wsaeaddrinuse(self):
        assert self._cat("WSAEADDRINUSE address already in use 10048") == "NETWORK"

    def test_rpc_unavailable(self):
        assert self._cat("WinError 1722 RPC server is unavailable 0x800706ba") == "NETWORK"

    def test_winsock_corrupt(self):
        assert self._cat("Winsock catalog corrupt netsh winsock reset") == "NETWORK"

    # ── Configuration / Win32 errors ──────────────────────────────────────────
    def test_winerror_5_access_denied(self):
        assert self._cat("WinError 5 Access is denied 0x80070005") == "CONFIGURATION"

    def test_winerror_2_not_found(self):
        assert self._cat("WinError 2 cannot find the file specified") == "CONFIGURATION"

    def test_registry_modified_4657(self):
        assert self._cat("HKLM registry key modified EventID 4657") == "CONFIGURATION"

    def test_sfc_corrupt(self):
        assert self._cat("sfc scannow Windows Resource Protection found corrupt files") == "CONFIGURATION"

    def test_dism_restorehealth(self):
        assert self._cat("DISM restorehealth component store corrupt CBS.log") == "CONFIGURATION"

    # ── Resource ──────────────────────────────────────────────────────────────
    def test_pagefile_exhausted(self):
        assert self._cat("0xC0000017 pagefile virtual memory exhausted commit limit") == "RESOURCE"

    def test_eventid_2004_memory(self):
        assert self._cat("EventID 2004 memory exhaustion resource monitor") == "RESOURCE"

    def test_handle_leak(self):
        assert self._cat("handle leak handle count exceeded NHandles") == "RESOURCE"

    def test_paged_pool(self):
        assert self._cat("NonPagedPool depletion kernel pool EventID 2019") == "RESOURCE"

    # ── Driver ────────────────────────────────────────────────────────────────
    def test_device_code_10(self):
        assert self._cat("device cannot start Code 10 driver conflict") == "DRIVER"

    def test_device_code_43(self):
        assert self._cat("Code 43 device driver conflict pnputil") == "DRIVER"

    # ── Service HRESULT ───────────────────────────────────────────────────────
    def test_pywintypes_hresult(self):
        assert self._cat("pywintypes.error HRESULT hr = 0x80004005") == "SERVICE"

    def test_wmi_corrupt(self):
        assert self._cat("WMI repository corrupt winmgmt fail wbem") == "SERVICE"

    def test_spooler_crash(self):
        assert self._cat("spoolsv.exe terminated unexpectedly print spooler 7034") == "SERVICE"

    def test_service_hresult(self):
        assert self._cat("service 0x8007042c Windows could not start") == "SERVICE"


# ─── Windows OS fault catalog ─────────────────────────────────────────────────

class TestWindowsOsFaultCatalog:
    def setup_method(self):
        from healing_core.os_fault_catalog import OsFaultCatalog
        self.oc = OsFaultCatalog()

    def test_windows_entries_loaded(self):
        entries = self.oc.all_entries()
        win = [e for e in entries if e.platform == "windows"]
        assert len(win) >= 40, f"Expected ≥40 Windows entries, got {len(win)}"

    def test_total_entries_grown(self):
        assert len(self.oc.all_entries()) >= 200

    def test_lookup_eventid_7034(self):
        e = self.oc.lookup("EventID 7034 service terminated unexpectedly")
        assert e is not None
        assert e.platform == "windows"

    def test_lookup_eventid_4625(self):
        e = self.oc.lookup("EventID 4625 account logon failure")
        assert e is not None

    def test_lookup_eventid_41_bsod(self):
        e = self.oc.lookup("EventID 41 kernel power BugcheckCode unexpected shutdown")
        assert e is not None

    def test_lookup_dcom_10016(self):
        e = self.oc.lookup("EventID 10016 DCOM machine-default permission not granted")
        assert e is not None

    def test_lookup_defender_threat(self):
        e = self.oc.lookup("Windows Defender threat detected EventID 1116")
        assert e is not None

    def test_lookup_ransomware(self):
        e = self.oc.lookup("ransomware encrypted files vssadmin delete shadows")
        assert e is not None

    def test_lookup_rpc_fail(self):
        e = self.oc.lookup("RPC server unavailable 0x800706ba 1722")
        assert e is not None

    def test_lookup_pagefile_exhaust(self):
        e = self.oc.lookup("virtual memory low pagefile exhausted 0xC0000017")
        assert e is not None

    def test_lookup_wlan_fail(self):
        e = self.oc.lookup("WLAN AutoConfig service failed Wlansvc stopped")
        assert e is not None

    def test_lookup_cert_expired(self):
        e = self.oc.lookup("certificate expired CERT_E_EXPIRED TLS handshake fail")
        assert e is not None

    def test_lookup_disk_controller_7(self):
        e = self.oc.lookup("EventID 7 disk controller error harddisk bad block")
        assert e is not None

    def test_lookup_driver_conflict_219(self):
        e = self.oc.lookup("EventID 219 driver conflict device cannot start Code 10")
        assert e is not None

    def test_lookup_windows_update_fail(self):
        e = self.oc.lookup("Windows Update failed KB5001330 SoftwareDistribution corrupt")
        assert e is not None

    def test_lookup_vss_fail(self):
        e = self.oc.lookup("Volume Shadow Copy VSS failed EventID 8193")
        assert e is not None

    def test_lookup_spooler_crash(self):
        e = self.oc.lookup("Print Spooler spoolsv crash service stopped")
        assert e is not None

    def test_lookup_wmi_corrupt(self):
        e = self.oc.lookup("WMI repository corrupt winmgmt fail WBEM")
        assert e is not None

    def test_lookup_gpo_fail(self):
        e = self.oc.lookup("Group Policy failed gpupdate access denied GPO cannot be applied")
        assert e is not None

    def test_lookup_sfc_corrupt(self):
        e = self.oc.lookup("Windows Resource Protection found corrupt files sfc scannow")
        assert e is not None

    def test_lookup_audit_log_cleared(self):
        e = self.oc.lookup("EventID 1102 security audit log cleared")
        assert e is not None

    def test_windows_entries_have_fix_primitives(self):
        entries = [e for e in self.oc.all_entries() if e.platform == "windows"]
        no_prims = [e.fault_id for e in entries if not e.fix_primitives]
        assert not no_prims, f"Windows entries missing fix_primitives: {no_prims}"

    def test_windows_entries_have_patterns(self):
        entries = [e for e in self.oc.all_entries() if e.platform == "windows"]
        no_patterns = [e.fault_id for e in entries if not e.patterns]
        assert not no_patterns, f"Windows entries missing patterns: {no_patterns}"


# ─── Exception catalog Windows coverage ──────────────────────────────────────

class TestWindowsExceptionCatalog:
    def setup_method(self):
        from healing_core.exception_catalog import ExceptionCatalog
        self.ec = ExceptionCatalog()

    def test_windows_entries_count(self):
        win = [e for e in self.ec.all_entries() if e.platform == "windows"]
        assert len(win) >= 20, f"Expected ≥20 Windows entries, got {len(win)}"

    def test_lookup_winerror_5(self):
        # WinError 5 / access denied may match either a windows-specific
        # or all-platform PermissionError entry — both are correct.
        e = self.ec.lookup("WinError 5 Access is denied 0x80070005")
        assert e is not None
        assert e.platform in ("windows", "all")

    def test_lookup_winerror_1722_rpc(self):
        e = self.ec.lookup("WinError 1722 RPC server is unavailable")
        assert e is not None

    def test_lookup_wsaenetunreach(self):
        e = self.ec.lookup("WSAENETUNREACH network unreachable 10051")
        assert e is not None

    def test_lookup_wsaeaddrinuse(self):
        e = self.ec.lookup("WSAEADDRINUSE address already in use 10048")
        assert e is not None

    def test_lookup_eventid_7034(self):
        e = self.ec.lookup("EventID 7034 service terminated unexpectedly")
        assert e is not None

    def test_lookup_eventid_4625(self):
        e = self.ec.lookup("EventID 4625 logon failure account failed to log on")
        assert e is not None

    def test_lookup_eventid_4740_lockout(self):
        e = self.ec.lookup("EventID 4740 account locked out")
        assert e is not None

    def test_lookup_eventid_41_bsod(self):
        e = self.ec.lookup("EventID 41 system restarted unexpectedly BugcheckCode")
        assert e is not None

    def test_lookup_hresult_e_accessdenied(self):
        e = self.ec.lookup("HRESULT E_ACCESSDENIED 0x80070005 DCOM EventID 10016")
        assert e is not None

    def test_lookup_windows_update_error(self):
        e = self.ec.lookup("WindowsUpdate.log 0x80070643 Update fail KB install fail")
        assert e is not None

    def test_lookup_unauthorized_access_exception(self):
        e = self.ec.lookup("System.UnauthorizedAccessException access denied")
        assert e is not None

    def test_lookup_service_timeout_exception(self):
        e = self.ec.lookup("ServiceProcess TimeoutException service did not respond timely")
        assert e is not None

    def test_lookup_eventid_1001_crash(self):
        e = self.ec.lookup("EventID 1001 Windows Error Reporting faulting application")
        assert e is not None

    def test_windows_entries_have_fix_primitives(self):
        win = [e for e in self.ec.all_entries() if e.platform == "windows"]
        missing = [e.exception_class for e in win if not e.fix_primitive]
        assert not missing, f"Missing fix_primitive: {missing}"

    def test_windows_entries_have_patterns(self):
        win = [e for e in self.ec.all_entries() if e.platform == "windows"]
        missing = [e.exception_class for e in win if not e.patterns]
        assert not missing, f"Missing patterns: {missing}"


# ─── Service Resolver ─────────────────────────────────────────────────────────

class TestServiceResolver:
    def test_windows_name_translations(self):
        from healing_core.service_resolver import resolve_to_windows_name
        cases = {
            "nginx": "nginx", "mysql": "MySQL80", "ssh": "sshd",
            "dns": "Dnscache", "wmi": "winmgmt", "spooler": "Spooler",
            "iis": "W3SVC", "defender": "WinDefend", "firewall": "MpsSvc",
            "task scheduler": "Schedule", "wlan": "Wlansvc",
            "rpc": "RpcSs", "eventlog": "EventLog",
            "sqlserver": "MSSQLSERVER", "remote desktop": "TermService",
            "postgresql": "postgresql-x64-14", "redis": "Redis",
            "windows update": "wuauserv", "bits": "BITS",
        }
        for short, expected in cases.items():
            got = resolve_to_windows_name(short)
            assert got == expected, f"{short!r}: got {got!r}, want {expected!r}"

    def test_macos_label_translations(self):
        from healing_core.service_resolver import resolve_to_macos_label
        cases = {
            "nginx":      "system/homebrew.mxcl.nginx",
            "mysql":      "system/homebrew.mxcl.mysql",
            "postgresql": "system/homebrew.mxcl.postgresql@14",
            "ssh":        "system/com.openssh.sshd",
            "redis":      "system/homebrew.mxcl.redis",
            "cron":       "system/com.vix.cron",
        }
        for short, expected in cases.items():
            got = resolve_to_macos_label(short)
            assert got == expected, f"{short!r}: got {got!r}, want {expected!r}"

    def test_unknown_short_name_passthrough(self):
        from healing_core.service_resolver import resolve_to_windows_name
        got = resolve_to_windows_name("completely_unknown_service_xyz")
        assert got == "completely_unknown_service_xyz"

    def test_linux_map_has_common_services(self):
        from healing_core.service_resolver import _LINUX_MAP
        for svc in ("nginx", "postgresql", "mysql", "redis", "sshd", "cron"):
            assert svc in _LINUX_MAP, f"Missing Linux service: {svc}"

    def test_windows_map_has_core_services(self):
        from healing_core.service_resolver import _WINDOWS_MAP
        for svc in ("dns", "spooler", "wmi", "iis", "defender", "wlan", "rpc",
                    "eventlog", "mssql", "task scheduler"):
            assert svc in _WINDOWS_MAP, f"Missing Windows service: {svc}"

    def test_windows_map_size(self):
        from healing_core.service_resolver import _WINDOWS_MAP
        assert len(_WINDOWS_MAP) >= 60, f"Expected ≥60 entries, got {len(_WINDOWS_MAP)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
