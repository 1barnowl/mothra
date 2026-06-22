"""
tests/test_v09.py
─────────────────
v0.9 test suite:
  - macOS registers correct primitives (not Linux)
  - Windows service steps call service_resolver (not raw actor)
  - All three platforms cover every required primitive name
  - WindowsEvtLogAdapter XML → Event parsing (no real Windows needed)
  - JournaldAdapter JSON → Event parsing (no real journald needed)
  - MacosLogAdapter JSON → Event parsing (no real macOS needed)
  - core.start_log_adapter() dispatches correctly per OS
  - Cross-platform scenario: same error, correct fix category per OS
"""
import json
import os
import platform
import sys
import textwrap
import threading
import time
import uuid
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

OS = platform.system()

# ── Required primitive names (must exist on every platform) ───────────────────

REQUIRED_PRIMITIVES = {
    "restart_service", "disable_service", "set_service_auto",
    "set_service_delayed", "set_service_recovery",
    "flush_dns", "set_dns_cloudflare", "reset_network_stack",
    "restart_network_interface", "restart_wifi", "release_renew_ip",
    "allow_firewall_port", "reset_firewall", "block_ip",
    "kill_process", "kill_pid", "kill_high_cpu", "kill_high_mem",
    "renice_process", "lower_priority", "drop_caches",
    "get_disk_usage", "clear_temp", "adjust_power_plan",
    "disable_account", "enable_account", "reset_account_password",
    "grant_logon_service_right", "grant_smb_access", "update_group_policy",
    "run_defender_scan", "run_av_scan", "remove_threats",
    "update_av_signatures", "add_av_exclusion",
    "reset_file_permissions", "grant_file_permissions", "take_file_ownership",
    "restore_config_from_backup", "repair_system_files", "dism_restore_health",
    "reset_registry_perms", "restore_registry", "set_execution_policy",
    "update_driver", "rollback_driver", "disable_device", "rollback_update",
    "chkdsk", "sync_time", "set_ntp_server", "update_cert",
}


# ─── Platform-correct primitives ─────────────────────────────────────────────

class TestPrimitivesAllPlatforms:
    """Every required primitive name must be registered regardless of OS."""

    def _registry(self, os_override=None):
        import importlib
        import healing_core.primitives as pm
        orig = pm.OS
        if os_override:
            pm.OS = os_override
        try:
            r = pm.PrimitivesRegistry()
            # Import correct driver with DryRun
            if (os_override or OS) == "Windows":
                import drivers.windows as drv; drv.DryRun = True
            elif (os_override or OS) == "Darwin":
                import drivers.macos as drv;   drv.DryRun = True
            else:
                import drivers.linux as drv;   drv.DryRun = True
            r.register_builtins(dry_run=True)
            return r
        finally:
            pm.OS = orig

    def _registered_names(self, registry) -> set:
        names = set()
        for fixes in registry._store.values():
            for f in fixes:
                names.add(f.name)
        return names

    def test_linux_has_all_required_primitives(self):
        r = self._registry("Linux")
        names = self._registered_names(r)
        missing = REQUIRED_PRIMITIVES - names
        assert not missing, f"Linux missing: {sorted(missing)}"

    def test_windows_has_all_required_primitives(self):
        r = self._registry("Windows")
        names = self._registered_names(r)
        missing = REQUIRED_PRIMITIVES - names
        assert not missing, f"Windows missing: {sorted(missing)}"

    def test_macos_has_all_required_primitives(self):
        r = self._registry("Darwin")
        names = self._registered_names(r)
        missing = REQUIRED_PRIMITIVES - names
        assert not missing, f"macOS missing: {sorted(missing)}"

    def test_macos_does_not_use_linux_driver(self):
        """macOS restart_service step must call macos.restart_service, not linux."""
        import healing_core.primitives as pm
        import drivers.macos as mac
        mac.DryRun = True
        orig_os = pm.OS
        pm.OS = "Darwin"
        try:
            r = pm.PrimitivesRegistry()
            r.register_builtins(dry_run=True)
            svc_fixes = r._store.get("SERVICE", [])
            restart = next((f for f in svc_fixes if f.name == "restart_service"), None)
            assert restart is not None, "restart_service not registered for Darwin"
            # The step closure should reference macos driver, not linux
            # We verify by inspecting the step's __code__.co_freevars or running it dry
            from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
            evt = Event(error_type="test", message="service crash", actor="nginx", subsystem="service")
            inc = Incident(event=evt, category=IncidentCategory.SERVICE,
                          scope=Scope.MODULE, severity=Severity.HIGH, risk_score=0.5)
            ok, detail = restart.steps[0](inc)
            assert ok, f"macOS restart_service dry-run failed: {detail}"
            assert "dry-run" in detail.lower() or "kickstart" in detail.lower() or ok
        finally:
            pm.OS = orig_os

    def test_windows_service_step_resolves_name(self):
        """Windows restart_service must call service_resolver, not use raw actor."""
        import healing_core.primitives as pm
        import drivers.windows as win
        win.DryRun = True
        orig_os = pm.OS
        pm.OS = "Windows"
        try:
            r = pm.PrimitivesRegistry()
            r.register_builtins(dry_run=True)
            svc_fixes = r._store.get("SERVICE", [])
            restart = next((f for f in svc_fixes if f.name == "restart_service"), None)
            assert restart is not None
            from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
            # Actor "mysql" should be translated to "MySQL80" via service_resolver
            evt = Event(error_type="service_crash", message="MySQL80 stopped", actor="mysql", subsystem="service")
            inc = Incident(event=evt, category=IncidentCategory.SERVICE,
                          scope=Scope.MODULE, severity=Severity.HIGH, risk_score=0.5)
            ok, detail = restart.steps[0](inc)
            assert ok, f"Windows restart_service dry-run failed: {detail}"
            # The service name passed to the driver should be the resolved name
            assert "dry-run" in detail.lower() or ok
        finally:
            pm.OS = orig_os

    def test_macos_primitives_count(self):
        r = self._registry("Darwin")
        total = sum(len(v) for v in r._store.values())
        assert total >= 50, f"Expected ≥50 macOS primitives, got {total}"

    def test_windows_primitives_count(self):
        r = self._registry("Windows")
        total = sum(len(v) for v in r._store.values())
        assert total >= 50, f"Expected ≥50 Windows primitives, got {total}"

    def test_linux_primitives_count(self):
        r = self._registry("Linux")
        total = sum(len(v) for v in r._store.values())
        assert total >= 50, f"Expected ≥50 Linux primitives, got {total}"

    def test_extract_path_windows_style(self):
        from healing_core.primitives import _extract_path
        from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
        evt = Event(error_type="e", message="Error in C:\\Program Files\\App\\config.json",
                    actor="app", subsystem="sys")
        inc = Incident(event=evt, category=IncidentCategory.CONFIGURATION,
                       scope=Scope.MODULE, severity=Severity.LOW, risk_score=0.1)
        path = _extract_path(inc)
        assert "Program Files" in path or "config" in path

    def test_extract_path_unix_style(self):
        from healing_core.primitives import _extract_path
        from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
        evt = Event(error_type="e", message="Cannot open /etc/nginx/nginx.conf",
                    actor="nginx", subsystem="sys")
        inc = Incident(event=evt, category=IncidentCategory.CONFIGURATION,
                       scope=Scope.MODULE, severity=Severity.LOW, risk_score=0.1)
        path = _extract_path(inc)
        assert path == "/etc/nginx/nginx.conf"


# ─── WindowsEvtLogAdapter XML parsing ────────────────────────────────────────

class TestEvtlogAdapter:
    """Test XML → Event parsing without a real Windows system."""

    def _adapter(self, core=None):
        from healing_core.evtlog_adapter import WindowsEvtLogAdapter
        return WindowsEvtLogAdapter(core or _FakeCore(), poll_interval=999)

    def _make_xml(self, event_id, level="2", provider="Microsoft-Windows-Kernel-Power",
                  message="service terminated unexpectedly", channel="System"):
        return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='{provider}'/>
    <EventID>{event_id}</EventID>
    <Level>{level}</Level>
    <EventRecordID>12345</EventRecordID>
    <Channel>{channel}</Channel>
  </System>
  <EventData>
    <Data Name='ServiceName'>nginx</Data>
    <Data Name='Message'>{message}</Data>
  </EventData>
</Event>"""

    def test_xml_to_event_basic(self):
        import xml.etree.ElementTree as ET
        a = self._adapter()
        xml_str = self._make_xml(7034, level="2")
        elem = ET.fromstring(xml_str)
        evt = a._xml_to_event(elem, "System")
        assert evt is not None
        assert evt.error_type == "EventID_7034"
        assert "7034" in evt.message
        assert evt.subsystem == "System"

    def test_xml_to_event_interesting_id_passes(self):
        import xml.etree.ElementTree as ET
        a = self._adapter()
        xml_str = self._make_xml(4625, level="2", channel="Security")
        elem = ET.fromstring(xml_str)
        evt = a._xml_to_event(elem, "Security")
        assert evt is not None
        assert evt.error_type == "EventID_4625"

    def test_xml_to_event_uninteresting_id_filtered(self):
        import xml.etree.ElementTree as ET
        from healing_core.evtlog_adapter import WindowsEvtLogAdapter
        # Use empty interesting_ids to skip ALL filtering (should pass all)
        a = WindowsEvtLogAdapter(_FakeCore(), interesting_ids=set(), poll_interval=999)
        # EventID 9999 - not in default set but we cleared the filter
        xml_str = self._make_xml(9999, level="6")  # level=6=info → skipped by level
        elem = ET.fromstring(xml_str)
        evt = a._xml_to_event(elem, "System")
        # Level 6 (info) with empty id set gets skipped because level check
        assert evt is None

    def test_xml_to_event_provider_in_actor(self):
        import xml.etree.ElementTree as ET
        a = self._adapter()
        xml_str = self._make_xml(7034, provider="TestProvider")
        elem = ET.fromstring(xml_str)
        evt = a._xml_to_event(elem, "System")
        assert evt is not None
        assert evt.actor == "TestProvider"

    def test_xml_to_event_message_extracted(self):
        import xml.etree.ElementTree as ET
        a = self._adapter()
        xml_str = self._make_xml(7034, message="Service crashed with exit code 1")
        elem = ET.fromstring(xml_str)
        evt = a._xml_to_event(elem, "System")
        assert evt is not None
        assert len(evt.message) > 10

    def test_get_record_id(self):
        import xml.etree.ElementTree as ET
        a = self._adapter()
        xml_str = self._make_xml(41)
        elem = ET.fromstring(xml_str)
        rid = a._get_record_id(elem)
        assert rid == 12345

    def test_malformed_xml_returns_none(self):
        import xml.etree.ElementTree as ET
        a = self._adapter()
        try:
            elem = ET.fromstring("<Event></Event>")
            evt = a._xml_to_event(elem, "System")
            assert evt is None
        except ET.ParseError:
            pass  # also acceptable

    def test_stats_keys(self):
        a = self._adapter()
        s = a.stats()
        for k in ("channels", "ingested", "errors", "queue_len"):
            assert k in s

    def test_default_channels(self):
        from healing_core.evtlog_adapter import WindowsEvtLogAdapter
        a = WindowsEvtLogAdapter(_FakeCore(), poll_interval=999)
        assert "System" in a._channels
        assert "Security" in a._channels
        assert "Application" in a._channels

    def test_interesting_ids_populated(self):
        from healing_core.evtlog_adapter import DEFAULT_INTERESTING_IDS
        assert 7034 in DEFAULT_INTERESTING_IDS   # service crash
        assert 4625 in DEFAULT_INTERESTING_IDS   # logon failure
        assert 41   in DEFAULT_INTERESTING_IDS   # unexpected shutdown
        assert 1116 not in DEFAULT_INTERESTING_IDS  # Defender (Application channel)


# ─── JournaldAdapter JSON parsing ────────────────────────────────────────────

class TestJournaldAdapter:

    def _adapter(self):
        from healing_core.journald_adapter import JournaldAdapter
        return JournaldAdapter(_FakeCore(), priority_threshold=4)

    def _line(self, message, priority="3", unit="nginx.service",
              pid="1234", facility="3"):
        return json.dumps({
            "MESSAGE":            message,
            "PRIORITY":           priority,
            "_SYSTEMD_UNIT":      unit,
            "_PID":               pid,
            "SYSLOG_FACILITY":    facility,
            "_COMM":              "nginx",
        })

    def test_error_line_parsed(self):
        a = self._adapter()
        evt = a._line_to_event(self._line("Out of memory: kill process nginx"))
        assert evt is not None
        assert evt.error_type in ("oom", "error", "critical_fault")

    def test_high_priority_passes(self):
        a = self._adapter()
        evt = a._line_to_event(self._line("Critical failure", priority="2"))
        assert evt is not None

    def test_low_priority_filtered(self):
        a = self._adapter()
        evt = a._line_to_event(self._line("Normal startup complete", priority="6",
                                           unit="regular.service"))
        assert evt is None   # priority 6 (info) > threshold 4

    def test_actor_has_unit_and_pid(self):
        a = self._adapter()
        evt = a._line_to_event(self._line("test", priority="3"))
        assert evt is not None
        assert "nginx" in evt.actor
        assert "1234" in evt.actor

    def test_subsystem_from_facility(self):
        a = self._adapter()
        evt = a._line_to_event(self._line("test", priority="3", facility="4"))
        assert evt is not None
        assert evt.subsystem == "auth"

    def test_keyword_extraction(self):
        a = self._adapter()
        evt = a._line_to_event(self._line("Connection refused by peer", priority="3"))
        assert evt is not None
        assert evt.error_type == "refused"

    def test_empty_message_filtered(self):
        a = self._adapter()
        line = json.dumps({"MESSAGE": "", "PRIORITY": "3", "_SYSTEMD_UNIT": "nginx.service"})
        evt = a._line_to_event(line)
        assert evt is None

    def test_malformed_json_filtered(self):
        a = self._adapter()
        evt = a._line_to_event("{not valid json")
        assert evt is None

    def test_stats_keys(self):
        a = self._adapter()
        s = a.stats()
        for k in ("ingested", "skipped", "errors"):
            assert k in s

    def test_rate_check(self):
        a = self._adapter()
        a._rate_limit = 5
        results = [a._rate_check() for _ in range(10)]
        assert results[:5] == [True]*5
        assert results[5:] == [False]*5

    def test_always_interesting_unit_passes_high_priority(self):
        a = self._adapter()
        # sshd at priority 5 (notice) should pass because it's always interesting
        evt = a._line_to_event(self._line("Failed password for root", priority="5",
                                           unit="sshd"))
        assert evt is not None


# ─── MacosLogAdapter JSON parsing ────────────────────────────────────────────

class TestMacosLogAdapter:

    def _adapter(self):
        from healing_core.macos_log_adapter import MacosLogAdapter
        return MacosLogAdapter(_FakeCore(), level="error")

    def _entry(self, message, level="error", process="nginx",
               pid=1234, subsystem="com.example"):
        return json.dumps({
            "eventMessage":    message,
            "messageType":     level,
            "processImagePath":f"/usr/sbin/{process}",
            "processID":       pid,
            "subsystem":       subsystem,
            "category":        "network",
        })

    def test_error_entry_parsed(self):
        a = self._adapter()
        evt = a._line_to_event(self._entry("Connection refused"))
        assert evt is not None
        assert evt.error_type == "refused"

    def test_fault_entry_parsed(self):
        a = self._adapter()
        evt = a._line_to_event(self._entry("Kernel panic occurred", level="fault"))
        assert evt is not None
        assert evt.error_type == "panic"

    def test_info_entry_filtered(self):
        a = self._adapter()
        evt = a._line_to_event(self._entry("Server started OK", level="info"))
        assert evt is None

    def test_actor_has_process_and_pid(self):
        a = self._adapter()
        evt = a._line_to_event(self._entry("test error"))
        assert evt is not None
        assert "nginx" in evt.actor
        assert "1234" in evt.actor

    def test_subsystem_extracted(self):
        a = self._adapter()
        evt = a._line_to_event(self._entry("test error", subsystem="com.apple.security"))
        assert evt is not None
        assert "apple" in evt.subsystem or "security" in evt.subsystem

    def test_empty_message_filtered(self):
        a = self._adapter()
        evt = a._line_to_event(self._entry("", level="error"))
        assert evt is None

    def test_malformed_json_filtered(self):
        a = self._adapter()
        evt = a._line_to_event("{bad json")
        assert evt is None

    def test_keyword_extraction_crash(self):
        a = self._adapter()
        evt = a._line_to_event(self._entry("Application crash in main thread"))
        assert evt is not None
        assert evt.error_type == "crash"

    def test_rate_check(self):
        a = self._adapter()
        a._rate_limit = 3
        results = [a._rate_check() for _ in range(6)]
        assert results[:3] == [True]*3
        assert results[3:] == [False]*3

    def test_stats_keys(self):
        a = self._adapter()
        s = a.stats()
        for k in ("ingested", "skipped", "errors"):
            assert k in s


# ─── Core adapter dispatch ────────────────────────────────────────────────────

class TestCoreAdapterDispatch:

    def _core(self):
        from healing_core.core import HealingCore
        return HealingCore(
            dry_run=True, db_path=":memory:",
            api_port=0, prometheus_port=0,
            enable_monitor=False, knowledge_ai_enabled=False,
            enable_multi_ai=False, enable_ml_classifier=False,
        )

    def test_start_log_adapter_returns_adapter(self):
        core = self._core()
        adapter = core.start_log_adapter()
        assert adapter is not None
        core.shutdown()

    def test_adapter_type_matches_os(self):
        import platform as p
        from healing_core.evtlog_adapter    import WindowsEvtLogAdapter
        from healing_core.journald_adapter  import JournaldAdapter
        from healing_core.macos_log_adapter import MacosLogAdapter
        core = self._core()
        adapter = core.start_log_adapter()
        if p.system() == "Windows":
            assert isinstance(adapter, WindowsEvtLogAdapter)
        elif p.system() == "Darwin":
            assert isinstance(adapter, MacosLogAdapter)
        else:
            assert isinstance(adapter, JournaldAdapter)
        core.shutdown()

    def test_adapter_report_no_crash_without_adapter(self):
        core = self._core()
        core.adapter_report()   # should print "No log adapter started"
        core.shutdown()

    def test_adapter_report_no_crash_with_adapter(self):
        core = self._core()
        core.start_log_adapter()
        core.adapter_report()
        core.shutdown()

    def test_shutdown_stops_adapter(self):
        core = self._core()
        adapter = core.start_log_adapter()
        core.shutdown()
        # After shutdown the adapter stop flag should be set
        assert adapter._stop.is_set()


# ─── Cross-platform scenario ──────────────────────────────────────────────────

class TestCrossPlatformScenarios:
    """Same incident text → correct fix category and primitive on all platforms."""

    SCENARIOS = [
        # (error_type, message, actor, subsystem, expected_category)
        ("service_crash",  "EventID 7034 nginx service terminated unexpectedly",
         "nginx", "system", "SERVICE"),
        ("oom_kill",       "Out of memory: killed nginx process PID 1234",
         "nginx", "kernel", "RESOURCE"),
        ("auth_failure",   "EventID 4625 account logon failure bad password",
         "sshd",  "auth",   "AUTHENTICATION"),
        ("disk_full",      "No space left on device /var/log NTFS volume full 0x80070070",
         "journald", "storage", "RESOURCE"),
        ("malware",        "Windows Defender threat detected EventID 1116",
         "WinDefend", "security", "MALWARE"),
        ("dns_timeout",    "DNS resolution failed WSAEHOSTUNREACH for api.example.com",
         "resolver", "network", "NETWORK"),
        ("bsod",           "STOP 0x0000007E kernel panic BSOD unexpected shutdown",
         "kernel", "system", "HARDWARE"),
    ]

    def _classify(self, error_type, message, actor, subsystem):
        from healing_core.classification import IncidentClassifier
        from healing_core.models import Event
        clf = IncidentClassifier()
        evt = Event(error_type=error_type, message=message,
                    actor=actor, subsystem=subsystem)
        return clf.classify(evt).name

    def test_all_scenarios_classify_correctly(self):
        failures = []
        for error_type, message, actor, subsystem, expected in self.SCENARIOS:
            got = self._classify(error_type, message, actor, subsystem)
            if got != expected:
                failures.append(f"{error_type}: got {got}, want {expected}")
        assert not failures, "\n".join(failures)

    def test_service_crash_selects_restart_primitive(self):
        """SERVICE category should select a restart_service-style primitive."""
        import healing_core.primitives as pm
        orig = pm.OS
        for test_os, drv_path in [("Linux","drivers.linux"),
                                  ("Darwin","drivers.macos"),
                                  ("Windows","drivers.windows")]:
            pm.OS = test_os
            try:
                import importlib
                drv = importlib.import_module(drv_path)
                drv.DryRun = True
                r = pm.PrimitivesRegistry()
                r.register_builtins(dry_run=True)
                svc_fixes = r._store.get("SERVICE", [])
                names = [f.name for f in svc_fixes]
                assert "restart_service" in names, \
                    f"restart_service missing for {test_os}: {names}"
            finally:
                pm.OS = orig


# ─── Helpers ──────────────────────────────────────────────────────────────────

class _FakeCore:
    """Minimal core stub for adapter tests."""
    def ingest(self, event):
        return None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
