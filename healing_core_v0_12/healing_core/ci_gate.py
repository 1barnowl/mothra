"""
healing_core.ci_gate — CIGate  (v0.12)

Formal CI harness. Closes guideline item 8:
  "chaos/red-team drills wired into a CI pipeline or configured as a
   blocking gate on primitive promotion"

Checks (in order):
  1. required_primitives  — all 52 named primitives registered on current OS
  2. catalog_integrity    — every entry has patterns + fix_primitive
  3. classifier_coverage  — 15 typed scenarios classify to expected category
  4. regression_scenarios — same 15 events through full ingest(); no exceptions
  5. chaos/seed=N         — ChaosHarness run per seed; 0 exc + chain valid
  6. audit_chain          — HMAC chain intact after all checks

Exit code: 0 = all pass, 1 = any fail.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING
if TYPE_CHECKING:
    from .core import HealingCore
from .models import Event, IncidentCategory

REQUIRED_PRIMITIVES = {
    "restart_service","disable_service","set_service_auto","set_service_delayed",
    "set_service_recovery","flush_dns","set_dns_cloudflare","reset_network_stack",
    "restart_network_interface","restart_wifi","release_renew_ip",
    "allow_firewall_port","reset_firewall","block_ip","kill_process","kill_pid",
    "kill_high_cpu","kill_high_mem","renice_process","lower_priority","drop_caches",
    "get_disk_usage","clear_temp","adjust_power_plan","disable_account",
    "enable_account","reset_account_password","grant_logon_service_right",
    "grant_smb_access","update_group_policy","run_defender_scan","run_av_scan",
    "remove_threats","update_av_signatures","add_av_exclusion",
    "reset_file_permissions","grant_file_permissions","take_file_ownership",
    "restore_config_from_backup","repair_system_files","dism_restore_health",
    "reset_registry_perms","restore_registry","set_execution_policy",
    "update_driver","rollback_driver","disable_device","rollback_update",
    "chkdsk","sync_time","set_ntp_server","update_cert",
}

REGRESSION_SCENARIOS = [
    ("svc_crash_eventid_7034",
     {"error_type":"EventID_7034","message":"EventID 7034: nginx service terminated unexpectedly","actor":"nginx","subsystem":"service"},
     "SERVICE", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("svc_start_timeout_7009",
     {"error_type":"EventID_7009","message":"EventID 7009: timed out waiting for MySQL service","actor":"mysql","subsystem":"service"},
     "SERVICE", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("oom_kill",
     {"error_type":"oom_kill","message":"Out of memory: kill process 1234 (nginx) score 851","actor":"nginx","subsystem":"kernel"},
     "RESOURCE", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("disk_full",
     {"error_type":"disk_full","message":"No space left on device /var/log — disk usage 100%","actor":"journald","subsystem":"storage"},
     "RESOURCE", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("pagefile_exhaust",
     {"error_type":"resource","message":"0xC0000017 pagefile virtual memory exhausted commit limit","actor":"kernel","subsystem":"system"},
     "RESOURCE", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("dns_timeout",
     {"error_type":"dns_timeout","message":"DNS resolution failed WSAEHOSTUNREACH for api.example.com","actor":"resolver","subsystem":"network"},
     "NETWORK", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("winsock_corrupt",
     {"error_type":"network","message":"Winsock catalog corrupt netsh winsock reset required","actor":"netsh","subsystem":"network"},
     "NETWORK", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("auth_failure_4625",
     {"error_type":"EventID_4625","message":"EventID 4625: account logon failure Status 0xC000006D","actor":"sshd","subsystem":"auth"},
     "AUTHENTICATION", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("account_lockout_4740",
     {"error_type":"EventID_4740","message":"EventID 4740: account locked out after too many attempts","actor":"winlogon","subsystem":"auth"},
     "AUTHENTICATION", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("defender_threat",
     {"error_type":"EventID_1116","message":"Windows Defender threat detected EventID 1116 Ransom.WannaCry","actor":"WinDefend","subsystem":"security"},
     "MALWARE", ["ESCALATED","SUPPRESSED"]),
    ("ransomware_indicator",
     {"error_type":"malware","message":"ransomware vssadmin delete shadows encrypted files bitcoin","actor":"suspicious_proc","subsystem":"security"},
     "MALWARE", ["ESCALATED","SUPPRESSED"]),
    ("bsod_stop_code",
     {"error_type":"hardware","message":"STOP 0x0000007E kernel panic BugcheckCode BSOD system crashed","actor":"kernel","subsystem":"system"},
     "HARDWARE", ["ESCALATED","SUPPRESSED","COMMITTED"]),
    ("disk_io_error_7",
     {"error_type":"EventID_7","message":"EventID 7: disk controller error harddisk bad block \\Device\\Harddisk0","actor":"disk","subsystem":"storage"},
     "HARDWARE", ["ESCALATED","SUPPRESSED","COMMITTED"]),
    ("driver_load_fail_7026",
     {"error_type":"EventID_7026","message":"EventID 7026: driver failed to load boot-start driver","actor":"nvlddmkm","subsystem":"driver"},
     "DRIVER", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
    ("sfc_corrupt",
     {"error_type":"configuration","message":"Windows Resource Protection found corrupt files sfc scannow CBS.log","actor":"sfc","subsystem":"system"},
     "CONFIGURATION", ["COMMITTED","ESCALATED","SUPPRESSED","CORRELATED","PENDING"]),
]


@dataclass
class CICheck:
    name:       str
    passed:     bool
    detail:     str   = ""
    duration_s: float = 0.0


@dataclass
class CIResult:
    checks:       List[CICheck] = field(default_factory=list)
    total:        int           = 0
    passed:       int           = 0
    failed:       int           = 0
    duration_s:   float         = 0.0
    seed_reports: List[Any]     = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return 0 if self.failed == 0 else 1

    @property
    def success(self) -> bool:
        return self.failed == 0


class CIGate:
    def __init__(self, chaos_seeds=None, chaos_events=200,
                 chaos_time_limit_s=30.0, strict=False):
        self.chaos_seeds      = chaos_seeds or [42, 123, 999]
        self.chaos_events     = chaos_events
        self.chaos_time_limit = chaos_time_limit_s
        self.strict           = strict

    def run(self, core: "HealingCore") -> CIResult:
        result  = CIResult()
        t_start = time.monotonic()
        checks  = [
            self._check_required_primitives(core),
            self._check_catalog_integrity(core),
            self._check_classifier_coverage(core),
            *self._check_regression_scenarios(core),
            *self._check_chaos_seeds(core, result),
            self._check_audit_chain(core),
        ]
        result.checks   = checks
        result.total    = len(checks)
        result.passed   = sum(1 for c in checks if c.passed)
        result.failed   = sum(1 for c in checks if not c.passed)
        result.duration_s = time.monotonic() - t_start
        return result

    def _check_required_primitives(self, core):
        t0 = time.monotonic()
        registered = {f.name for fixes in core.primitives._store.values() for f in fixes}
        missing    = REQUIRED_PRIMITIVES - registered
        passed     = len(missing) == 0
        detail     = "all present" if passed else f"missing ({len(missing)}): {sorted(missing)}"
        return CICheck("required_primitives", passed, detail, time.monotonic()-t0)

    def _check_catalog_integrity(self, core):
        t0  = time.monotonic()
        bad = []
        for e in core.exception_catalog.all_entries():
            if not e.patterns:        bad.append(f"exc/{e.exception_class}: no patterns")
            if not e.fix_primitive:   bad.append(f"exc/{e.exception_class}: no fix_primitive")
        for e in core.os_fault_catalog.all_entries():
            if not e.patterns:        bad.append(f"fault/{e.fault_id}: no patterns")
            if not e.fix_primitives:  bad.append(f"fault/{e.fault_id}: no fix_primitives")
        passed = len(bad) == 0
        detail = "all valid" if passed else f"{len(bad)} issues: {bad[:3]}"
        return CICheck("catalog_integrity", passed, detail, time.monotonic()-t0)

    def _check_classifier_coverage(self, core):
        t0  = time.monotonic()
        from .classification import IncidentClassifier
        clf = IncidentClassifier()
        bad = []
        for name, evkw, expected_cat, _ in REGRESSION_SCENARIOS:
            got = clf.classify(Event(**evkw)).name
            if got != expected_cat:
                bad.append(f"{name}: expected {expected_cat} got {got}")
            if self.strict and got == "UNKNOWN":
                bad.append(f"{name}: UNKNOWN (strict)")
        passed = len(bad) == 0
        detail = "all classified correctly" if passed else f"{len(bad)} wrong: {bad}"
        return CICheck("classifier_coverage", passed, detail, time.monotonic()-t0)

    def _check_regression_scenarios(self, core):
        orig_wait = None
        if getattr(core, "canary", None) is not None:
            orig_wait = core.canary._cfg.wait_seconds
            core.canary._cfg.wait_seconds = 0.0
        checks = []
        try:
            for name, evkw, _, allowed in REGRESSION_SCENARIOS:
                t0 = time.monotonic()
                try:
                    inc    = core.ingest(Event(**evkw))
                    status = inc.status.name if inc else "filtered"
                    passed = status in allowed
                    detail = f"status={status}" + ("" if passed else f" (allowed:{allowed})")
                    core._cooldowns.clear()
                except Exception as exc:
                    passed = False
                    detail = f"EXCEPTION: {type(exc).__name__}: {exc}"
                checks.append(CICheck(f"scenario/{name}", passed, detail, time.monotonic()-t0))
        finally:
            if orig_wait is not None:
                core.canary._cfg.wait_seconds = orig_wait
        return checks

    def _check_chaos_seeds(self, core, result):
        from .chaos import ChaosHarness
        checks = []
        for seed in self.chaos_seeds:
            t0 = time.monotonic()
            try:
                report  = ChaosHarness(seed=seed).run(core, n_events=self.chaos_events, fast_canary=True)
                result.seed_reports.append(report)
                elapsed = time.monotonic() - t0
                fails   = []
                if report.exceptions > 0:
                    fails.append(f"{report.exceptions} exceptions")
                if not report.audit_chain_valid_after:
                    fails.append("chain broken")
                if elapsed > self.chaos_time_limit:
                    fails.append(f"timeout {elapsed:.1f}s>{self.chaos_time_limit:.0f}s")
                passed  = len(fails) == 0
                detail  = (f"seed={seed} events={report.total_events} "
                           f"exc={report.exceptions} chain={report.audit_chain_valid_after} "
                           f"{elapsed:.2f}s" + (f" FAIL:{fails}" if fails else ""))
            except Exception as exc:
                passed  = False
                detail  = f"harness crashed: {exc}"
            checks.append(CICheck(f"chaos/seed={seed}", passed, detail, time.monotonic()-t0))
        return checks

    def _check_audit_chain(self, core):
        t0 = time.monotonic()
        try:
            ok, bad = core.audit.verify_chain()
            s       = core.audit.chain_summary()
            detail  = f"entries={s['total_entries']} valid={ok} tampered={s['tampered_entries']}"
            if bad: detail += f" bad_ids={bad[:3]}"
        except Exception as exc:
            ok     = False
            detail = f"verify_chain() raised: {exc}"
        return CICheck("audit_chain", ok, detail, time.monotonic()-t0)

    def format_report(self, result: CIResult) -> str:
        hr    = "─" * 72
        lines = [
            "", hr,
            f"  HealingCore CI Gate  —  {'PASS ✓' if result.success else 'FAIL ✗'}",
            f"  {result.passed}/{result.total} checks  ({result.duration_s:.2f}s)",
            hr,
        ]
        for c in result.checks:
            ms   = f"  ({c.duration_s*1000:.0f}ms)" if c.duration_s >= 0.001 else ""
            lines.append(f"  [{'✓' if c.passed else '✗'}] {c.name:<40s} {c.detail[:60]}{ms}")
        if result.seed_reports:
            lines.append("\n  Chaos seed outcomes:")
            for r in result.seed_reports:
                lines.append(f"    seed={r.seed:<6} events={r.total_events:<5} "
                             f"exc={r.exceptions:<3} chain={'ok' if r.audit_chain_valid_after else 'BROKEN'} "
                             f"{r.duration_s:.2f}s  {r.outcomes}")
        lines.append(hr)
        return "\n".join(lines)
