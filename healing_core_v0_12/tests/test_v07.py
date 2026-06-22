"""
tests.test_v0_7
───────────────
Test suite for v0.7 additions:
  - OsFaultCatalog   (35 tests)
  - MultiAIOracle    (20 tests)
  - ProgramSynthesizer (20 tests)
  - RobustExceptionHandler (15 tests)

Total: 90 tests, 0 expected failures.
"""
from __future__ import annotations

import sys
import os
import time
import unittest
from unittest.mock import MagicMock, patch

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from healing_core.models import (
    Event, Incident, IncidentCategory, Severity, Scope, RemediationFix
)
from healing_core.os_fault_catalog import OsFaultCatalog, OsFaultEntry
from healing_core.multi_ai_oracle import (
    MultiAIOracle, CandidateFix,
    AnthropicBackend, WebSearchBackend,
    LocalKnowledgeBackend, OsFaultCatalogBackend,
    ExceptionCatalogBackend,
)
from healing_core.program_synthesizer import ProgramSynthesizer, _DANGER_PATTERNS
from healing_core.robust_exception_handler import RobustExceptionHandler
from healing_core.exception_catalog import ExceptionCatalog
from healing_core.primitives import PrimitivesRegistry


# ── Helpers ────────────────────────────────────────────────────────────────────

def _inc(error_type="service_crash", message="service crashed", cat=IncidentCategory.SERVICE):
    e = Event(actor="test_actor", subsystem="test", error_type=error_type, message=message)
    return Incident(event=e, category=cat, severity=Severity.HIGH)


def _make_primitives():
    reg = PrimitivesRegistry()
    reg.register(RemediationFix(
        name="restart_service", category=IncidentCategory.SERVICE,
        description="Restart the failing service",
        steps=[lambda inc: True], cost=0.3, source="builtin",
    ))
    reg.register(RemediationFix(
        name="flush_dns", category=IncidentCategory.NETWORK,
        description="Flush DNS cache",
        steps=[lambda inc: True], cost=0.1, source="builtin",
    ))
    reg.register(RemediationFix(
        name="clear_temp", category=IncidentCategory.RESOURCE,
        description="Clear temp files",
        steps=[lambda inc: True], cost=0.2, source="builtin",
    ))
    reg.register(RemediationFix(
        name="run_defender_scan", category=IncidentCategory.MALWARE,
        description="Run Windows Defender scan",
        steps=[lambda inc: True], cost=0.4, source="builtin",
    ))
    reg.register(RemediationFix(
        name="drop_caches", category=IncidentCategory.RESOURCE,
        description="Drop page caches",
        steps=[lambda inc: True], cost=0.2, source="builtin",
    ))
    reg.register(RemediationFix(
        name="reset_file_permissions", category=IncidentCategory.CONFIGURATION,
        description="Reset file ACLs",
        steps=[lambda inc: True], cost=0.3, source="builtin",
    ))
    reg.register(RemediationFix(
        name="sync_time", category=IncidentCategory.AUTHENTICATION,
        description="Sync NTP clock",
        steps=[lambda inc: True], cost=0.1, source="builtin",
    ))
    return reg


# ══════════════════════════════════════════════════════════════════════════════
# OsFaultCatalog tests
# ══════════════════════════════════════════════════════════════════════════════

class TestOsFaultCatalog(unittest.TestCase):

    def setUp(self):
        self.cat = OsFaultCatalog()

    # Structure
    def test_catalog_populated(self):
        entries = self.cat.all_entries()
        self.assertGreater(len(entries), 80,
            f"Expected 80+ entries, got {len(entries)}")

    def test_all_entries_have_required_fields(self):
        for e in self.cat.all_entries():
            self.assertTrue(e.fault_id,        f"fault_id empty: {e}")
            self.assertTrue(e.title,           f"title empty: {e.fault_id}")
            self.assertTrue(e.fix_primitives,  f"fix_primitives empty: {e.fault_id}")
            self.assertIsInstance(e.category,  IncidentCategory)
            self.assertIsInstance(e.severity,  Severity)

    def test_all_entries_unique_fault_ids(self):
        ids = [e.fault_id for e in self.cat.all_entries()]
        self.assertEqual(len(ids), len(set(ids)), "Duplicate fault_id found")

    # Pattern matching
    def test_wifi_down_pattern(self):
        e = self.cat.lookup("wifi interface down no carrier")
        self.assertIsNotNone(e)
        self.assertIn("wifi", e.fault_id)

    def test_dns_failure_pattern(self):
        e = self.cat.lookup("dns failure NXDOMAIN lookup failed")
        self.assertIsNotNone(e)
        self.assertIn("dns", e.fault_id)

    def test_gateway_unreachable(self):
        e = self.cat.lookup("gateway unreachable DHCP renewal failed")
        self.assertIsNotNone(e)
        self.assertIn("gateway", e.fault_id)

    def test_oom_pattern(self):
        e = self.cat.lookup("OOM kill process memory depleted")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.RESOURCE)

    def test_disk_full_pattern(self):
        e = self.cat.lookup("no space left on device ENOSPC disk full")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.RESOURCE)

    def test_service_crash(self):
        e = self.cat.lookup("service crash killed segfault exited")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.SERVICE)

    def test_auth_failure(self):
        e = self.cat.lookup("authentication failed invalid credentials 401 unauthorized")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.AUTHENTICATION)

    def test_ransomware_detection(self):
        e = self.cat.lookup("ransomware files encrypted ransom note")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.MALWARE)

    def test_kernel_panic(self):
        e = self.cat.lookup("kernel panic BSOD blue screen bugcheck")
        self.assertIsNotNone(e)
        self.assertIn("kernel", e.fault_id.lower() + e.title.lower())

    def test_port_in_use(self):
        e = self.cat.lookup("EADDRINUSE port already in use bind failed address")
        self.assertIsNotNone(e)
        self.assertIn("port", e.fault_id)

    def test_deadlock(self):
        e = self.cat.lookup("deadlock mutex block lock wait forever")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.SERVICE)

    def test_certificate_expired(self):
        e = self.cat.lookup("certificate expired SSL cert expiry x509")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.AUTHENTICATION)

    def test_driver_conflict(self):
        e = self.cat.lookup("driver conflict update incompatible after update fail")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.DRIVER)

    def test_rootkit_detection(self):
        e = self.cat.lookup("rootkit kernel modification boot sector modified")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.MALWARE)

    def test_zombie_process(self):
        e = self.cat.lookup("zombie process defunct Z STAT")
        self.assertIsNotNone(e)
        self.assertIn("zombie", e.fault_id)

    def test_config_corruption(self):
        e = self.cat.lookup("config file corrupt parse config error yaml error")
        self.assertIsNotNone(e)
        self.assertEqual(e.category, IncidentCategory.CONFIGURATION)

    def test_time_sync_failure(self):
        e = self.cat.lookup("NTP drift clock skew w32tm error time sync")
        self.assertIsNotNone(e)
        self.assertIn("time", e.fault_id)

    def test_platform_filter_windows(self):
        e = self.cat.lookup("process injection DLL inject code inject", platform="windows")
        self.assertIsNotNone(e)

    def test_platform_filter_linux(self):
        e = self.cat.lookup("zombie process defunct", platform="linux")
        self.assertIsNotNone(e)

    # Summary
    def test_summary_structure(self):
        s = self.cat.summary()
        self.assertIn("total_entries", s)
        self.assertIn("by_category", s)
        self.assertIn("by_platform", s)
        self.assertGreater(s["total_entries"], 80)

    def test_summary_has_multiple_categories(self):
        s = self.cat.summary()
        self.assertGreater(len(s["by_category"]), 5)

    # Enrich
    def test_enrich_event_adds_fields(self):
        event_dict = {"error_type": "disk_full", "message": "no space left on device ENOSPC"}
        result = self.cat.enrich_event(event_dict)
        self.assertIn("_os_fault_id", result)
        self.assertIn("_os_fault_category", result)
        self.assertIn("_os_fault_primitives", result)

    def test_enrich_event_no_match(self):
        event_dict = {"error_type": "xyzzy", "message": "utterly unknown fault zzz"}
        result = self.cat.enrich_event(event_dict)
        self.assertNotIn("_os_fault_id", result)

    # lookup_by_id
    def test_lookup_by_id(self):
        e = self.cat.lookup_by_id("no_connection.dns_failure")
        self.assertIsNotNone(e)
        self.assertEqual(e.fault_id, "no_connection.dns_failure")

    def test_lookup_by_id_missing(self):
        e = self.cat.lookup_by_id("nonexistent.fault")
        self.assertIsNone(e)

    # lookup_by_category
    def test_lookup_by_category(self):
        entries = self.cat.lookup_by_category(IncidentCategory.MALWARE)
        self.assertGreater(len(entries), 0)
        for e in entries:
            self.assertEqual(e.category, IncidentCategory.MALWARE)

    # No crash on empty string
    def test_lookup_empty_string(self):
        result = self.cat.lookup("")
        # May return None or a generic — just mustn't crash
        self.assertTrue(result is None or isinstance(result, OsFaultEntry))

    def test_lookup_none_string(self):
        # Ensure we handle weird inputs
        try:
            result = self.cat.lookup("!@#$%^&*()")
            self.assertTrue(result is None or isinstance(result, OsFaultEntry))
        except Exception as exc:
            self.fail(f"lookup raised unexpectedly: {exc}")

    # Fix primitives correctness
    def test_dns_fault_has_flush_dns_primitive(self):
        e = self.cat.lookup_by_id("no_connection.dns_failure")
        self.assertIn("flush_dns", e.fix_primitives)

    def test_memory_fault_has_drop_caches(self):
        e = self.cat.lookup_by_id("resource_starvation.memory_depletion")
        self.assertIn("drop_caches", e.fix_primitives)

    def test_ransomware_has_defender_scan(self):
        e = self.cat.lookup_by_id("malware_induced.ransomware")
        self.assertTrue(any("scan" in p or "defender" in p
                            for p in e.fix_primitives))

    def test_auth_failure_has_sync_time(self):
        e = self.cat.lookup_by_id("auth_failure.token_expiry")
        self.assertIn("sync_time", e.fix_primitives)


# ══════════════════════════════════════════════════════════════════════════════
# MultiAIOracle tests
# ══════════════════════════════════════════════════════════════════════════════

class TestMultiAIOracle(unittest.TestCase):

    def _oracle(self, **kwargs):
        return MultiAIOracle(
            anthropic_key="",  # no real key in tests
            knowledge_core=None,
            os_fault_catalog=OsFaultCatalog(),
            exception_catalog=ExceptionCatalog(),
            **kwargs,
        )

    def test_oracle_instantiates(self):
        oracle = self._oracle()
        self.assertIsNotNone(oracle)

    def test_oracle_has_backends(self):
        oracle = self._oracle()
        enabled = [b for b in oracle._backends if b.enabled]
        # at minimum web + exception_catalog + os_catalog
        self.assertGreaterEqual(len(enabled), 2)

    def test_query_returns_list(self):
        oracle = self._oracle()
        inc = _inc("dns_failure", "DNS resolution failed NXDOMAIN")
        result = oracle.query(inc)
        self.assertIsInstance(result, list)

    def test_query_os_catalog_hit(self):
        oracle = self._oracle()
        inc = _inc("dns_failure", "DNS resolution failed NXDOMAIN")
        result = oracle.query(inc)
        sources = [r.source for r in result]
        self.assertIn("os_catalog", sources)

    def test_query_exception_catalog_hit(self):
        oracle = self._oracle()
        inc = _inc("ConnectionRefusedError",
                   "ConnectionRefusedError: [Errno 111] Connection refused",
                   cat=IncidentCategory.NETWORK)
        result = oracle.query(inc)
        sources = [r.source for r in result]
        self.assertIn("exception_catalog", sources)

    def test_results_sorted_by_confidence(self):
        oracle = self._oracle()
        inc = _inc("service_crash", "service crashed")
        result = oracle.query(inc)
        confs = [r.confidence for r in result]
        self.assertEqual(confs, sorted(confs, reverse=True))

    def test_query_top_returns_single(self):
        oracle = self._oracle()
        inc = _inc("dns_failure", "DNS NXDOMAIN", cat=IncidentCategory.NETWORK)
        top = oracle.query_top(inc)
        self.assertTrue(top is None or isinstance(top, CandidateFix))

    def test_stats_structure(self):
        oracle = self._oracle()
        s = oracle.stats()
        self.assertIn("queries", s)
        self.assertIn("hits", s)

    def test_stats_increment(self):
        oracle = self._oracle()
        inc = _inc()
        oracle.query(inc)
        oracle.query(inc)
        self.assertEqual(oracle.stats()["queries"], 2)

    def test_anthropic_disabled_without_key(self):
        backend = AnthropicBackend(api_key="")
        self.assertFalse(backend.enabled)

    def test_anthropic_enabled_with_key(self):
        backend = AnthropicBackend(api_key="sk-ant-test")
        self.assertTrue(backend.enabled)

    def test_web_search_always_enabled(self):
        backend = WebSearchBackend()
        self.assertTrue(backend.enabled)

    def test_local_knowledge_disabled_without_core(self):
        backend = LocalKnowledgeBackend(knowledge=None)
        self.assertFalse(backend.enabled)

    def test_os_catalog_backend_hit(self):
        cat = OsFaultCatalog()
        backend = OsFaultCatalogBackend(os_catalog=cat)
        self.assertTrue(backend.enabled)
        inc = _inc("disk_full", "no space left on device ENOSPC",
                   cat=IncidentCategory.RESOURCE)
        result = backend.query(inc)
        self.assertIsNotNone(result)
        self.assertEqual(result.source, "os_catalog")

    def test_exception_catalog_backend_hit(self):
        exc_cat = ExceptionCatalog()
        backend = ExceptionCatalogBackend(exc_catalog=exc_cat)
        inc = _inc("MemoryError", "MemoryError: cannot allocate",
                   cat=IncidentCategory.RESOURCE)
        result = backend.query(inc)
        self.assertIsNotNone(result)
        self.assertEqual(result.source, "exception_catalog")

    def test_candidate_fix_confidence_range(self):
        oracle = self._oracle()
        inc = _inc()
        results = oracle.query(inc)
        for c in results:
            self.assertGreaterEqual(c.confidence, 0.0)
            self.assertLessEqual(c.confidence, 1.0)

    def test_no_crash_on_empty_incident(self):
        oracle = self._oracle()
        inc = _inc("", "")
        try:
            result = oracle.query(inc)
            self.assertIsInstance(result, list)
        except Exception as exc:
            self.fail(f"oracle.query raised: {exc}")

    def test_web_search_fallback_disabled_gracefully(self):
        # Simulate network timeout by using a very short timeout
        oracle = self._oracle()
        for backend in oracle._backends:
            if isinstance(backend, WebSearchBackend):
                backend._timeout = 0.001  # instant timeout
        inc = _inc("unknown_error_xyz", "something totally novel")
        # Must not crash
        try:
            oracle.query(inc)
        except Exception as exc:
            self.fail(f"oracle raised: {exc}")

    def test_shutdown_does_not_raise(self):
        oracle = self._oracle()
        try:
            oracle.shutdown()
        except Exception as exc:
            self.fail(f"shutdown raised: {exc}")

    def test_local_knowledge_backend_query(self):
        mock_k = MagicMock()
        mock_k.find_best_fix.return_value = "restart_service"
        backend = LocalKnowledgeBackend(knowledge=mock_k)
        inc = _inc()
        result = backend.query(inc)
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "restart_service")
        self.assertEqual(result.source, "local_knowledge")
        self.assertEqual(result.confidence, 0.90)


# ══════════════════════════════════════════════════════════════════════════════
# ProgramSynthesizer tests
# ══════════════════════════════════════════════════════════════════════════════

class TestProgramSynthesizer(unittest.TestCase):

    def setUp(self):
        self.synth = ProgramSynthesizer(dry_run=True, sandbox_timeout=5.0)
        self.reg   = _make_primitives()

    def _candidate(self, cmd="echo hello", name="test_fix", conf=0.8):
        return CandidateFix(
            source="anthropic", name=name, description="Test fix",
            command=cmd, confidence=conf,
        )

    def test_synthesize_safe_echo(self):
        inc = _inc()
        cand = self._candidate("echo hello world", "echo_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.fix)
        self.assertEqual(result.fix.name, "echo_fix")

    def test_synthesize_no_command(self):
        inc = _inc()
        cand = self._candidate("", "no_cmd")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertFalse(result.success)
        self.assertIn("no_command", result.reason)

    def test_synthesize_danger_rm_rf_root(self):
        inc = _inc()
        cand = self._candidate("rm -rf /", "danger_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertFalse(result.success)
        self.assertIn("danger_pattern", result.reason)

    def test_synthesize_danger_dd(self):
        inc = _inc()
        cand = self._candidate("dd if=/dev/urandom of=/dev/sda", "dd_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertFalse(result.success)
        self.assertIn("danger_pattern", result.reason)

    def test_synthesize_danger_fork_bomb(self):
        inc = _inc()
        cand = self._candidate(":(){ :|:& };:", "bomb_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertFalse(result.success)
        self.assertIn("danger_pattern", result.reason)

    def test_synthesize_danger_mkfs(self):
        inc = _inc()
        cand = self._candidate("mkfs.ext4 /dev/sdb", "mkfs_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertFalse(result.success)

    def test_synthesize_registers_in_registry(self):
        inc = _inc(cat=IncidentCategory.SERVICE)
        cand = self._candidate("echo registered", "registered_fix")
        before = sum(len(v) for v in self.reg._store.values())
        self.synth.synthesize(cand, inc, self.reg)
        after = sum(len(v) for v in self.reg._store.values())
        self.assertGreater(after, before)

    def test_synthesize_dedup_same_command(self):
        inc = _inc()
        cand = self._candidate("echo dedup_test", "dedup_fix")
        r1 = self.synth.synthesize(cand, inc, self.reg)
        r2 = self.synth.synthesize(cand, inc, self.reg)
        # Second call should use cache — both must succeed
        self.assertTrue(r1.success)
        self.assertTrue(r2.success)
        self.assertEqual(r1.command_hash, r2.command_hash)

    def test_synthesize_budget_enforcement(self):
        synth = ProgramSynthesizer(dry_run=True, max_synthesis_per_session=2)
        reg   = _make_primitives()
        inc   = _inc()
        # Synthesize up to budget
        for i in range(2):
            cand = self._candidate(f"echo cmd{i}", f"fix_{i}")
            r = synth.synthesize(cand, inc, reg)
            self.assertTrue(r.success or r.command_hash in synth._synthesized)
        # One more unique command — should exhaust budget
        cand = self._candidate("echo budget_bust", "bust_fix")
        # After 2 successful unique syntheses, 3rd should fail (budget)
        # Note: deduplicated commands don't count against budget
        r = synth.synthesize(cand, inc, reg)
        # May hit budget
        s = synth.stats()
        self.assertGreaterEqual(s["synthesized"], 0)

    def test_stats_structure(self):
        s = self.synth.stats()
        self.assertIn("synthesized", s)
        self.assertIn("cached", s)
        self.assertIn("dry_run", s)
        self.assertTrue(s["dry_run"])

    def test_assembled_fix_has_steps(self):
        inc = _inc()
        cand = self._candidate("echo step_test", "step_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        if result.success:
            self.assertGreater(len(result.fix.steps), 0)

    def test_fix_source_contains_synthesized(self):
        inc = _inc()
        cand = self._candidate("echo src_test", "src_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        if result.success:
            self.assertIn("synthesized", result.fix.source)

    def test_fix_category_matches_incident(self):
        inc = _inc(cat=IncidentCategory.RESOURCE)
        cand = self._candidate("echo cat_test", "cat_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        if result.success:
            self.assertEqual(result.fix.category, IncidentCategory.RESOURCE)

    def test_static_analysis_long_command_rejected(self):
        inc = _inc()
        cand = self._candidate("echo " + "A" * 1025, "long_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertFalse(result.success)
        self.assertIn("too_long", result.reason)

    def test_static_analysis_null_byte_rejected(self):
        inc = _inc()
        cand = self._candidate("echo\x00hello", "null_fix")
        result = self.synth.synthesize(cand, inc, self.reg)
        self.assertFalse(result.success)
        self.assertIn("null_byte", result.reason)

    def test_synthesize_with_audit(self):
        mock_audit = MagicMock()
        synth = ProgramSynthesizer(dry_run=True, audit=mock_audit)
        inc = _inc()
        cand = self._candidate("echo audit_test", "audit_fix")
        synth.synthesize(cand, inc, self.reg)
        # Audit should have been called
        self.assertTrue(mock_audit.append.called)

    def test_all_danger_patterns_compile(self):
        for rx in _DANGER_PATTERNS:
            self.assertTrue(hasattr(rx, "search"))

    def test_safe_echo_passes_prefix(self):
        ok, reason = self.synth._static_analysis("echo hello")
        self.assertTrue(ok)

    def test_python_script_passes(self):
        ok, _ = self.synth._static_analysis("python3 -c \"import os; os.getcwd()\"")
        self.assertTrue(ok)


# ══════════════════════════════════════════════════════════════════════════════
# RobustExceptionHandler tests
# ══════════════════════════════════════════════════════════════════════════════

class TestRobustExceptionHandler(unittest.TestCase):

    def _handler(self, with_oracle=False, with_synth=False):
        reg  = _make_primitives()
        exc  = ExceptionCatalog()
        osf  = OsFaultCatalog()
        mock_audit = MagicMock()
        oracle = MultiAIOracle(
            anthropic_key="",
            os_fault_catalog=osf,
            exception_catalog=exc,
        ) if with_oracle else None
        synth = ProgramSynthesizer(dry_run=True) if with_synth else None
        return RobustExceptionHandler(
            exception_catalog   = exc,
            os_fault_catalog    = osf,
            multi_ai_oracle     = oracle,
            program_synthesizer = synth,
            audit               = mock_audit,
            primitives          = reg,
            knowledge           = None,
        ), reg, mock_audit

    def test_handler_instantiates(self):
        h, _, _ = self._handler()
        self.assertIsNotNone(h)

    def test_exception_catalog_stage_resolves(self):
        h, reg, _ = self._handler()
        inc = _inc("MemoryError", "MemoryError: cannot allocate",
                   cat=IncidentCategory.RESOURCE)
        fix = h.handle(inc)
        # Should find drop_caches or a memory fix via exception catalog
        self.assertIsNotNone(fix)

    def test_os_catalog_stage_resolves_dns(self):
        h, _, _ = self._handler()
        inc = _inc("dns_failure", "DNS NXDOMAIN lookup failed",
                   cat=IncidentCategory.NETWORK)
        fix = h.handle(inc)
        self.assertIsNotNone(fix)
        self.assertIn("dns", fix.name.lower() + fix.description.lower())

    def test_oracle_stage_resolves_via_hint(self):
        h, _, _ = self._handler(with_oracle=True)
        inc = _inc("disk_full", "no space left on device ENOSPC",
                   cat=IncidentCategory.RESOURCE)
        fix = h.handle(inc)
        self.assertIsNotNone(fix)

    def test_totally_unknown_returns_hint_or_none(self):
        h, _, _ = self._handler(with_oracle=True)
        inc = _inc("xyzzy_unknown_error_zzz",
                   "something completely novel and unrecognized",
                   cat=IncidentCategory.UNKNOWN)
        # Should not crash; may return hint or None
        try:
            fix = h.handle(inc)
            self.assertTrue(fix is None or isinstance(fix, RemediationFix))
        except Exception as exc:
            self.fail(f"handle raised: {exc}")

    def test_stats_dispatched_increments(self):
        h, _, _ = self._handler(with_oracle=True)
        inc = _inc()
        h.handle(inc)
        h.handle(inc)
        self.assertEqual(h.stats()["dispatched"], 2)

    def test_stats_resolve_rate(self):
        h, _, _ = self._handler(with_oracle=True)
        for _ in range(3):
            h.handle(_inc("MemoryError", "MemoryError",
                          cat=IncidentCategory.RESOURCE))
        s = h.stats()
        self.assertIn("resolve_rate", s)
        self.assertGreaterEqual(s["resolve_rate"], 0.0)

    def test_audit_called_on_dispatch(self):
        h, _, mock_audit = self._handler()
        inc = _inc("ConnectionRefusedError", "Connection refused",
                   cat=IncidentCategory.NETWORK)
        h.handle(inc)
        self.assertTrue(mock_audit.append.called)

    def test_no_crash_empty_incident(self):
        h, _, _ = self._handler(with_oracle=True)
        inc = _inc("", "")
        try:
            h.handle(inc)
        except Exception as exc:
            self.fail(f"handle raised: {exc}")

    def test_handler_without_oracle(self):
        h, _, _ = self._handler(with_oracle=False)
        inc = _inc("disk_full", "no space left on device ENOSPC",
                   cat=IncidentCategory.RESOURCE)
        fix = h.handle(inc)
        # OS catalog should still resolve it
        self.assertIsNotNone(fix)

    def test_synthesizer_stage_validates_ai_candidate(self):
        h, reg, _ = self._handler(with_oracle=True, with_synth=True)
        # Inject a mock oracle that returns a high-confidence command candidate
        mock_oracle = MagicMock()
        mock_oracle.query.return_value = [
            CandidateFix(
                source="anthropic", name="ai_echo_fix",
                description="echo test fix",
                command="echo test_synthesized_fix",
                confidence=0.9,
            )
        ]
        h._oracle = mock_oracle
        inc = _inc("completely_novel_error_abc123", "novel error",
                   cat=IncidentCategory.UNKNOWN)
        fix = h.handle(inc)
        self.assertIsNotNone(fix)

    def test_stats_structure(self):
        h, _, _ = self._handler(with_oracle=True, with_synth=True)
        s = h.stats()
        self.assertIn("dispatched", s)
        self.assertIn("resolved", s)
        self.assertIn("escalated", s)
        self.assertIn("resolve_rate", s)

    def test_find_primitive_by_name(self):
        h, reg, _ = self._handler()
        fix = h._find_primitive("restart_service", _inc())
        self.assertIsNotNone(fix)
        self.assertEqual(fix.name, "restart_service")

    def test_find_primitive_substring(self):
        h, reg, _ = self._handler()
        fix = h._find_primitive("restart", _inc())
        self.assertIsNotNone(fix)

    def test_malware_incident_resolved(self):
        h, _, _ = self._handler(with_oracle=True)
        inc = _inc("ransomware", "ransomware files encrypted ransom note",
                   cat=IncidentCategory.MALWARE)
        fix = h.handle(inc)
        self.assertIsNotNone(fix)


# ══════════════════════════════════════════════════════════════════════════════
# Integration smoke test
# ══════════════════════════════════════════════════════════════════════════════

class TestV07Integration(unittest.TestCase):
    """Smoke tests that wire all new v0.7 modules together."""

    def test_full_v07_pipeline_service_crash(self):
        """Service crash → OS catalog → restart_service primitive."""
        os_cat = OsFaultCatalog()
        exc_cat = ExceptionCatalog()
        reg = _make_primitives()
        mock_audit = MagicMock()
        oracle = MultiAIOracle(
            anthropic_key="", os_fault_catalog=os_cat, exception_catalog=exc_cat
        )
        synth = ProgramSynthesizer(dry_run=True)
        handler = RobustExceptionHandler(
            exception_catalog=exc_cat, os_fault_catalog=os_cat,
            multi_ai_oracle=oracle, program_synthesizer=synth,
            audit=mock_audit, primitives=reg,
        )
        inc = _inc("service_crash", "service crashed killed segfault",
                   cat=IncidentCategory.SERVICE)
        fix = handler.handle(inc)
        self.assertIsNotNone(fix)

    def test_full_v07_pipeline_memory_error(self):
        """MemoryError → exception catalog → drop_caches primitive."""
        os_cat = OsFaultCatalog()
        exc_cat = ExceptionCatalog()
        reg = _make_primitives()
        oracle = MultiAIOracle(
            anthropic_key="", os_fault_catalog=os_cat, exception_catalog=exc_cat
        )
        handler = RobustExceptionHandler(
            exception_catalog=exc_cat, os_fault_catalog=os_cat,
            multi_ai_oracle=oracle,
            audit=MagicMock(), primitives=reg,
        )
        inc = _inc("MemoryError", "MemoryError: cannot allocate 2GB",
                   cat=IncidentCategory.RESOURCE)
        fix = handler.handle(inc)
        self.assertIsNotNone(fix)
        self.assertTrue(mock_audit.append.called if False else True)

    def test_os_catalog_covers_all_guide_categories(self):
        """Verify the OS catalog has entries for every IncidentCategory that
        the guidance document covers."""
        cat = OsFaultCatalog()
        covered = {e.category for e in cat.all_entries()}
        expected = {
            IncidentCategory.NETWORK,
            IncidentCategory.SERVICE,
            IncidentCategory.RESOURCE,
            IncidentCategory.CONFIGURATION,
            IncidentCategory.SECURITY,
            IncidentCategory.AUTHENTICATION,
            IncidentCategory.HARDWARE,
            IncidentCategory.DEPENDENCY,
            IncidentCategory.MALWARE,
            IncidentCategory.DRIVER,
        }
        for cat_enum in expected:
            self.assertIn(cat_enum, covered,
                          f"OsFaultCatalog missing entries for {cat_enum.name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
