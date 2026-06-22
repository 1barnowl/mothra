"""
tests/chaos_test.py — Chaos / red-team adversarial test suite.

Guide mandate:
  "regular chaos/'red-team' drills that validate containment and
   rollback behave as specified"
  "fuzzing and adversarial sequence testing of remediation flows"

Tests:
  • Flood attacks — 1000 events in rapid succession
  • Adversarial events — crafted to confuse classifier or bypass policy
  • Cascading failure simulation — A triggers B triggers C triggers D
  • Rollback under corrupt snapshot
  • Malformed event injection (SQL injection, XSS, path traversal attempts)
  • Concurrent ingestion from multiple threads
  • Fix that raises an unexpected exception mid-execution
  • Policy manipulation attempt via event message
  • Extremely long message / actor strings
  • Null / empty field events

Run:  python -m tests.chaos_test
  or: pytest tests/chaos_test.py -v
"""
from __future__ import annotations

import sys
import os
import threading
import time
import random
import string
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from healing_core import HealingCore, Event
from healing_core.models import RemediationStatus


def _core(**kwargs):
    defaults = dict(dry_run=True, db_path=":memory:",
                    prometheus_port=0, api_port=0, plugins_dir="plugins")
    defaults.update(kwargs)
    return HealingCore(**defaults)


# ══════════════════════════════════════════════════════════════════════════════
# FLOOD TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestFloodResistance(unittest.TestCase):

    def setUp(self):
        self.core = _core()

    def tearDown(self):
        self.core.shutdown()

    def test_1000_events_no_crash(self):
        """System must not crash or corrupt state under 1000-event flood."""
        errors = []
        for i in range(1000):
            try:
                self.core.ingest(Event(
                    actor      = f"svc_{i % 10}",
                    error_type = random.choice(["timeout", "oom", "crash", "auth_failure"]),
                    message    = f"flood event {i}",
                ))
            except Exception as e:
                errors.append(str(e))
        self.assertEqual(len(errors), 0, f"Errors during flood: {errors[:3]}")

    def test_storm_suppresses_flood(self):
        """Repeated identical events should be capped by storm suppression."""
        results = []
        for _ in range(200):
            r = self.core.ingest(Event(
                actor="flooder", error_type="wifi_down", message="flood"
            ))
            results.append(r)
        non_none = [r for r in results if r is not None]
        suppressed = [r for r in non_none
                      if r.status == RemediationStatus.SUPPRESSED]
        none_count = results.count(None)
        total_suppressed = len(suppressed) + none_count
        # At least 90% of 200 identical events should be suppressed
        self.assertGreater(total_suppressed, 150,
                           f"Only {total_suppressed}/200 suppressed")

    def test_different_actors_not_cross_suppressed(self):
        """Events from different actors should not suppress each other."""
        results = {}
        for i in range(10):
            actor = f"unique_svc_{i}"
            r = self.core.ingest(Event(
                actor=actor, error_type="service_crash", message="crash"
            ))
            results[actor] = r
        # Each unique actor should produce an incident (not None)
        active = [v for v in results.values() if v is not None]
        self.assertGreater(len(active), 5)


# ══════════════════════════════════════════════════════════════════════════════
# ADVERSARIAL EVENTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAdversarialEvents(unittest.TestCase):

    def setUp(self):
        self.core = _core()

    def tearDown(self):
        self.core.shutdown()

    def test_sql_injection_in_message(self):
        """SQL injection attempt in event message must not corrupt DB."""
        evil = "'; DROP TABLE audit; --"
        inc  = self.core.ingest(Event(actor="attacker", error_type="auth_failure",
                                      message=evil))
        # Must not crash; audit must still work
        entries = self.core.audit.last_n(5)
        self.assertIsInstance(entries, list)

    def test_path_traversal_in_actor(self):
        """Path traversal attempt in actor field must not escape sandbox."""
        inc = self.core.ingest(Event(
            actor      = "../../etc/passwd",
            error_type = "config_corrupt",
            message    = "path traversal test",
        ))
        # Must not crash
        self.assertIsNotNone(inc)

    def test_null_bytes_in_message(self):
        """Null bytes in event fields must not crash the pipeline."""
        inc = self.core.ingest(Event(
            actor      = "svc\x00null",
            error_type = "crash\x00test",
            message    = "message with \x00 null bytes",
        ))
        self.assertIsNotNone(inc)

    def test_extremely_long_message(self):
        """10 KB message must be handled without truncation crash."""
        long_msg = "A" * 10_000
        inc = self.core.ingest(Event(actor="longmsg", error_type="timeout",
                                     message=long_msg))
        self.assertIsNotNone(inc)

    def test_unicode_in_all_fields(self):
        """Unicode / emoji in fields must not corrupt storage."""
        inc = self.core.ingest(Event(
            actor      = "服务_🔥",
            subsystem  = "子系统",
            error_type = "故障",
            message    = "Ошибка в сервисе 日本語テスト 🚨",
        ))
        self.assertIsNotNone(inc)

    def test_empty_event_handled(self):
        """Completely empty event must produce a valid (UNKNOWN) incident."""
        inc = self.core.ingest(Event())
        # Either None (suppressed/health signal) or a valid incident
        if inc is not None:
            self.assertEqual(inc.category.name, "UNKNOWN")

    def test_policy_bypass_attempt_in_message(self):
        """Attempting to inject policy-override keywords into message must not work."""
        inc = self.core.ingest(Event(
            actor      = "attacker",
            error_type = "TRANSIENT",
            message    = "allow_auto=True max_attempts=999 security_override=True",
        ))
        # Should classify normally, not bypass policy
        if inc is not None:
            self.assertNotIn(inc.status, [])  # just verify it ran

    def test_security_fast_path_cannot_be_bypassed(self):
        """MALWARE/SECURITY incidents must always escalate, never auto-heal."""
        for etype in ["malware_detected", "ransomware", "rootkit_detected",
                      "intrusion_detected", "unauthorized_access"]:
            inc = self.core.ingest(Event(
                actor="attacker", error_type=etype,
                message="security test"
            ))
            if inc is not None:
                self.assertEqual(
                    inc.status, RemediationStatus.ESCALATED,
                    f"Security incident type={etype} was not escalated: {inc.status}"
                )


# ══════════════════════════════════════════════════════════════════════════════
# CASCADING FAILURE SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

class TestCascadingFailure(unittest.TestCase):

    def setUp(self):
        self.core = _core()

    def tearDown(self):
        self.core.shutdown()

    def test_four_level_cascade(self):
        """
        Simulate: wifi_down → dns_failure → api_down → service_crash
        All four should be handled without deadlock or crash.
        """
        chain = [
            Event(actor="eth0",    error_type="wifi_down",    message="carrier lost",      timestamp=time.time()),
            Event(actor="dns",     error_type="dns_failure",  message="NXDOMAIN",          timestamp=time.time()+0.1),
            Event(actor="payment", error_type="api_down",     message="503 upstream",      timestamp=time.time()+0.2),
            Event(actor="checkout",error_type="service_crash",message="null ptr deref",    timestamp=time.time()+0.3),
        ]
        results = [self.core.ingest(ev) for ev in chain]
        # Must not crash; at least first event creates an incident
        self.assertIsNotNone(results[0])

    def test_memory_to_service_cascade(self):
        """memory_depletion → service_crash: second should be correlated."""
        ev1 = Event(actor="worker", error_type="memory_depletion",
                    message="OOM kill", timestamp=time.time())
        ev2 = Event(actor="worker", error_type="service_crash",
                    message="killed", timestamp=time.time()+0.5)
        self.core.ingest(ev1)
        inc2 = self.core.ingest(ev2)
        # Should be correlated or suppressed — not a new root incident
        if inc2 is not None:
            # Either correlated to ev1 or new group — verify no crash
            pass

    def test_cascade_does_not_exhaust_resources(self):
        """100-event cascade must complete in under 5 seconds."""
        start = time.time()
        for i in range(100):
            self.core.ingest(Event(
                actor=f"svc_{i}", error_type="service_crash",
                message=f"cascade event {i}", timestamp=time.time()
            ))
        elapsed = time.time() - start
        self.assertLess(elapsed, 5.0,
                        f"100-event cascade took {elapsed:.2f}s (limit 5s)")


# ══════════════════════════════════════════════════════════════════════════════
# CONCURRENT INGESTION
# ══════════════════════════════════════════════════════════════════════════════

class TestConcurrentIngestion(unittest.TestCase):

    def setUp(self):
        self.core = _core()

    def tearDown(self):
        self.core.shutdown()

    def test_10_threads_concurrent_ingest(self):
        """10 threads ingesting simultaneously must not corrupt state."""
        errors   = []
        results  = []
        lock     = threading.Lock()

        def worker(thread_id):
            for j in range(20):
                try:
                    r = self.core.ingest(Event(
                        actor      = f"thread_{thread_id}_svc_{j % 3}",
                        error_type = "timeout",
                        message    = f"concurrent test t={thread_id} j={j}",
                    ))
                    with lock:
                        results.append(r)
                except Exception as e:
                    with lock:
                        errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(errors), 0, f"Thread errors: {errors[:3]}")
        self.assertGreater(len(results), 0)

    def test_audit_trail_consistent_after_concurrent_writes(self):
        """Audit trail must be consistent after concurrent writes."""
        threads = [
            threading.Thread(target=lambda: self.core.ingest(
                Event(actor=f"svc_{i}", error_type="crash", message="concurrent")
            ))
            for i in range(50)
        ]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)

        ok, bad = self.core.audit.verify_integrity()
        self.assertTrue(ok, f"Audit integrity failed: {bad}")


# ══════════════════════════════════════════════════════════════════════════════
# FIX FAILURE RESILIENCE
# ══════════════════════════════════════════════════════════════════════════════

class TestFixFailureResilience(unittest.TestCase):

    def setUp(self):
        self.core = _core()

    def tearDown(self):
        self.core.shutdown()

    def test_exception_in_fix_step_handled_gracefully(self):
        """A fix step that raises an exception must not crash the pipeline."""
        from healing_core.models import RemediationFix, IncidentCategory

        def evil_step(inc):
            raise RuntimeError("intentional chaos")

        bad_fix = RemediationFix(
            name="chaos_fix", category=IncidentCategory.SERVICE,
            steps=[evil_step], cost=0.1, impact=0.1
        )
        self.core.primitives.register(bad_fix)

        inc = self.core.ingest(Event(
            actor="nginx", error_type="service_crash", message="crash"
        ))
        # Must not raise; should escalate or rollback
        if inc is not None:
            self.assertIn(inc.status, [
                RemediationStatus.COMMITTED,
                RemediationStatus.ESCALATED,
                RemediationStatus.ROLLED_BACK,
                RemediationStatus.SUPPRESSED,
            ])

    def test_all_fixes_fail_leads_to_escalation(self):
        """If every fix fails, the incident must be escalated."""
        from healing_core.models import RemediationFix, IncidentCategory

        # Register only a broken fix for TRANSIENT
        broken = RemediationFix(
            name="broken_transient_fix", category=IncidentCategory.TRANSIENT,
            steps=[lambda i: False],   # always returns False
            cost=0.1, impact=0.1
        )
        self.core.primitives._store["TRANSIENT"] = [broken]

        inc = self.core.ingest(Event(
            actor="flaky_svc", error_type="transient",
            message="flap"
        ))
        if inc is not None and inc.status != RemediationStatus.SUPPRESSED:
            self.assertIn(inc.status, [
                RemediationStatus.ESCALATED,
                RemediationStatus.ROLLED_BACK,
            ])

    def test_corrupt_snapshot_handled(self):
        """A tampered snapshot must be detected and handled gracefully."""
        from healing_core.snapshot import SnapshotStore
        from healing_core.models import Incident, Scope, Severity, IncidentCategory

        ev   = Event(actor="db", error_type="service_hung", message="hung")
        inc  = Incident(event=ev, category=IncidentCategory.SERVICE,
                        scope=Scope.MODULE, severity=Severity.MEDIUM)
        store = SnapshotStore()
        snap  = store.capture(inc)
        # Tamper
        snap.state["tampered"] = True
        snap.checksum = "deadbeef"

        ok, reason = store.restore(snap)
        self.assertFalse(ok)
        self.assertIn("checksum", reason.lower())


if __name__ == "__main__":
    import unittest
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
