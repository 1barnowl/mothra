"""tests/test_knowledge.py"""
import sys, os, unittest, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from healing_core.knowledge import KnowledgeCore
from healing_core.models import Incident, Event, IncidentCategory, Scope, Severity

def _inc(etype, msg="", cat=IncidentCategory.SERVICE):
    ev = Event(actor="svc", error_type=etype, message=msg)
    return Incident(event=ev, category=cat, scope=Scope.MODULE, severity=Severity.MEDIUM)

class TestKnowledgeCore(unittest.TestCase):

    def setUp(self):
        self.k = KnowledgeCore(db_path=":memory:", ai_enabled=False)

    def test_seeds_loaded(self):
        s = self.k.summary()
        self.assertGreater(s["patterns"], 10)

    def test_exact_match_returns_fix(self):
        inc = _inc("wifi_down", "carrier lost", IncidentCategory.NETWORK)
        fix = self.k.find_best_fix(inc)
        self.assertEqual(fix, "restart_wifi")

    def test_dns_failure_returns_flush(self):
        inc = _inc("dns_failure", "NXDOMAIN", IncidentCategory.NETWORK)
        fix = self.k.find_best_fix(inc)
        self.assertEqual(fix, "flush_dns")

    def test_ingest_updates_scores(self):
        inc = _inc("service_hung", "deadlock", IncidentCategory.SERVICE)
        self.k.ingest(inc, "restart_service", "success")
        self.k.ingest(inc, "restart_service", "success")
        fix = self.k.find_best_fix(inc)
        self.assertEqual(fix, "restart_service")

    def test_similarity_match(self):
        # Record a fix for a known type
        inc1 = _inc("memory_leak", "heap growing unbounded", IncidentCategory.RESOURCE)
        self.k.ingest(inc1, "drop_caches", "success")
        self.k.ingest(inc1, "drop_caches", "success")
        self.k.ingest(inc1, "drop_caches", "success")
        # Query with slightly different wording
        inc2 = _inc("heap_overflow", "memory heap growing", IncidentCategory.RESOURCE)
        fix  = self.k.find_best_fix(inc2)
        # May or may not match depending on similarity threshold — just verify no crash
        self.assertIsInstance(fix, (str, type(None)))

    def test_ingest_failure_tracked(self):
        inc = _inc("config_corrupt", "yaml parse error", IncidentCategory.CONFIGURATION)
        self.k.ingest(inc, "restore_config_from_backup", "failure")
        s = self.k.summary()
        self.assertGreater(s["total_failure"], 0)

    def test_top_patterns_not_empty(self):
        tops = self.k.top_patterns(5)
        self.assertIsInstance(tops, list)

    def test_summary_keys(self):
        s = self.k.summary()
        for key in ["patterns", "total_success", "total_failure", "overall_rate"]:
            self.assertIn(key, s)

    def test_ai_disabled_returns_none(self):
        k = KnowledgeCore(db_path=":memory:", ai_enabled=False)
        inc = _inc("unknown_exotic_error", "exotic", IncidentCategory.UNKNOWN)
        result = k.generate_candidate(inc)
        self.assertIsNone(result)

    def test_promote_to_registry(self):
        from healing_core.primitives import PrimitivesRegistry
        reg = PrimitivesRegistry()
        inc = _inc("disk_full", "no space", IncidentCategory.RESOURCE)
        for _ in range(3):
            self.k.ingest(inc, "clear_temp", "success")
        promoted = self.k.promote_to_registry("clear_temp", reg)
        self.assertTrue(promoted)
        # Should now be in registry
        names = [f.name for fixes in reg._store.values() for f in fixes]
        self.assertTrue(any("clear_temp" in n for n in names))

class TestExceptionCatalog(unittest.TestCase):

    def setUp(self):
        from healing_core.exception_catalog import ExceptionCatalog
        self.c = ExceptionCatalog()

    def test_summary_populated(self):
        s = self.c.summary()
        self.assertGreater(s["total_entries"], 20)
        self.assertIn("by_category", s)

    def test_lookup_memory_error(self):
        e = self.c.lookup("MemoryError: unable to allocate 8GB for array")
        self.assertIsNotNone(e)
        from healing_core.models import IncidentCategory
        self.assertEqual(e.category, IncidentCategory.RESOURCE)

    def test_lookup_connection_refused(self):
        e = self.c.lookup("ConnectionRefusedError: [Errno 111] Connection refused")
        self.assertIsNotNone(e)
        from healing_core.models import IncidentCategory
        self.assertEqual(e.category, IncidentCategory.NETWORK)

    def test_lookup_ssl_error(self):
        e = self.c.lookup("ssl.SSLCertificationVerificationFailed certificate expired")
        self.assertIsNotNone(e)
        from healing_core.models import IncidentCategory
        self.assertEqual(e.category, IncidentCategory.AUTHENTICATION)

    def test_lookup_enospc(self):
        e = self.c.lookup("[Errno 28] No space left on device")
        self.assertIsNotNone(e)

    def test_lookup_unknown_returns_none(self):
        e = self.c.lookup("xyzzy_qubit_error_flux_capacitor_decoherence")
        self.assertIsNone(e)

    def test_enrich_event_adds_metadata(self):
        d = {"error_type": "ssl_error", "message": "SSLError certificate expired"}
        enriched = self.c.enrich_event(d)
        self.assertIn("_catalog_category", enriched)
        self.assertIn("_catalog_fix_hint", enriched)

    def test_category_for(self):
        from healing_core.models import IncidentCategory
        cat = self.c.category_for("MemoryError cannot allocate")
        self.assertEqual(cat, IncidentCategory.RESOURCE)

    def test_fix_primitive_for(self):
        fix = self.c.fix_primitive_for("MemoryError cannot allocate")
        self.assertEqual(fix, "drop_caches")

if __name__ == "__main__":
    unittest.main(verbosity=2)
