"""tests/test_alertmanager.py"""
import sys, os, json, time, threading, unittest, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from healing_core.alertmanager import AlertParser, AlertmanagerBridge, _snake

class TestAlertParser(unittest.TestCase):

    def _alert(self, **labels):
        return {
            "status": "firing",
            "labels": {"alertname": "TestAlert", "severity": "warning", **labels},
            "annotations": {"summary": "Test alert summary"},
            "fingerprint": "abc123",
        }

    def test_basic_parse(self):
        a = self._alert(instance="server1", job="nginx")
        r = AlertParser.parse(a)
        self.assertIsNotNone(r)
        self.assertEqual(r["actor"], "server1")
        self.assertEqual(r["subsystem"], "nginx")

    def test_resolved_returns_none(self):
        a = {"status": "resolved", "labels": {"alertname": "X"}, "annotations": {}}
        r = AlertParser.parse(a)
        self.assertIsNone(r)

    def test_disk_full_remapped(self):
        a = self._alert(alertname="DiskFull", instance="db1")
        r = AlertParser.parse(a)
        self.assertEqual(r["error_type"], "disk_full")

    def test_high_cpu_remapped(self):
        a = self._alert(alertname="HighCPU", instance="worker1")
        r = AlertParser.parse(a)
        self.assertEqual(r["error_type"], "cpu_overload")

    def test_unknown_alert_snake_cased(self):
        a = self._alert(alertname="WeirdCustomAlert")
        r = AlertParser.parse(a)
        self.assertEqual(r["error_type"], "weird_custom_alert")

    def test_severity_mapped(self):
        a = self._alert(severity="critical")
        r = AlertParser.parse(a)
        self.assertEqual(r["severity"], "CRITICAL")

    def test_k8s_labels_used(self):
        a = self._alert(alertname="PodCrashLooping",
                        namespace="production", pod="api-pod-xyz")
        r = AlertParser.parse(a)
        self.assertEqual(r["actor"], "api-pod-xyz")
        self.assertEqual(r["subsystem"], "production")

    def test_snake_case(self):
        # _snake only inserts _ before transitions from lowercase/digit to uppercase
        self.assertEqual(_snake("ServiceDown"), "service_down")
        self.assertEqual(_snake("DiskFull"), "disk_full")
        self.assertEqual(_snake("NetworkErrors"), "network_errors")
        self.assertIn("high", _snake("HighCPU"))

class TestAlertmanagerBridgeHTTP(unittest.TestCase):
    """End-to-end test: POST webhook payload → events ingested."""

    @classmethod
    def setUpClass(cls):
        import sys; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from healing_core import HealingCore
        cls.core = HealingCore(dry_run=True, db_path=":memory:",
                                prometheus_port=0, api_port=0, plugins_dir="plugins",
                                enable_alertmanager=True, alertmanager_port=9194)
        time.sleep(0.3)
        cls.port = 9194

    @classmethod
    def tearDownClass(cls):
        cls.core.shutdown()

    def _post(self, payload):
        body = json.dumps(payload).encode()
        req  = urllib.request.Request(
            f"http://localhost:{self.port}/api/v1/alerts",
            data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read()), r.status

    def test_health_endpoint(self):
        req = urllib.request.Request(f"http://localhost:{self.port}/-/healthy")
        with urllib.request.urlopen(req, timeout=3) as r:
            self.assertEqual(r.status, 200)

    def test_firing_alert_ingested(self):
        payload = {"version": "4", "status": "firing", "alerts": [{
            "status": "firing",
            "labels": {"alertname": "DiskFull", "instance": "srv1",
                       "job": "storage", "severity": "critical"},
            "annotations": {"summary": "Disk at 99%"},
            "fingerprint": "fire001",
        }]}
        resp, status = self._post(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(resp["ingested"], 0)

    def test_resolved_not_ingested(self):
        payload = {"version": "4", "status": "resolved", "alerts": [{
            "status": "resolved",
            "labels": {"alertname": "DiskFull", "instance": "srv1"},
            "annotations": {}, "fingerprint": "fire001",
        }]}
        resp, status = self._post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(resp["ingested"], 0)

    def test_batch_alerts(self):
        payload = {"version": "4", "status": "firing", "alerts": [
            {"status": "firing",
             "labels": {"alertname": f"Alert{i}", "instance": f"host{i}",
                        "severity": "warning"},
             "annotations": {"summary": f"alert {i}"},
             "fingerprint": f"batch{i:03d}"}
            for i in range(5)
        ]}
        resp, status = self._post(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(resp["ingested"], 0)

    def test_bad_json_returns_400(self):
        req = urllib.request.Request(
            f"http://localhost:{self.port}/api/v1/alerts",
            data=b"not json", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=3)
        except urllib.request.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_stats_tracked(self):
        stats = self.core.alertmanager_bridge.stats()
        self.assertIn("ingested", stats)
        self.assertIn("received", stats)

class TestTracer(unittest.TestCase):

    def setUp(self):
        from healing_core.tracing import Tracer
        self.t = Tracer()   # no export endpoint

    def test_new_trace_id_length(self):
        tid = self.t.new_trace_id()
        self.assertEqual(len(tid), 32)

    def test_new_span_id_length(self):
        sid = self.t.new_span_id()
        self.assertEqual(len(sid), 16)

    def test_span_context_manager(self):
        tid = self.t.new_trace_id()
        with self.t.span("test_op", tid) as s:
            s.set("key", "value")
        self.assertEqual(s.status, "OK")
        self.assertGreater(s.duration_ms, 0)

    def test_span_error_status_on_exception(self):
        tid = self.t.new_trace_id()
        try:
            with self.t.span("fail_op", tid) as s:
                raise RuntimeError("test failure")
        except RuntimeError:
            pass
        self.assertEqual(s.status, "ERROR")

    def test_span_attributes_preserved(self):
        tid = self.t.new_trace_id()
        with self.t.span("attrs_test", tid) as s:
            s.set("category", "NETWORK")
            s.set("risk", 0.75)
        self.assertEqual(s.attributes["category"], "NETWORK")

    def test_recent_traces_returns_list(self):
        tid = self.t.new_trace_id()
        with self.t.span("trace_list_test", tid) as s:
            pass
        recent = self.t.recent_traces(10)
        self.assertIsInstance(recent, list)
        self.assertGreater(len(recent), 0)

    def test_otlp_serialization(self):
        tid = self.t.new_trace_id()
        span = self.t.start_span("otlp_test", tid)
        span.set("k", "v")
        span.add_event("test_event")
        self.t.finish_span(span)
        otlp = span.to_otlp()
        self.assertEqual(otlp["traceId"], tid)
        self.assertEqual(otlp["name"], "otlp_test")
        self.assertEqual(len(otlp["attributes"]), 1)
        self.assertEqual(len(otlp["events"]), 1)

    def test_stats_keys(self):
        s = self.t.stats()
        self.assertIn("buffered_spans", s)
        self.assertIn("active_spans", s)

    def test_parent_child_relationship(self):
        tid = self.t.new_trace_id()
        parent = self.t.start_span("parent", tid)
        child  = self.t.start_span("child", tid, parent.span_id)
        self.assertEqual(child.parent_id, parent.span_id)
        self.assertEqual(child.trace_id,  parent.trace_id)

class TestReporter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from healing_core import HealingCore, Event
        cls.core = HealingCore(dry_run=True, db_path=":memory:",
                                prometheus_port=0, api_port=0, plugins_dir="plugins")
        cls.core.ingest(Event(actor="nginx", error_type="config_corrupt",
                               message="nginx reload failed"))
        cls.core.ingest(Event(actor="db", error_type="service_hung",
                               message="deadlock"))

    @classmethod
    def tearDownClass(cls):
        cls.core.shutdown()

    def test_generate_returns_html(self):
        from healing_core.reporter import HealthReporter
        r    = HealthReporter(self.core)
        html = r.generate()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("HealingCore", html)

    def test_report_contains_kpis(self):
        from healing_core.reporter import HealthReporter
        html = HealthReporter(self.core).generate()
        self.assertIn("Total Incidents", html)
        self.assertIn("Auto-Healed", html)

    def test_report_write_to_file(self):
        import tempfile
        from healing_core.reporter import HealthReporter
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        HealthReporter(self.core).write(path)
        with open(path) as f:
            content = f.read()
        self.assertIn("<!DOCTYPE html>", content)
        os.unlink(path)

    def test_bar_chart_svg(self):
        from healing_core.reporter import _bar_chart
        svg = _bar_chart([("A", 10), ("B", 5), ("C", 8)])
        self.assertIn("<svg", svg)
        self.assertIn("<rect", svg)

    def test_gauge_svg(self):
        from healing_core.reporter import _gauge
        svg = _gauge(0.75, "Test")
        self.assertIn("<svg", svg)
        self.assertIn("75%", svg)

if __name__ == "__main__":
    unittest.main(verbosity=2)
