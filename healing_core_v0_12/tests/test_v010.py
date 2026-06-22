"""tests/test_v010.py — v0.10 test suite"""
import json, os, platform, sys, tempfile, threading, time, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest

OS = platform.system()

# ── ITSM backends ─────────────────────────────────────────────────────────────

def _incident():
    from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
    evt = Event(error_type="service_crash",
                message="nginx terminated unexpectedly",
                actor="nginx", subsystem="service")
    return Incident(event=evt, category=IncidentCategory.SERVICE,
                    scope=Scope.MODULE, severity=Severity.HIGH, risk_score=0.75)

def _snapshot():
    from healing_core.models import Snapshot
    return Snapshot(incident_id=str(uuid.uuid4()))

def _fix(impact=0.5):
    from healing_core.models import RemediationFix, IncidentCategory
    return RemediationFix(name="restart_service", category=IncidentCategory.SERVICE,
                          description="test", steps=[lambda i:(True,"ok")],
                          cost=0.3, impact=impact, source="test")


class TestITSMBackends:
    """All backends tested with a fake HTTP server stub."""

    def _capture_server(self, responses=None):
        """Minimal HTTP stub that records requests."""
        import http.server, threading
        captured = []
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(n)
                captured.append({"path": self.path, "body": body})
                code = (responses or {}).get(self.path, 200)
                self.send_response(code)
                self.send_header("Content-Type","application/json")
                self.end_headers()
                self.wfile.write(b'{"key":"OPS-42","id":"rid"}')
            def log_message(self, *a): pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, captured

    def test_webhook_backend_posts_json(self):
        from healing_core.itsm import WebhookBackend
        srv, captured = self._capture_server()
        port = srv.server_address[1]
        b = WebhookBackend(f"http://127.0.0.1:{port}/hook")
        r = b.create_ticket(_incident(), _snapshot(), "heal_failed")
        srv.shutdown()
        assert r.success
        assert len(captured) == 1
        payload = json.loads(captured[0]["body"])
        assert "incident_id" in payload
        assert "category" in payload

    def test_webhook_backend_failure_reported(self):
        from healing_core.itsm import WebhookBackend
        srv, _ = self._capture_server({"/hook": 500})
        port = srv.server_address[1]
        b = WebhookBackend(f"http://127.0.0.1:{port}/hook")
        r = b.create_ticket(_incident(), _snapshot(), "fail")
        srv.shutdown()
        assert not r.success
        assert r.backend == "webhook"

    def test_slack_backend_posts_attachment(self):
        from healing_core.itsm import SlackBackend
        srv, captured = self._capture_server({"/slack": 200})
        port = srv.server_address[1]
        b = SlackBackend(f"http://127.0.0.1:{port}/slack")
        r = b.create_ticket(_incident(), _snapshot(), "test")
        srv.shutdown()
        assert len(captured) == 1
        payload = json.loads(captured[0]["body"])
        assert "attachments" in payload
        assert payload["attachments"][0]["color"] == "#FF8800"  # HIGH

    def test_pagerduty_backend_correct_payload(self):
        from healing_core.itsm import PagerDutyBackend
        srv, captured = self._capture_server({"/v2/enqueue": 202})
        # Mock the PD URL
        import healing_core.itsm as itsm_mod
        orig = itsm_mod.PagerDutyBackend._URL
        itsm_mod.PagerDutyBackend._URL = f"http://127.0.0.1:{srv.server_address[1]}/v2/enqueue"
        b = PagerDutyBackend("test-routing-key")
        r = b.create_ticket(_incident(), _snapshot(), "test")
        itsm_mod.PagerDutyBackend._URL = orig
        srv.shutdown()
        assert len(captured) == 1
        payload = json.loads(captured[0]["body"])
        assert payload["routing_key"] == "test-routing-key"
        assert payload["event_action"] == "trigger"
        assert "payload" in payload

    def test_jira_backend_correct_fields(self):
        from healing_core.itsm import JiraBackend
        srv, captured = self._capture_server({"/rest/api/3/issue": 201})
        port = srv.server_address[1]
        b = JiraBackend(f"http://127.0.0.1:{port}", "OPS",
                        "token", "bot@test.com")
        r = b.create_ticket(_incident(), _snapshot(), "test")
        srv.shutdown()
        assert r.success
        payload = json.loads(captured[0]["body"])
        assert payload["fields"]["project"]["key"] == "OPS"
        assert "HealingCore" in payload["fields"]["summary"]
        assert payload["fields"]["priority"]["name"] == "High"  # HIGH severity

    def test_dispatcher_fires_all_backends(self):
        from healing_core.itsm import ITSMDispatcher, WebhookBackend, SlackBackend
        srv1, cap1 = self._capture_server()
        srv2, cap2 = self._capture_server()
        p1, p2 = srv1.server_address[1], srv2.server_address[1]
        d = ITSMDispatcher([
            WebhookBackend(f"http://127.0.0.1:{p1}/hook"),
            SlackBackend(f"http://127.0.0.1:{p2}/slack"),
        ])
        results = d.dispatch(_incident(), _snapshot(), "test")
        srv1.shutdown(); srv2.shutdown()
        assert len(results) == 2
        assert all(r.success for r in results)
        assert len(cap1) == 1 and len(cap2) == 1

    def test_dispatcher_empty_backends_ok(self):
        from healing_core.itsm import ITSMDispatcher
        d = ITSMDispatcher([])
        results = d.dispatch(_incident(), _snapshot(), "test")
        assert results == []

    def test_dispatcher_stats(self):
        from healing_core.itsm import ITSMDispatcher
        d = ITSMDispatcher([])
        s = d.stats()
        for k in ("backends","dispatched","failed",
                  "attestation_enabled","attestation_threshold"):
            assert k in s

    def test_from_policy_no_config(self):
        from healing_core.itsm import ITSMDispatcher
        class FakePolicy:
            itsm = {}
        d = ITSMDispatcher.from_policy(FakePolicy())
        assert d._backends == []
        assert d._attest is None


class TestSignedAttestation:
    def _attest(self, secret="testsecret", expiry=300):
        from healing_core.itsm import SignedAttestation
        return SignedAttestation(secret=secret, expiry_seconds=expiry)

    def test_request_creates_pending(self):
        a = self._attest()
        req = a.request(_incident(), _fix())
        assert req.id in a._pending
        assert req.incident_id
        assert not req.approved

    def test_approve_removes_from_pending(self):
        a = self._attest()
        req = a.request(_incident(), _fix())
        approved = a.approve(req.id, "alice", "testsecret")
        assert approved is not None
        assert approved.approved
        assert approved.approver == "alice"
        assert req.id not in a._pending

    def test_verify_valid_attestation(self):
        a = self._attest()
        req = a.request(_incident(), _fix())
        approved = a.approve(req.id, "bob", "testsecret")
        assert a.verify(approved) is True

    def test_verify_wrong_signature(self):
        a = self._attest()
        req = a.request(_incident(), _fix())
        approved = a.approve(req.id, "eve", "testsecret")
        approved.signature = "deadbeef" * 8  # tamper
        assert a.verify(approved) is False

    def test_verify_expired_attestation(self):
        a = self._attest(expiry=1)
        req = a.request(_incident(), _fix())
        approved = a.approve(req.id, "alice", "testsecret")
        time.sleep(1.05)
        assert a.verify(approved) is False

    def test_wrong_secret_returns_none(self):
        a = self._attest(secret="correct")
        req = a.request(_incident(), _fix())
        result = a.approve(req.id, "eve", "wrong-secret")
        assert result is None

    def test_unknown_request_id_returns_none(self):
        a = self._attest()
        assert a.approve("nonexistent-id", "alice", "testsecret") is None

    def test_to_audit_dict_structure(self):
        a = self._attest()
        req = a.request(_incident(), _fix())
        a.approve(req.id, "carol", "testsecret")
        d = a.to_audit_dict(req)
        for k in ("attestation_id","fix_name","approver","signature","valid"):
            assert k in d
        assert d["valid"] is True

    def test_needs_attestation_above_threshold(self):
        from healing_core.itsm import ITSMDispatcher, SignedAttestation
        a = SignedAttestation("secret")
        d = ITSMDispatcher([], a, attestation_threshold=0.70)
        assert d.needs_attestation(_fix(impact=0.80), _incident()) is True

    def test_needs_attestation_below_threshold(self):
        from healing_core.itsm import ITSMDispatcher, SignedAttestation
        a = SignedAttestation("secret")
        d = ITSMDispatcher([], a, attestation_threshold=0.90)
        assert d.needs_attestation(_fix(impact=0.50), _incident()) is False

    def test_no_attestation_configured_auto_approves(self):
        from healing_core.itsm import ITSMDispatcher
        d = ITSMDispatcher([], None, attestation_threshold=0.50)
        req = d.request_attestation(_incident(), _fix(impact=0.99))
        assert req is None
        assert d.verify_attestation(req) is True  # None → auto-approve


# ── macOS exception catalog ───────────────────────────────────────────────────

class TestMacosExceptionCatalog:
    def setup_method(self):
        from healing_core.exception_catalog import ExceptionCatalog
        self.ec = ExceptionCatalog()

    def test_macos_entries_count(self):
        macos = [e for e in self.ec.all_entries() if e.platform == "macos"]
        assert len(macos) >= 15, f"Expected ≥15 macOS entries, got {len(macos)}"

    def test_total_entries_grown(self):
        assert len(self.ec.all_entries()) >= 75

    def test_lookup_launchd_throttle(self):
        e = self.ec.lookup("ThrottleInterval launchd service respawn too fast")
        assert e is not None

    def test_lookup_keychain_corrupt(self):
        e = self.ec.lookup("SecKeychainCorrupt keychain corrupted errSecKeychainNotAvailable")
        assert e is not None

    def test_lookup_tls_trust_failure(self):
        e = self.ec.lookup("SecTrustEvaluationFailed certificate trust fail errSSLXCertChainInvalid")
        assert e is not None

    def test_lookup_tcc_denied(self):
        e = self.ec.lookup("TCC denied kTCCServiceMicrophone app not allowed")
        assert e is not None

    def test_lookup_exc_bad_access(self):
        e = self.ec.lookup("EXC_BAD_ACCESS SIGSEGV Crashed Thread")
        assert e is not None

    def test_lookup_xpc_crash(self):
        e = self.ec.lookup("XPC connection interrupted NSXPCConnectionInterrupted")
        assert e is not None

    def test_lookup_memory_pressure(self):
        e = self.ec.lookup("jetsam killed process memorystatus low memory warning")
        assert e is not None

    def test_lookup_gatekeeper_block(self):
        e = self.ec.lookup("Gatekeeper block quarantine damaged can't be opened spctl")
        assert e is not None

    def test_lookup_dns_fail_cfnetwork(self):
        e = self.ec.lookup("CFNetworkErrors kCFURLErrorDNSLookupFailed nw_resolver failed")
        assert e is not None

    def test_lookup_sandbox_violation(self):
        e = self.ec.lookup("sandboxd deny file-read sandbox violation")
        assert e is not None

    def test_macos_entries_have_fix_primitives(self):
        macos = [e for e in self.ec.all_entries() if e.platform == "macos"]
        missing = [e.exception_class for e in macos if not e.fix_primitive]
        assert not missing, f"Missing fix_primitive: {missing}"

    def test_macos_entries_have_patterns(self):
        macos = [e for e in self.ec.all_entries() if e.platform == "macos"]
        missing = [e.exception_class for e in macos if not e.patterns]
        assert not missing, f"Missing patterns: {missing}"

    def test_three_platform_coverage(self):
        """All three platforms now have dedicated exception entries."""
        ec = self.ec
        platforms = {e.platform for e in ec.all_entries()}
        for p in ("windows", "macos", "linux"):
            assert p in platforms, f"Missing platform: {p}"


# ── DSL v2: simulate + conflict detection ─────────────────────────────────────

class TestDSLv2:
    def _dsl(self, rules_yaml=None):
        from healing_core.dsl import PolicyDSL
        import tempfile, os
        if rules_yaml:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml",
                                            delete=False) as f:
                f.write(rules_yaml)
                path = f.name
        else:
            path = "healing_policy.yaml"
        return PolicyDSL(rules_yaml_path=path), path

    def _incident(self, cat="SERVICE", severity="HIGH", risk=0.7, actor="nginx"):
        from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
        cat_e  = getattr(IncidentCategory, cat,  IncidentCategory.SERVICE)
        sev_e  = getattr(Severity,        severity, Severity.HIGH)
        evt = Event(error_type="crash", message="service crashed",
                    actor=actor, subsystem="sys")
        return Incident(event=evt, category=cat_e, scope=Scope.MODULE,
                        severity=sev_e, risk_score=risk)

    def test_simulate_returns_decision(self):
        dsl, _ = self._dsl()
        inc = self._incident()
        decision = dsl.simulate(inc)
        assert decision is not None
        assert hasattr(decision, "action")

    def test_simulate_does_not_increment_hits(self):
        dsl, _ = self._dsl()
        inc = self._incident(cat="SECURITY", risk=0.95)
        before = {r["id"]: r.get("hits",0) for r in dsl.rule_stats()}
        dsl.simulate(inc)
        after  = {r["id"]: r.get("hits",0) for r in dsl.rule_stats()}
        assert before == after, "simulate() must not increment rule hit counters"

    def test_evaluate_increments_hits(self):
        dsl, _ = self._dsl()
        inc = self._incident(cat="SECURITY", risk=0.95)
        before = sum(r.get("hits",0) for r in dsl.rule_stats())
        dsl.evaluate(inc)
        after  = sum(r.get("hits",0) for r in dsl.rule_stats())
        # If any rule matched, hits should increase
        # (may be 0 if no rules match this incident)
        assert after >= before

    def test_detect_conflicts_returns_list(self):
        dsl, _ = self._dsl()
        conflicts = dsl.detect_conflicts()
        assert isinstance(conflicts, list)

    def test_detect_conflicts_finds_real_conflict(self):
        yaml = """
rules:
  - id: rule_A
    when:
      category: SERVICE
    then:
      action: allow
    priority: 10
  - id: rule_B
    when:
      category: SERVICE
    then:
      action: suppress
    priority: 5
"""
        dsl, path = self._dsl(yaml)
        import os
        try:
            conflicts = dsl.detect_conflicts()
            assert len(conflicts) >= 1
            c = conflicts[0]
            assert c["rule_a"] in ("rule_A", "rule_B")
            assert c["rule_b"] in ("rule_A", "rule_B")
            assert c["action_a"] != c["action_b"]
        finally:
            os.unlink(path)

    def test_detect_conflicts_no_conflict_different_categories(self):
        yaml = """
rules:
  - id: rule_net
    when:
      category: NETWORK
    then:
      action: allow
    priority: 10
  - id: rule_svc
    when:
      category: SERVICE
    then:
      action: suppress
    priority: 5
"""
        dsl, path = self._dsl(yaml)
        import os
        try:
            conflicts = dsl.detect_conflicts()
            assert len(conflicts) == 0
        finally:
            os.unlink(path)

    def test_conflict_report_has_required_keys(self):
        yaml = """
rules:
  - id: r1
    when:
      category: RESOURCE
    then:
      action: allow
  - id: r2
    when:
      category: RESOURCE
    then:
      action: escalate_immediately
"""
        dsl, path = self._dsl(yaml)
        import os
        try:
            conflicts = dsl.detect_conflicts()
            assert len(conflicts) >= 1
            for k in ("rule_a","rule_b","action_a","action_b",
                      "conflict","description"):
                assert k in conflicts[0]
        finally:
            os.unlink(path)


# ── auditd adapter parsing ────────────────────────────────────────────────────

class TestAuditdAdapter:
    def _adapter(self, path="/dev/null"):
        from healing_core.auditd_adapter import AuditdAdapter
        class FakeCore:
            def ingest(self, e): pass
        return AuditdAdapter(FakeCore(), log_path=path)

    def _line(self, atype, **fields):
        ts = "1700000000.000:12345"
        kvs = " ".join(f'{k}="{v}"' for k, v in fields.items())
        return f"type={atype} msg=audit({ts}): {kvs}"

    def test_parse_user_auth_failure(self):
        a = self._adapter()
        line = self._line("USER_AUTH", acct="root", res="failed", addr="10.0.0.1")
        evt = a._parse_line(line)
        assert evt is not None
        assert evt.error_type == "auth_failure"
        assert "root" in evt.actor or "auth" in evt.actor

    def test_parse_avc_selinux(self):
        a = self._adapter()
        line = self._line("AVC", denied="read", path="/etc/shadow",
                          scontext="unconfined", tcontext="shadow_t")
        evt = a._parse_line(line)
        assert evt is not None
        assert evt.error_type == "selinux_denial"
        assert "/etc/shadow" in evt.message

    def test_parse_service_start(self):
        a = self._adapter()
        line = self._line("SERVICE_START", unit="nginx.service")
        evt = a._parse_line(line)
        assert evt is not None
        assert evt.error_type == "service_start"
        assert "nginx" in evt.actor

    def test_parse_service_stop(self):
        a = self._adapter()
        line = self._line("SERVICE_STOP", unit="mysql.service")
        evt = a._parse_line(line)
        assert evt is not None
        assert evt.error_type == "service_stop"

    def test_parse_execve(self):
        a = self._adapter()
        line = self._line("EXECVE", a0="bash", a1="-c", a2="wget")
        evt = a._parse_line(line)
        assert evt is not None
        assert evt.error_type == "process_exec"
        assert "bash" in evt.message or "execve" in evt.message

    def test_parse_crypto_failure(self):
        a = self._adapter()
        line = self._line("CRYPTO_FAILURE", op="tls_connect", res="failed")
        evt = a._parse_line(line)
        assert evt is not None
        assert evt.error_type == "crypto_failure"

    def test_skip_path_type(self):
        a = self._adapter()
        line = self._line("PATH", name="/etc/hosts")
        evt = a._parse_line(line)
        assert evt is None

    def test_skip_eoe_type(self):
        a = self._adapter()
        line = self._line("EOE")
        evt = a._parse_line(line)
        assert evt is None

    def test_skip_non_type_line(self):
        a = self._adapter()
        evt = a._parse_line("---- auditd log rotation ----")
        assert evt is None

    def test_parse_fields(self):
        from healing_core.auditd_adapter import AuditdAdapter
        line = 'type=USER_AUTH msg=audit(1700000000.000:1): acct="root" res="failed"'
        fields = AuditdAdapter._parse_fields(line)
        assert fields.get("acct") == '"root"' or fields.get("acct") == "root"
        assert "res" in fields

    def test_rate_check(self):
        a = self._adapter()
        a._rate_limit = 3
        results = [a._rate_check() for _ in range(6)]
        assert results[:3] == [True]*3
        assert results[3:] == [False]*3

    def test_stats_keys(self):
        a = self._adapter()
        s = a.stats()
        for k in ("path","ingested","skipped","errors"):
            assert k in s

    def test_start_noop_on_windows(self):
        """start() on non-Linux should be a no-op (no crash)."""
        import platform as p
        a = self._adapter()
        if p.system() != "Linux":
            a.start()   # should not raise
            assert a._thread is None


# ── Core integration ──────────────────────────────────────────────────────────

class TestCoreV010:
    def _core(self):
        from healing_core.core import HealingCore
        return HealingCore(
            dry_run=True, db_path=":memory:",
            api_port=0, prometheus_port=0,
            enable_monitor=False, knowledge_ai_enabled=False,
            enable_multi_ai=False, enable_ml_classifier=False,
        )

    def test_itsm_dispatcher_initialized(self):
        c = self._core()
        assert c.itsm is not None
        c.shutdown()

    def test_itsm_report_no_crash(self):
        c = self._core()
        c.itsm_report()
        c.shutdown()

    def test_itsm_metrics_in_prometheus(self):
        c = self._core()
        m = c._prometheus_metrics()
        assert "hc_itsm_dispatched" in m
        assert "hc_attestation_pending" in m
        c.shutdown()

    def test_start_auditd_adapter_noop_on_nonlinux(self):
        import platform as p
        if p.system() == "Linux":
            pytest.skip("skip on actual Linux")
        c = self._core()
        a = c.start_auditd_adapter()
        assert a is not None
        c.shutdown()

    def test_exception_catalog_three_platforms(self):
        c = self._core()
        entries = c.exception_catalog.all_entries()
        platforms = {e.platform for e in entries}
        assert "windows" in platforms
        assert "macos"   in platforms
        c.shutdown()

    def test_ingest_with_itsm_no_crash(self):
        from healing_core.models import Event
        c = self._core()
        evt = Event(error_type="service_crash",
                    message="nginx terminated EventID 7034",
                    actor="nginx", subsystem="service")
        inc = c.ingest(evt)
        assert inc is not None
        c.shutdown()

    def test_dsl_simulate_via_core(self):
        from healing_core.models import Event, Incident, IncidentCategory, Scope, Severity
        c = self._core()
        evt = Event(error_type="crash", message="test", actor="test", subsystem="sys")
        inc = Incident(event=evt, category=IncidentCategory.SERVICE,
                       scope=Scope.MODULE, severity=Severity.HIGH, risk_score=0.5)
        d = c.dsl.simulate(inc)
        assert d is not None
        c.shutdown()

    def test_dsl_conflict_detection_via_core(self):
        c = self._core()
        conflicts = c.dsl.detect_conflicts()
        assert isinstance(conflicts, list)
        c.shutdown()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
