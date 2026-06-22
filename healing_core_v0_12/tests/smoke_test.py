"""tests/smoke_test.py — v0.6 smoke test.   Run: python run.py --smoke"""
from __future__ import annotations
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from healing_core import HealingCore, Event

def run():
    print("\n" + "═"*72)
    print("  HEALING CORE  v0.6  —  Smoke Test")
    print("═"*72)

    core = HealingCore(
        dry_run=True, db_path=":memory:",
        prometheus_port=9091, api_port=8740,
        plugins_dir="plugins", node_id="smoke_node",
        enable_monitor=False, knowledge_ai_enabled=False,
    )

    scenarios = [
        # Network causal chain
        Event(actor="wlan0",       error_type="wifi_down",        message="carrier lost",                 timestamp=time.time()),
        Event(actor="dns",         error_type="dns_failure",       message="NXDOMAIN api.example.com",    timestamp=time.time()+0.1),
        Event(actor="gateway",     error_type="gateway_unreachable",message="192.168.1.1 unreachable",   timestamp=time.time()+0.2),
        # Storm: 7 identical → suppress after threshold
        *[Event(actor="wlan0",     error_type="wifi_down",         message="storm test") for _ in range(7)],
        # Exception catalog enrichment — Python exception in message
        Event(actor="api_server",  error_type="exception",         message="MemoryError: cannot allocate 4GB"),
        Event(actor="web_app",     error_type="exception",         message="ConnectionRefusedError: [Errno 111] Connection refused"),
        Event(actor="auth_svc",    error_type="exception",         message="ssl.SSLCertVerificationError certificate verify failed"),
        # Service
        Event(actor="nginx",       error_type="config_corrupt",    message="nginx config syntax error"),
        Event(actor="postgres",    error_type="service_hung",      message="deadlock in transaction pool"),
        Event(actor="docker",      error_type="service_crash",     message="Docker daemon exited"),
        # Resource
        Event(actor="worker",      error_type="memory_depletion",  message="RSS at 96%, OOM kill imminent"),
        Event(actor="log_writer",  error_type="disk_full",         message="/var/log at 99%"),
        Event(actor="api_server",  error_type="cpu_overload",      message="CPU at 98% for 5 minutes"),
        # Security fast-path
        Event(actor="host",        error_type="malware_detected",  message="Ransomware encryption on /data"),
        Event(actor="sshd",        error_type="unauthorized_access",message="20 failed logins from 1.2.3.4"),
        # Auth + cert
        Event(actor="admin",       error_type="auth_failure",      message="Account locked — bad passwords"),
        Event(actor="api_key",     error_type="cert_expiry",       message="TLS cert expired 3 days ago"),
        # Dependency
        Event(actor="payment_svc", error_type="api_down",          message="Stripe API 503 for 10 requests"),
        # Knowledge hit: time_sync_failure maps directly in seed patterns
        Event(actor="ntp_client",  error_type="time_sync_failure", message="NTP sync failed, clock drift 8 minutes"),
        # Unknown → web search fallback + AI disabled
        Event(actor="quantum_svc", error_type="qubit_decoherence", message="Q7 register lost coherence"),
        # DSL suppression
        Event(actor="test_sensor", error_type="timeout",           message="should be DSL-suppressed"),
    ]

    from healing_core.models import RemediationStatus
    results, suppressed_count = [], 0
    for ev in scenarios:
        inc = core.ingest(ev)
        if inc is None:
            suppressed_count += 1
            print(f"  ◌  [storm/null]    {ev.actor:<20s}  {ev.error_type}")
            continue
        if inc.status == RemediationStatus.SUPPRESSED:
            suppressed_count += 1
            reason = inc.suppression_reason.split(":")[-1][:16]
            print(f"  ◌  [{reason:<18s}]  {ev.actor:<20s}  {ev.error_type}")
            continue
        results.append(inc)
        corr  = f"  ↳corr={inc.correlation_id[:8]}" if inc.correlation_id else ""
        chain = f"  chain={len(inc.causal_chain)}"   if inc.causal_chain   else ""
        print(f"  ▶  [{ev.actor:<18s}]  {ev.message[:48]:<50s}"
              f"  cat={inc.category.name:<18s}  sev={inc.severity.name:<8s}"
              f"  risk={inc.risk_score:.2f}  {inc.status.name}{corr}{chain}")

    print(f"\n  Scenarios={len(scenarios)}  Incidents={len(results)}"
          f"  Suppressed/Storm={suppressed_count}")

    core.audit_report()
    core.knowledge_report()
    core.exception_report()
    core.tracing_report()
    core.ratchet_report()
    core.dsl_report()
    core.primitives_report()

    print(f"\n{'─'*72}\n  CORRELATOR\n{'─'*72}")
    for k, v in core.correlator.summary().items():
        print(f"  {k:<30s}  {v}")

    print(f"\n{'─'*72}\n  METRICS\n{'─'*72}")
    for k, v in core.poll_metrics().items():
        print(f"  {k:<22s}  {v}")

    report_path = "/tmp/healing_report_v06.html"
    core.generate_report(report_path)
    print(f"\n  HTML report written → {report_path}")
    print(f"  API:        http://localhost:8740/api/v1/health")
    print(f"  Prometheus: http://localhost:9091/metrics")
    print(f"\n  ✓ v0.6 smoke test complete")
    core.shutdown()

if __name__ == "__main__":
    run()
