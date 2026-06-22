#!/usr/bin/env python3
"""
HealingCore v0.8 — command-line launcher

New flags in v0.8
  --no-ml              Disable the sklearn ML classifier (regex-only)
  --budget-cost F      Max remediation cost units per hour  (default 5.0)
  --budget-impact F    Max remediation impact units per hour (default 3.0)
  --canary-threshold F  Impact score that triggers canary gate (default 0.50)
  --grafana-export     Write grafana_healing.json and exit
  --grafana-push URL   Push dashboard to Grafana at URL (requires --grafana-key)
  --grafana-key KEY    Grafana API key for --grafana-push
  --ml-report          Print ML classifier stats
  --budget-report      Print budget tracker stats
  --canary-report      Print canary deployment stats
"""
import argparse, logging, platform, time, sys

VERSION = "0.11.0"
OS = platform.system()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="healing_core",
        description=f"HealingCore v{VERSION} — policy-driven self-healing subsystem",
    )

    # ── Core behaviour ────────────────────────────────────────────────────
    p.add_argument("--live",        action="store_true",
                   help="Disable dry-run (execute real commands)")
    p.add_argument("--db",          default="healing_core.db", metavar="PATH",
                   help="SQLite database path (default: healing_core.db)")
    p.add_argument("--policy",      default="healing_policy.yaml", metavar="PATH",
                   help="Policy YAML path (default: healing_policy.yaml)")
    p.add_argument("--node",        default="node_0", metavar="ID",
                   help="Node identifier for distributed audit log")
    p.add_argument("--plugins",     default="plugins", metavar="DIR",
                   help="Plugin directory (default: plugins)")

    # ── Network / API ─────────────────────────────────────────────────────
    p.add_argument("--api-port",    type=int, default=8740, metavar="PORT",
                   help="REST API port (0 = disabled)")
    p.add_argument("--api-key",     default="", metavar="KEY",
                   help="REST API authentication key (leave blank to disable)")
    p.add_argument("--prom-port",   type=int, default=9091, metavar="PORT",
                   help="Prometheus metrics port (0 = disabled)")
    p.add_argument("--alertmanager", action="store_true",
                   help="Enable Alertmanager webhook bridge")
    p.add_argument("--am-port",     type=int, default=9094, metavar="PORT",
                   help="Alertmanager bridge port (default: 9094)")

    # ── AI / Knowledge ────────────────────────────────────────────────────
    p.add_argument("--anthropic-key", default="", metavar="KEY",
                   help="Anthropic API key for knowledge core AI features")
    p.add_argument("--no-ai",       action="store_true",
                   help="Disable all AI-backed features (knowledge + multi-AI oracle)")
    p.add_argument("--otlp",        default="", metavar="URL",
                   help="OpenTelemetry OTLP endpoint for distributed tracing")

    # ── Health monitor ────────────────────────────────────────────────────
    p.add_argument("--monitor",     action="store_true",
                   help="Enable background health monitor")
    p.add_argument("--cpu-thresh",  type=float, default=90.0,
                   help="CPU %% alert threshold (default: 90)")
    p.add_argument("--mem-thresh",  type=float, default=85.0,
                   help="Memory %% alert threshold (default: 85)")
    p.add_argument("--disk-thresh", type=float, default=90.0,
                   help="Disk %% alert threshold (default: 90)")

    # ── v0.8: ML classifier ───────────────────────────────────────────────
    p.add_argument("--no-ml",       action="store_true",
                   help="Disable ML classifier; use regex-only classification")

    # ── v0.8: Budget tracker ──────────────────────────────────────────────
    p.add_argument("--budget-cost",   type=float, default=5.0, metavar="F",
                   help="Max total remediation cost per hour (default: 5.0)")
    p.add_argument("--budget-impact", type=float, default=3.0, metavar="F",
                   help="Max total remediation impact per hour (default: 3.0)")

    # ── v0.8: Canary deployment ───────────────────────────────────────────
    p.add_argument("--canary-threshold", type=float, default=0.50, metavar="F",
                   help="Impact score that triggers canary gate (default: 0.50)")
    p.add_argument("--canary-wait",      type=float, default=30.0, metavar="S",
                   help="Canary metric window seconds (default: 30)")

    # ── v0.9: Log Adapters ────────────────────────────────────────────────
    p.add_argument("--evtlog",     action="store_true",
                   help="[Windows] Start Windows Event Log ingest adapter")
    p.add_argument("--evtlog-channels", default="System,Application,Security",
                   metavar="LIST",
                   help="Comma-separated Event Log channels (default: System,Application,Security)")
    p.add_argument("--evtlog-interval", type=float, default=10.0, metavar="S",
                   help="Event Log poll interval seconds (default: 10)")
    p.add_argument("--syslog",     action="store_true",
                   help="[Linux] Start journald/syslog ingest adapter")
    p.add_argument("--syslog-priority", type=int, default=4, metavar="N",
                   help="Journald max PRIORITY to ingest 0-7 (default: 4=warning)")
    p.add_argument("--macos-log",  action="store_true",
                   help="[macOS] Start Unified Log ingest adapter")
    p.add_argument("--macos-log-level", default="error",
                   choices=["fault","error","default","info"],
                   help="macOS log level threshold (default: error)")
    p.add_argument("--log-adapter",action="store_true",
                   help="Auto-detect OS and start appropriate log adapter")
    p.add_argument("--adapter-report", action="store_true",
                   help="Print log adapter stats and exit")

    # ── v0.10: ITSM escalation ───────────────────────────────────────────
    p.add_argument("--itsm-webhook",   default="", metavar="URL",
                   help="Webhook URL for escalation notifications")
    p.add_argument("--itsm-slack",     default="", metavar="URL",
                   help="Slack Incoming Webhook URL")
    p.add_argument("--itsm-pd-key",    default="", metavar="KEY",
                   help="PagerDuty routing key")
    p.add_argument("--itsm-jira-url",  default="", metavar="URL",
                   help="Jira base URL (e.g. https://myco.atlassian.net)")
    p.add_argument("--itsm-jira-key",  default="", metavar="KEY",
                   help="Jira API token")
    p.add_argument("--itsm-jira-email",default="", metavar="EMAIL",
                   help="Jira account email")
    p.add_argument("--itsm-jira-project",default="OPS", metavar="KEY",
                   help="Jira project key (default: OPS)")
    p.add_argument("--attest-secret",  default="", metavar="SECRET",
                   help="HMAC secret for signed attestation")
    p.add_argument("--attest-threshold",type=float, default=0.80, metavar="F",
                   help="Impact/risk score requiring human attestation (default: 0.80)")

    # ── v0.10: auditd ─────────────────────────────────────────────────────
    p.add_argument("--auditd",         action="store_true",
                   help="[Linux] Start auditd log adapter (/var/log/audit/audit.log)")
    p.add_argument("--auditd-path",    default="/var/log/audit/audit.log",
                   metavar="PATH", help="auditd log file path")
    p.add_argument("--itsm-report",    action="store_true",
                   help="Print ITSM dispatcher stats")

    # ── v0.11: Audit chain / signed checkpoints ──────────────────────────
    p.add_argument("--audit-secret",   default="", metavar="SECRET",
                   help="HMAC secret for the audit hash-chain (else ephemeral/keyfile)")
    p.add_argument("--audit-key-path", default=".healing_core_audit.key",
                   metavar="PATH",
                   help="Path to persist/load the audit HMAC key "
                        "(default: .healing_core_audit.key)")
    p.add_argument("--audit-chain-report", action="store_true",
                   help="Verify and print audit hash-chain integrity, then exit")
    p.add_argument("--replay-report",  default="", metavar="REPLAY_ID",
                   help="Print all audit entries for one replay_id")

    # ── v0.11: Versioned primitives ───────────────────────────────────────
    p.add_argument("--primitive-versions", action="store_true",
                   help="Print versioned-primitive provenance/test history")

    # ── v0.11: Chaos / fuzz harness ────────────────────────────────────────
    p.add_argument("--chaos",          action="store_true",
                   help="Run the deterministic chaos/fuzz harness and exit")
    p.add_argument("--chaos-events",   type=int, default=200, metavar="N",
                   help="Number of adversarial events to generate (default: 200)")
    p.add_argument("--chaos-seed",     type=int, default=42, metavar="N",
                   help="Deterministic RNG seed for chaos sequence (default: 42)")

    # ── v0.8: Grafana ─────────────────────────────────────────────────────
    p.add_argument("--grafana-export", action="store_true",
                   help="Generate grafana_healing.json dashboard and exit")
    p.add_argument("--grafana-push",   default="", metavar="URL",
                   help="Push dashboard to Grafana API at URL")
    p.add_argument("--grafana-key",    default="", metavar="KEY",
                   help="Grafana API key for --grafana-push")

    # ── Reports ───────────────────────────────────────────────────────────
    p.add_argument("--report",      action="store_true",
                   help="Print a full runtime report and exit")
    p.add_argument("--audit",       action="store_true",
                   help="Print last-20 audit trail entries and exit")
    p.add_argument("--primitives",  action="store_true",
                   help="Print registered primitives and exit")
    p.add_argument("--knowledge",   action="store_true",
                   help="Print knowledge-core summary and exit")
    p.add_argument("--exceptions",  action="store_true",
                   help="Print exception catalog summary and exit")
    p.add_argument("--dsl-report",  action="store_true",
                   help="Print DSL rule stats and exit")
    p.add_argument("--ratchet-report", action="store_true",
                   help="Print ratchet session summary and exit")
    p.add_argument("--os-faults",   action="store_true",
                   help="Print OS fault catalog summary and exit")
    p.add_argument("--exc-handler", action="store_true",
                   help="Print robust exception handler stats and exit")
    # v0.8
    p.add_argument("--ml-report",     action="store_true",
                   help="Print ML classifier stats and exit")
    p.add_argument("--budget-report", action="store_true",
                   help="Print budget tracker state and exit")
    p.add_argument("--canary-report", action="store_true",
                   help="Print canary deployment stats and exit")

    # ── Demo / test ───────────────────────────────────────────────────────
    p.add_argument("--demo",        action="store_true",
                   help="Inject a sample incident stream for demonstration")
    p.add_argument("--demo-count",  type=int, default=5, metavar="N",
                   help="Number of demo incidents (default: 5)")
    p.add_argument("--html-report", default="", metavar="PATH",
                   help="Generate HTML health report at PATH and exit")

    # ── Logging ───────────────────────────────────────────────────────────
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                   help="Log verbosity (default: INFO)")
    p.add_argument("--version",   action="store_true",
                   help="Print version and exit")

    return p


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def _banner(dry: bool) -> None:
    mode = "DRY-RUN" if dry else "⚡ LIVE"
    print(f"""
╔══════════════════════════════════════════════════════════╗
║  HealingCore v{VERSION:<8s}  ·  {OS:<10s}  ·  {mode:<12s}  ║
╚══════════════════════════════════════════════════════════╝""")


def _build_core(args):
    from healing_core.core        import HealingCore
    from healing_core.monitor     import MonitorThresholds
    from healing_core.budget_tracker import BudgetConfig
    from healing_core.canary         import CanaryConfig

    dry = not args.live
    thresholds = MonitorThresholds(
        cpu_pct=args.cpu_thresh,
        mem_pct=args.mem_thresh,
        disk_pct=args.disk_thresh,
    )
    budget_cfg = BudgetConfig(
        max_cost=args.budget_cost,
        max_impact=args.budget_impact,
    )
    canary_cfg = CanaryConfig(
        impact_threshold=args.canary_threshold,
        wait_seconds=args.canary_wait,
    )

    # ── ITSM config via policy YAML keys ─────────────────────────────────
    # Inject CLI values into policy object so ITSMDispatcher.from_policy() picks them up
    if not hasattr(core_policy := type('P', (), {})(), 'itsm'):
        pass  # handled below in core

    return HealingCore(
        dry_run              = dry,
        db_path              = args.db,
        policy_yaml_path     = args.policy,
        prometheus_port      = args.prom_port,
        api_port             = args.api_port,
        api_key              = args.api_key or None,
        plugins_dir          = args.plugins,
        node_id              = args.node,
        enable_monitor       = args.monitor,
        monitor_thresholds   = thresholds,
        anthropic_key        = args.anthropic_key,
        enable_alertmanager  = args.alertmanager,
        alertmanager_port    = args.am_port,
        otlp_endpoint        = args.otlp,
        knowledge_ai_enabled = not args.no_ai,
        enable_multi_ai      = not args.no_ai,
        # v0.8
        enable_ml_classifier = not args.no_ml,
        budget_config        = budget_cfg,
        canary_config        = canary_cfg,
        canary_impact_threshold = args.canary_threshold,
        # v0.11
        audit_secret    = args.audit_secret or None,
        audit_key_path  = args.audit_key_path,
    )


def _run_demo(core, count: int) -> None:
    from healing_core.models import Event
    import random, uuid

    scenarios = [
        {"error_type": "oom_kill",       "message": "Out of memory: kill process 1234 (nginx)",
         "actor": "nginx",               "subsystem": "kernel"},
        {"error_type": "disk_full",      "message": "No space left on device /var/log",
         "actor": "journald",            "subsystem": "storage"},
        {"error_type": "dns_timeout",    "message": "DNS resolution timeout for api.example.com",
         "actor": "resolver",            "subsystem": "network"},
        {"error_type": "auth_failure",   "message": "Authentication failed for user root",
         "actor": "sshd",               "subsystem": "auth"},
        {"error_type": "service_crash",  "message": "Service mysql exited with code 1",
         "actor": "mysql",              "subsystem": "service"},
        {"error_type": "cpu_spike",      "message": "CPU usage 98% sustained for 120s",
         "actor": "app_worker",         "subsystem": "compute"},
        {"error_type": "port_conflict",  "message": "Address already in use: port 8080",
         "actor": "nginx",              "subsystem": "network"},
        {"error_type": "cert_expired",   "message": "TLS certificate expired for domain.com",
         "actor": "tls_handler",        "subsystem": "security"},
        {"error_type": "db_timeout",     "message": "Database query timeout after 30s",
         "actor": "postgres",           "subsystem": "database"},
        {"error_type": "mem_leak",       "message": "Process heap growing unbounded: 4.2 GB",
         "actor": "java_app",           "subsystem": "memory"},
    ]

    chosen = random.choices(scenarios, k=count)
    print(f"\n  Injecting {count} demo incidents...\n")
    healed = 0
    for i, sc in enumerate(chosen):
        evt = Event(**sc)
        evt.id = str(uuid.uuid4())
        inc = core.ingest(evt)
        status = inc.status.name if inc else "filtered"
        if inc and inc.status.name == "COMMITTED":
            healed += 1
        print(f"  [{i+1}/{count}] {sc['error_type']:<22s} → {status}")
        time.sleep(0.15)

    print(f"\n  Healed: {healed}/{count}  ({100*healed//max(1,count)}%)")


def main(argv=None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    if args.version:
        print(f"HealingCore v{VERSION} ({OS})")
        return 0

    _configure_logging(args.log_level)

    # ── Grafana export (no core needed) ───────────────────────────────────
    if args.grafana_export and not args.grafana_push:
        from healing_core.grafana import GrafanaDashboard
        path = GrafanaDashboard().export("grafana_healing.json")
        print(f"  Dashboard written → {path}")
        return 0

    _banner(not args.live)
    core = _build_core(args)

    try:
        # ── One-shot report flags ─────────────────────────────────────────
        any_report = False
        if args.grafana_export:
            path = core.export_grafana("grafana_healing.json")
            print(f"  Dashboard written → {path}")
            any_report = True
        if args.grafana_push and args.grafana_key:
            ok = core.grafana.push(args.grafana_push, args.grafana_key)
            print(f"  Grafana push → {'OK' if ok else 'FAILED'}")
            any_report = True
        if args.audit:          core.audit_report();          any_report = True
        if args.primitives:     core.primitives_report();     any_report = True
        if args.knowledge:      core.knowledge_report();      any_report = True
        if args.exceptions:     core.exception_report();      any_report = True
        if args.dsl_report:     core.dsl_report();            any_report = True
        if args.ratchet_report: core.ratchet_report();        any_report = True
        if args.os_faults:      core.os_fault_report();       any_report = True
        if args.exc_handler:    core.exception_handler_report(); any_report = True
        if args.adapter_report: core.adapter_report();         any_report = True
        if args.itsm_report:    core.itsm_report();           any_report = True
        if args.audit_chain_report:
            core.audit_chain_report();  any_report = True
        if args.replay_report:
            core.replay_report(args.replay_report); any_report = True
        if args.primitive_versions:
            core.primitive_versions_report(); any_report = True
        if args.chaos:
            core.chaos_report(n_events=args.chaos_events, seed=args.chaos_seed)
            any_report = True
        if args.ml_report:      core.ml_report();             any_report = True
        if args.budget_report:  core.budget_report();         any_report = True
        if args.canary_report:  core.canary_report();         any_report = True
        if args.html_report:
            p = core.generate_report(args.html_report)
            print(f"  HTML report → {p}")
            any_report = True
        if any_report and not args.demo:
            return 0

        if args.report:
            for fn in (core.primitives_report, core.knowledge_report,
                       core.exception_report, core.os_fault_report,
                       core.dsl_report, core.ratchet_report,
                       core.exception_handler_report, core.ml_report,
                       core.budget_report, core.canary_report,
                       core.tracing_report, core.audit_report):
                fn()
            return 0

        if args.demo:
            _run_demo(core, args.demo_count)
            print()
            core.ml_report()
            core.budget_report()
            core.canary_report()
            return 0

        # ── v0.10: ITSM backends from CLI ────────────────────────────────
        from healing_core.itsm import (WebhookBackend, SlackBackend,
                                        PagerDutyBackend, JiraBackend,
                                        SignedAttestation, ITSMDispatcher)
        cli_backends = []
        if args.itsm_webhook: cli_backends.append(WebhookBackend(args.itsm_webhook))
        if args.itsm_slack:   cli_backends.append(SlackBackend(args.itsm_slack))
        if args.itsm_pd_key:  cli_backends.append(PagerDutyBackend(args.itsm_pd_key))
        if args.itsm_jira_url and args.itsm_jira_key:
            cli_backends.append(JiraBackend(
                args.itsm_jira_url, args.itsm_jira_project,
                args.itsm_jira_key, args.itsm_jira_email))
        if cli_backends:
            attest = (SignedAttestation(args.attest_secret)
                      if args.attest_secret else None)
            core.itsm = ITSMDispatcher(cli_backends, attest,
                                       args.attest_threshold)
            print(f"  ITSM backends: {[b.name for b in cli_backends]}")

        # ── v0.10: auditd adapter ─────────────────────────────────────────
        if args.auditd:
            core.start_auditd_adapter(log_path=args.auditd_path)
            print(f"  auditd adapter started ({args.auditd_path})")

        # ── v0.9: Start log adapters ──────────────────────────────────────────
        import platform as _plat
        _OS = _plat.system()
        if args.log_adapter or (args.evtlog   and _OS == "Windows") or \
                               (args.syslog   and _OS != "Windows") or \
                               (args.macos_log and _OS == "Darwin"):
            adapter_kwargs = {}
            if _OS == "Windows":
                adapter_kwargs = {
                    "channels":       args.evtlog_channels.split(","),
                    "poll_interval":  args.evtlog_interval,
                }
            elif _OS == "Darwin":
                adapter_kwargs = {"level": args.macos_log_level}
            else:
                adapter_kwargs = {"priority_threshold": args.syslog_priority}
            core.start_log_adapter(**adapter_kwargs)
            print(f"  Log adapter started ({_OS})")

        # ── Daemon mode ───────────────────────────────────────────────────
        print(f"  Listening for events (API :{args.api_port}  "
              f"Prom :{args.prom_port}) — Ctrl-C to stop\n")
        while True:
            time.sleep(5)

    except KeyboardInterrupt:
        print("\n  Shutting down…")
    finally:
        core.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
