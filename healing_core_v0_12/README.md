# HealingCore/MOTHRA

Policy-driven, self-healing subsystem — detects, classifies, contains and
remediates faults while preserving auditability and safe recovery.

---

## What's new in v0.8

| Module | Description |
|---|---|
| `drivers/macos.py` | Full macOS primitives — `launchctl`, `networksetup`, `diskutil`, `pfctl`, `sntp` |
| `drivers/macos_catalog.py` | 30+ macOS-specific RemediationFix objects |
| `healing_core/ml_classifier.py` | TF-IDF + LogisticRegression classifier; auto-retrains on healed incidents; falls back to regex when sklearn absent |
| `healing_core/budget_tracker.py` | Sliding-window cost/impact ledger; global + per-category ceilings; blocks fixes that would exceed budget |
| `healing_core/canary.py` | 3-stage canary gate for high-impact fixes — dry-run probe → metric window → commit/rollback |
| `healing_core/grafana.py` | Auto-generates a Grafana 9/10 dashboard JSON from Prometheus metrics |
| `core.py` | Wires all v0.8 modules; ML classify path; budget check before every fix; canary gate before apply |
| `run.py` | New CLI flags: `--no-ml`, `--budget-cost/impact`, `--canary-threshold/wait`, `--grafana-export/push/key`, `--ml/budget/canary-report` |

---

## Architecture

```
EventStream
    │
    ▼
EventAuthenticator ──(rejected)──► [drop]
    │
    ▼
MLClassifier / IncidentClassifier
    │
    ▼
TriageEngine  ──  CorrelationEngine
    │
    ▼
ContainmentEngine
    │
    ▼
PolicyDSL ──(suppress/notify/escalate)──► EscalationManager
    │
    ▼  (auto-remediation allowed)
BudgetTracker ──(budget exceeded)──► EscalationManager
    │
    ▼  (budget ok)
CanaryDeployment ─── Stage 1: dry-run probe
    │                Stage 2: metric window
    │                Stage 3: commit / rollback
    │
    ▼  (canary passed)
VerifierHarness ── RatchetTest
    │
    ▼
RemediationEngine.apply_staged()
    │
    ├─(success)──► BudgetTracker.record()
    │              MLClassifier.record() → maybe_retrain()
    │              KnowledgeCore.ingest()
    │              AuditTrail
    │
    └─(failure)──► Rollback → LearningStore → retry
```

### OS support matrix

| OS | Primitives | Catalog | Service mgr |
|---|---|---|---|
| Linux | `drivers/linux.py` | `linux_catalog.py` | `systemctl` |
| Windows | `drivers/windows.py` | `windows_catalog.py` | `sc` / PowerShell |
| macOS ★ | `drivers/macos.py` | `macos_catalog.py` | `launchctl` |

★ New in v0.8

---

## Quick start

```bash
pip install PyYAML
# Optional — enables ML classifier:
pip install scikit-learn
# Optional — live system metrics for canary:
pip install psutil

# Dry-run demo (safe, no real commands):
python run.py --demo --demo-count 8

# Show all reports:
python run.py --report

# v0.8 specific reports:
python run.py --ml-report
python run.py --budget-report
python run.py --canary-report

# Export Grafana dashboard:
python run.py --grafana-export
# → writes grafana_healing.json

# Push to live Grafana:
python run.py --grafana-push http://grafana:3000 --grafana-key glsa_xxx

# Custom budget limits (cost units per hour):
python run.py --budget-cost 3.0 --budget-impact 2.0 --demo

# Canary gate at 40% impact threshold:
python run.py --canary-threshold 0.40 --canary-wait 10 --live --monitor

# Disable ML classifier (regex only):
python run.py --no-ml --demo
```

---

## CLI reference

```
--live                   Disable dry-run — execute real OS commands
--db PATH                SQLite database path (default: healing_core.db)
--policy PATH            Policy YAML path

-- v0.8 ML Classifier --
--no-ml                  Disable sklearn ML classifier (regex-only)

-- v0.8 Budget Tracker --
--budget-cost F          Max cost units per hour   (default 5.0)
--budget-impact F        Max impact units per hour (default 3.0)

-- v0.8 Canary --
--canary-threshold F     Impact score triggering canary gate (default 0.50)
--canary-wait S          Metric window duration seconds   (default 30)

-- v0.8 Grafana --
--grafana-export         Write grafana_healing.json and exit
--grafana-push URL       Push dashboard to Grafana API
--grafana-key KEY        Grafana API key for --grafana-push

-- Reports --
--report                 Print full runtime report
--ml-report              ML classifier stats
--budget-report          Budget tracker state
--canary-report          Canary deployment stats
--audit                  Last 20 audit trail entries
--primitives             Registered fix primitives
--knowledge              Knowledge core summary
--exceptions             Exception catalog
--os-faults              OS fault catalog
--dsl-report             DSL rule hits
--ratchet-report         Ratchet session summary

-- API / Telemetry --
--api-port PORT          REST API port (default 8740; 0 = off)
--prom-port PORT         Prometheus port (default 9091; 0 = off)
--otlp URL               OpenTelemetry OTLP endpoint
--monitor                Enable background health monitor

-- AI --
--anthropic-key KEY      Anthropic API key
--no-ai                  Disable all AI features
```

---

## Running the tests

```bash
# All tests including v0.8:
pytest tests/ -v

# v0.8 tests only:
pytest tests/test_v08.py -v

# With coverage:
pytest tests/ --cov=healing_core --cov=drivers --cov-report=term-missing
```

---

## v0.8 implementation notes

### ML Classifier
- Falls back silently to regex when `scikit-learn` is not installed.
- Seeded at startup from ExceptionCatalog (~32 entries) + OsFaultCatalog (~150 entries).
- Retrains every 50 confirmed-healed incidents (configurable via `RETRAIN_EVERY`).
- Confidence below 0.55 → regex fallback (configurable via `MLClassifier.CONFIDENCE_THRESHOLD`).
- `ml_conf` is written to every audit trail and trace span.

### Budget Tracker
- Sliding window: 1 hour by default (`BudgetConfig.window_seconds`).
- Two ceilings: global (`max_cost`, `max_impact`) and per-category (`max_cost_per_cat`, `max_impact_per_cat`).
- Warns at 80% utilisation (`warn_at_pct`).
- Budget spend is recorded **only on successful** fix application (never on failures or dry-runs).
- Blocked fixes are audit-logged and counted in Prometheus.

### Canary Deployment
- Triggered only when `fix.impact >= canary_config.impact_threshold` (default 0.50).
- Stage 1 runs fix steps as `step(incident)` — the same dry-run-aware functions.
- Stage 2 polls `core.poll_metrics()` every 5 s during the metric window.
- Pass `wait_seconds=0` in tests for instant stage 2 completion.
- Latency is measured end-to-end and stored in `CanaryResult.latency_ms`.

### macOS Driver
- Uses `launchctl kickstart -k system/<label>` for service restarts.
- Label mapping: short names like `nginx` → `homebrew.mxcl.nginx`; dotted names pass through.
- DNS flush: `dscacheutil -flushcache` + `killall -HUP mDNSResponder`.
- Firewall: pf anchors in `/etc/pf.anchors/healing_core`.
- All functions respect `DryRun` and log at INFO level when dry.

### Grafana Dashboard
- Compatible with Grafana 9 and 10 (`schemaVersion: 37`).
- Datasource UID defaults to `"Prometheus"` — match your actual datasource name.
- `dashboard.push(url, api_key)` uses stdlib `urllib` — no extra HTTP lib required.

---

## Roadmap — v0.9

- OpenTelemetry baggage propagation across microservices
- Kubernetes operator + CRD-based policy configuration
- Distributed Raft-backed audit log (etcd)
- Policy DSL v2: formal conflict detection + simulation mode
- ITSM ticket integration (Jira / ServiceNow webhook)
- Human-in-the-loop signed attestation for high-risk fixes
- Windows Event Log native ingest adapter
- macOS Endpoint Security framework integration

---

## What's new in v0.9

| Change | Detail |
|---|---|
| **`primitives.py` — macOS builtins** | `register_builtins()` now dispatches to `_register_macos_builtins()` on Darwin instead of silently falling through to Linux. All 52 required primitives registered using `launchctl`, `networksetup`, `dscacheutil`, `diskutil`, `pfctl`, `sntp` |
| **`primitives.py` — Windows service resolve** | Windows service steps now call `service_resolver.resolve(incident)` before hitting `sc.exe`/`net.exe`. `mysql` → `MySQL80`, `iis` → `W3SVC`, `task scheduler` → `Schedule`, etc. |
| **`primitives.py` — universal coverage** | All 52 required primitive names registered on Linux, Windows, and macOS. Tested with `REQUIRED_PRIMITIVES` set in `test_v09.py` |
| **`evtlog_adapter.py`** | Native Windows Event Log ingest. Polls `System`, `Application`, `Security` via `wevtutil qe`, parses EVTX XML, converts to `Event` objects. No pywin32 required. Tracks last `RecordId` per channel to avoid re-processing. Rate-limited. |
| **`journald_adapter.py`** | Native Linux journald ingest. Streams `journalctl -f --output=json`, filters by PRIORITY ≤ threshold (default 4=warning), extracts unit/PID/facility/message, always passes sshd/sudo/kernel regardless of priority |
| **`macos_log_adapter.py`** | Native macOS Unified Log ingest. Streams `log stream --style json --level error`, extracts process/subsystem/message, keyword-derives `error_type` |
| **`core.start_log_adapter()`** | Auto-detects OS and starts the right adapter. All adapters stopped cleanly in `shutdown()` |
| **`run.py`** | New flags: `--evtlog`, `--evtlog-channels`, `--evtlog-interval`, `--syslog`, `--syslog-priority`, `--macos-log`, `--macos-log-level`, `--log-adapter` (auto), `--adapter-report` |

### OS parity status after v0.9

| Capability | Linux | Windows | macOS |
|---|---|---|---|
| Driver primitives | ✅ | ✅ | ✅ |
| Service resolver | ✅ | ✅ | ✅ |
| OS fault catalog | ✅ (149) | ✅ (72) | ✅ (30+) |
| Exception catalog | ✅ | ✅ (29) | partial |
| Classifier patterns | ✅ | ✅ | ✅ |
| Native log ingest | ✅ journald | ✅ wevtutil | ✅ log stream |
| Fix selection | ✅ | ✅ | ✅ |

### Usage — log adapters

```bash
# Linux: stream journald warnings and above
python run.py --syslog --syslog-priority 4 --live

# Windows: poll System + Security channels every 5s
python run.py --evtlog --evtlog-channels "System,Security" --evtlog-interval 5 --live

# macOS: stream fault-level events
python run.py --macos-log --macos-log-level fault --live

# Auto-detect OS
python run.py --log-adapter --live

# Check adapter stats
python run.py --log-adapter --live &
sleep 30 && python run.py --adapter-report
```

### Remaining gaps → v0.10

- macOS exception catalog (currently 0 macOS-specific entries)
- Windows pywin32 fast-path for evtlog_adapter (lower latency than wevtutil subprocess)
- Linux auditd adapter (read `/var/log/audit/audit.log`)
- macOS Endpoint Security framework integration (requires entitlement)
- Cross-platform chaos test suite (inject real faults, verify healing)
- ITSM webhook escalation (Jira / ServiceNow)
- Human-in-the-loop signed attestation for high-risk fixes
