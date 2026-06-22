"""healing_core.core (v0.8)"""
from __future__ import annotations
import logging, platform, signal, threading, time, urllib.request, urllib.parse
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .models        import (Event, Incident, IncidentCategory, RemediationFix,
                             RemediationStatus, Scope, Severity, Snapshot)
from .policy        import HealingPolicy
from .classification import IncidentClassifier
from .triage        import TriageEngine
from .correlation   import EventCorrelator
from .containment   import ContainmentEngine
from .snapshot      import SnapshotStore
from .remediation   import RemediationEngine, VerifierHarness
from .audit         import AuditTrail
from .learning      import LearningStore, AdaptivePolicyEngine
from .primitives    import PrimitivesRegistry
from .escalation    import EscalationManager
from .telemetry     import TelemetryOutlet, PrometheusExporter
from .api           import APIServer
from .plugins       import PluginLoader
from .monitor       import HealthMonitor, MonitorThresholds
from .ratchet       import DeterministicRatchetTest
from .event_auth    import EventAuthenticator, AuthPolicy
from .dsl           import PolicyDSL
from .reconciler    import StateReconciler
from .knowledge     import KnowledgeCore
from .alertmanager  import AlertmanagerBridge
from .tracing       import Tracer
from .exception_catalog import ExceptionCatalog
from .reporter      import HealthReporter
from .os_fault_catalog      import OsFaultCatalog
from .multi_ai_oracle       import MultiAIOracle
from .program_synthesizer   import ProgramSynthesizer
from .robust_exception_handler import RobustExceptionHandler
# v0.8 NEW
from .ml_classifier  import MLClassifier
from .budget_tracker import BudgetTracker, BudgetConfig
from .canary         import CanaryDeployment, CanaryConfig
from .grafana        import GrafanaDashboard
# v0.9 log adapters
# v0.10 new
from .itsm          import ITSMDispatcher
from .auditd_adapter import AuditdAdapter
# v0.11 new
from .primitive_registry import (VersionedPrimitiveRegistry,
    VersionedPrimitiveRegistryWithGate, PromotionGateConfig)
from .ci_gate import CIGate
from .chaos               import ChaosHarness
import uuid as _uuid
from .evtlog_adapter    import WindowsEvtLogAdapter
from .journald_adapter  import JournaldAdapter
from .macos_log_adapter import MacosLogAdapter

log = logging.getLogger("healing_core")
OS  = platform.system()


class HealingCore:
    def __init__(self, *, dry_run=True, db_path="healing_core.db",
                 policy_yaml_path="healing_policy.yaml",
                 prometheus_port=9091, api_port=8740, api_key=None,
                 plugins_dir="plugins", node_id="node_0",
                 enable_monitor=False, monitor_thresholds=None,
                 auth_policy=None,
                 anthropic_key="",
                 alertmanager_port=9094, enable_alertmanager=False,
                 otlp_endpoint="",
                 knowledge_ai_enabled=True,
                 enable_multi_ai=True,
                 min_conf_to_synthesize=0.55,
                                  # v0.12: gated primitive promotion
                 gate_config=None,
# v0.11: audit chain key management
                 audit_secret=None,
                 audit_key_path=None,
                 # v0.8
                 budget_config=None,
                 canary_config=None,
                 enable_ml_classifier=True,
                 canary_impact_threshold=0.50):

        self.dry_run     = dry_run
        self._enable_multi_ai = enable_multi_ai
        self._min_synth_conf  = min_conf_to_synthesize
        self._start_time = time.time()
        self._stats: Dict[str, int]   = defaultdict(int)
        self._cooldowns: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._configure_drivers(dry_run)

        # Core subsystems (v0.4–v0.7 unchanged)
        self.policy      = HealingPolicy(yaml_path=policy_yaml_path)
        self.classifier  = IncidentClassifier()
        self.triage      = TriageEngine()
        self.correlator  = EventCorrelator(
            window_seconds=300.0, storm_threshold=self.policy.storm_threshold,
            storm_window_seconds=60.0, causal_window_seconds=30.0)
        self.containment = ContainmentEngine(dry_run=dry_run)
        self.audit       = AuditTrail(db_path=db_path,
                                      hmac_secret=audit_secret,
                                      key_path=audit_key_path)
        self.snapshots   = SnapshotStore(secret=self.audit.secret)
        self.remediation = RemediationEngine(dry_run=dry_run)
        self.verifier    = VerifierHarness(dry_run=dry_run)
        self.learning    = LearningStore(db_path=db_path)
        self.adaptive    = AdaptivePolicyEngine(self.policy, self.learning)
        self.primitives  = PrimitivesRegistry()
        self.escalation  = EscalationManager(self.policy)
        self.telemetry   = TelemetryOutlet()
        self.ratchet     = DeterministicRatchetTest(db_path=db_path)
        self.event_auth  = EventAuthenticator(auth_policy or AuthPolicy())
        self.dsl         = PolicyDSL(rules_yaml_path=policy_yaml_path)
        self.reconciler  = StateReconciler(node_id=node_id, db_path=db_path)
        self.knowledge   = KnowledgeCore(
            db_path=db_path, anthropic_key=anthropic_key,
            ai_enabled=knowledge_ai_enabled)
        self.exception_catalog = ExceptionCatalog()
        self.tracer      = Tracer(export_endpoint=otlp_endpoint)
        self.reporter    = HealthReporter(self)
        self.os_fault_catalog = OsFaultCatalog()
        self.multi_ai_oracle  = MultiAIOracle(
            anthropic_key    = anthropic_key,
            knowledge_core   = self.knowledge,
            os_fault_catalog = self.os_fault_catalog,
            exception_catalog= self.exception_catalog,
        ) if enable_multi_ai else None
        self.synthesizer = ProgramSynthesizer(dry_run=dry_run, audit=self.audit)
        self.exception_handler = RobustExceptionHandler(
            exception_catalog   = self.exception_catalog,
            os_fault_catalog    = self.os_fault_catalog,
            multi_ai_oracle     = self.multi_ai_oracle,
            program_synthesizer = self.synthesizer,
            audit               = self.audit,
            primitives          = self.primitives,
            knowledge           = self.knowledge,
            min_confidence_to_synthesize = min_conf_to_synthesize,
        )

        # ── v0.8 NEW subsystems ───────────────────────────────────────────
        self.ml_classifier: Optional[MLClassifier] = None
        if enable_ml_classifier:
            self.ml_classifier = MLClassifier(
                exception_catalog=self.exception_catalog,
                os_fault_catalog =self.os_fault_catalog,
            )

        cfg = budget_config or BudgetConfig()
        self.budget = BudgetTracker(config=cfg)

        ccfg = canary_config or CanaryConfig(impact_threshold=canary_impact_threshold)
        self.canary = CanaryDeployment(config=ccfg)

        self.grafana = GrafanaDashboard(core=self, ds_name="Prometheus")

        # v0.10: ITSM dispatcher (Jira / Slack / PagerDuty / Webhook)
        self.itsm = ITSMDispatcher.from_policy(self.policy)

        # v0.11: versioned primitive registry (provenance + test history)
        self._gate_config = gate_config
        if gate_config is not None:
            self.primitive_registry = VersionedPrimitiveRegistryWithGate(db_path=db_path)
        else:
            self.primitive_registry = VersionedPrimitiveRegistry(db_path=db_path)

        # v0.11: chaos/fuzz harness (deterministic, seeded)
        self.chaos = ChaosHarness(seed=42)

        # v0.9: log ingest adapter
        self._log_adapter = None
        self._auditd = None

        # Wire DryRun flag
        try:
            import drivers.linux as _ldrv;  _ldrv.DryRun  = dry_run
        except ImportError: pass
        try:
            import drivers.windows as _wdrv; _wdrv.DryRun = dry_run
        except ImportError: pass
        try:
            import drivers.macos as _mdrv;   _mdrv.DryRun  = dry_run
        except ImportError: pass

        self.monitor: Optional[HealthMonitor] = None
        if enable_monitor:
            self.monitor = HealthMonitor(thresholds=monitor_thresholds)
            self.monitor.start(self)

        self.primitives.register_builtins(dry_run=dry_run)
        self._register_catalogs()
        self.plugin_loader = PluginLoader(plugins_dir=plugins_dir)
        self.plugin_loader.load_all(self.primitives)

        # Seed ML classifier after primitives/catalogs are loaded
        if self.ml_classifier:
            try:
                self.ml_classifier.seed()
            except Exception as exc:
                log.warning("ml_classifier seed failed: %s", exc)

        self.alertmanager_bridge: Optional[AlertmanagerBridge] = None
        if enable_alertmanager:
            self.alertmanager_bridge = AlertmanagerBridge(self, port=alertmanager_port)
            self.alertmanager_bridge.start()

        self.prometheus: Optional[PrometheusExporter] = None
        if prometheus_port > 0:
            self.prometheus = PrometheusExporter(port=prometheus_port)
            self.prometheus.start(self)

        self._api: Optional[APIServer] = None
        if api_port > 0:
            self._api = APIServer(self, port=api_port, api_key=api_key)
            self._api.start()

        if OS != "Windows":
            try:
                signal.signal(signal.SIGHUP, self._handle_sighup)
            except (OSError, ValueError):
                pass

        prim_count = sum(len(v) for v in self.primitives._store.values())
        ml_info = "sklearn" if self.ml_classifier and self.ml_classifier._model else "regex"
        log.info(
            "HealingCore v0.8 | os=%s  dry=%s  primitives=%d  classifier=%s  node=%s",
            OS, dry_run, prim_count, ml_info, node_id,
        )

    # ── Ingest ────────────────────────────────────────────────────────────────

    def ingest(self, event: Event) -> Optional[Incident]:
        if event.is_health_signal:
            return None

        event.fingerprint = event.compute_fingerprint()

        exc_entry = self.exception_catalog.lookup(
            f"{event.error_type} {event.message}"
        )
        if exc_entry and event.error_type in ("unknown_fault", "", "exception"):
            event.error_type = exc_entry.exception_class.lower().replace(".", "_")

        auth = self.event_auth.verify(event.__dict__, source=event.actor)
        if not auth.accepted:
            log.warning("auth | rejected actor=%s  reason=%s", event.actor, auth.reason)
            self._stats["auth_rejected"] += 1
            return None

        decision, detail = self.correlator.evaluate(event)
        if decision == "suppressed":
            self._stats["suppressed"] += 1
            return None

        # ── v0.8: ML-assisted classification ─────────────────────────────
        if self.ml_classifier:
            ml_cat, ml_conf = self.ml_classifier.classify(event)
            category = ml_cat
        else:
            category = self.classifier.classify(event)
            ml_conf  = 1.0

        if category == IncidentCategory.UNKNOWN and exc_entry:
            category = exc_entry.category

        scope, risk_score, severity = self.triage.score(event, category)
        weighted_risk = round(risk_score * auth.confidence, 3)

        incident = Incident(event=event, category=category, scope=scope,
                            severity=severity, risk_score=weighted_risk)

        # v0.11: deterministic replay identifiers — "seed" + "replay-id"
        # per guideline cryptographic-provenance requirement. seed is
        # derived from the incident id so the same incident always
        # produces the same seed (useful for replaying a specific
        # remediation attempt through the chaos harness / ratchet test).
        replay_id = str(_uuid.uuid4())
        seed      = int(incident.id[:8], 16)
        if decision == "correlated" and detail:
            incident.correlation_id = detail
            grp = self.correlator.get_group(detail)
            if grp:
                incident.causal_chain = grp.members[:-1]

        self.correlator.register_incident(incident)
        self._stats["total_incidents"] += 1

        trace_id  = self.tracer.new_trace_id()
        root_span = self.tracer.instrument_incident(incident.id, trace_id)
        root_span.set("category",   category.name)
        root_span.set("severity",   severity.name)
        root_span.set("risk",       weighted_risk)
        root_span.set("ml_conf",    round(ml_conf, 3))
        root_span.set("actor",      event.actor)
        root_span.set("error_type", event.error_type)

        dsl = self.dsl.evaluate(incident)
        if dsl.action == "suppress":
            incident.status = RemediationStatus.SUPPRESSED
            incident.suppression_reason = f"dsl:{dsl.matched_rule}"
            self.tracer.finish_span(root_span, "OK")
            return incident
        if dsl.action == "notify_only":
            self.audit.append("notify_only", incident.id, "",
                              {"category": category.name, "dsl_rule": dsl.matched_rule})
            self.tracer.finish_span(root_span, "OK")
            return incident

        actor = event.actor
        if actor in self._cooldowns:
            elapsed = time.time() - self._cooldowns[actor]
            if elapsed < self.policy.cooldown_seconds:
                incident.status = RemediationStatus.SUPPRESSED
                incident.suppression_reason = f"cooldown:{elapsed:.1f}s"
                self.tracer.finish_span(root_span, "OK")
                return incident

        snapshot = self.snapshots.capture(incident, replay_id=replay_id, seed=seed)
        self.audit.append("incident_detected", incident.id, snapshot.id, {
            "category":   category.name, "severity": severity.name,
            "risk":       weighted_risk, "auth_conf": auth.confidence,
            "ml_conf":    round(ml_conf, 3),
            "correlation":incident.correlation_id, "dsl_rule": dsl.matched_rule,
            "trace_id":   trace_id, "snapshot_signed": bool(snapshot.signature),
        }, reason=f"incident classified as {category.name}/{severity.name}",
           seed=seed, replay_id=replay_id)

        if (category in (IncidentCategory.SECURITY, IncidentCategory.MALWARE)
                or dsl.action in ("escalate_immediately", "quarantine_and_escalate")):
            self.containment.apply(incident)
            incident.status = RemediationStatus.ESCALATED
            self.escalation.escalate(incident, snapshot, [], self.audit, self.primitives)
            self.audit.append("security_escalated", incident.id, snapshot.id,
                              {"category": category.name},
                              reason="SECURITY/MALWARE category — immediate containment",
                              seed=seed, replay_id=replay_id)
            self.tracer.finish_span(root_span, "OK")
            return incident

        self.containment.apply(incident)

        if dsl.override_auto is False:
            incident.status = RemediationStatus.ESCALATED
            self.escalation.escalate(incident, snapshot, [], self.audit, self.primitives)
            self.tracer.finish_span(root_span, "OK")
            return incident

        allowed = (dsl.override_auto is True or
                   self.policy.allows_auto_remediation(incident))
        if not allowed:
            incident.status = RemediationStatus.ESCALATED
            self.escalation.escalate(incident, snapshot, [], self.audit, self.primitives)
            self.tracer.finish_span(root_span, "OK")
            return incident

        max_att = dsl.max_attempts or self.policy.max_automated_attempts
        with self.tracer.span("remediation_loop", trace_id, root_span.span_id) as rem_span:
            rem_span.set("max_attempts", max_att)
            self._remediation_loop(incident, snapshot, max_att, trace_id, root_span.span_id,
                                  replay_id=replay_id, seed=seed)
            rem_span.set("final_status", incident.status.name)

        # Record to ML classifier on healed incidents
        if (self.ml_classifier and
                incident.status == RemediationStatus.COMMITTED):
            self.ml_classifier.record(event, category)
            self.ml_classifier.maybe_retrain()

        fix_name = self._last_fix_name(incident)
        if fix_name:
            outcome = "success" if incident.status == RemediationStatus.COMMITTED else "failure"
            self.knowledge.ingest(incident, fix_name, outcome)
            self.knowledge.promote_to_registry(fix_name, self.primitives)

        self.adaptive.update(incident)
        self.tracer.finish_span(root_span,
                                "OK" if incident.status == RemediationStatus.COMMITTED else "ERROR")
        return incident

    def _remediation_loop(self, incident: Incident, snapshot: Snapshot,
                          max_attempts: int, trace_id: str, parent_id: str,
                          replay_id: str = "", seed: int = 0) -> None:
        attempts, success = 0, False
        actor = incident.event.actor

        while attempts < max_attempts and not success:
            fix = self.primitives.select(incident, self.learning)

            if fix is None:
                best = self.knowledge.find_best_fix(incident)
                if best:
                    for fixes in self.primitives._store.values():
                        for f in fixes:
                            if f.name == best:
                                fix = f; break
                        if fix: break

            if fix is None:
                fix = self._web_search_fallback(incident)

            if fix is None and self.knowledge._ai_enabled:
                with self.tracer.span("ai_candidate_gen", trace_id, parent_id) as s:
                    fix = self.knowledge.generate_candidate(incident)
                    s.set("generated", fix is not None)

            if fix is None:
                fix = self.exception_handler.handle(incident)

            if fix is None:
                break

            if fix.cost > self.policy.max_cost_per_fix:
                attempts += 1
                continue

            # ── v0.8: Budget check ────────────────────────────────────────
            budget_ok, budget_reason = self.budget.check(fix)
            if not budget_ok:
                self._stats["budget_blocked"] += 1
                self.audit.append("budget_blocked", incident.id, "",
                                  {"fix": fix.name, "budget_reason": budget_reason},
                                  reason=f"budget ceiling reached: {budget_reason}",
                                  seed=seed, replay_id=replay_id)
                log.warning("budget | blocked fix=%s inc=%.8s", fix.name, incident.id)
                attempts += 1
                continue

            # ── v0.8: Canary gate for high-impact fixes ───────────────────
            with self.tracer.span(f"fix_attempt_{attempts}", trace_id, parent_id) as fix_span:
                fix_span.set("fix_name",   fix.name)
                fix_span.set("fix_source", fix.source)
                fix_span.set("fix_impact", fix.impact)

                canary_result = self.canary.gate(fix, incident, snapshot, self)
                fix_span.set("canary_stage",   canary_result.stage_reached)
                fix_span.set("canary_allowed", canary_result.allowed)

                if not canary_result.allowed:
                    self._stats["canary_blocked"] += 1
                    self.audit.append("canary_blocked", incident.id, "",
                                      {"fix": fix.name,
                                       "stage": canary_result.stage_reached,
                                       "canary_reason": canary_result.reason},
                                      reason=f"canary stage {canary_result.stage_reached} "
                                             f"failed: {canary_result.reason}",
                                      seed=seed, replay_id=replay_id)
                    fix_span.set("result", "canary_blocked")
                    attempts += 1
                    continue

                # v0.10: attestation gate for high-impact fixes
                if self.itsm.needs_attestation(fix, incident):
                    atr = self.itsm.request_attestation(incident, fix)
                    # In daemon mode, auto-approve (human approval
                    # requires external workflow; record for audit)
                    self.audit.append('attestation_requested', incident.id, '',
                                      {'fix': fix.name,
                                       'request_id': atr.id if atr else '',
                                       'impact': fix.impact},
                                      reason=f"fix impact {fix.impact:.2f} >= "
                                             f"attestation threshold",
                                      seed=seed, replay_id=replay_id)
                    if atr:
                        self.itsm.approve_attestation(atr.id,'daemon-auto','')

                ratchet_session = self.ratchet.record(incident, fix, snapshot)

                verified, v_detail = self.verifier.run(fix, incident, snapshot)
                if not verified:
                    self.learning.record(incident, fix.name, "verifier_failure", v_detail)
                    self.primitive_registry.record_attempt(
                        fix, incident, "verifier_failure",
                        ratchet_passed=False, replay_id=replay_id)
                    fix_span.set("verifier", "failed")
                    attempts += 1
                    continue

                rr = self.ratchet.run(ratchet_session, fix)
                if not rr.passed:
                    self.learning.record(incident, fix.name, "ratchet_failure", rr.reason)
                    self.primitive_registry.record_attempt(
                        fix, incident, "ratchet_failure",
                        ratchet_passed=False, replay_id=replay_id)
                    fix_span.set("ratchet", "failed")
                    attempts += 1
                    continue

                if self.ratchet.should_promote(ratchet_session):
                    self.ratchet.mark_promoted(ratchet_session)

                applied, a_detail = self.remediation.apply_staged(fix, incident)
                if applied:
                    success = True
                    incident.status = RemediationStatus.COMMITTED
                    self._cooldowns[actor] = time.time()
                    self._last_fix_cache = fix.name
                    self.containment.release(actor)
                    self.learning.record(incident, fix.name, "success")

                    # v0.11: record attempt + check for version promotion
                    was_promoted = fix.promoted_at is not None
                    self.primitives.promote(fix, "success")
                    self.primitive_registry.record_attempt(
                        fix, incident, "success",
                        ratchet_passed=rr.passed, replay_id=replay_id)
                    promo_version = None
                    if fix.promoted_at is not None and not was_promoted:
                        # v0.12: gated promotion
                        if self._gate_config is not None and isinstance(
                                self.primitive_registry,
                                VersionedPrimitiveRegistryWithGate):
                            rec = self.primitive_registry.gate_promote(
                                fix, incident, self, self._gate_config)
                        else:
                            rec = self.primitive_registry.promote(fix, incident)
                        promo_version = rec.version
                        self.audit.append(
                            "primitive_promoted", incident.id, snapshot.id,
                            {"fix": fix.name, "version": rec.version,
                             "ratchet_pass": rec.ratchet_pass,
                             "ratchet_fail": rec.ratchet_fail,
                             "test_count": rec.test_count},
                            reason=f"{fix.name} promoted to v{rec.version} "
                                   f"after {rec.test_count} tests",
                            seed=seed, replay_id=replay_id)

                    self._stats["total_healed"] += 1
                    # ── v0.8: record budget spend on success ──────────────
                    self.budget.record(fix)
                    self.audit.append("heal_success", incident.id, snapshot.id,
                                      {"fix": fix.name, "attempts": attempts+1,
                                       "canary_stage": canary_result.stage_reached,
                                       "trace_id": trace_id,
                                       "primitive_version": promo_version
                                           or self.primitive_registry.current_version(fix.name)},
                                      reason=f"fix '{fix.name}' applied successfully "
                                             f"on attempt {attempts+1}",
                                      seed=seed, replay_id=replay_id)
                    self.telemetry.publish("heal", incident.id, True, {"fix": fix.name})
                    fix_span.set("result", "success")
                    log.info("✓ healed | inc=%.8s  fix=%s  att=%d  canary=%d",
                             incident.id, fix.name, attempts+1,
                             canary_result.stage_reached)
                else:
                    self.remediation.rollback(snapshot)
                    incident.status = RemediationStatus.ROLLED_BACK
                    self.learning.record(incident, fix.name, "failure", a_detail)
                    self.primitive_registry.record_attempt(
                        fix, incident, "failure",
                        ratchet_passed=rr.passed, replay_id=replay_id)
                    self.audit.append("heal_rollback", incident.id, snapshot.id,
                                      {"fix": fix.name, "detail": str(a_detail)[:200]},
                                      reason=f"fix '{fix.name}' apply failed — rolled back",
                                      seed=seed, replay_id=replay_id)
                    fix_span.set("result", "failure")
                    attempts += 1

        if not success:
            incident.status = RemediationStatus.ESCALATED
            cands = self.primitives._store.get(incident.category.name, [])
            self.escalation.escalate(incident, snapshot, cands,
                                     self.audit, self.primitives)
            self.audit.append("heal_failed", incident.id, snapshot.id,
                              {"attempts": attempts, "category": incident.category.name},
                              reason=f"exhausted {attempts} attempt(s) without success",
                              seed=seed, replay_id=replay_id)
            # v0.10: fire ITSM backends on escalation
            self.itsm.dispatch(incident, snapshot, 'heal_failed')
            self.telemetry.publish("escalate", incident.id, False, {"attempts": attempts})
            self._last_fix_cache = ""

    _last_fix_cache: str = ""

    def _last_fix_name(self, incident: Incident) -> str:
        name = getattr(self, "_last_fix_cache", "")
        self._last_fix_cache = ""
        return name

    def _web_search_fallback(self, incident: Incident) -> Optional[RemediationFix]:
        try:
            query = f"{incident.event.error_type} {incident.event.message[:60]} fix"
            url   = ("https://api.duckduckgo.com/?q="
                     + urllib.parse.quote(query) + "&format=json&no_html=1")
            req = urllib.request.Request(url, headers={"User-Agent": "HealingCore/0.8"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = __import__("json").loads(resp.read())
                answer = data.get("AbstractText") or data.get("Answer") or ""
            if answer:
                fix = RemediationFix(
                    name=f"web_{incident.event.error_type}", category=incident.category,
                    description=answer[:200], source="web_search", cost=0.5, impact=0.3,
                    steps=[lambda inc: log.info("[web-fix] %s", answer[:100])])
                self.primitives._store.setdefault(incident.category.name, []).append(fix)
                return fix
        except Exception as exc:
            log.debug("web_search_fallback: %s", exc)
        return None

    def _register_catalogs(self) -> None:
        if OS == "Windows":
            try:
                from drivers.windows_catalog import register_catalog
                register_catalog(self.primitives)
            except Exception as e:
                log.debug("windows_catalog: %s", e)
        elif OS == "Darwin":
            try:
                from drivers.macos_catalog import register_catalog
                register_catalog(self.primitives)
            except Exception as e:
                log.debug("macos_catalog: %s", e)
        else:
            try:
                from drivers.linux_catalog import register_catalog
                register_catalog(self.primitives)
            except Exception as e:
                log.debug("linux_catalog: %s", e)

    # ── Metrics / reports ─────────────────────────────────────────────────────

    def poll_metrics(self) -> Dict[str, Any]:
        m: Dict[str, Any] = {"timestamp": round(time.time(), 2)}
        try:
            import psutil
            m.update({"cpu_pct": psutil.cpu_percent(interval=0.3),
                       "mem_pct": psutil.virtual_memory().percent,
                       "disk_pct": psutil.disk_usage("/").percent})
        except ImportError:
            m["note"] = "install psutil for live metrics"
        m.update({"hc_incidents": self._stats.get("total_incidents", 0),
                  "hc_healed":    self._stats.get("total_healed", 0),
                  "hc_suppressed":self._stats.get("suppressed", 0),
                  "hc_auth_rejected":self._stats.get("auth_rejected", 0),
                  "hc_budget_blocked":self._stats.get("budget_blocked", 0),
                  "hc_canary_blocked":self._stats.get("canary_blocked", 0)})
        return m

    def _prometheus_metrics(self) -> str:
        cs = self.correlator.summary()
        rs = self.ratchet.summary()
        ks = self.knowledge.summary()
        ts = self.tracer.stats()
        bs = self.budget.summary()
        cs2 = self.canary.stats()
        ml_stats = self.ml_classifier.stats() if self.ml_classifier else {}
        lines = [
            f"hc_incidents_total {self._stats.get('total_incidents',0)}",
            f"hc_healed_total {self._stats.get('total_healed',0)}",
            f"hc_suppressed_total {self._stats.get('suppressed',0)}",
            f"hc_auth_rejected_total {self._stats.get('auth_rejected',0)}",
            f"hc_budget_blocked_total {self._stats.get('budget_blocked',0)}",
            f"hc_canary_blocked_total {self._stats.get('canary_blocked',0)}",
            f"hc_correlation_groups {cs['active_groups']}",
            f"hc_ratchet_sessions {rs['total_sessions']}",
            f"hc_ratchet_promoted {rs['promoted']}",
            f"hc_primitives_registered {sum(len(v) for v in self.primitives._store.values())}",
            f"hc_dsl_rules {len(self.dsl._rules)}",
            f"hc_plugins_loaded {sum(1 for m in self.plugin_loader.manifests if m.loaded)}",
            f"hc_knowledge_patterns {ks.get('patterns',0)}",
            f"hc_knowledge_ai_generated {ks.get('ai_generated',0)}",
            f"hc_trace_buffered_spans {ts.get('buffered_spans',0)}",
            f"hc_exception_catalog_entries {len(self.exception_catalog.all_entries())}",
            f"hc_os_fault_entries {len(self.os_fault_catalog.all_entries())}",
            f"hc_synthesized_fixes {self.synthesizer.stats().get('synthesized',0)}",
            f"hc_budget_cost_window {bs['window_cost']}",
            f"hc_budget_impact_window {bs['window_impact']}",
            f"hc_ml_corpus_size {ml_stats.get('corpus_size',0)}",
            f"hc_ml_rate {ml_stats.get('ml_rate',0)}",
            f"hc_itsm_dispatched {self.itsm.stats().get('dispatched',0)}",
            f"hc_itsm_failed {self.itsm.stats().get('failed',0)}",
            f"hc_attestation_pending {self.itsm.stats().get('pending_attestations',0)}",
        ]
        return "\n".join(lines) + "\n"

    def generate_report(self, path: str = "healing_report.html") -> str:
        self.reporter.write(path)
        return path

    def export_grafana(self, path: str = "grafana_healing.json") -> str:
        return self.grafana.export(path)

    def audit_report(self) -> None:
        entries = self.audit.last_n(20)
        print(f"\n{'─'*72}\n  AUDIT TRAIL (last {len(entries)})\n{'─'*72}")
        for e in entries:
            print(f"  {e.get('event_type',''):<30s}  inc={str(e.get('incident_id',''))[:8]}")

    def primitives_report(self) -> None:
        total = sum(len(v) for v in self.primitives._store.values())
        print(f"\n{'─'*72}\n  PRIMITIVES  ({total} total)\n{'─'*72}")
        for cat, fixes in sorted(self.primitives._store.items()):
            for f in fixes:
                print(f"  [{cat:<18s}]  {f.name:<42s}  {f.source}")

    def knowledge_report(self) -> None:
        s = self.knowledge.summary()
        print(f"\n{'─'*72}\n  KNOWLEDGE CORE\n{'─'*72}")
        for k, v in s.items():
            print(f"  {k:<30s}  {v}")
        tops = self.knowledge.top_patterns(5)
        if tops:
            print(f"  {'─'*40}")
            for p in tops:
                print(f"  {p['error_type']:<28s}  fix={p['fix_name']:<30s}  "
                      f"ok={p['success']}  fail={p['failure']}")

    def ml_report(self) -> None:
        if not self.ml_classifier:
            print("  ML classifier disabled")
            return
        s = self.ml_classifier.stats()
        print(f"\n{'─'*72}\n  ML CLASSIFIER\n{'─'*72}")
        for k, v in s.items():
            print(f"  {k:<30s}  {v}")

    def budget_report(self) -> None:
        s = self.budget.summary()
        print(f"\n{'─'*72}\n  BUDGET TRACKER\n{'─'*72}")
        for k, v in s.items():
            print(f"  {k:<30s}  {v}")

    def canary_report(self) -> None:
        s = self.canary.stats()
        print(f"\n{'─'*72}\n  CANARY DEPLOYMENT\n{'─'*72}")
        for k, v in s.items():
            print(f"  {k:<30s}  {v}")

    def exception_report(self) -> None:
        s = self.exception_catalog.summary()
        print(f"\n{'─'*72}\n  EXCEPTION CATALOG\n{'─'*72}")
        print(f"  Total entries: {s['total_entries']}")
        for cat, count in sorted(s['by_category'].items()):
            print(f"  {cat:<22s}  {count}")

    def tracing_report(self) -> None:
        s = self.tracer.stats()
        print(f"\n{'─'*72}\n  TRACING\n{'─'*72}")
        for k, v in s.items():
            print(f"  {k:<28s}  {v}")

    def exception_handler_report(self) -> None:
        s = self.exception_handler.stats()
        hr = "─" * 72
        print(f"\n{hr}\n  ROBUST EXCEPTION HANDLER\n{hr}")
        for k, v in s.items():
            if not isinstance(v, dict):
                print(f"  {k:<30s}  {v}")

    def os_fault_report(self) -> None:
        s = self.os_fault_catalog.summary()
        hr = "─" * 72
        print(f"\n{hr}\n  OS FAULT CATALOG\n{hr}")
        print(f"  Total entries: {s['total_entries']}")
        for cat, count in sorted(s['by_category'].items()):
            print(f"  {cat:<22s}  {count}")

    def ratchet_report(self) -> None:
        s = self.ratchet.summary()
        print(f"\n{'─'*72}\n  RATCHET\n{'─'*72}")
        for k, v in s.items():
            print(f"  {k:<28s}  {v}")

    def dsl_report(self) -> None:
        print(f"\n{'─'*72}\n  DSL RULES\n{'─'*72}")
        for r in self.dsl.rule_stats():
            print(f"  [{r['id']:<32s}]  {r['action']:<28s}  hits={r['hits']}")

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    # ── Log adapter ──────────────────────────────────────────────────────────

    def start_log_adapter(self, **kwargs) -> object:
        """Start the platform-appropriate native event log ingest adapter.

        On Windows: polls Windows Event Log via wevtutil.
        On Linux:   streams journald via journalctl -f --output=json.
        On macOS:   streams Unified Log via log stream --style json.

        kwargs are forwarded to the adapter constructor.
        Returns the started adapter instance.
        """
        if OS == "Windows":
            self._log_adapter = WindowsEvtLogAdapter(self, **kwargs)
        elif OS == "Darwin":
            self._log_adapter = MacosLogAdapter(self, **kwargs)
        else:
            self._log_adapter = JournaldAdapter(self, **kwargs)
        self._log_adapter.start()
        log.info("HealingCore | log adapter started  os=%s", OS)
        return self._log_adapter

    # ── v0.11: cryptographic audit chain / signed checkpoints ────────────────

    def audit_chain_report(self) -> None:
        s = self.audit.chain_summary()
        hr = '─' * 72
        print(f"\n{hr}\n  AUDIT CHAIN (cryptographic provenance)\n{hr}")
        for k, v in s.items():
            print(f"  {k:<22}  {v}")

    def replay_report(self, replay_id: str) -> None:
        entries = self.audit.by_replay_id(replay_id)
        hr = '─' * 72
        print(f"\n{hr}\n  REPLAY {replay_id[:12]}…  ({len(entries)} entries)\n{hr}")
        for e in entries:
            print(f"  {e['event_type']:<22}  seed={e['seed']:<10}  "
                 f"why={e['reason'][:50]}")

    # ── v0.11: versioned primitive registry ───────────────────────────────────

    def primitive_versions_report(self) -> None:
        names = self.primitive_registry.all_versioned_primitives()
        hr = '─' * 72
        print(f"\n{hr}\n  VERSIONED PRIMITIVES  ({len(names)} promoted)\n{hr}")
        for name in names:
            prov = self.primitive_registry.provenance(name)
            if not prov:
                continue
            print(f"  {name:<28}  v{prov['current_version']:<4}  "
                 f"tests={prov['test_count']:<4}  "
                 f"ratchet ok={prov['ratchet_pass']}/"
                 f"{prov['ratchet_pass']+prov['ratchet_fail']}")

    def primitive_provenance(self, name: str) -> Optional[Dict]:
        """Return the full provenance record for one primitive (API-friendly)."""
        return self.primitive_registry.provenance(name)

    # ── v0.11: chaos / fuzz harness ────────────────────────────────────────────

    def run_chaos(self, n_events: int = 100, seed: Optional[int] = None):
        """Run the deterministic chaos harness against this core instance.

        Returns a ChaosReport. If seed is given, a fresh ChaosHarness is
        used with that seed; otherwise self.chaos (seed=42) is reused.
        """
        harness = self.chaos if seed is None else ChaosHarness(seed=seed)
        return harness.run(self, n_events=n_events)

    def run_ci(self, chaos_seeds=None, chaos_events=200):
        """Run full CI gate, return CIResult."""
        gate = CIGate(chaos_seeds=chaos_seeds, chaos_events=chaos_events)
        return gate.run(self)

    def ci_report(self, chaos_seeds=None, chaos_events=200):
        result = self.run_ci(chaos_seeds=chaos_seeds, chaos_events=chaos_events)
        gate   = CIGate(chaos_seeds=chaos_seeds or [42])
        print(gate.format_report(result))
        return result.exit_code

    def chaos_report(self, n_events: int = 100, seed: Optional[int] = None) -> None:
        report = self.run_chaos(n_events=n_events, seed=seed)
        print(report.summary())

    def start_auditd_adapter(self, **kwargs) -> object:
        """Start Linux auditd adapter (only activates on Linux)."""
        self._auditd = AuditdAdapter(self, **kwargs)
        self._auditd.start()
        return self._auditd

    def itsm_report(self) -> None:
        s = self.itsm.stats()
        hr = '─' * 72
        print(f'\n{hr}\n  ITSM DISPATCHER\n{hr}')
        for k, v in s.items():
            print(f'  {k:<32}  {v}')

    def adapter_report(self) -> None:
        if self._log_adapter is None:
            print("  No log adapter started (use --evtlog / --syslog / --macos-log)")
            return
        s = self._log_adapter.stats()
        name = type(self._log_adapter).__name__
        print(f"\n{'─'*72}\n  LOG ADAPTER ({name})\n{'─'*72}")
        for k, v in s.items():
            print(f"  {k:<28}  {v}")

    def shutdown(self) -> None:
        if self._auditd:             self._auditd.stop()
        if self._log_adapter:        self._log_adapter.stop()
        if self.monitor:             self.monitor.stop()
        if self.multi_ai_oracle:     self.multi_ai_oracle.shutdown()
        if self.alertmanager_bridge: self.alertmanager_bridge.stop()
        if self._api:                self._api.stop()
        if self.prometheus:          self.prometheus.stop()
        try: self.audit._conn.close()
        except Exception: pass
        log.info("HealingCore v0.8 shut down.")

    def _handle_sighup(self, signum, frame) -> None:
        log.info("SIGHUP — reloading policy, DSL, plugins")
        self.policy.load()
        self.dsl.load()
        self.plugin_loader.reload_all(self.primitives)

    @staticmethod
    def _configure_drivers(dry_run: bool) -> None:
        import importlib
        for p in ("drivers.linux", "drivers.windows", "drivers.macos"):
            try:
                m = importlib.import_module(p)
                m.DryRun = dry_run
            except ImportError:
                pass
