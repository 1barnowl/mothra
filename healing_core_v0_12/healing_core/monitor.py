"""
healing_core.monitor
────────────────────
HealthMonitor — continuously samples runtime health signals and injects
Events into HealingCore when thresholds are breached.

Guide mandate:
  "continuously samples runtime health signals (scheduler ticks,
   allocation/I-O errors, model divergence, verification results,
   and scheduler metrics) and runs lightweight anomaly classifiers"

Key design choices:
  • Hysteresis bands per metric — prevents alert flapping (must go below
    recovery_pct before re-triggering)
  • Confidence calibration — only fires after N consecutive breaching
    samples (false-positive management)
  • Per-source signing — every generated event is signed by EventAuthenticator
  • Pluggable collectors — register custom metric functions at runtime
"""
from __future__ import annotations

import logging
import platform
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

log = logging.getLogger("healing_core.monitor")

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

OS = platform.system()


# ── Threshold config ──────────────────────────────────────────────────────────

@dataclass
class MonitorThresholds:
    cpu_warn:          float = 80.0   # %
    cpu_crit:          float = 95.0
    cpu_recovery:      float = 60.0   # below this → can re-trigger
    mem_warn:          float = 80.0
    mem_crit:          float = 92.0
    mem_recovery:      float = 65.0
    disk_warn:         float = 85.0
    disk_crit:         float = 95.0
    disk_recovery:     float = 75.0
    net_err_rate:      float = 0.05   # fraction of packets with errors
    swap_warn:         float = 70.0
    swap_crit:         float = 90.0
    proc_count_warn:   int   = 500
    fd_warn:           int   = 10000  # open file descriptors
    poll_interval_s:   float = 5.0
    confirmation_runs: int   = 2      # samples above threshold before firing


@dataclass
class MetricSample:
    name:      str
    value:     float
    unit:      str
    source:    str
    timestamp: float = field(default_factory=time.time)
    breaching: bool  = False
    severity:  str   = "info"   # info | warn | crit


# ── HealthMonitor ─────────────────────────────────────────────────────────────

class HealthMonitor:
    """
    Background daemon thread that polls system metrics and injects
    events into HealingCore when anomalies are detected.
    """

    def __init__(
        self,
        thresholds:     Optional[MonitorThresholds] = None,
        custom_collectors: List[Callable[[], List[MetricSample]]] = None,
    ) -> None:
        self.thresholds  = thresholds or MonitorThresholds()
        self._collectors: List[Callable] = list(custom_collectors or [])
        self._core: Optional["HealingCore"] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()

        # Hysteresis: metric_name → currently_firing (bool)
        self._firing: Dict[str, bool]   = defaultdict(bool)
        # Confidence: metric_name → deque of (timestamp, breaching)
        self._window: Dict[str, deque]  = defaultdict(lambda: deque(maxlen=10))
        # History for trend analysis
        self._history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=60))

    def start(self, core: "HealingCore") -> None:
        self._core = core
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="hc-monitor"
        )
        self._thread.start()
        log.info("monitor | started  interval=%.1fs", self.thresholds.poll_interval_s)

    def stop(self) -> None:
        self._stop_evt.set()

    def add_collector(self, fn: Callable[[], List[MetricSample]]) -> None:
        """Register a custom metric collector function."""
        self._collectors.append(fn)

    def latest_snapshot(self) -> Dict[str, Any]:
        """Return the latest sample for every tracked metric."""
        return {k: list(v)[-1] if v else None for k, v in self._history.items()}

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                samples = self._collect()
                for sample in samples:
                    self._evaluate(sample)
            except Exception as exc:
                log.warning("monitor | poll error: %s", exc)
            self._stop_evt.wait(self.thresholds.poll_interval_s)

    # ── Collection ────────────────────────────────────────────────────────────

    def _collect(self) -> List[MetricSample]:
        samples: List[MetricSample] = []
        if _PSUTIL:
            samples += self._psutil_samples()
        for collector in self._collectors:
            try:
                samples += collector()
            except Exception as e:
                log.debug("monitor | custom collector error: %s", e)
        return samples

    def _psutil_samples(self) -> List[MetricSample]:
        out: List[MetricSample] = []
        t = self.thresholds

        # CPU
        cpu = psutil.cpu_percent(interval=0.1)
        out.append(MetricSample("cpu_pct", cpu, "%", "psutil",
                                breaching=cpu >= t.cpu_warn,
                                severity="crit" if cpu >= t.cpu_crit else "warn"))

        # Memory
        mem = psutil.virtual_memory()
        out.append(MetricSample("mem_pct", mem.percent, "%", "psutil",
                                breaching=mem.percent >= t.mem_warn,
                                severity="crit" if mem.percent >= t.mem_crit else "warn"))

        # Disk (root partition)
        try:
            disk = psutil.disk_usage("/")
            pct  = disk.percent
            out.append(MetricSample("disk_pct", pct, "%", "psutil",
                                    breaching=pct >= t.disk_warn,
                                    severity="crit" if pct >= t.disk_crit else "warn"))
        except Exception:
            pass

        # Swap
        swap = psutil.swap_memory()
        if swap.total > 0:
            out.append(MetricSample("swap_pct", swap.percent, "%", "psutil",
                                    breaching=swap.percent >= t.swap_warn,
                                    severity="crit" if swap.percent >= t.swap_crit else "warn"))

        # Process count
        proc_count = len(psutil.pids())
        out.append(MetricSample("proc_count", proc_count, "procs", "psutil",
                                breaching=proc_count >= t.proc_count_warn,
                                severity="warn"))

        # Network errors
        try:
            net = psutil.net_io_counters()
            total_pkts = net.packets_sent + net.packets_recv
            if total_pkts > 0:
                err_rate = (net.errin + net.errout + net.dropin + net.dropout) / total_pkts
                out.append(MetricSample("net_err_rate", err_rate, "rate", "psutil",
                                        breaching=err_rate >= t.net_err_rate,
                                        severity="warn"))
        except Exception:
            pass

        # Open file descriptors (Linux only)
        if OS == "Linux":
            try:
                fds = sum(p.num_fds() for p in psutil.process_iter(["num_fds"]) if p.info["num_fds"])
                out.append(MetricSample("open_fds", fds, "fds", "psutil",
                                        breaching=fds >= t.fd_warn,
                                        severity="warn"))
            except Exception:
                pass

        # Per-process top offenders (injected as signals, not events)
        try:
            top_cpu = sorted(psutil.process_iter(["pid", "name", "cpu_percent"]),
                             key=lambda p: p.info.get("cpu_percent") or 0, reverse=True)[:3]
            for p in top_cpu:
                if (p.info.get("cpu_percent") or 0) > 50:
                    out.append(MetricSample(
                        f"proc_cpu_{p.info['name']}", p.info.get("cpu_percent", 0),
                        "%", "psutil", breaching=True, severity="warn"
                    ))
        except Exception:
            pass

        return out

    # ── Evaluation + event injection ─────────────────────────────────────────

    def _evaluate(self, sample: MetricSample) -> None:
        key = sample.name
        self._history[key].append((sample.timestamp, sample.value))
        self._window[key].append(sample.breaching)

        # Confidence: require confirmation_runs consecutive breaches
        window = list(self._window[key])
        n      = self.thresholds.confirmation_runs
        confirmed = len(window) >= n and all(window[-n:])

        currently_firing = self._firing[key]

        if confirmed and not currently_firing:
            # Rising edge — fire event
            self._firing[key] = True
            self._inject_event(sample)

        elif currently_firing and not sample.breaching:
            # Check recovery (hysteresis)
            recovery = self._recovery_threshold(key)
            if sample.value < recovery:
                self._firing[key] = False
                log.debug("monitor | %s recovered (%.1f < %.1f)", key, sample.value, recovery)

    def _inject_event(self, sample: MetricSample) -> None:
        if self._core is None:
            return
        error_type, message = self._map_to_event(sample)
        from .models import Event
        event = Event(
            actor      = "health_monitor",
            subsystem  = "system",
            error_type = error_type,
            message    = message,
        )
        log.warning("monitor | ▶ injecting event  metric=%s  val=%.2f  sev=%s",
                    sample.name, sample.value, sample.severity)
        self._core.ingest(event)

    def _map_to_event(self, sample: MetricSample) -> Tuple[str, str]:
        t = self.thresholds
        mapping = {
            "cpu_pct":    ("cpu_overload",      f"CPU at {sample.value:.1f}% (threshold {t.cpu_warn}%)"),
            "mem_pct":    ("memory_depletion",  f"Memory at {sample.value:.1f}% (threshold {t.mem_warn}%)"),
            "disk_pct":   ("disk_full",         f"Disk at {sample.value:.1f}% (threshold {t.disk_warn}%)"),
            "swap_pct":   ("swap_exhausted",    f"Swap at {sample.value:.1f}% (threshold {t.swap_warn}%)"),
            "proc_count": ("excessive_processes",f"Process count {sample.value:.0f} (threshold {t.proc_count_warn})"),
            "net_err_rate":("network_errors",   f"Network error rate {sample.value:.3f} (threshold {t.net_err_rate})"),
            "open_fds":   ("fd_exhaustion",     f"Open FDs {sample.value:.0f} (threshold {t.fd_warn})"),
        }
        # Per-process entries
        if sample.name.startswith("proc_cpu_"):
            proc = sample.name.split("proc_cpu_", 1)[-1]
            return "cpu_overload", f"Process {proc!r} consuming {sample.value:.1f}% CPU"
        return mapping.get(sample.name, ("unknown_metric", f"{sample.name}={sample.value:.2f}"))

    def _recovery_threshold(self, key: str) -> float:
        t = self.thresholds
        return {
            "cpu_pct":    t.cpu_recovery,
            "mem_pct":    t.mem_recovery,
            "disk_pct":   t.disk_recovery,
            "swap_pct":   50.0,
            "net_err_rate": 0.01,
        }.get(key, 0.0)
