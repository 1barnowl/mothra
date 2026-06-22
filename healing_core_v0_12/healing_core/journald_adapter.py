"""
healing_core.journald_adapter
──────────────────────────────
JournaldAdapter — streams Linux journal entries and converts them to
healing_core Event objects fed to HealingCore.ingest().

Uses `journalctl -f --output=json --no-pager` subprocess.
No external dependencies beyond stdlib.

Severity mapping (journal PRIORITY field, syslog scale):
  0 emerg / 1 alert / 2 crit → "critical"
  3 err                       → "error"
  4 warning                   → "warning"  (default threshold)
  5 notice / 6 info / 7 debug → skipped unless unit filter matches

Usage:
    adapter = JournaldAdapter(core, priority_threshold=4, units=["nginx","mysql"])
    adapter.start()
    ...
    adapter.stop()
"""
from __future__ import annotations

import json
import logging
import platform
import subprocess
import threading
import time
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

from .models import Event

log = logging.getLogger("healing_core.journald_adapter")

_PRIORITY_MAP = {
    "0": "critical", "1": "critical", "2": "critical",
    "3": "error",
    "4": "warning",
    "5": "notice", "6": "info", "7": "debug",
}

# Syslog facility names → subsystem
_FACILITY_MAP = {
    "0": "kernel",     "3": "system",   "4": "auth",
    "9": "cron",       "10": "auth",    "16": "local0",
}

# Unit patterns that are always interesting regardless of priority
_ALWAYS_INTERESTING = {
    "kernel", "systemd", "sshd", "sudo", "su",
    "firewalld", "auditd", "fail2ban",
}


class JournaldAdapter:
    """Streams journald output and ingests events into HealingCore."""

    def __init__(
        self,
        core: "HealingCore",
        priority_threshold: int = 4,      # 0-7, inclusive upper bound
        units: Optional[List[str]] = None,
        since: str = "now",               # journalctl --since
        rate_limit: int = 100,            # max events per minute
    ) -> None:
        self._core      = core
        self._priority  = priority_threshold
        self._units     = units or []
        self._since     = since
        self._rate_limit = rate_limit
        self._stop      = threading.Event()
        self._thread:   Optional[threading.Thread] = None
        self._proc:     Optional[subprocess.Popen] = None
        self._ingested  = 0
        self._skipped   = 0
        self._errors    = 0
        self._rate_ts:  float = time.time()
        self._rate_cnt: int   = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self) -> None:
        if platform.system() == "Windows":
            log.warning("journald_adapter | not on Linux/macOS, no-op")
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._stream_loop, name="journald", daemon=True)
        self._thread.start()
        log.info("journald_adapter | started  priority≤%d  units=%s",
                 self._priority, self._units or "all")

    def stop(self) -> None:
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        log.info("journald_adapter | stopped  ingested=%d  skipped=%d  errors=%d",
                 self._ingested, self._skipped, self._errors)

    def stats(self) -> dict:
        return {
            "ingested": self._ingested,
            "skipped":  self._skipped,
            "errors":   self._errors,
        }

    # ── Stream loop ────────────────────────────────────────────────────────

    def _stream_loop(self) -> None:
        cmd = ["journalctl", "-f", "--output=json",
               "--no-pager", "--since", self._since]
        for unit in self._units:
            cmd += ["-u", unit]

        while not self._stop.is_set():
            try:
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True, bufsize=1,
                )
                for line in self._proc.stdout:
                    if self._stop.is_set():
                        break
                    if not line.strip():
                        continue
                    evt = self._line_to_event(line)
                    if evt is None:
                        continue
                    if self._rate_check():
                        try:
                            self._core.ingest(evt)
                            self._ingested += 1
                        except Exception as exc:
                            log.debug("journald | ingest error: %s", exc)
                            self._errors += 1
                    else:
                        self._skipped += 1
            except FileNotFoundError:
                log.warning("journald_adapter | journalctl not found")
                return
            except Exception as exc:
                log.debug("journald_adapter | stream error: %s", exc)
                self._errors += 1
                if not self._stop.is_set():
                    time.sleep(5)

    # ── Line → Event ───────────────────────────────────────────────────────

    def _line_to_event(self, line: str) -> Optional[Event]:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        priority = entry.get("PRIORITY", "6")
        try:
            prio_int = int(priority)
        except ValueError:
            prio_int = 6

        unit = (entry.get("_SYSTEMD_UNIT") or
                entry.get("SYSLOG_IDENTIFIER") or
                entry.get("_COMM") or "unknown")
        unit = unit.replace(".service", "")

        # Only ingest if: priority ≤ threshold OR unit is always-interesting
        if prio_int > self._priority and unit not in _ALWAYS_INTERESTING:
            return None

        message = (entry.get("MESSAGE") or "").strip()
        if not message:
            return None

        facility_code = entry.get("SYSLOG_FACILITY", "3")
        subsystem = _FACILITY_MAP.get(str(facility_code), "system")

        pid = entry.get("_PID", "")
        if pid:
            actor = f"{unit}[{pid}]"
        else:
            actor = unit

        error_type = _PRIORITY_MAP.get(priority, "info")
        if prio_int <= 2:
            error_type = "critical_fault"
        elif prio_int == 3:
            error_type = "error"

        # Try to extract a more specific error type from the message
        import re
        m = re.search(r"\b(oom|segfault|panic|failed|timeout|refused|denied|"
                      r"unreachable|crashed|killed|abort|fault)\b",
                      message, re.IGNORECASE)
        if m:
            error_type = m.group(1).lower()

        return Event(
            error_type = error_type,
            message    = message[:512],
            actor      = actor,
            subsystem  = subsystem,
        )

    def _rate_check(self) -> bool:
        """Returns True if we're within rate limit."""
        now = time.time()
        if now - self._rate_ts > 60.0:
            self._rate_ts  = now
            self._rate_cnt = 0
        self._rate_cnt += 1
        return self._rate_cnt <= self._rate_limit
