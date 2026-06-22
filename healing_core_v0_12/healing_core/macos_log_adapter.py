"""
healing_core.macos_log_adapter
────────────────────────────────
MacosLogAdapter — streams macOS Unified Log entries and converts them to
healing_core Event objects fed to HealingCore.ingest().

Uses `log stream --style json --level error` subprocess.
No external dependencies beyond stdlib.

Log levels: default < info < debug < error < fault
We capture error + fault by default (most actionable).

Usage:
    adapter = MacosLogAdapter(core, level="error")
    adapter.start()
    ...
    adapter.stop()
"""
from __future__ import annotations

import json
import logging
import platform
import re
import subprocess
import threading
import time
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

from .models import Event

log = logging.getLogger("healing_core.macos_log_adapter")

# macOS log level → internal severity string
_LEVEL_MAP = {
    "fault":   "critical",
    "error":   "error",
    "default": "warning",
    "info":    "info",
    "debug":   "debug",
}

# Subsystem prefixes we're always interested in
_INTERESTING_SUBSYSTEMS = {
    "com.apple.launchd",
    "com.apple.xpc",
    "com.apple.security",
    "com.apple.network",
    "com.apple.systemd",
    "com.apple.diskmanagement",
    "com.apple.kext",
}


class MacosLogAdapter:
    """Streams macOS Unified Log and ingests events into HealingCore."""

    def __init__(
        self,
        core: "HealingCore",
        level: str = "error",              # error | fault | default | info
        predicate: Optional[str] = None,   # custom log predicate
        processes: Optional[List[str]] = None,
        rate_limit: int = 100,
    ) -> None:
        self._core      = core
        self._level     = level
        self._predicate = predicate
        self._processes = processes or []
        self._rate_limit = rate_limit
        self._stop      = threading.Event()
        self._thread:   Optional[threading.Thread] = None
        self._proc:     Optional[subprocess.Popen] = None
        self._ingested  = 0
        self._skipped   = 0
        self._errors    = 0
        self._rate_ts:  float = time.time()
        self._rate_cnt: int   = 0
        self._buf:      str   = ""          # partial JSON buffer

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self) -> None:
        if platform.system() != "Darwin":
            log.warning("macos_log_adapter | not on macOS, no-op")
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._stream_loop, name="macos-log", daemon=True)
        self._thread.start()
        log.info("macos_log_adapter | started  level=%s", self._level)

    def stop(self) -> None:
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)
        log.info("macos_log_adapter | stopped  ingested=%d  errors=%d",
                 self._ingested, self._errors)

    def stats(self) -> dict:
        return {
            "ingested": self._ingested,
            "skipped":  self._skipped,
            "errors":   self._errors,
        }

    # ── Stream loop ────────────────────────────────────────────────────────

    def _stream_loop(self) -> None:
        cmd = ["log", "stream", "--style", "json", "--level", self._level]
        if self._predicate:
            cmd += ["--predicate", self._predicate]
        for proc in self._processes:
            cmd += ["--process", proc]

        while not self._stop.is_set():
            try:
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True, bufsize=1,
                )
                # `log stream --style json` emits a JSON array incrementally.
                # We buffer and parse objects one at a time.
                for line in self._proc.stdout:
                    if self._stop.is_set():
                        break
                    line = line.strip()
                    if not line:
                        continue
                    # Strip leading array bracket or comma
                    if line in ("[", "]", ","):
                        continue
                    line = line.lstrip(",").strip()
                    evt = self._line_to_event(line)
                    if evt is None:
                        continue
                    if self._rate_check():
                        try:
                            self._core.ingest(evt)
                            self._ingested += 1
                        except Exception as exc:
                            log.debug("macos_log | ingest error: %s", exc)
                            self._errors += 1
                    else:
                        self._skipped += 1

            except FileNotFoundError:
                log.warning("macos_log_adapter | `log` command not found")
                return
            except Exception as exc:
                log.debug("macos_log_adapter | stream error: %s", exc)
                self._errors += 1
                if not self._stop.is_set():
                    time.sleep(5)

    # ── Line → Event ───────────────────────────────────────────────────────

    def _line_to_event(self, line: str) -> Optional[Event]:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        level = (entry.get("messageType") or
                 entry.get("eventType") or "default").lower()

        if level not in ("error", "fault"):
            return None

        message = (entry.get("eventMessage") or "").strip()
        if not message:
            return None

        # Actor: process name + PID
        proc_path = entry.get("processImagePath") or ""
        proc_name = proc_path.split("/")[-1] if proc_path else "unknown"
        pid       = entry.get("processID", "")
        actor     = f"{proc_name}[{pid}]" if pid else proc_name

        # Subsystem
        subsystem = (entry.get("subsystem") or
                     entry.get("category") or "system")

        # error_type: derive from message keywords
        error_type = _LEVEL_MAP.get(level, "error")
        m = re.search(
            r"\b(crash|panic|fault|oom|timeout|refused|denied|unreachable|"
            r"fail|abort|killed|segfault|exception)\b",
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
        now = time.time()
        if now - self._rate_ts > 60.0:
            self._rate_ts  = now
            self._rate_cnt = 0
        self._rate_cnt += 1
        return self._rate_cnt <= self._rate_limit
