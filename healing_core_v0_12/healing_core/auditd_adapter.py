"""
healing_core.auditd_adapter
─────────────────────────────
AuditdAdapter — tails /var/log/audit/audit.log and converts Linux
audit records to healing_core Event objects.

No external dependencies. Falls back gracefully when auditd not running.

Audit record types handled:
  EXECVE / SYSCALL(execve)  → potential malware / unexpected execution
  USER_AUTH / USER_LOGIN    → authentication events
  AVC / SELINUX             → SELinux/AppArmor denials
  SERVICE_START/STOP        → service lifecycle
  NETFILTER_PKT             → firewall drops
  USER_ACCT                 → account changes
  DAEMON_START/END          → auditd state changes
  CRYPTO_FAILURES           → TLS/crypto errors
  CWD / PATH                → file access (with SYSCALL context)

Usage:
    adapter = AuditdAdapter(core, log_path="/var/log/audit/audit.log")
    adapter.start()
    ...
    adapter.stop()
"""
from __future__ import annotations

import logging
import os
import platform
import re
import subprocess
import threading
import time
from typing import Dict, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

from .models import Event

log = logging.getLogger("healing_core.auditd_adapter")

_DEFAULT_LOG = "/var/log/audit/audit.log"

# audit type → (error_type, category_hint)
_TYPE_MAP: Dict[str, Tuple[str, str]] = {
    "USER_AUTH":       ("auth_failure",    "AUTHENTICATION"),
    "USER_LOGIN":      ("auth_login",      "AUTHENTICATION"),
    "USER_LOGOUT":     ("auth_logout",     "AUTHENTICATION"),
    "USER_ACCT":       ("account_change",  "AUTHENTICATION"),
    "ANOM_LOGIN_ACCT": ("auth_failure",    "AUTHENTICATION"),
    "ANOM_LOGIN_FAIL": ("auth_failure",    "AUTHENTICATION"),
    "USER_MGMT":       ("account_change",  "AUTHENTICATION"),
    "CRED_REFUSAL":    ("auth_denial",     "AUTHENTICATION"),
    "AVC":             ("selinux_denial",  "SECURITY"),
    "SELINUX_ERR":     ("selinux_error",   "SECURITY"),
    "APPARMOR_DENIED": ("apparmor_denial", "SECURITY"),
    "SERVICE_START":   ("service_start",   "SERVICE"),
    "SERVICE_STOP":    ("service_stop",    "SERVICE"),
    "DAEMON_START":    ("daemon_start",    "SERVICE"),
    "DAEMON_END":      ("daemon_stop",     "SERVICE"),
    "EXECVE":          ("process_exec",    "SECURITY"),
    "SYSCALL":         ("syscall",         "SECURITY"),
    "NETFILTER_PKT":   ("firewall_drop",   "NETWORK"),
    "CRYPTO_FAILURE":  ("crypto_failure",  "AUTHENTICATION"),
    "CRYPTO_FAILURES": ("crypto_failure",  "AUTHENTICATION"),
    "KERN_MODULE":     ("kernel_module",   "DRIVER"),
    "OBJ_PID":         ("process_change",  "SECURITY"),
    "BPF":             ("bpf_prog_load",   "SECURITY"),
}

# Patterns we skip (too noisy)
_SKIP_TYPES = {"PATH", "CWD", "PROCTITLE", "EOE", "CONFIG_CHANGE",
               "UNKNOWN[1327]", "UNKNOWN[1334]"}


class AuditdAdapter:
    """Tails auditd log and ingests security events into HealingCore."""

    def __init__(
        self,
        core: "HealingCore",
        log_path: str = _DEFAULT_LOG,
        rate_limit: int = 60,          # max events per minute
        interesting_types: Optional[set] = None,
    ) -> None:
        self._core    = core
        self._path    = log_path
        self._rate_limit = rate_limit
        self._itypes  = interesting_types or set(_TYPE_MAP.keys())
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ingested = 0
        self._skipped  = 0
        self._errors   = 0
        self._rate_ts: float = time.time()
        self._rate_cnt: int  = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self) -> None:
        if platform.system() != "Linux":
            log.warning("auditd_adapter | not on Linux, no-op")
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._tail_loop, name="auditd", daemon=True)
        self._thread.start()
        log.info("auditd_adapter | started  path=%s", self._path)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("auditd_adapter | stopped  ingested=%d  skipped=%d",
                 self._ingested, self._skipped)

    def stats(self) -> dict:
        return {
            "path":      self._path,
            "ingested":  self._ingested,
            "skipped":   self._skipped,
            "errors":    self._errors,
        }

    # ── Tail loop ──────────────────────────────────────────────────────────

    def _tail_loop(self) -> None:
        # Seek to end of file first (don't replay old events)
        try:
            offset = os.path.getsize(self._path) if os.path.exists(self._path) else 0
        except OSError:
            offset = 0

        while not self._stop.is_set():
            try:
                if not os.path.exists(self._path):
                    self._stop.wait(5)
                    continue
                with open(self._path, "r", errors="replace") as f:
                    f.seek(offset)
                    while not self._stop.is_set():
                        line = f.readline()
                        if not line:
                            self._stop.wait(1)
                            # Check for log rotation
                            try:
                                if os.path.getsize(self._path) < offset:
                                    offset = 0
                                    break
                            except OSError:
                                break
                            continue
                        offset += len(line.encode("utf-8", errors="replace"))
                        evt = self._parse_line(line.strip())
                        if evt and self._rate_check():
                            try:
                                self._core.ingest(evt)
                                self._ingested += 1
                            except Exception as exc:
                                log.debug("auditd | ingest error: %s", exc)
                                self._errors += 1
                        elif evt:
                            self._skipped += 1
            except PermissionError:
                log.warning("auditd_adapter | permission denied reading %s "
                            "(run as root or add user to adm/audit group)",
                            self._path)
                self._stop.wait(30)
            except Exception as exc:
                log.debug("auditd_adapter | tail error: %s", exc)
                self._errors += 1
                self._stop.wait(5)

    # ── Line → Event ───────────────────────────────────────────────────────

    def _parse_line(self, line: str) -> Optional[Event]:
        if not line.startswith("type="):
            return None

        # Extract type
        m = re.match(r"type=(\S+)", line)
        if not m:
            return None
        atype = m.group(1)

        if atype in _SKIP_TYPES:
            return None
        if atype not in self._itypes:
            return None

        fields = self._parse_fields(line)
        error_type, _ = _TYPE_MAP.get(atype, (atype.lower(), "UNKNOWN"))

        # Determine actor
        actor = (fields.get("comm") or
                 fields.get("exe", "").split("/")[-1] or
                 fields.get("id") or
                 fields.get("acct") or
                 "audit")
        actor = actor.strip('"')

        # Build message
        msg_parts = []

        if atype == "AVC":
            denied  = fields.get("denied", "?")
            path    = fields.get("path", fields.get("name", "?")).strip('"')
            scontext= fields.get("scontext", "?")
            tcontext= fields.get("tcontext", "?")
            msg_parts.append(f"SELinux denied={denied} path={path} "
                             f"scontext={scontext} tcontext={tcontext}")

        elif atype in ("USER_AUTH", "ANOM_LOGIN_FAIL", "ANOM_LOGIN_ACCT"):
            acct   = fields.get("acct", "?").strip('"')
            res    = fields.get("res", "?")
            addr   = fields.get("addr", "?")
            msg_parts.append(f"auth acct={acct} res={res} addr={addr}")
            if res == "failed":
                error_type = "auth_failure"

        elif atype in ("SERVICE_START", "SERVICE_STOP"):
            unit = fields.get("unit", actor).strip('"')
            msg_parts.append(f"service unit={unit} {atype.lower()}")
            actor = unit

        elif atype == "EXECVE":
            argv = " ".join(
                v.strip('"') for k, v in fields.items() if k.startswith("a")
            )
            msg_parts.append(f"execve: {argv[:200]}")

        elif atype == "NETFILTER_PKT":
            saddr = fields.get("saddr", "?")
            dport = fields.get("dport", "?")
            proto = fields.get("proto", "?")
            msg_parts.append(f"firewall drop saddr={saddr} dport={dport} proto={proto}")

        elif atype == "CRYPTO_FAILURE":
            op  = fields.get("op", "?")
            res = fields.get("res", "?")
            msg_parts.append(f"crypto op={op} res={res}")

        else:
            # Generic: include first 5 interesting fields
            skip = {"type", "msg", "arch", "syscall", "success",
                    "exit", "a0", "a1", "a2", "a3", "items", "ppid",
                    "pid", "auid", "uid", "gid", "euid", "suid", "fsuid",
                    "egid", "sgid", "fsgid", "tty", "ses", "key"}
            parts = [f"{k}={v}" for k, v in fields.items()
                     if k not in skip][:5]
            if parts:
                msg_parts.append(" ".join(parts))

        message = f"{atype}: " + ("; ".join(msg_parts) or line[40:200])

        return Event(
            error_type = error_type,
            message    = message[:512],
            actor      = actor[:64],
            subsystem  = "audit",
        )

    # ── Field parser ───────────────────────────────────────────────────────

    @staticmethod
    def _parse_fields(line: str) -> Dict[str, str]:
        """Parse audit record fields into a dict."""
        fields: Dict[str, str] = {}
        # Remove type= prefix and msg= timestamp
        text = re.sub(r"^type=\S+\s+msg=audit\(\S+\):\s*", "", line)
        for m in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', text):
            fields[m.group(1)] = m.group(2)
        return fields

    def _rate_check(self) -> bool:
        now = time.time()
        if now - self._rate_ts > 60.0:
            self._rate_ts  = now
            self._rate_cnt = 0
        self._rate_cnt += 1
        return self._rate_cnt <= self._rate_limit
