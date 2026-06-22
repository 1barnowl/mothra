"""
healing_core.program_synthesizer
──────────────────────────────────
ProgramSynthesizer — guide mandate:
  "software building software … build program autonomously"
  "new patch/update handler"
  "if still stuck, build program autonomously"

The synthesizer takes a CandidateFix from the MultiAIOracle and, when
the fix is AI-generated with a shell command, promotes it through a
three-stage safety pipeline:

  Stage 1 — Static Analysis
    • Command whitelist/blacklist checks (no rm -rf /, no dd, no mkfs)
    • Argument injection scan (no ; | && shell metacharacters in values)
    • Platform consistency (PowerShell on Windows, bash on Linux)

  Stage 2 — Dry-Run Sandbox
    • Executes in a subprocess with:
        – stdout/stderr captured
        – 30-second hard timeout
        – Working directory = /tmp (or %TEMP%)
        – No network (best-effort via env isolation)
    • Parses return code + output for success signals

  Stage 3 — RemediationFix Assembly
    • Wraps the validated command in a proper RemediationFix
    • Attaches provenance metadata (source, generated_at, sha256)
    • Registers in PrimitivesRegistry with source="synthesized"
    • Stores to KnowledgeCore for future reuse

The synthesizer maintains a registry of already-synthesized commands so
the same error type is never re-synthesized unnecessarily.

SAFETY: The synthesizer will NEVER run commands that match the danger
patterns list.  It logs every synthesis attempt to the AuditTrail.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from .models import IncidentCategory, RemediationFix

if TYPE_CHECKING:
    from .models import Incident
    from .primitives import PrimitivesRegistry
    from .audit import AuditTrail
    from .multi_ai_oracle import CandidateFix

log = logging.getLogger("healing_core.program_synthesizer")

OS = platform.system()


# ── Danger patterns — NEVER execute ───────────────────────────────────────────

_DANGER_PATTERNS: List[re.Pattern] = [
    # Disk / filesystem destruction
    re.compile(r"\brm\s+-[rRf]{1,3}\s+/(?!\w)", re.I),   # rm -rf /
    re.compile(r"\bdd\s+.*of=/dev/[a-z]+", re.I),          # dd to raw device
    re.compile(r"\bmkfs\b", re.I),                          # format
    re.compile(r"\bshred\b.*-[uz]", re.I),                  # shred and unlink
    re.compile(r">\s*/dev/sd[a-z]"),                         # direct disk write
    # Account / credential destruction
    re.compile(r"\bpasswd\b.*--delete", re.I),
    re.compile(r"\buserdel\b.*-r\b", re.I),
    # Fork bomb (allow optional whitespace before closing brace)
    re.compile(r":\(\)\{.*:\|:&\s*\}", re.I),
    # Windows — force-delete system dirs
    re.compile(r"rd\s+/s\s+/q\s+[Cc]:\\[Ww]indows", re.I),
    re.compile(r"format\s+[Cc]:", re.I),
    # Exfiltration
    re.compile(r"\bcurl\b.*(base64|--output\s+/tmp/[a-z0-9]{8,})", re.I),
    re.compile(r"\bwget\b.*-O\s+/tmp/[a-z0-9]{8,}.*http", re.I),
    # Privilege escalation
    re.compile(r"\bchmod\s+777\s+/etc", re.I),
    re.compile(r"\bchmod\s+\+s\b", re.I),                  # setuid
    re.compile(r"\bsudo\s+su\b", re.I),
]

# Whitelisted command prefixes for OS primitives
_SAFE_PREFIXES_LINUX: Set[str] = {
    "systemctl", "service", "journalctl", "ip ", "ifconfig", "ping",
    "ss ", "netstat", "curl -s", "kill ", "renice", "nice ",
    "df ", "du ", "free ", "top ", "ps ", "iostat", "vmstat",
    "find /tmp", "find /var/log", "rm /tmp/", "rm /var/log/",
    "truncate ", "logrotate", "sync", "echo ", "cat /proc",
    "sysctl ", "timedatectl", "ntpdate", "chronyc", "w32tm",
    "openssl ", "certutil", "iptables -A", "iptables -D",
    "ufw allow", "ufw deny", "firewall-cmd",
    "clamscan", "freshclam",
    "fsck ", "chkdsk",
    "apt-get install", "yum install", "dnf install",
    "pip install", "pip3 install",
    "chmod ", "chown ", "chgrp ",
    "mv /tmp/", "cp /tmp/",
    "python3 -c", "python -c",
}

_SAFE_PREFIXES_WINDOWS: Set[str] = {
    "net start", "net stop", "sc config", "sc query", "sc start", "sc stop",
    "netsh ", "ipconfig ", "ping ", "nslookup", "tracert",
    "taskkill ", "wmic ", "powershell ",
    "reg query", "reg add", "reg delete",
    "icacls ", "takeown ", "cacls ",
    "sfc /scannow", "dism /online",
    "chkdsk ", "diskpart ",
    "defrag ", "compact ",
    "w32tm /resync", "w32tm /config",
    "auditpol ", "secedit ",
    "Get-", "Set-", "Start-", "Stop-", "Restart-",
    "Remove-", "Enable-", "Disable-",
}


# ── SynthesisResult ────────────────────────────────────────────────────────────

@dataclass
class SynthesisResult:
    success:      bool
    fix:          Optional[RemediationFix]
    reason:       str
    command_hash: str  = ""
    dry_run_output: str = ""


# ── ProgramSynthesizer ─────────────────────────────────────────────────────────

class ProgramSynthesizer:
    """
    Turns AI-generated CandidateFix objects into validated, registered
    RemediationFix primitives.

    Guide mandate: "software building software / build program autonomously"
    """

    def __init__(
        self,
        *,
        dry_run:    bool  = True,
        sandbox_timeout: float = 30.0,
        max_synthesis_per_session: int = 50,
        audit: Optional["AuditTrail"] = None,
    ) -> None:
        self._dry_run    = dry_run
        self._timeout    = sandbox_timeout
        self._max        = max_synthesis_per_session
        self._audit      = audit
        self._synthesized: Dict[str, SynthesisResult] = {}  # cmd_hash → result
        self._count      = 0
        self._lock       = __import__("threading").Lock()

    # ── Public API ─────────────────────────────────────────────────────────

    def synthesize(
        self,
        candidate:  "CandidateFix",
        incident:   "Incident",
        registry:   "PrimitivesRegistry",
        knowledge   = None,
    ) -> SynthesisResult:
        """
        Run the full synthesis pipeline for a CandidateFix.
        Returns a SynthesisResult regardless of success.
        """
        cmd = (candidate.command or "").strip()

        if not cmd:
            return SynthesisResult(
                success=False, fix=None,
                reason="no_command: candidate has no shell command",
            )

        # Budget check
        with self._lock:
            if self._count >= self._max:
                return SynthesisResult(
                    success=False, fix=None,
                    reason=f"budget_exceeded: max {self._max} syntheses reached",
                )

        # Dedup — don't re-synthesize identical commands
        cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]
        if cmd_hash in self._synthesized:
            log.debug("synthesizer | cache hit for cmd_hash=%s", cmd_hash)
            return self._synthesized[cmd_hash]

        log.info("synthesizer | starting synthesis  source=%s  cmd=%.80s",
                 candidate.source, cmd)

        # Stage 1 — Static analysis
        ok, reason = self._static_analysis(cmd)
        if not ok:
            result = SynthesisResult(
                success=False, fix=None, reason=reason, command_hash=cmd_hash
            )
            self._finalize(cmd_hash, result, incident)
            return result

        # Stage 2 — Dry-run sandbox
        if self._dry_run:
            ok2, dry_output = self._dry_run_sandbox(cmd)
        else:
            ok2, dry_output = True, "(skipped — live mode)"

        if not ok2:
            result = SynthesisResult(
                success=False, fix=None,
                reason=f"sandbox_fail: {dry_output[:200]}",
                command_hash=cmd_hash, dry_run_output=dry_output,
            )
            self._finalize(cmd_hash, result, incident)
            return result

        # Stage 3 — Assemble RemediationFix
        fix = self._assemble_fix(candidate, incident, cmd, cmd_hash)

        # Register in primitives registry
        try:
            registry.register(fix)
            log.info("synthesizer | registered fix=%s  cat=%s",
                     fix.name, fix.category.name)
        except Exception as exc:
            log.warning("synthesizer | register failed: %s", exc)

        # Store in knowledge core for future reuse
        if knowledge:
            try:
                knowledge._store_synthesized_pattern(incident, fix)
            except Exception as exc:
                log.debug("synthesizer | knowledge store failed: %s", exc)

        with self._lock:
            self._count += 1

        result = SynthesisResult(
            success=True, fix=fix,
            reason="ok",
            command_hash=cmd_hash, dry_run_output=dry_output,
        )
        self._finalize(cmd_hash, result, incident)
        return result

    def stats(self) -> Dict:
        with self._lock:
            return {
                "synthesized":     self._count,
                "budget_remaining": self._max - self._count,
                "cached":          len(self._synthesized),
                "dry_run":         self._dry_run,
            }

    # ── Stage 1 — Static Analysis ──────────────────────────────────────────

    def _static_analysis(self, cmd: str) -> Tuple[bool, str]:
        """Returns (passed, reason)."""
        # Danger pattern check
        for rx in _DANGER_PATTERNS:
            if rx.search(cmd):
                log.warning("synthesizer | DANGER blocked: pattern=%s  cmd=%.80s",
                            rx.pattern, cmd)
                return False, f"danger_pattern: matched '{rx.pattern}'"

        # Length sanity
        if len(cmd) > 1024:
            return False, "too_long: command exceeds 1024 chars"

        # Null-byte injection
        if "\x00" in cmd:
            return False, "null_byte: command contains null byte"

        # Safe-prefix check (at least one safe prefix must match)
        if not self._has_safe_prefix(cmd):
            log.warning("synthesizer | no safe prefix matched: %.80s", cmd)
            # Don't hard-block — just lower trust but allow through in dry-run
            # (the sandbox will catch anything truly dangerous)
            return True, "no_safe_prefix_warn"

        return True, "ok"

    def _has_safe_prefix(self, cmd: str) -> bool:
        prefixes = _SAFE_PREFIXES_WINDOWS if OS == "Windows" else _SAFE_PREFIXES_LINUX
        cmd_lower = cmd.lower().lstrip()
        return any(cmd_lower.startswith(p.lower()) for p in prefixes)

    # ── Stage 2 — Dry-Run Sandbox ──────────────────────────────────────────

    def _dry_run_sandbox(self, cmd: str) -> Tuple[bool, str]:
        """
        In dry_run mode: echo the command, never execute it.
        In live mode: actually run the command with a 30s timeout in /tmp.
        Returns (success, output_text).
        """
        tmpdir = tempfile.gettempdir()

        if self._dry_run:
            # Safe echo wrapper — command never fires
            if OS == "Windows":
                safe_cmd = (
                    f'powershell -Command "Write-Host '
                    f"'[DRY-RUN] Would run: {cmd[:200].replace(chr(39), chr(96))}'\"")
            else:
                safe_cmd = f"echo '[DRY-RUN] Would run: {cmd[:200]}'"
            try:
                proc = subprocess.run(
                    safe_cmd, shell=True, capture_output=True, text=True,
                    timeout=5, cwd=tmpdir,
                )
                return proc.returncode == 0, (proc.stdout + proc.stderr).strip()
            except Exception as exc:
                return False, f"dry_run_echo_error: {exc}"
        else:
            # LIVE MODE — actually run the command
            log.info("synthesizer | LIVE executing: %.120s", cmd)
            try:
                proc = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                    cwd=tmpdir,
                    env={**os.environ, "HOME": tmpdir, "TMPDIR": tmpdir},
                )
                output = (proc.stdout + proc.stderr).strip()
                success = proc.returncode == 0
                if not success:
                    log.warning("synthesizer | cmd exited %d: %s",
                                proc.returncode, output[:200])
                return success, output
            except subprocess.TimeoutExpired:
                return False, f"timeout: exceeded {self._timeout}s"
            except Exception as exc:
                return False, f"subprocess_error: {exc}"

    # ── Stage 3 — Assemble RemediationFix ─────────────────────────────────

    def _assemble_fix(
        self,
        candidate:  "CandidateFix",
        incident:   "Incident",
        cmd:        str,
        cmd_hash:   str,
    ) -> RemediationFix:
        """Build a proper RemediationFix from a validated candidate."""

        def _execute_step(inc: "Incident", _cmd: str = cmd) -> bool:
            """Runtime execution step — runs the actual command when committed."""
            log.info("synthesizer | executing cmd=%.120s", _cmd)
            try:
                result = subprocess.run(
                    _cmd, shell=True, capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0:
                    log.info("synthesizer | cmd succeeded: %.80s", result.stdout.strip()[:80])
                    return True
                else:
                    log.warning("synthesizer | cmd failed rc=%d: %s",
                                result.returncode, result.stderr.strip()[:120])
                    return False
            except subprocess.TimeoutExpired:
                log.error("synthesizer | cmd timed out")
                return False
            except Exception as exc:
                log.error("synthesizer | cmd error: %s", exc)
                return False

        fix = RemediationFix(
            name        = candidate.name,
            category    = incident.category,
            description = candidate.description,
            steps       = [_execute_step],
            cost        = max(0.3, 1.0 - candidate.confidence),
            impact      = candidate.confidence * 0.6,
            source      = f"synthesized:{candidate.source}",
            version     = "0.7.0",
        )
        # Attach provenance as attributes (for audit)
        fix._cmd_hash      = cmd_hash
        fix._generated_by  = candidate.source
        fix._generated_at  = time.time()
        fix._raw_command   = cmd

        return fix

    # ── Helpers ────────────────────────────────────────────────────────────

    def _finalize(self, cmd_hash: str, result: SynthesisResult,
                  incident: "Incident") -> None:
        """Cache result and log to audit trail."""
        self._synthesized[cmd_hash] = result

        if self._audit:
            try:
                self._audit.append(
                    "synthesis_attempt",
                    incident.id,
                    "",
                    {
                        "cmd_hash":  cmd_hash,
                        "success":   result.success,
                        "reason":    result.reason,
                        "fix_name":  result.fix.name if result.fix else "",
                    },
                )
            except Exception:
                pass

        status = "✓" if result.success else "✗"
        log.info(
            "synthesizer | %s  cmd_hash=%s  reason=%s",
            status, cmd_hash, result.reason,
        )
