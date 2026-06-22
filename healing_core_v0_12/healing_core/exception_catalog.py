"""
healing_core.exception_catalog
───────────────────────────────
ExceptionCatalog — structured taxonomy of Python and system exceptions
with remediation hints, category mappings, and detection patterns.

Guide mandate:
  "exception tree — exception list and data on each Exception"
  "exception analysis for everything in list"
  "Robust exception handler — web search for solution / redirect to related module"

The catalog enables the classifier to give precise categories to Python
tracebacks and OS-level errors, and gives the knowledge core a head start
on remediation without needing AI generation.

Usage:
    catalog = ExceptionCatalog()
    entry   = catalog.lookup("MemoryError: unable to allocate 8GB")
    # → ExceptionEntry(category=RESOURCE, fix_hints=[...], severity=CRITICAL)

    # Enrich event before ingestion
    event = catalog.enrich_event(event)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import IncidentCategory, Severity


@dataclass
class ExceptionEntry:
    exception_class:  str
    parent_class:     str
    category:         IncidentCategory
    severity:         Severity
    description:      str
    common_causes:    List[str]
    fix_hints:        List[str]      # ordered by likelihood
    fix_primitive:    str            # preferred primitive name
    patterns:         List[str]      # regex patterns for message matching
    platform:         str = "all"    # all | linux | windows | python


_E = ExceptionEntry   # shorthand


def _make_catalog() -> List[ExceptionEntry]:
    R  = IncidentCategory.RESOURCE
    S  = IncidentCategory.SERVICE
    N  = IncidentCategory.NETWORK
    C  = IncidentCategory.CONFIGURATION
    SC = IncidentCategory.SECURITY
    A  = IncidentCategory.AUTHENTICATION
    H  = IncidentCategory.HARDWARE
    D  = IncidentCategory.DEPENDENCY
    TR = IncidentCategory.TRANSIENT
    SE = IncidentCategory.SEMANTIC
    DR = IncidentCategory.DRIVER
    ML = IncidentCategory.MALWARE
    UK = IncidentCategory.UNKNOWN

    LO = Severity.LOW
    ME = Severity.MEDIUM
    HI = Severity.HIGH
    CR = Severity.CRITICAL

    return [
        # ── Memory ────────────────────────────────────────────────────────────
        _E("MemoryError",          "Exception",     R,  CR,
           "Python could not allocate requested memory",
           ["Memory leak in application", "RSS approaching system limit",
            "Competing processes exhausting RAM"],
           ["Kill top memory consumer", "Drop OS page cache",
            "Increase swap space", "Restart service"],
           "drop_caches",
           [r"MemoryError", r"cannot allocate memory", r"out of memory",
            r"oom.?kill", r"kill process.*oom"]),

        _E("OverflowError",        "ArithmeticError", R, ME,
           "Integer or float overflow in arithmetic",
           ["Counter wrapping without reset", "Unbounded accumulator"],
           ["Check accumulator for unbounded growth", "Add overflow guard"],
           "restart_service",
           [r"OverflowError", r"integer overflow", r"value too large"]),

        # ── I/O ───────────────────────────────────────────────────────────────
        _E("IOError",              "OSError",       R,  HI,
           "I/O operation failed",
           ["Disk full", "Disk failure", "Permissions", "File locked"],
           ["Check disk space", "Check disk health (SMART)", "Reset file permissions"],
           "clear_temp",
           [r"IOError", r"Errno 28", r"No space left", r"Input/output error",
            r"EIO\b"]),

        _E("FileNotFoundError",    "OSError",       C,  ME,
           "Required file or directory does not exist",
           ["Config file deleted", "Wrong working directory", "Race condition"],
           ["Restore config from backup", "Check path configuration"],
           "restore_config_from_backup",
           [r"FileNotFoundError", r"No such file or directory",
            r"ENOENT", r"cannot open.*no such"]),

        _E("PermissionError",      "OSError",       C,  HI,
           "File system permission denied",
           ["Wrong file owner", "Restrictive ACL", "SELinux/AppArmor policy"],
           ["Reset file permissions (icacls / chmod)", "Take ownership",
            "Check SELinux context"],
           "reset_file_permissions",
           [r"PermissionError", r"EACCES", r"Permission denied",
            r"Access is denied"]),

        _E("IsADirectoryError",    "OSError",       C,  LO,
           "Expected file but found directory",
           ["Misconfigured path", "Symlink pointing wrong"],
           ["Fix path configuration", "Remove erroneous directory"],
           "restore_config_from_backup",
           [r"IsADirectoryError", r"EISDIR"]),

        _E("BlockingIOError",      "OSError",       S,  ME,
           "Non-blocking I/O operation would block",
           ["Socket buffer full", "Slow consumer"],
           ["Restart service", "Increase socket buffer size"],
           "restart_service",
           [r"BlockingIOError", r"EAGAIN", r"EWOULDBLOCK", r"Resource temporarily unavailable"]),

        _E("BrokenPipeError",      "OSError",       S,  ME,
           "Broken pipe — reader closed before writer finished",
           ["Client disconnected early", "Upstream service restarted"],
           ["Restart service", "Add retry logic"],
           "restart_service",
           [r"BrokenPipeError", r"EPIPE", r"Broken pipe"]),

        _E("ConnectionRefusedError","OSError",      N,  HI,
           "Network connection refused by remote host",
           ["Target service down", "Wrong port", "Firewall block"],
           ["Restart target service", "Check firewall rules", "Verify port config"],
           "restart_service",
           [r"ConnectionRefusedError", r"ECONNREFUSED", r"Connection refused",
            r"No connection could be made"]),

        _E("ConnectionResetError", "OSError",       N,  ME,
           "Connection reset by peer",
           ["Server crash", "Network interruption", "Idle timeout"],
           ["Restart service", "Check network stability"],
           "restart_service",
           [r"ConnectionResetError", r"ECONNRESET", r"Connection reset by peer"]),

        _E("TimeoutError",         "OSError",       N,  ME,
           "Operation timed out",
           ["Slow network", "Overloaded server", "Deadlock"],
           ["Check network latency", "Restart service", "Increase timeout setting"],
           "flush_dns",
           [r"TimeoutError", r"ETIMEDOUT", r"timed out", r"deadline exceeded",
            r"connection timeout"]),

        _E("SSLError",             "OSError",       A,  HI,
           "SSL/TLS handshake or certificate error",
           ["Expired certificate", "Clock skew > 5 min", "CA bundle out of date"],
           ["Sync system clock (NTP)", "Renew TLS certificate", "Update CA bundle"],
           "sync_time",
           [r"SSLError", r"SSL:", r"certificate.*expired", r"CERTIFICATE_VERIFY_FAILED",
            r"ssl.SSLCertVerification"]),

        _E("gaierror",             "OSError",       N,  HI,
           "DNS address resolution failed",
           ["DNS server down", "Missing record", "Network partition"],
           ["Flush DNS cache", "Set alternate DNS server"],
           "flush_dns",
           [r"gaierror", r"Name or service not known",
            r"getaddrinfo failed", r"nodename nor servname provided"]),

        # ── OS / process ──────────────────────────────────────────────────────
        _E("OSError",              "Exception",     S,  ME,
           "Generic OS-level error",
           ["System call failure", "Resource exhaustion"],
           ["Check system logs", "Restart service"],
           "restart_service",
           [r"\[Errno \d+\]", r"OSError:"]),

        _E("ProcessLookupError",   "OSError",       S,  LO,
           "Target process does not exist (already exited)",
           ["Race condition between check and signal"],
           ["Restart service"],
           "restart_service",
           [r"ProcessLookupError", r"ESRCH", r"No such process"]),

        _E("ChildProcessError",    "OSError",       S,  ME,
           "Child process error or zombie",
           ["Uncollected zombie processes", "Fork bomb"],
           ["Restart parent service", "Kill zombie processes"],
           "restart_service",
           [r"ChildProcessError", r"ECHILD", r"No child processes"]),

        # ── Python runtime ────────────────────────────────────────────────────
        _E("RecursionError",       "RuntimeError",  SE, HI,
           "Maximum recursion depth exceeded",
           ["Infinite recursive call", "Circular data structure"],
           ["Restart service", "Check for circular references in code"],
           "restart_service",
           [r"RecursionError", r"maximum recursion depth exceeded"]),

        _E("RuntimeError",         "Exception",     S,  ME,
           "Generic runtime error",
           ["Unhandled application state", "Thread safety violation"],
           ["Restart service", "Check application logs"],
           "restart_service",
           [r"RuntimeError:"]),

        _E("AssertionError",       "Exception",     SE, ME,
           "Assertion failed — invariant violated",
           ["Data corruption", "Unexpected state", "Logic bug"],
           ["Restart service", "Check for data corruption"],
           "restart_service",
           [r"AssertionError", r"assert.*failed"]),

        _E("SystemExit",           "BaseException", S,  ME,
           "Explicit sys.exit() or clean shutdown request",
           ["Graceful shutdown", "Init system stopping service"],
           ["Check if shutdown was intentional", "Restart service if unintended"],
           "restart_service",
           [r"SystemExit"]),

        _E("KeyboardInterrupt",    "BaseException", S,  LO,
           "SIGINT received (Ctrl-C or kill -2)",
           ["Manual interrupt", "Init system SIGINT"],
           ["Restart service"],
           "restart_service",
           [r"KeyboardInterrupt"]),

        # ── Import / module ───────────────────────────────────────────────────
        _E("ImportError",          "Exception",     C,  HI,
           "Failed to import a Python module",
           ["Missing package", "Wrong Python version", "Broken virtualenv"],
           ["Install missing package (pip install)", "Check Python environment"],
           "restore_config_from_backup",
           [r"ImportError", r"ModuleNotFoundError", r"No module named",
            r"cannot import name"]),

        _E("ModuleNotFoundError",  "ImportError",   C,  HI,
           "Specific module not found",
           ["Package not installed", "Wrong PYTHONPATH"],
           ["pip install <package>", "Check PYTHONPATH"],
           "restore_config_from_backup",
           [r"ModuleNotFoundError", r"No module named '[^']+'"]),

        # ── Data / encoding ───────────────────────────────────────────────────
        _E("UnicodeDecodeError",   "ValueError",    C,  ME,
           "Cannot decode bytes as Unicode",
           ["Binary file read as text", "Wrong encoding assumed"],
           ["Fix encoding in config/code", "Restart service"],
           "restore_config_from_backup",
           [r"UnicodeDecodeError", r"codec can't decode", r"invalid start byte"]),

        _E("json.JSONDecodeError", "ValueError",    C,  ME,
           "Malformed JSON input",
           ["Config file truncated", "API returned HTML error page"],
           ["Restore config from backup", "Check API health"],
           "restore_config_from_backup",
           [r"JSONDecodeError", r"json.decoder", r"Expecting value",
            r"Unterminated string"]),

        _E("ValueError",           "Exception",     C,  LO,
           "Inappropriate value for operation",
           ["Config value out of range", "Data validation failure"],
           ["Check config values", "Restore from backup"],
           "restore_config_from_backup",
           [r"ValueError:"]),

        # ── Database ──────────────────────────────────────────────────────────
        _E("OperationalError",     "DatabaseError", S,  HI,
           "Database operational error (connection, lock, disk)",
           ["DB connection dropped", "Disk full", "Lock timeout"],
           ["Restart database service", "Check disk space"],
           "restart_service",
           [r"OperationalError", r"database is locked",
            r"FATAL:.*connection", r"could not connect to server"]),

        _E("IntegrityError",       "DatabaseError", SE, HI,
           "Database integrity constraint violated",
           ["Duplicate key", "Foreign key violation", "Data corruption"],
           ["Check for data corruption", "Restart service"],
           "restart_service",
           [r"IntegrityError", r"UNIQUE constraint", r"FOREIGN KEY constraint",
            r"Duplicate entry"]),

        # ── System-level errno (Linux/Windows) ────────────────────────────────
        _E("ENOSPC",               "errno",         R,  CR,
           "No space left on device (errno 28)",
           ["Disk full"],
           ["Clear temp files", "Compress logs", "Extend disk"],
           "clear_temp",
           [r"Errno 28", r"ENOSPC", r"No space left on device",
            r"disk quota exceeded"],
           platform="linux"),

        _E("ENOMEM",               "errno",         R,  CR,
           "Cannot allocate memory (errno 12)",
           ["OOM kill imminent", "Memory leak"],
           ["Drop caches", "Kill high-mem process", "Restart service"],
           "drop_caches",
           [r"Errno 12", r"ENOMEM", r"Cannot allocate memory"],
           platform="linux"),

        _E("ECONNREFUSED",         "errno",         N,  HI,
           "Connection refused (errno 111)",
           ["Target service not running", "Wrong port"],
           ["Restart target service", "Check port config"],
           "restart_service",
           [r"Errno 111", r"ECONNREFUSED"],
           platform="linux"),

        _E("WSAECONNREFUSED",      "errno",         N,  HI,
           "Connection refused (Windows 10061)",
           ["Service not listening", "Firewall block"],
           ["Start service", "Allow port in Windows Firewall"],
           "restart_service",
           [r"10061", r"WSAECONNREFUSED"],
           platform="windows"),
    ]


# ── ExceptionCatalog ──────────────────────────────────────────────────────────

class ExceptionCatalog:
    """
    Looks up exception entries by class name or message pattern.
    Enriches Events with category + fix hints before ingestion.
    """

    def __init__(self) -> None:
        self._entries = _make_catalog() + _make_windows_entries() + _make_macos_entries()
        self._by_class: Dict[str, ExceptionEntry] = {
            e.exception_class: e for e in self._entries
        }
        # Pre-compile patterns
        self._patterns: List[Tuple[re.Pattern, ExceptionEntry]] = [
            (re.compile(p, re.IGNORECASE), entry)
            for entry in self._entries
            for p in entry.patterns
        ]

    def lookup(self, text: str) -> Optional[ExceptionEntry]:
        """Find the best matching ExceptionEntry for a message string."""
        # Class name exact match first
        for cls_name, entry in self._by_class.items():
            if cls_name in text:
                return entry
        # Pattern scan
        for rx, entry in self._patterns:
            if rx.search(text):
                return entry
        return None

    def lookup_by_class(self, class_name: str) -> Optional[ExceptionEntry]:
        return self._by_class.get(class_name)

    def enrich_event(self, event_dict: dict) -> dict:
        """
        Given an event dict, improve error_type and add fix_hints
        if message matches a known exception pattern.
        """
        text = f"{event_dict.get('error_type','')} {event_dict.get('message','')}"
        entry = self.lookup(text)
        if entry:
            event_dict.setdefault("_catalog_category",  entry.category.name)
            event_dict.setdefault("_catalog_fix_hint",  entry.fix_primitive)
            event_dict.setdefault("_catalog_severity",  entry.severity.name)
            event_dict.setdefault("_catalog_causes",    entry.common_causes[:2])
        return event_dict

    def category_for(self, text: str) -> Optional[IncidentCategory]:
        e = self.lookup(text)
        return e.category if e else None

    def fix_primitive_for(self, text: str) -> Optional[str]:
        e = self.lookup(text)
        return e.fix_primitive if e else None

    def all_entries(self) -> List[ExceptionEntry]:
        return list(self._entries)

    def summary(self) -> Dict:
        from collections import Counter
        cats = Counter(e.category.name for e in self._entries)
        return {
            "total_entries": len(self._entries),
            "by_category":   dict(cats),
        }


def _make_windows_entries():
    """Windows-specific exception entries appended to the catalog."""
    R  = IncidentCategory.RESOURCE
    S  = IncidentCategory.SERVICE
    N  = IncidentCategory.NETWORK
    C  = IncidentCategory.CONFIGURATION
    SC = IncidentCategory.SECURITY
    A  = IncidentCategory.AUTHENTICATION
    H  = IncidentCategory.HARDWARE
    D  = IncidentCategory.DEPENDENCY
    TR = IncidentCategory.TRANSIENT
    SE = IncidentCategory.SEMANTIC
    DR = IncidentCategory.DRIVER
    ML = IncidentCategory.MALWARE

    LO = Severity.LOW
    ME = Severity.MEDIUM
    HI = Severity.HIGH
    CR = Severity.CRITICAL

    return [
        # ── Win32 OS errors (OSError with WinError codes) ─────────────────────
        _E("OSError[WinError 5]",    "OSError",  C,  HI,
           "Access is denied (ERROR_ACCESS_DENIED)",
           ["Insufficient privileges", "File/registry ACL blocks access",
            "UAC blocking elevation"],
           ["icacls /grant", "takeown", "Run as administrator", "gpupdate /force"],
           "reset_file_permissions",
           [r"WinError 5\b", r"Access is denied", r"0x80070005",
            r"ERROR_ACCESS_DENIED", r"access denied"],
           platform="windows"),

        _E("OSError[WinError 32]",   "OSError",  S,  ME,
           "File locked by another process (ERROR_SHARING_VIOLATION)",
           ["Another process holds an exclusive handle",
            "Antivirus scanning the file"],
           ["taskkill conflicting process", "Restart service", "Antivirus exclusion"],
           "restart_service",
           [r"WinError 32\b", r"sharing.violation", r"0x80070020",
            r"ERROR_SHARING_VIOLATION", r"used by another process"],
           platform="windows"),

        _E("OSError[WinError 2]",    "OSError",  C,  ME,
           "File or directory not found (ERROR_FILE_NOT_FOUND)",
           ["Path deleted or renamed", "Drive not mapped",
            "Config points to wrong location"],
           ["Restore from backup", "Fix config path", "Remap drive"],
           "restore_config_from_backup",
           [r"WinError 2\b", r"0x80070002", r"ERROR_FILE_NOT_FOUND",
            r"cannot find the file specified"],
           platform="windows"),

        _E("OSError[WinError 3]",    "OSError",  C,  ME,
           "Path not found (ERROR_PATH_NOT_FOUND)",
           ["Directory structure missing", "Drive letter changed"],
           ["Recreate directory", "Fix config path"],
           "restore_config_from_backup",
           [r"WinError 3\b", r"0x80070003", r"ERROR_PATH_NOT_FOUND",
            r"cannot find the path specified"],
           platform="windows"),

        _E("OSError[WinError 1060]", "OSError",  S,  HI,
           "Service does not exist (ERROR_SERVICE_DOES_NOT_EXIST)",
           ["Service uninstalled", "Wrong service name"],
           ["Reinstall service", "Verify service name with sc query"],
           "repair_system_files",
           [r"WinError 1060\b", r"0x8007041c", r"ERROR_SERVICE_DOES_NOT_EXIST",
            r"specified service does not exist"],
           platform="windows"),

        _E("OSError[WinError 1061]", "OSError",  S,  ME,
           "Service not in runnable state (ERROR_SERVICE_NOT_ACTIVE)",
           ["Service is stopped or in a transition state"],
           ["net start ServiceName", "sc start ServiceName"],
           "restart_service",
           [r"WinError 1061\b", r"0x8007041d", r"ERROR_SERVICE_NOT_ACTIVE",
            r"service has not been started"],
           platform="windows"),

        _E("OSError[WinError 1067]", "OSError",  S,  CR,
           "Service process terminated (ERROR_PROCESS_ABORTED)",
           ["Service process crashed during startup",
            "Missing dependency DLL"],
           ["Check Event ID 7034", "sfc /scannow", "Reinstall service"],
           "repair_system_files",
           [r"WinError 1067\b", r"0x8007042b", r"ERROR_PROCESS_ABORTED",
            r"process terminated unexpectedly"],
           platform="windows"),

        _E("OSError[WinError 1722]", "OSError",  N,  HI,
           "RPC server unavailable (RPC_S_SERVER_UNAVAILABLE)",
           ["RpcSs service stopped", "Firewall blocking RPC ports 135/49152+",
            "Network connectivity lost"],
           ["net start RpcSs", "Allow RPC in firewall", "Restart networking"],
           "restart_service",
           [r"WinError 1722\b", r"0x800706ba", r"RPC_S_SERVER_UNAVAILABLE",
            r"rpc server is unavailable", r"RPC.*unavailable"],
           platform="windows"),

        _E("OSError[WinError 1784]", "OSError",  H,  HI,
           "Invalid user buffer - disk/memory error",
           ["Bad sector on disk", "Faulty RAM"],
           ["chkdsk /r", "Memory diagnostic"],
           "chkdsk",
           [r"WinError 1784\b", r"0x800706f0", r"invalid user buffer"],
           platform="windows"),

        # ── Windows network (WSAE*) ────────────────────────────────────────────
        _E("WSAENETUNREACH",  "OSError",  N,  HI,
           "Network unreachable (WSAENETUNREACH)",
           ["No route to destination", "Network interface down"],
           ["ipconfig /release /renew", "netsh winsock reset", "Check gateway"],
           "reset_network_stack",
           [r"WSAENETUNREACH", r"10051", r"network.*unreachable"],
           platform="windows"),

        _E("WSAETIMEDOUT",    "OSError",  TR, ME,
           "Connection timed out (WSAETIMEDOUT)",
           ["Remote host not responding", "Firewall silently dropping packets"],
           ["Ping host", "Check firewall rules", "Increase timeout"],
           "allow_firewall_port",
           [r"WSAETIMEDOUT", r"10060", r"connection.*timed.out"],
           platform="windows"),

        _E("WSAEHOSTUNREACH", "OSError",  N,  HI,
           "Host unreachable (WSAEHOSTUNREACH)",
           ["No route to host", "Remote host offline"],
           ["ping -4 host", "tracert host", "Check routing table"],
           "reset_network_stack",
           [r"WSAEHOSTUNREACH", r"10065", r"host.*unreachable"],
           platform="windows"),

        _E("WSAEADDRINUSE",   "OSError",  N,  ME,
           "Port already in use (WSAEADDRINUSE)",
           ["Another process bound to the port"],
           ["netstat -ano | findstr :PORT", "taskkill conflicting process",
            "Change service port"],
           "kill_process",
           [r"WSAEADDRINUSE", r"10048", r"address.*already.*in.*use",
            r"only.*one.*usage.*each.*socket.*address"],
           platform="windows"),

        _E("WSAECONNABORTED", "OSError",  N,  ME,
           "Connection aborted (WSAECONNABORTED)",
           ["Keep-alive timeout", "Network error"],
           ["Retry connection", "Increase keep-alive interval"],
           "restart_service",
           [r"WSAECONNABORTED", r"10053", r"connection.*aborted"],
           platform="windows"),

        # ── Windows COM / registry ────────────────────────────────────────────
        _E("pywintypes.error",       "Exception", S,  ME,
           "Win32 API error raised via pywin32",
           ["Windows API call failed", "Permissions issue", "Invalid handle"],
           ["Check WinError code in args[0]", "Run as administrator"],
           "reset_file_permissions",
           [r"pywintypes\.error", r"com_error", r"HRESULT", r"hr ="],
           platform="windows"),

        _E("HRESULT E_ACCESSDENIED", "Exception", C,  HI,
           "COM/DCOM access denied (0x80070005)",
           ["DCOM permissions", "UAC", "Firewall blocking DCOM"],
           ["dcomcnfg - set launch permissions", "gpupdate /force"],
           "update_group_policy",
           [r"0x80070005", r"E_ACCESSDENIED", r"Access.*denied.*DCOM",
            r"EventID.?10016"],
           platform="windows"),

        _E("HRESULT E_FAIL",         "Exception", S,  HI,
           "Unspecified COM failure (0x80004005)",
           ["COM server crash", "Missing type library"],
           ["Reinstall application", "Re-register COM component"],
           "repair_system_files",
           [r"0x80004005", r"E_FAIL", r"unspecified error"],
           platform="windows"),

        # ── Windows Update ────────────────────────────────────────────────────
        _E("WindowsUpdateError",     "Exception", C,  ME,
           "Windows Update failed to install",
           ["Corrupted SoftwareDistribution folder", "BITS service stopped",
            "Disk space low"],
           ["net stop wuauserv", "rd /s SoftwareDistribution", "net start wuauserv",
            "Ensure 2GB free disk space"],
           "repair_system_files",
           [r"WindowsUpdate\.log", r"0x80070643", r"0x8024.*",
            r"0x80240017", r"Update.*fail", r"KB\d+ install.*fail"],
           platform="windows"),

        # ── .NET managed exceptions ───────────────────────────────────────────
        _E("System.UnauthorizedAccessException", "Exception", C, HI,
           ".NET access denied — usually mirrors Win32 access denied",
           ["Process lacks NTFS permissions", "Running without elevation"],
           ["icacls /grant", "Run as administrator"],
           "reset_file_permissions",
           [r"UnauthorizedAccessException", r"System\.UnauthorizedAccess"],
           platform="windows"),

        _E("System.IO.IOException",  "Exception", S,  ME,
           ".NET I/O error — disk, network share, or pipe failure",
           ["Disk full", "Network share lost", "File locked"],
           ["Check disk space", "Restart service", "Verify share access"],
           "chkdsk",
           [r"System\.IO\.IOException", r"IOException.*Windows"],
           platform="windows"),

        _E("System.ComponentModel.Win32Exception", "Exception", C, ME,
           ".NET wrapping of a Win32 error code",
           ["Varies by NativeErrorCode"],
           ["Check NativeErrorCode field", "Elevate process", "Fix ACLs"],
           "reset_file_permissions",
           [r"Win32Exception", r"NativeErrorCode"],
           platform="windows"),

        _E("System.ServiceProcess.TimeoutException", "Exception", S, HI,
           ".NET service start/stop timed out",
           ["Service startup too slow", "Dependency not ready"],
           ["sc config start= delayed-auto", "Increase timeout via registry"],
           "set_service_delayed",
           [r"ServiceProcess.*TimeoutException", r"service.*did not respond.*timely"],
           platform="windows"),

        # ── Windows Event Log native entries ──────────────────────────────────
        _E("EventID_7034",           "WinEvent",  S,  CR,
           "Service terminated unexpectedly (Event ID 7034)",
           ["Service crash", "Missing DLL", "Bad configuration"],
           ["Restart service", "sfc /scannow", "Check Application event log"],
           "restart_service",
           [r"EventID.?7034", r"Event ID 7034", r"terminated unexpectedly"],
           platform="windows"),

        _E("EventID_7023",           "WinEvent",  S,  HI,
           "Service stopped with error (Event ID 7023)",
           ["Service stopped due to internal error"],
           ["net start ServiceName", "Check service error code"],
           "restart_service",
           [r"EventID.?7023", r"Event ID 7023", r"service.*stopped.*error"],
           platform="windows"),

        _E("EventID_4625",           "WinEvent",  A,  HI,
           "Account logon failed (Event ID 4625)",
           ["Wrong password", "Account locked", "Kerberos failure"],
           ["Unlock account", "Reset password", "Check logon type"],
           "enable_account",
           [r"EventID.?4625", r"Event ID 4625", r"logon.*failure",
            r"account.*failed.*log.?on"],
           platform="windows"),

        _E("EventID_4740",           "WinEvent",  A,  HI,
           "Account locked out (Event ID 4740)",
           ["Too many failed logon attempts", "Cached credentials incorrect"],
           ["Unlock account", "Clear cached credentials", "Reset password"],
           "enable_account",
           [r"EventID.?4740", r"Event ID 4740", r"account.*locked.?out"],
           platform="windows"),

        _E("EventID_1001",           "WinEvent",  S,  CR,
           "Application crash dump (Event ID 1001 / WER)",
           ["Application fault", "Heap corruption", "Stack overflow"],
           ["Restart application", "Update application", "Run sfc /scannow"],
           "repair_system_files",
           [r"EventID.?1001", r"Event ID 1001", r"Windows Error Reporting",
            r"Fault.*module", r"faulting.*application"],
           platform="windows"),

        _E("EventID_41",             "WinEvent",  H,  CR,
           "System rebooted without clean shutdown (Event ID 41)",
           ["Power loss", "BSOD", "Kernel hang"],
           ["Check UPS", "Review minidump in C:\\Windows\\Minidump",
            "Run memory diagnostic"],
           "chkdsk",
           [r"EventID.?41\b", r"Event ID 41\b", r"unexpected.reboot",
            r"did not shut.?down.*cleanly"],
           platform="windows"),
    ]


def _make_macos_entries():
    """macOS-specific exception entries."""
    R  = IncidentCategory.RESOURCE
    S  = IncidentCategory.SERVICE
    N  = IncidentCategory.NETWORK
    C  = IncidentCategory.CONFIGURATION
    SC = IncidentCategory.SECURITY
    A  = IncidentCategory.AUTHENTICATION
    H  = IncidentCategory.HARDWARE
    D  = IncidentCategory.DEPENDENCY
    TR = IncidentCategory.TRANSIENT
    ML = IncidentCategory.MALWARE
    DR = IncidentCategory.DRIVER

    LO = Severity.LOW
    ME = Severity.MEDIUM
    HI = Severity.HIGH
    CR = Severity.CRITICAL

    return [
        # ── launchd / launchctl ───────────────────────────────────────────
        _E("launchd.ThrottleInterval", "launchd", S, HI,
           "launchd throttling service respawn — crashing too fast",
           ["Service crashing faster than ThrottleInterval allows",
            "Missing dependency", "Bad plist configuration"],
           ["launchctl kickstart -k", "Check Console.app logs",
            "diskutil verifyVolume /"],
           "restart_service",
           [r"ThrottleInterval", r"launchd.*throttl", r"respawn.*too fast",
            r"Job appears to have crashed", r"com\.apple\.launchd.*respawn"],
           platform="macos"),

        _E("launchd.PlistInvalid", "launchd", C, HI,
           "Invalid launchd plist — service will not load",
           ["Malformed XML in .plist", "Missing required keys",
            "Wrong permissions on plist file"],
           ["plutil -lint /path/to/plist", "launchctl load -w plist",
            "chmod 644 plist"],
           "restore_config_from_backup",
           [r"plist.*invalid", r"malformed.*plist", r"plutil.*error",
            r"Could not import.*plist", r"Invalid property list"],
           platform="macos"),

        _E("launchd.SocketActivationFail", "launchd", S, ME,
           "launchd socket activation failed for service",
           ["Port already in use", "Firewall blocking socket"],
           ["launchctl kickstart -k", "Check port conflicts"],
           "restart_service",
           [r"socket.*activation.*fail", r"launchd.*socket.*fail",
            r"bind.*EADDRINUSE.*launchd"],
           platform="macos"),

        # ── macOS Security Framework ──────────────────────────────────────
        _E("SecKeychainItemNotFound", "Security", A, ME,
           "Keychain item not found — credentials missing",
           ["Keychain locked", "Item deleted", "Wrong keychain"],
           ["security unlock-keychain", "security find-generic-password",
            "Keychain First Aid via Keychain Access.app"],
           "reset_account_password",
           [r"SecKeychainItemNotFound", r"-25300\b", r"errSecItemNotFound",
            r"keychain.*item.*not.*found"],
           platform="macos"),

        _E("SecKeychainCorrupt", "Security", A, HI,
           "Keychain database corrupted",
           ["Sudden power loss during write", "Disk error"],
           ["mv ~/Library/Keychains ~/Library/Keychains.bak",
            "Restart — macOS creates new default keychain"],
           "repair_system_files",
           [r"SecKeychainCorrupt", r"keychain.*corrupt", r"-25307\b",
            r"errSecKeychainNotAvailable", r"Keychain.*corrupted"],
           platform="macos"),

        _E("SecTrustEvaluationFailed", "Security", A, HI,
           "TLS/SSL certificate trust evaluation failed",
           ["Self-signed cert", "Root CA not trusted", "Clock skew"],
           ["security add-trusted-cert", "sntp -sS pool.ntp.org",
            "security verify-cert"],
           "update_cert",
           [r"SecTrustEvaluationFailed", r"errSSLXCertChainInvalid",
            r"certificate.*trust.*fail", r"-9812\b", r"kCFStreamErrorDomainSSL",
            r"trust evaluation failed", r"CSSMERR_TP_CERT_EXPIRED"],
           platform="macos"),

        _E("TCC.Denied", "Security", SC, ME,
           "TCC privacy/permission denied (camera, mic, disk, etc.)",
           ["App not granted permission in Privacy settings",
            "System Integrity Protection blocking access"],
           ["System Preferences → Security & Privacy → grant permission",
            "tccutil reset All com.example.app"],
           "reset_file_permissions",
           [r"TCC.*denied", r"NSPrivacy.*denied", r"kTCCServiceCamera",
            r"kTCCServiceMicrophone", r"kTCCServiceSystemPolicyAllFiles",
            r"access.*Privacy.*permission", r"This app is not allowed"],
           platform="macos"),

        _E("Gatekeeper.Block", "Security", SC, ME,
           "Gatekeeper blocked app execution",
           ["App not code-signed", "Quarantine flag set",
            "App from unidentified developer"],
           ["xattr -d com.apple.quarantine /path/to/app",
            "spctl --assess --verbose app"],
           "reset_file_permissions",
           [r"Gatekeeper.*block", r"quarantine.*block",
            r"com\.apple\.quarantine", r"not from.*identified developer",
            r"damaged and can.t be opened", r"spctl.*reject"],
           platform="macos"),

        # ── APFS / HFS+ Disk ─────────────────────────────────────────────
        _E("APFS.VolumeCorrupt", "IOKit", H, CR,
           "APFS volume corruption detected",
           ["Sudden power loss", "Hardware fault", "Bad sectors"],
           ["diskutil repairVolume /", "fsck_apfs -n disk1s1",
            "First Aid in Disk Utility"],
           "repair_disk",
           [r"APFS.*corrupt", r"apfs.*error", r"fsck_apfs.*fail",
            r"volume.*corrupt.*APFS", r"IOMediaBSDClient.*error",
            r"disk.*I\/O.*error.*APFS"],
           platform="macos"),

        _E("NSFileHandleOperationException", "Foundation", R, ME,
           "NSFileHandle read/write error — disk full or permission denied",
           ["Disk full", "File locked", "Network share dropped"],
           ["df -h", "diskutil info /", "clear ~/Library/Caches"],
           "get_disk_usage",
           [r"NSFileHandleOperationException",
            r"NSFileHandleError.*domain", r"NSPOSIXErrorDomain.*28\b",
            r"No space left on device.*NSFileHandle"],
           platform="macos"),

        # ── Network ───────────────────────────────────────────────────────
        _E("CFNetworkError.DNSFail", "CFNetwork", N, HI,
           "CFNetwork DNS resolution failure",
           ["DNS server unreachable", "VPN blocking DNS", "mDNSResponder crash"],
           ["sudo killall -HUP mDNSResponder",
            "networksetup -setdnsservers Wi-Fi 1.1.1.1",
            "dscacheutil -flushcache"],
           "flush_dns",
           [r"CFNetworkErrors.*kCFURLErrorDNSLookupFailed",
            r"NSURLErrorDomain.*-1003\b",
            r"A server with the specified hostname could not be found",
            r"nw_resolver.*failed", r"mDNSResponder.*crash"],
           platform="macos"),

        _E("NEVPNError.Connect", "NetworkExtension", N, HI,
           "VPN connection failure",
           ["Invalid credentials", "Server unreachable",
            "VPN profile misconfigured"],
           ["networksetup -disconnectpppoeservice",
            "Delete and re-add VPN profile"],
           "reset_network_stack",
           [r"NEVPNError", r"NEVPNConnectionFailed",
            r"VPN.*connection.*fail", r"networkd.*vpn.*fail"],
           platform="macos"),

        _E("NSURL.Timeout", "Foundation", TR, ME,
           "NSURLConnection/URLSession request timed out",
           ["Remote server slow/down", "Network congestion"],
           ["Check network connectivity", "ping host", "retry"],
           "flush_dns",
           [r"NSURLErrorTimedOut", r"NSURLErrorDomain.*-1001\b",
            r"The request timed out", r"kCFURLErrorTimedOut"],
           platform="macos"),

        # ── Crash types ───────────────────────────────────────────────────
        _E("EXC_BAD_ACCESS", "Mach", S, CR,
           "Process received EXC_BAD_ACCESS (SIGSEGV/SIGBUS) — crash",
           ["Null pointer dereference", "Buffer overflow",
            "Use-after-free", "Heap corruption"],
           ["Restart process", "Check Console.app for crash report",
            "Update application"],
           "restart_service",
           [r"EXC_BAD_ACCESS", r"SIGSEGV", r"SIGBUS",
            r"Crashed Thread.*EXC_BAD_ACCESS",
            r"Exception Type:.*EXC_BAD_ACCESS"],
           platform="macos"),

        _E("EXC_CRASH_SIGABRT", "Mach", S, CR,
           "Process aborted (SIGABRT) — assertion or fatal error",
           ["Failed assertion", "Uncaught exception",
            "Stack overflow", "Memory corruption"],
           ["Restart process", "Check crash report in ~/Library/Logs/DiagnosticReports"],
           "restart_service",
           [r"EXC_CRASH.*SIGABRT", r"SIGABRT",
            r"Exception Type:.*EXC_CRASH",
            r"abort\(\) called", r"Abort trap: 6"],
           platform="macos"),

        _E("NSException.Unhandled", "Foundation", S, CR,
           "Unhandled Objective-C exception — app crash",
           ["Uncaught NSException", "Invalid collection mutation",
            "Index out of bounds"],
           ["Restart app", "Update application", "Check crash logs"],
           "restart_service",
           [r"NSInternalInconsistencyException",
            r"NSRangeException", r"NSInvalidArgumentException",
            r"Terminating app due to uncaught exception",
            r"\*\*\* Terminating app"],
           platform="macos"),

        # ── XPC / IPC ─────────────────────────────────────────────────────
        _E("XPC.ServiceCrash", "XPC", S, HI,
           "XPC service crashed or connection interrupted",
           ["XPC service process crashed", "entitlement mismatch"],
           ["launchctl kickstart -k system/com.service",
            "Check Console.app for xpc errors"],
           "restart_service",
           [r"xpc.*crash", r"XPC.*connection.*interrupted",
            r"XPCService.*died", r"remote.*object.*proxy.*error",
            r"NSXPCConnectionInterrupted",
            r"xpc_connection_call_event_handler.*XPC_ERROR_CONNECTION_INTERRUPTED"],
           platform="macos"),

        # ── macOS Update ──────────────────────────────────────────────────
        _E("SoftwareUpdateError", "softwareupdate", C, ME,
           "macOS software update failure",
           ["Network issue", "Insufficient disk space",
            "Corrupted update package"],
           ["softwareupdate --list", "softwareupdate -i -r",
            "Restart and retry from System Preferences"],
           "repair_system_files",
           [r"softwareupdate.*fail", r"Update.*failed.*install",
            r"Software Update.*error", r"macOSUpdate.*fail",
            r"SUError", r"softwareupdated.*fail"],
           platform="macos"),

        # ── IOKit / Drivers ───────────────────────────────────────────────
        _E("IOKit.KextLoadFail", "IOKit", DR, HI,
           "Kernel extension (kext) failed to load",
           ["Unsigned kext", "SIP blocking kext", "Incompatible macOS version"],
           ["kextstat | grep kext", "kextload /path/to.kext",
            "Disable SIP for legacy kexts (last resort)"],
           "update_driver",
           [r"kext.*fail.*load", r"kextload.*error",
            r"IOKit.*kext.*refused", r"could not be loaded.*kext",
            r"OSKext.*error"],
           platform="macos"),

        # ── Sandbox ───────────────────────────────────────────────────────
        _E("Sandbox.Violation", "Sandbox", SC, ME,
           "App sandbox violation — process blocked by sandbox profile",
           ["App attempting disallowed syscall", "Entitlement missing"],
           ["Check Console.app sandbox logs",
            "sandbox-exec -f profile app"],
           "reset_file_permissions",
           [r"sandbox.*violation", r"deny.*file-read",
            r"deny.*file-write", r"deny.*network",
            r"sandboxd.*deny", r"Sandbox: .+ deny"],
           platform="macos"),

        # ── Memory pressure ───────────────────────────────────────────────
        _E("MemoryPressure.Critical", "kernel", R, CR,
           "Critical memory pressure — system compressing / swapping",
           ["Too many apps open", "Memory leak", "Insufficient RAM"],
           ["sudo purge", "Kill high-memory processes",
            "vm_stat | grep free"],
           "drop_caches",
           [r"memory.*pressure.*critical", r"jetsam.*killed",
            r"Process.*killed.*jetsam", r"memorystatus.*kill",
            r"low memory.*warning", r"kernel.*jetsam"],
           platform="macos"),
    ]
