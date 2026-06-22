"""
healing_core.service_resolver
──────────────────────────────
OS-aware service name resolver.  Maps an incident to the correct platform
service name before calling restart_service / disable_service / etc.

Priority (all platforms):
  1. Exact match in platform-specific name map
  2. Actor already looks like a valid service name  →  verify it exists
  3. Keyword scan of message + actor + error_type
  4. Category heuristic
  5. Raw actor field as-is

Windows service names differ significantly from Linux daemon names:
  Linux: nginx / postgresql / sshd / networkmanager
  Windows: nginx / postgresql-x64-14 / sshd / Netman / W32Time ...
"""
from __future__ import annotations

import logging
import platform
import re
import subprocess
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Incident

log = logging.getLogger("healing_core.service_resolver")
_OS = platform.system()   # "Linux" | "Windows" | "Darwin"


# ── Linux keyword → service name ──────────────────────────────────────────────

_LINUX_MAP: dict = {
    "nginx":              "nginx",
    "apache":             "apache2",
    "apache2":            "apache2",
    "httpd":              "httpd",
    "lighttpd":           "lighttpd",
    "caddy":              "caddy",
    "haproxy":            "haproxy",
    "traefik":            "traefik",
    "postgresql":         "postgresql",
    "postgres":           "postgresql",
    "mysql":              "mysql",
    "mariadb":            "mariadb",
    "mongodb":            "mongod",
    "redis":              "redis",
    "redis-server":       "redis",
    "elasticsearch":      "elasticsearch",
    "opensearch":         "opensearch",
    "rabbitmq":           "rabbitmq-server",
    "kafka":              "kafka",
    "zookeeper":          "zookeeper",
    "celery":             "celery",
    "ssh":                "ssh",
    "sshd":               "ssh",
    "cron":               "cron",
    "crond":              "crond",
    "ntp":                "ntp",
    "ntpd":               "ntp",
    "chronyd":            "chronyd",
    "systemd-resolved":   "systemd-resolved",
    "networkmanager":     "NetworkManager",
    "dnsmasq":            "dnsmasq",
    "named":              "named",
    "bind":               "named",
    "postfix":            "postfix",
    "dovecot":            "dovecot",
    "sendmail":           "sendmail",
    "prometheus":         "prometheus",
    "grafana":            "grafana-server",
    "influxdb":           "influxdb",
    "node_exporter":      "node_exporter",
    "docker":             "docker",
    "containerd":         "containerd",
    "kubelet":            "kubelet",
    "ufw":                "ufw",
    "firewalld":          "firewalld",
    "sssd":               "sssd",
    "ldap":               "slapd",
    "clamav":             "clamav-daemon",
    "fail2ban":           "fail2ban",
    "logrotate":          "logrotate",
    "journald":           "systemd-journald",
}


# ── Windows keyword → service name ────────────────────────────────────────────
# Maps short/alias names → canonical Windows service name (sc.exe name)

_WINDOWS_MAP: dict = {
    # Core OS
    "w32time":            "w32time",
    "time":               "w32time",
    "windows time":       "w32time",
    "dnscache":           "Dnscache",
    "dns":                "Dnscache",
    "dhcp":               "Dhcp",
    "dhcpv6":             "Dhcp",
    "netlogon":           "Netlogon",
    "rpc":                "RpcSs",
    "rpcss":              "RpcSs",
    "rpc endpoint":       "RpcEptMapper",
    "eventlog":           "EventLog",
    "event log":          "EventLog",
    "wuauserv":           "wuauserv",
    "windows update":     "wuauserv",
    "update":             "wuauserv",
    "bits":               "BITS",
    "trustedinstaller":   "TrustedInstaller",
    "schedule":           "Schedule",
    "task scheduler":     "Schedule",
    "taskschd":           "Schedule",
    "spooler":            "Spooler",
    "print spooler":      "Spooler",
    "lmhosts":            "lmhosts",
    "netman":             "Netman",
    "network connections":"Netman",
    "winmgmt":            "winmgmt",
    "wmi":                "winmgmt",
    "wbem":               "winmgmt",
    "termservice":        "TermService",
    "remote desktop":     "TermService",
    "rdp":                "TermService",
    "mstermservice":      "TermService",
    "wlansvc":            "Wlansvc",
    "wlan":               "Wlansvc",
    "wifi":               "Wlansvc",
    "wireless":           "Wlansvc",
    "dot3svc":            "dot3svc",          # Wired AutoConfig
    "netbios":            "NetBIOS",
    "lanmanserver":       "LanmanServer",
    "server":             "LanmanServer",
    "smb":                "LanmanServer",
    "lanmanworkstation":  "LanmanWorkstation",
    "workstation":        "LanmanWorkstation",
    # Security
    "mpssvc":             "MpsSvc",           # Windows Firewall
    "firewall":           "MpsSvc",
    "windefend":          "WinDefend",
    "defender":           "WinDefend",
    "windows defender":   "WinDefend",
    "securitycenter":     "wscsvc",
    "wscsvc":             "wscsvc",
    "lsass":              "LSASS",
    "lsa":                "LSASS",
    "kdc":                "Kdc",
    "kerberos":           "Kdc",
    "cryptsvc":           "CryptSvc",
    "crypto":             "CryptSvc",
    "certpropsvc":        "CertPropSvc",
    # Application servers
    "mssql":              "MSSQLSERVER",
    "sqlserver":          "MSSQLSERVER",
    "sql server":         "MSSQLSERVER",
    "mssqlserver":        "MSSQLSERVER",
    "sqlbrowser":         "SQLBrowser",
    "iis":                "W3SVC",
    "w3svc":              "W3SVC",
    "was":                "WAS",              # IIS process activation
    "aspnet":             "W3SVC",
    "httpsys":            "HTTP",
    "http":               "HTTP",
    "nginx":              "nginx",
    "apache":             "Apache2.4",
    "apache2":            "Apache2.4",
    "httpd":              "Apache2.4",
    "postgresql":         "postgresql-x64-14",
    "postgres":           "postgresql-x64-14",
    "mysql":              "MySQL80",
    "mariadb":            "MariaDB",
    "mongodb":            "MongoDB",
    "redis":              "Redis",
    "redis-server":       "Redis",
    "elasticsearch":      "elasticsearch-service-x64",
    "rabbitmq":           "RabbitMQ",
    "kafka":              "kafka",
    "docker":             "docker",
    "containerd":         "containerd",
    "kubelet":            "kubelet",
    "prometheus":         "prometheus",
    "grafana":            "grafana",
    # SSH (OpenSSH for Windows)
    "ssh":                "sshd",
    "sshd":               "sshd",
    "openssh":            "sshd",
    # Audio / UI
    "audiosrv":           "AudioSrv",
    "audio":              "AudioSrv",
    "audioendpoint":      "AudioEndpointBuilder",
    "themes":             "Themes",
    # System utility
    "sens":               "SENS",             # System Event Notification
    "sfc":                "sfc",
    "superfetch":         "SysMain",
    "sysmain":            "SysMain",
    "prefetch":           "SysMain",
    "wsearch":            "WSearch",
    "windows search":     "WSearch",
    "search":             "WSearch",
    "vss":                "VSS",              # Volume Shadow Copy
    "shadow":             "VSS",
    "disk":               "Disk",
    "storage":            "StorSvc",
    "storsvc":            "StorSvc",
    "power":              "Power",
    "battery":            "Power",
    # Monitoring
    "wdiservhost":        "WdiServiceHost",
    "diagtrack":          "DiagTrack",
    # Print
    "print":              "Spooler",
    # Group policy
    "gpsvc":              "gpsvc",
    "group policy":       "gpsvc",
    # Certificate
    "certsvc":            "CertSvc",
    "certificate":        "CertSvc",
    "certenroll":         "CertSvc",
}


# ── macOS keyword → launchctl label ───────────────────────────────────────────

_MACOS_MAP: dict = {
    "nginx":              "homebrew.mxcl.nginx",
    "apache":             "homebrew.mxcl.httpd",
    "apache2":            "homebrew.mxcl.httpd",
    "httpd":              "homebrew.mxcl.httpd",
    "postgresql":         "homebrew.mxcl.postgresql@14",
    "postgres":           "homebrew.mxcl.postgresql@14",
    "mysql":              "homebrew.mxcl.mysql",
    "mariadb":            "homebrew.mxcl.mariadb",
    "mongodb":            "homebrew.mxcl.mongodb-community",
    "redis":              "homebrew.mxcl.redis",
    "elasticsearch":      "homebrew.mxcl.elasticsearch",
    "rabbitmq":           "homebrew.mxcl.rabbitmq",
    "ssh":                "com.openssh.sshd",
    "sshd":               "com.openssh.sshd",
    "cron":               "com.vix.cron",
    "docker":             "com.docker.dockerd",
    "prometheus":         "homebrew.mxcl.prometheus",
    "grafana":            "homebrew.mxcl.grafana",
    "ntp":                "org.ntp.ntpd",
    "ntpd":               "org.ntp.ntpd",
    "dnsmasq":            "homebrew.mxcl.dnsmasq",
    "networking":         "com.apple.networking",
    "mDNSResponder":      "com.apple.mDNSResponder",
    "mdns":               "com.apple.mDNSResponder",
    "configd":            "com.apple.configd",
}


# ── Windows category heuristics ───────────────────────────────────────────────

_WINDOWS_CAT_MAP: dict = {
    "NETWORK":        "Dnscache",
    "AUTHENTICATION": "LSASS",
    "SERVICE":        "",          # use actor
    "CONFIGURATION":  "gpsvc",
    "SECURITY":       "MpsSvc",
    "MALWARE":        "WinDefend",
    "DRIVER":         "",
    "RESOURCE":       "",
}

_LINUX_CAT_MAP: dict = {
    "NETWORK":        "NetworkManager",
    "AUTHENTICATION": "sssd",
    "SERVICE":        "",
    "CONFIGURATION":  "",
    "SECURITY":       "ufw",
    "MALWARE":        "clamav-daemon",
}


# ── Public API ─────────────────────────────────────────────────────────────────

def resolve(incident: "Incident") -> str:
    """Return the platform-correct service name for this incident."""
    actor = (incident.event.actor or "").lower().strip()
    msg   = (incident.event.message or "").lower()
    etype = (incident.event.error_type or "").lower()
    combined = f"{actor} {msg} {etype}"

    if _OS == "Windows":
        return _resolve_windows(actor, combined, incident)
    elif _OS == "Darwin":
        return _resolve_macos(actor, combined, incident)
    else:
        return _resolve_linux(actor, combined, incident)


def resolve_to_windows_name(short: str) -> str:
    """Utility: translate a short/Linux service name to its Windows equivalent."""
    key = short.lower().strip()
    return _WINDOWS_MAP.get(key, short)


def resolve_to_macos_label(short: str) -> str:
    """Utility: translate a short service name to its macOS launchctl label."""
    key = short.lower().strip()
    label = _MACOS_MAP.get(key, f"com.{short}")
    return f"system/{label}"


# ── Per-OS resolution ─────────────────────────────────────────────────────────

def _resolve_windows(actor: str, combined: str, incident: "Incident") -> str:
    # 1. Direct actor match in Windows map
    svc = _WINDOWS_MAP.get(actor)
    if svc is not None:
        return svc or actor

    # 2. Scan combined text for Windows service name keywords (longest-first)
    for kw, svc_name in sorted(_WINDOWS_MAP.items(), key=lambda kv: -len(kv[0])):
        if kw in combined and svc_name:
            return svc_name

    # 3. Actor looks like a Windows service name already (sc query to verify)
    if actor and re.match(r"^[a-zA-Z][a-zA-Z0-9._\-]{0,63}$", actor):
        if _win_service_exists(actor):
            return actor

    # 4. Extract "ServiceName.exe" or "ServiceName service"
    m = re.search(r"([A-Za-z][A-Za-z0-9_\-]+)\s+service\b", combined, re.IGNORECASE)
    if m:
        candidate = m.group(1)
        if _win_service_exists(candidate):
            return candidate

    # 5. Category heuristic
    cat_name = getattr(incident.category, "name", "")
    fallback = _WINDOWS_CAT_MAP.get(cat_name, "") or actor or "unknown"
    return fallback


def _resolve_macos(actor: str, combined: str, incident: "Incident") -> str:
    # 1. Direct actor match
    svc = _MACOS_MAP.get(actor)
    if svc is not None:
        return svc or actor

    # 2. Keyword scan
    for kw, label in sorted(_MACOS_MAP.items(), key=lambda kv: -len(kv[0])):
        if kw in combined and label:
            return label

    # 3. Actor matches homebrew pattern
    if actor.startswith("homebrew.") or "." in actor:
        return actor

    # 4. Guess homebrew label
    if actor:
        return f"homebrew.mxcl.{actor}"

    return actor or "unknown"


def _resolve_linux(actor: str, combined: str, incident: "Incident") -> str:
    # 1. Direct actor match
    svc = _LINUX_MAP.get(actor)
    if svc is not None:
        return svc or actor

    # 2. Actor looks like a systemd service name
    if actor and re.match(r"^[a-z][a-z0-9_@.\-]{1,64}$", actor):
        if _linux_service_exists(actor):
            return actor

    # 3. Keyword scan
    for kw, svc_name in sorted(_LINUX_MAP.items(), key=lambda kv: -len(kv[0])):
        if kw in combined and svc_name:
            return svc_name

    # 4. Extract ".service" pattern
    m = re.search(r"([a-z][a-z0-9_\-]+)\.service", combined)
    if m:
        return m.group(1)

    # 5. Category heuristic
    cat_name = getattr(incident.category, "name", "")
    fallback = _LINUX_CAT_MAP.get(cat_name, "") or actor or "unknown"
    return fallback


# ── OS-level service existence checks ─────────────────────────────────────────

def _win_service_exists(name: str) -> bool:
    try:
        r = subprocess.run(
            ["sc", "query", name],
            capture_output=True, text=True, timeout=3, creationflags=0x08000000
        )
        return r.returncode == 0
    except Exception:
        return False


def _linux_service_exists(name: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--all", "--no-legend", name + ".service"],
            capture_output=True, text=True, timeout=3
        )
        return name in r.stdout
    except Exception:
        return False
