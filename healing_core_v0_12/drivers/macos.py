"""
drivers.macos
─────────────
Real macOS healing primitives.  All functions return (success: bool, detail: str).

DryRun is set to True by HealingCore at startup when dry_run=True.
When DryRun=False every function shells out for real.

macOS primitives use:
  - launchctl      for service management  (replaces systemctl)
  - networksetup   for network/Wi-Fi configuration
  - dscacheutil    for DNS cache flush
  - ifconfig       for interface management
  - diskutil       for disk repair
  - pfctl          for packet-filter firewall
  - pmset          for power management
  - sntp           for NTP time sync
  - softwareupdate for OS patching
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from typing import Optional, Tuple

log = logging.getLogger("healing_core.drivers.macos")

DryRun: bool = True   # Flipped to False by HealingCore / primitives.register_builtins


# ── Executor ──────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 30, shell: bool = False) -> Tuple[bool, str]:
    if DryRun:
        display = cmd if isinstance(cmd, str) else " ".join(str(c) for c in cmd)
        log.info("[dry-run] %s", display)
        return True, f"dry-run: {display}"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=shell
        )
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        if result.returncode == 0:
            return True, out or "ok"
        return False, err or out or f"exit {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    except FileNotFoundError as exc:
        return False, f"command not found: {exc}"
    except Exception as exc:
        return False, str(exc)


def _has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# ── SERVICE (launchctl) ────────────────────────────────────────────────────────

def _svc_label(name: str) -> str:
    """Convert a short name to a launchctl domain/label path."""
    # Already a dotted label like com.mysql.mysqld
    if "." in name:
        return f"system/{name}"
    # Common homebrew pattern
    if name.startswith("homebrew."):
        return f"system/{name}"
    # Try reversed domain guesses
    _KNOWN = {
        "nginx":      "homebrew.mxcl.nginx",
        "mysql":      "homebrew.mxcl.mysql",
        "postgresql": "homebrew.mxcl.postgresql@14",
        "redis":      "homebrew.mxcl.redis",
        "mongodb":    "homebrew.mxcl.mongodb-community",
        "ssh":        "com.openssh.sshd",
        "sshd":       "com.openssh.sshd",
        "cron":       "com.vix.cron",
        "apache2":    "homebrew.mxcl.httpd",
        "httpd":      "homebrew.mxcl.httpd",
    }
    label = _KNOWN.get(name.lower(), f"com.{name}")
    return f"system/{label}"


def restart_service(name: str) -> Tuple[bool, str]:
    """Kickstart (restart) a launchd service."""
    if not name or name.lower() in ("", "unknown", "none"):
        return False, f"invalid service name: {name!r}"
    label = _svc_label(name)
    ok, d = _run(["launchctl", "kickstart", "-k", label])
    if not ok:
        # Fallback: unload + load plist
        plist = f"/Library/LaunchDaemons/{name}.plist"
        if os.path.exists(plist) or DryRun:
            _run(["launchctl", "unload", plist])
            return _run(["launchctl", "load", "-w", plist])
    return ok, d


def start_service(name: str) -> Tuple[bool, str]:
    label = _svc_label(name)
    ok, d = _run(["launchctl", "start", label])
    if not ok:
        plist = f"/Library/LaunchDaemons/{name}.plist"
        return _run(["launchctl", "load", "-w", plist])
    return ok, d


def stop_service(name: str) -> Tuple[bool, str]:
    label = _svc_label(name)
    ok, d = _run(["launchctl", "stop", label])
    if not ok:
        plist = f"/Library/LaunchDaemons/{name}.plist"
        return _run(["launchctl", "unload", plist])
    return ok, d


def enable_service(name: str) -> Tuple[bool, str]:
    """Enable a service so it starts at boot."""
    label = _svc_label(name)
    return _run(["launchctl", "enable", label])


def disable_service(name: str) -> Tuple[bool, str]:
    label = _svc_label(name)
    return _run(["launchctl", "disable", label])


def query_service(name: str) -> Tuple[bool, str]:
    label = _svc_label(name)
    return _run(["launchctl", "print", label])


def set_service_auto(name: str) -> Tuple[bool, str]:
    ok1, d1 = enable_service(name)
    ok2, d2 = start_service(name)
    return ok2, d2


def reload_service(name: str) -> Tuple[bool, str]:
    label = _svc_label(name)
    ok, d = _run(["launchctl", "kill", "HUP", label])
    if not ok:
        return restart_service(name)
    return ok, d


# ── NETWORK ───────────────────────────────────────────────────────────────────

def restart_network_interface(iface: str = "en0") -> Tuple[bool, str]:
    """Bring interface down then up."""
    _run(["ifconfig", iface, "down"])
    time.sleep(1)
    return _run(["ifconfig", iface, "up"])


def toggle_wifi(on: bool = True, iface: str = "Wi-Fi") -> Tuple[bool, str]:
    """Enable or disable Wi-Fi via networksetup."""
    state = "on" if on else "off"
    return _run(["networksetup", "-setairportpower", iface, state])


def connect_wifi(ssid: str, iface: str = "en0") -> Tuple[bool, str]:
    """Associate with a known Wi-Fi network."""
    return _run(["networksetup", "-setairportnetwork", iface, ssid])


def flush_dns() -> Tuple[bool, str]:
    """Flush the macOS DNS cache."""
    ok1, d1 = _run(["dscacheutil", "-flushcache"])
    ok2, d2 = _run(["killall", "-HUP", "mDNSResponder"])
    return (ok1 and ok2), f"{d1} | {d2}"


def set_dns(server: str, iface: str = "Wi-Fi") -> Tuple[bool, str]:
    """Set DNS server for a network interface."""
    return _run(["networksetup", "-setdnsservers", iface, server])


def release_renew_ip(iface: str = "en0") -> Tuple[bool, str]:
    """Release and renew DHCP lease."""
    _run(["ipconfig", "set", iface, "NONE"])
    time.sleep(1)
    return _run(["ipconfig", "set", iface, "DHCP"])


def reset_network_stack() -> Tuple[bool, str]:
    """Reload the network kernel extensions (approximation)."""
    ok, d = _run(["networksetup", "-detectnewhardware"])
    return ok, d


def set_gateway(gateway: str, iface: str = "en0") -> Tuple[bool, str]:
    """Set default gateway via route."""
    _run(["route", "delete", "default"])
    return _run(["route", "add", "default", gateway])


# ── PROCESS ───────────────────────────────────────────────────────────────────

def kill_process(name: str) -> Tuple[bool, str]:
    return _run(["pkill", "-9", "-f", name])


def kill_pid(pid: int) -> Tuple[bool, str]:
    return _run(["kill", "-9", str(pid)])


def renice_process(name: str, nice: int = 10) -> Tuple[bool, str]:
    return _run(["renice", str(nice), "-n", name])


def get_high_cpu_processes() -> Tuple[bool, str]:
    return _run(["ps", "-eo", "pid,comm,%cpu", "-r"])


def get_high_mem_processes() -> Tuple[bool, str]:
    return _run(["ps", "-eo", "pid,comm,%mem", "-m"])


def purge_memory() -> Tuple[bool, str]:
    """Purge inactive memory (requires sudo)."""
    if _has("purge"):
        return _run(["purge"])
    return False, "purge command not found"


# ── DISK ──────────────────────────────────────────────────────────────────────

def verify_disk(volume: str = "/") -> Tuple[bool, str]:
    return _run(["diskutil", "verifyVolume", volume])


def repair_disk(volume: str = "/") -> Tuple[bool, str]:
    return _run(["diskutil", "repairVolume", volume])


def get_disk_usage() -> Tuple[bool, str]:
    return _run(["df", "-h"])


def clear_temp_files() -> Tuple[bool, str]:
    if DryRun:
        log.info("[dry-run] rm -rf /private/tmp/* ~/Library/Caches/*")
        return True, "dry-run"
    try:
        import glob
        patterns = ["/private/tmp/*", "/private/var/folders/*/*/T/*"]
        removed = 0
        for pat in patterns:
            for path in glob.glob(pat):
                try:
                    if os.path.isfile(path):
                        os.unlink(path)
                        removed += 1
                except Exception:
                    pass
        return True, f"removed {removed} temp files"
    except Exception as exc:
        return False, str(exc)


def check_disk_health() -> Tuple[bool, str]:
    """Use diskutil info to check disk health."""
    return _run(["diskutil", "info", "-all"])


# ── FIREWALL ──────────────────────────────────────────────────────────────────

def enable_firewall() -> Tuple[bool, str]:
    """Enable the macOS Application Firewall."""
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    return _run([fw, "--setglobalstate", "on"])


def disable_firewall() -> Tuple[bool, str]:
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    return _run([fw, "--setglobalstate", "off"])


def block_ip(ip: str) -> Tuple[bool, str]:
    """Add a pf rule to block an IP."""
    rule = f"block drop from {ip} to any"
    anchor = "healing_core"
    if DryRun:
        log.info("[dry-run] pfctl block %s", ip)
        return True, "dry-run"
    try:
        # Write anchor file
        anchor_path = f"/etc/pf.anchors/{anchor}"
        with open(anchor_path, "a") as f:
            f.write(f"{rule}\n")
        _run(["pfctl", "-a", anchor, "-f", anchor_path])
        return _run(["pfctl", "-e"])
    except Exception as exc:
        return False, str(exc)


def allow_port(port: int, proto: str = "tcp") -> Tuple[bool, str]:
    """Add pf pass rule for a port."""
    if DryRun:
        log.info("[dry-run] pfctl allow %s/%d", proto, port)
        return True, "dry-run"
    rule = f"pass in proto {proto} from any to any port {port}"
    try:
        anchor_path = "/etc/pf.anchors/healing_core"
        with open(anchor_path, "a") as f:
            f.write(f"{rule}\n")
        _run(["pfctl", "-a", "healing_core", "-f", anchor_path])
        return True, f"allowed {proto}/{port}"
    except Exception as exc:
        return False, str(exc)


def reset_firewall() -> Tuple[bool, str]:
    """Disable pf and clear healing_core anchor."""
    _run(["pfctl", "-d"])
    try:
        if os.path.exists("/etc/pf.anchors/healing_core"):
            os.unlink("/etc/pf.anchors/healing_core")
    except Exception:
        pass
    return True, "firewall reset"


# ── AUTH / ACCOUNTS ───────────────────────────────────────────────────────────

def disable_account(username: str) -> Tuple[bool, str]:
    return _run(["dscl", ".", "-create", f"/Users/{username}", "AuthenticationAuthority", ";DisabledUser;"])


def enable_account(username: str) -> Tuple[bool, str]:
    return _run(["dscl", ".", "-delete", f"/Users/{username}", "AuthenticationAuthority"])


def reset_account_password(username: str, new_password: str = "TempPass!123") -> Tuple[bool, str]:
    return _run(["dscl", ".", "-passwd", f"/Users/{username}", new_password])


# ── ANTIVIRUS / SECURITY ──────────────────────────────────────────────────────

def run_av_scan(path: str = "/") -> Tuple[bool, str]:
    """Run XProtect/MRT scan via MRT directly if available."""
    mrt = "/Library/Application Support/Apple/ParentalControls/Users"
    # Use built-in malware removal tool
    if _has("mrt"):
        return _run(["mrt", "--run"])
    # Fallback: ClamAV if installed
    if _has("clamscan"):
        return _run(["clamscan", "-r", "--remove", path], timeout=120)
    return False, "no AV scanner found (install ClamAV or use XProtect)"


def update_av_signatures() -> Tuple[bool, str]:
    """Trigger XProtect/MRT update via softwareupdate."""
    return _run(["softwareupdate", "--background"])


# ── TIME ──────────────────────────────────────────────────────────────────────

def sync_time() -> Tuple[bool, str]:
    """Sync system clock via sntp."""
    if _has("sntp"):
        return _run(["sntp", "-sS", "pool.ntp.org"])
    return _run(["systemsetup", "-setusingnetworktime", "on"])


def set_ntp_server(server: str = "pool.ntp.org") -> Tuple[bool, str]:
    return _run(["systemsetup", "-setnetworktimeserver", server])


# ── SYSTEM / CONFIG ───────────────────────────────────────────────────────────

def repair_system_files() -> Tuple[bool, str]:
    """Run First Aid on the boot volume."""
    return _run(["diskutil", "repairVolume", "/"])


def restore_config_from_backup(src: str, dst: str) -> Tuple[bool, str]:
    return _run(["cp", "-f", src, dst])


def reset_file_permissions(path: str) -> Tuple[bool, str]:
    """Reset POSIX permissions and ACLs."""
    ok1, d1 = _run(["chmod", "-RN", path])   # strip ACLs
    ok2, d2 = _run(["chmod", "755", path])
    return ok2, d2


def grant_file_permissions(path: str, user: str, mode: str = "755") -> Tuple[bool, str]:
    ok1, _ = _run(["chown", user, path])
    ok2, d = _run(["chmod", mode, path])
    return ok2, d


def run_software_update() -> Tuple[bool, str]:
    """Install recommended OS updates."""
    return _run(["softwareupdate", "-i", "-r"], timeout=300)


def reboot_system() -> Tuple[bool, str]:
    """Schedule a graceful reboot."""
    if DryRun:
        log.info("[dry-run] reboot")
        return True, "dry-run"
    return _run(["shutdown", "-r", "+1", "HealingCore triggered reboot"])
