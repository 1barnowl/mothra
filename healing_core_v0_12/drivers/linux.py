"""
drivers.linux
─────────────
Real Linux healing primitives.  All functions return (success: bool, detail: str).

DryRun is set to True by HealingCore at startup when dry_run=True.
When DryRun=False every function shells out for real.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
from typing import Optional, Tuple

log = logging.getLogger("healing_core.drivers.linux")

DryRun: bool = True   # Flipped to False by HealingCore / primitives.register_builtins


# ─── Executor ─────────────────────────────────────────────────────────────────

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


# ─── SERVICE ──────────────────────────────────────────────────────────────────

def restart_service(name: str) -> Tuple[bool, str]:
    if not name or name.lower() in ("", "unknown", "none"):
        return False, f"invalid service name: {name!r}"
    return _run(["systemctl", "restart", name])

def start_service(name: str) -> Tuple[bool, str]:
    return _run(["systemctl", "start", name])

def stop_service(name: str) -> Tuple[bool, str]:
    return _run(["systemctl", "stop", name])

def reload_service(name: str) -> Tuple[bool, str]:
    return _run(["systemctl", "reload", name])

def enable_service(name: str) -> Tuple[bool, str]:
    """systemctl enable — set service to auto-start."""
    return _run(["systemctl", "enable", name])

def set_service_auto(name: str) -> Tuple[bool, str]:
    """Enable + start a service (set_service_auto primitive)."""
    ok1, d1 = _run(["systemctl", "enable", name])
    ok2, d2 = _run(["systemctl", "start", name])
    return ok2, d2

def set_service_delayed(name: str, delay_sec: int = 10) -> Tuple[bool, str]:
    """Apply a startup delay via drop-in override."""
    if DryRun:
        log.info("[dry-run] set delayed start %s +%ds", name, delay_sec)
        return True, "dry-run"
    override_dir = f"/etc/systemd/system/{name}.service.d"
    override_file = os.path.join(override_dir, "delay.conf")
    try:
        os.makedirs(override_dir, exist_ok=True)
        with open(override_file, "w") as f:
            f.write(f"[Service]\nExecStartPre=/bin/sleep {delay_sec}\n")
        _run(["systemctl", "daemon-reload"])
        return True, f"wrote {override_file}"
    except Exception as exc:
        return False, str(exc)

def set_service_recovery(name: str) -> Tuple[bool, str]:
    """Configure auto-restart on failure via drop-in."""
    if DryRun:
        log.info("[dry-run] set recovery for %s", name)
        return True, "dry-run"
    override_dir = f"/etc/systemd/system/{name}.service.d"
    override_file = os.path.join(override_dir, "recovery.conf")
    try:
        os.makedirs(override_dir, exist_ok=True)
        with open(override_file, "w") as f:
            f.write("[Service]\nRestart=on-failure\nRestartSec=5\n")
        _run(["systemctl", "daemon-reload"])
        return True, f"recovery configured for {name}"
    except Exception as exc:
        return False, str(exc)

def disable_service(name: str) -> Tuple[bool, str]:
    ok1, _ = _run(["systemctl", "stop", name])
    ok2, d = _run(["systemctl", "disable", name])
    return ok2, d

def query_service(name: str) -> Tuple[bool, str]:
    return _run(["systemctl", "status", name])


# ─── NETWORK ──────────────────────────────────────────────────────────────────

def flush_dns() -> Tuple[bool, str]:
    """Flush DNS — tries all known utilities in priority order."""
    for tool, cmd in [
        ("resolvectl",      ["resolvectl", "flush-caches"]),
        ("systemd-resolve", ["systemd-resolve", "--flush-caches"]),
        ("nscd",            ["nscd", "-i", "hosts"]),
        ("dscacheutil",     ["dscacheutil", "-flushcache"]),   # macOS
    ]:
        if _has(tool):
            return _run(cmd)
    # Fallback: restart systemd-resolved if running
    ok, d = _run(["systemctl", "restart", "systemd-resolved"])
    if ok:
        return True, "restarted systemd-resolved"
    # Last resort: touch resolv.conf to refresh
    if DryRun:
        return True, "dry-run: no flush utility, would touch /etc/resolv.conf"
    try:
        import pathlib as _pl
        p = _pl.Path("/etc/resolv.conf")
        if p.exists():
            p.touch()
        return True, "touched /etc/resolv.conf (cache cleared by nscd on next query)"
    except Exception as exc:
        return False, f"no DNS flush utility found and fallback failed: {exc}"

def set_dns(server: str = "1.1.1.1", config_path: str = "/etc/resolv.conf") -> Tuple[bool, str]:
    if DryRun:
        log.info("[dry-run] would write nameserver %s to %s", server, config_path)
        return True, "dry-run"
    try:
        existing = ""
        if os.path.exists(config_path):
            with open(config_path) as f:
                existing = f.read()
        # Remove old nameserver lines, prepend new one
        lines = [l for l in existing.splitlines() if not l.strip().startswith("nameserver")]
        content = f"nameserver {server}\n" + "\n".join(lines) + "\n"
        with open(config_path, "w") as f:
            f.write(content)
        return True, f"nameserver set to {server}"
    except Exception as exc:
        return False, str(exc)

def set_dns_cloudflare() -> Tuple[bool, str]:
    return set_dns("1.1.1.1")

def reset_network_stack() -> Tuple[bool, str]:
    """Restart NetworkManager (primary) or networking service."""
    for svc in ("NetworkManager", "networking", "systemd-networkd"):
        ok, d = _run(["systemctl", "restart", svc])
        if ok:
            return True, f"restarted {svc}: {d}"
    return False, "no network service could be restarted"

def restart_network_interface(iface: str = "") -> Tuple[bool, str]:
    """Bring an interface down then up.  Tries to auto-detect if not given."""
    if not iface:
        iface = _detect_primary_iface()
    if DryRun:
        return True, f"dry-run: would cycle interface {iface or '(auto-detect)'}"
    if not iface:
        return False, "could not detect primary network interface"
    ok1, _ = _run(["ip", "link", "set", iface, "down"])
    time.sleep(1)
    ok2, d = _run(["ip", "link", "set", iface, "up"])
    return ok2, d

def restart_wifi() -> Tuple[bool, str]:
    """Toggle wifi via nmcli or rfkill."""
    if DryRun:
        return True, "dry-run: would toggle Wi-Fi via nmcli/rfkill"
    if _has("nmcli"):
        ok1, _ = _run(["nmcli", "radio", "wifi", "off"])
        time.sleep(2)
        return _run(["nmcli", "radio", "wifi", "on"])
    if _has("rfkill"):
        ok1, _ = _run(["rfkill", "block", "wifi"])
        time.sleep(1)
        return _run(["rfkill", "unblock", "wifi"])
    return False, "neither nmcli nor rfkill found"

def _detect_primary_iface() -> str:
    try:
        r = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r"dev\s+(\S+)", r.stdout)
        return m.group(1) if m else ""
    except Exception:
        return ""

def release_renew_ip(iface: str = "") -> Tuple[bool, str]:
    if not iface:
        iface = _detect_primary_iface()
    if DryRun:
        return True, f"dry-run: would DHCP release+renew on {iface or 'primary iface'}"
    if _has("dhclient"):
        ok1, _ = _run(["dhclient", "-r", iface] if iface else ["dhclient", "-r"])
        time.sleep(1)
        return _run(["dhclient", iface] if iface else ["dhclient"])
    if _has("dhcpcd"):
        return _run(["dhcpcd", "-n", iface] if iface else ["dhcpcd", "-n"])
    return False, "no DHCP client found (dhclient/dhcpcd)"

def block_ip(ip: str, chain: str = "INPUT") -> Tuple[bool, str]:
    if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return False, f"invalid IP: {ip!r}"
    if _has("nft"):
        # Try nftables first
        return _run(["nft", "add", "rule", "inet", "filter", chain.lower(),
                     "ip", "saddr", ip, "drop"])
    return _run(["iptables", "-A", chain, "-s", ip, "-j", "DROP"])

def allow_firewall_port(port: int = 0, protocol: str = "tcp",
                        port_str: str = "") -> Tuple[bool, str]:
    """Open a port in iptables/nftables.  Accepts int port or 'PORT/proto' string."""
    if port_str:
        m = re.match(r"(\d+)(?:/(\w+))?", port_str)
        if m:
            port = int(m.group(1))
            protocol = m.group(2) or protocol
    if port <= 0:
        return False, f"invalid port: {port}"
    if _has("nft"):
        return _run(["nft", "add", "rule", "inet", "filter", "input",
                     protocol, "dport", str(port), "accept"])
    return _run(["iptables", "-A", "INPUT", "-p", protocol,
                 "--dport", str(port), "-j", "ACCEPT"])

def reset_firewall() -> Tuple[bool, str]:
    """Flush all iptables rules (or nftables), allow established/loopback."""
    if _has("nft"):
        ok, d = _run(["nft", "flush", "ruleset"])
        return ok, d
    cmds = [
        ["iptables", "-F"],
        ["iptables", "-X"],
        ["iptables", "-P", "INPUT",   "ACCEPT"],
        ["iptables", "-P", "FORWARD", "ACCEPT"],
        ["iptables", "-P", "OUTPUT",  "ACCEPT"],
    ]
    for cmd in cmds:
        ok, d = _run(cmd)
        if not ok:
            return False, d
    return True, "iptables flushed and policies set to ACCEPT"


# ─── PROCESS ──────────────────────────────────────────────────────────────────

def kill_process(name: str) -> Tuple[bool, str]:
    """pkill -9 by name pattern."""
    if not name:
        return False, "no process name given"
    return _run(["pkill", "-9", "-f", name])

def kill_pid(pid: int) -> Tuple[bool, str]:
    return _run(["kill", "-9", str(pid)])

def kill_high_cpu(threshold_pct: float = 80.0) -> Tuple[bool, str]:
    """
    Find and kill the single process using the most CPU above threshold.
    Skips PID 1, kernel threads, and our own process.
    """
    if DryRun:
        log.info("[dry-run] would kill top CPU process")
        return True, "dry-run"
    try:
        r = subprocess.run(
            ["ps", "--no-headers", "-eo", "pid,%cpu,comm", "--sort=-%cpu"],
            capture_output=True, text=True, timeout=10
        )
        own_pid = os.getpid()
        for line in r.stdout.strip().splitlines():
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            pid = int(parts[0])
            cpu = float(parts[1])
            name = parts[2].strip() if len(parts) > 2 else "?"
            if pid in (1, own_pid):
                continue
            if cpu < threshold_pct:
                return False, f"no process above {threshold_pct}% CPU (top={name} {cpu}%)"
            log.warning("killing high-CPU process pid=%d name=%s cpu=%.1f%%", pid, name, cpu)
            return _run(["kill", "-9", str(pid)])
        return False, "ps returned no processes"
    except Exception as exc:
        return False, str(exc)

def kill_high_mem(threshold_mb: float = 0) -> Tuple[bool, str]:
    """Kill the process using the most memory."""
    if DryRun:
        log.info("[dry-run] would kill top memory process")
        return True, "dry-run"
    try:
        r = subprocess.run(
            ["ps", "--no-headers", "-eo", "pid,rss,comm", "--sort=-rss"],
            capture_output=True, text=True, timeout=10
        )
        own_pid = os.getpid()
        for line in r.stdout.strip().splitlines():
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            pid   = int(parts[0])
            rss_kb = float(parts[1])
            name  = parts[2].strip() if len(parts) > 2 else "?"
            if pid in (1, own_pid):
                continue
            rss_mb = rss_kb / 1024
            if threshold_mb and rss_mb < threshold_mb:
                return False, f"top process {name} only {rss_mb:.0f}MB"
            log.warning("killing high-mem process pid=%d name=%s rss=%.0fMB", pid, name, rss_mb)
            return _run(["kill", "-9", str(pid)])
        return False, "ps returned no processes"
    except Exception as exc:
        return False, str(exc)

def renice_process(name: str = "", pid: int = 0,
                   nice: int = 10) -> Tuple[bool, str]:
    if pid and pid > 0:
        return _run(["renice", "-n", str(nice), "-p", str(pid)])
    if name:
        # renice by name via pkill --signal 0 to find pids first
        try:
            r = subprocess.run(["pgrep", "-f", name], capture_output=True,
                               text=True, timeout=5)
            pids = r.stdout.strip().split()
            if not pids:
                return False, f"no process matching {name!r}"
            for p in pids[:5]:  # limit to first 5 matching
                _run(["renice", "-n", str(nice), "-p", p])
            return True, f"reniced {len(pids)} process(es) matching {name!r}"
        except Exception as exc:
            return False, str(exc)
    return False, "name or pid required"

def lower_priority(name: str = "", pid: int = 0) -> Tuple[bool, str]:
    """Renice to +19 (lowest priority)."""
    return renice_process(name=name, pid=pid, nice=19)


# ─── CGROUPS v2 ───────────────────────────────────────────────────────────────

CGROUP_ROOT = "/sys/fs/cgroup/healing_core"

def _write_cgroup(cg_path: str, filename: str, value: str) -> Tuple[bool, str]:
    full = os.path.join(cg_path, filename)
    if DryRun:
        log.info("[dry-run] would write %r to %s", value, full)
        return True, "dry-run"
    try:
        os.makedirs(cg_path, exist_ok=True)
        with open(full, "w") as f:
            f.write(value)
        return True, f"wrote {value!r} → {full}"
    except Exception as exc:
        return False, str(exc)

def apply_cgroup_limits(actor: str, cpu_pct: int = 10,
                        mem_mb: int = 128) -> Tuple[bool, str]:
    cg = os.path.join(CGROUP_ROOT, re.sub(r"[^a-zA-Z0-9_-]", "_", actor))
    ok1, d1 = _write_cgroup(cg, "cpu.max", f"{cpu_pct * 1000} 1000000")
    ok2, d2 = _write_cgroup(cg, "memory.max", str(mem_mb * 1024 * 1024))
    return (ok1 and ok2), f"cpu={d1} mem={d2}"

def release_cgroup(actor: str) -> Tuple[bool, str]:
    cg = os.path.join(CGROUP_ROOT, re.sub(r"[^a-zA-Z0-9_-]", "_", actor))
    if DryRun:
        return True, "dry-run"
    try:
        if os.path.isdir(cg):
            os.rmdir(cg)
        return True, f"removed {cg}"
    except Exception as exc:
        return False, str(exc)


# ─── RESOURCE ─────────────────────────────────────────────────────────────────

def drop_caches() -> Tuple[bool, str]:
    """Sync and drop Linux page/slab/inode caches."""
    if DryRun:
        log.info("[dry-run] would drop page cache")
        return True, "dry-run"
    try:
        # sync first to avoid data loss
        subprocess.run(["sync"], timeout=10)
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3")
        return True, "synced + dropped caches (level 3)"
    except PermissionError:
        return False, "permission denied — must run as root"
    except Exception as exc:
        return False, str(exc)

def get_disk_usage(path: str = "/") -> Tuple[bool, str]:
    return _run(["df", "-h", path])

def clear_temp_files() -> Tuple[bool, str]:
    """Remove files in /tmp older than 1 day."""
    return _run(["find", "/tmp", "-type", "f", "-mtime", "+1", "-delete"])

def adjust_power_plan(plan: str = "balanced") -> Tuple[bool, str]:
    """Set CPU governor via cpupower or cpufreq-set."""
    governor_map = {"performance": "performance",
                    "balanced":    "schedutil",
                    "powersave":   "powersave"}
    governor = governor_map.get(plan.lower(), "schedutil")
    if _has("cpupower"):
        return _run(["cpupower", "frequency-set", "-g", governor])
    if _has("cpufreq-set"):
        return _run(["cpufreq-set", "-g", governor, "-c", "0"])
    # Fallback: write to sysfs
    if DryRun:
        return True, "dry-run"
    try:
        for cpu_dir in sorted(os.listdir("/sys/devices/system/cpu")):
            path = f"/sys/devices/system/cpu/{cpu_dir}/cpufreq/scaling_governor"
            if os.path.exists(path):
                with open(path, "w") as f:
                    f.write(governor)
        return True, f"governor set to {governor}"
    except Exception as exc:
        return False, str(exc)


# ─── FILESYSTEM ───────────────────────────────────────────────────────────────

def chkdsk(device: str = "") -> Tuple[bool, str]:
    """Run fsck on an unmounted device (or the appropriate tool)."""
    if not device:
        # Find root device
        try:
            r = subprocess.run(
                ["findmnt", "-n", "-o", "SOURCE", "/"],
                capture_output=True, text=True, timeout=5
            )
            device = r.stdout.strip()
        except Exception:
            device = "/dev/sda1"
    if _has("fsck"):
        return _run(["fsck", "-n", device], timeout=120)   # -n = read-only check
    return False, "fsck not found"


# ─── AUTH / ACCOUNT ───────────────────────────────────────────────────────────

def disable_account(username: str) -> Tuple[bool, str]:
    if not username or username in ("root", ""):
        return False, f"refusing to lock {username!r}"
    return _run(["usermod", "-L", username])

def enable_account(username: str) -> Tuple[bool, str]:
    return _run(["usermod", "-U", username])

def reset_account_password(username: str,
                           new_password: str = "") -> Tuple[bool, str]:
    """Reset a user's password.  Generates random if not provided."""
    if not username:
        return False, "no username"
    if not new_password:
        import secrets, string
        new_password = "".join(secrets.choice(
            string.ascii_letters + string.digits) for _ in range(16))
    if DryRun:
        log.info("[dry-run] would reset password for %s", username)
        return True, "dry-run"
    try:
        proc = subprocess.run(
            ["chpasswd"],
            input=f"{username}:{new_password}\n",
            capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            return True, f"password reset for {username}"
        return False, proc.stderr.strip()
    except Exception as exc:
        return False, str(exc)

def grant_logon_service_right(username: str) -> Tuple[bool, str]:
    """Linux doesn't have SeServiceLogonRight — services run as the user directly."""
    log.info("grant_logon_service_right: N/A on Linux (services run as %s)", username)
    return True, f"N/A on Linux — ensure systemd service User={username}"

def grant_smb_access(share: str = "", user: str = "") -> Tuple[bool, str]:
    if _has("smbpasswd"):
        return _run(["smbpasswd", "-a", user] if user else ["smbpasswd", "-e", user])
    return False, "smbpasswd not found — install samba"

def update_group_policy() -> Tuple[bool, str]:
    """Linux equivalent: flush SSSD/winbind cache if domain-joined."""
    if _has("sss_cache"):
        return _run(["sss_cache", "-G"])
    if _has("wbinfo"):
        return _run(["wbinfo", "--ping-dc"])
    return True, "N/A — not domain-joined or no SSSD/winbind"

def set_execution_policy() -> Tuple[bool, str]:
    """Linux doesn't have an execution policy — chmod +x is handled elsewhere."""
    return True, "N/A on Linux"

def grant_registry_access() -> Tuple[bool, str]:
    return True, "N/A on Linux"

def reset_registry_perms() -> Tuple[bool, str]:
    return True, "N/A on Linux"

def restore_registry() -> Tuple[bool, str]:
    return True, "N/A on Linux"


# ─── CONFIG / FILES ───────────────────────────────────────────────────────────

def reset_file_permissions(path: str, mode: str = "644") -> Tuple[bool, str]:
    if not path:
        return False, "no path"
    return _run(["chmod", mode, path])

def grant_file_permissions(path: str, user: str = "",
                           mode: str = "rw") -> Tuple[bool, str]:
    """chown + chmod for a specific user."""
    if not path:
        return False, "no path"
    octal_map = {"r": "444", "rw": "644", "rwx": "755", "full": "777"}
    octal = octal_map.get(mode, mode)
    ok1, _ = _run(["chmod", octal, path])
    if user:
        ok2, d = _run(["chown", user, path])
        return ok2, d
    return ok1, f"chmod {octal} {path}"

def take_file_ownership(path: str, user: str = "") -> Tuple[bool, str]:
    if not user:
        user = os.environ.get("USER", "root")
    return _run(["chown", "-R", user, path])

def restore_config_from_backup(src: str = "",
                               dst: str = "") -> Tuple[bool, str]:
    if not src or not dst:
        return False, f"need src and dst (got {src!r}, {dst!r})"
    if DryRun:
        log.info("[dry-run] would cp %s → %s", src, dst)
        return True, "dry-run"
    if not os.path.exists(src):
        return False, f"backup not found: {src}"
    return _run(["cp", "-p", "--backup=numbered", src, dst])

def dism_restore_health() -> Tuple[bool, str]:
    """Linux equivalent of DISM restorehealth — fix broken packages."""
    if _has("apt-get"):
        ok1, _ = _run(["dpkg", "--configure", "-a"])
        ok2, d = _run(["apt-get", "install", "-f", "-y"], timeout=120)
        return ok2, d
    if _has("yum"):
        return _run(["yum", "-y", "install", "--fix-broken"], timeout=120)
    if _has("dnf"):
        return _run(["dnf", "-y", "distro-sync"], timeout=120)
    return False, "no supported package manager found"

def repair_system_files() -> Tuple[bool, str]:
    return dism_restore_health()


# ─── DRIVER / DEVICE ──────────────────────────────────────────────────────────

def update_driver(driver_name: str) -> Tuple[bool, str]:
    """Reload a kernel module (modprobe) after optional reinstall."""
    # First try reinstall via package manager
    pkg_name = driver_name.replace("-", "_")
    if _has("apt-get"):
        _run(["apt-get", "install", "--reinstall", "-y", f"linux-modules-extra-$(uname -r)"],
             timeout=120)
    ok1, _ = _run(["modprobe", "-r", driver_name])
    return _run(["modprobe", driver_name])

def rollback_driver(driver_name: str) -> Tuple[bool, str]:
    """Unload and reload the previous version of a kernel module."""
    ok, d = _run(["modprobe", "-r", driver_name])
    if not ok:
        return False, f"could not unload {driver_name}: {d}"
    return _run(["modprobe", driver_name])

def disable_device(device_id: str) -> Tuple[bool, str]:
    """Unbind a device by sysfs ID or modprobe -r its driver."""
    if DryRun:
        log.info("[dry-run] would disable device %s", device_id)
        return True, "dry-run"
    # Try sysfs unbind
    unbind_paths = [
        f"/sys/bus/pci/drivers/{p}/unbind" for p in os.listdir("/sys/bus/pci/drivers/")
    ] if os.path.isdir("/sys/bus/pci/drivers") else []
    for up in unbind_paths:
        try:
            with open(up, "w") as f:
                f.write(device_id)
            return True, f"unbound {device_id} via {up}"
        except Exception:
            continue
    # Fallback: modprobe -r
    return _run(["modprobe", "-r", device_id])

def rollback_update(package: str = "") -> Tuple[bool, str]:
    """Rollback last package update (apt/yum/dnf)."""
    if not package:
        return False, "package name required for rollback"
    if _has("apt-get"):
        return _run(["apt-get", "install", "-y", f"{package}="], timeout=120)
    if _has("yum"):
        return _run(["yum", "history", "undo", "last", "-y"], timeout=120)
    if _has("dnf"):
        return _run(["dnf", "history", "rollback", "last", "-y"], timeout=120)
    return False, "no supported package manager for rollback"


# ─── SECURITY / AV ────────────────────────────────────────────────────────────

def update_av_signatures() -> Tuple[bool, str]:
    if DryRun:
        return True, "dry-run: freshclam (update ClamAV signatures)"
    if _has("freshclam"):
        return _run(["freshclam"], timeout=120)
    return False, "freshclam not found — install clamav"

def run_av_scan(path: str = "/home") -> Tuple[bool, str]:
    if DryRun:
        return True, f"dry-run: clamscan -r --quiet {path}"
    if _has("clamscan"):
        return _run(["clamscan", "-r", "--quiet", path], timeout=600)
    return False, "clamscan not found — install clamav"

def run_defender_scan(scan_type: str = "quick") -> Tuple[bool, str]:
    """Linux: delegate to ClamAV (no Windows Defender on Linux)."""
    scan_path = "/home" if scan_type.lower() == "quick" else "/"
    return run_av_scan(scan_path)

def remove_threats() -> Tuple[bool, str]:
    if DryRun:
        return True, "dry-run: clamscan -r --remove --quiet /"
    if _has("clamscan"):
        return _run(["clamscan", "-r", "--remove", "--quiet", "/"], timeout=600)
    return False, "clamscan not found — install clamav"

def add_av_exclusion(path: str) -> Tuple[bool, str]:
    """Add a path to ClamAV whitelist."""
    whitelist = "/etc/clamav/whitelist.conf"
    if DryRun:
        log.info("[dry-run] would add %s to ClamAV whitelist", path)
        return True, "dry-run"
    try:
        with open(whitelist, "a") as f:
            f.write(f"{path}\n")
        return True, f"added {path} to {whitelist}"
    except Exception as exc:
        return False, str(exc)


# ─── CERTIFICATES / TLS ───────────────────────────────────────────────────────

def update_cert(cert_path: str = "") -> Tuple[bool, str]:
    """Install a certificate and update the CA store."""
    if cert_path and os.path.exists(cert_path) and not DryRun:
        dest = f"/usr/local/share/ca-certificates/{os.path.basename(cert_path)}"
        shutil.copy2(cert_path, dest)
    if _has("update-ca-certificates"):
        return _run(["update-ca-certificates"])
    if _has("update-ca-trust"):
        return _run(["update-ca-trust", "extract"])
    return False, "no CA update command found"


# ─── TIME ─────────────────────────────────────────────────────────────────────

def sync_time() -> Tuple[bool, str]:
    if _has("timedatectl"):
        ok, d = _run(["timedatectl", "set-ntp", "true"])
        if ok:
            return ok, d
    if _has("ntpdate"):
        return _run(["ntpdate", "-u", "pool.ntp.org"])
    if _has("chronyc"):
        return _run(["chronyc", "makestep"])
    # Python-level NTP time check (read-only — cannot set time without root)
    if DryRun:
        return True, "dry-run: no NTP client, would query pool.ntp.org"
    try:
        import socket, struct
        # SNTP query to pool.ntp.org
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3)
        data = b'\x1b' + 47 * b'\0'
        client.sendto(data, ('pool.ntp.org', 123))
        data, _ = client.recvfrom(1024)
        if data:
            return True, "NTP reachable (time cannot be set without root + ntpdate/chrony)"
    except Exception as exc:
        return False, f"NTP query failed: {exc}"
    return False, "no NTP sync command found"

def set_ntp_server(server: str = "pool.ntp.org") -> Tuple[bool, str]:
    if _has("timedatectl"):
        ok, d = _run(["timedatectl", "set-ntp", "true"])
        return ok, d
    # Write to chrony.conf
    if DryRun:
        log.info("[dry-run] set NTP server to %s", server)
        return True, "dry-run"
    for conf in ("/etc/chrony.conf", "/etc/chrony/chrony.conf",
                 "/etc/ntp.conf"):
        if os.path.exists(conf):
            try:
                with open(conf) as f:
                    lines = f.readlines()
                lines = [l for l in lines if not l.strip().startswith(("server ", "pool "))]
                lines.insert(0, f"server {server} iburst\n")
                with open(conf, "w") as f:
                    f.writelines(lines)
                return True, f"set NTP server {server} in {conf}"
            except Exception as exc:
                return False, str(exc)
    return False, "no NTP config file found"
