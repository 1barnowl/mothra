"""
drivers.windows
───────────────
Real Windows healing primitives — executes netsh, sc.exe, PowerShell, etc.
All functions are safe to call in dry_run=True mode (log only, no execution).

Each primitive returns (success: bool, detail: str).
"""
from __future__ import annotations

import logging
import subprocess
import time
from typing import Tuple

log = logging.getLogger("healing_core.drivers.windows")

DryRun = False   # set by HealingCore at startup


def _run(cmd: list, timeout: int = 30) -> Tuple[bool, str]:
    """Execute a shell command, return (success, output/error)."""
    if DryRun:
        log.info("[dry-run] would execute: %s", " ".join(str(c) for c in cmd))
        return True, "dry-run"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, (result.stderr or result.stdout).strip()
    except subprocess.TimeoutExpired:
        return False, f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return False, f"command not found: {e}"
    except Exception as e:
        return False, str(e)


def _ps(script: str, timeout: int = 30) -> Tuple[bool, str]:
    """Execute a PowerShell script string."""
    return _run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def restart_wifi(interface: str = "Wi-Fi") -> Tuple[bool, str]:
    """Disable then re-enable the Wi-Fi adapter."""
    ok1, d1 = _run(["netsh", "interface", "set", "interface", interface, "disable"])
    time.sleep(2)
    ok2, d2 = _run(["netsh", "interface", "set", "interface", interface, "enable"])
    return (ok1 and ok2), f"disable={d1} | enable={d2}"


def connect_wifi(ssid: str) -> Tuple[bool, str]:
    return _run(["netsh", "wlan", "connect", f"name={ssid}"])


def flush_dns() -> Tuple[bool, str]:
    return _run(["ipconfig", "/flushdns"])


def set_dns(interface: str = "Wi-Fi", dns: str = "1.1.1.1") -> Tuple[bool, str]:
    return _run([
        "netsh", "interface", "ip", "set", "dns",
        f"name={interface}", "source=static", f"addr={dns}"
    ])


def reset_network_stack() -> Tuple[bool, str]:
    ok1, d1 = _run(["netsh", "winsock", "reset"])
    ok2, d2 = _run(["netsh", "int", "ip", "reset"])
    return (ok1 and ok2), f"winsock={d1} | ip={d2}"


def release_renew_ip() -> Tuple[bool, str]:
    ok1, d1 = _run(["ipconfig", "/release"])
    time.sleep(1)
    ok2, d2 = _run(["ipconfig", "/renew"])
    return (ok1 and ok2), f"release={d1} | renew={d2}"


def allow_firewall_port(port: int, protocol: str = "TCP", rule_name: str = "HealingCore_Allow") -> Tuple[bool, str]:
    return _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=allow",
        f"protocol={protocol}", f"localport={port}",
    ])


def block_ip_firewall(ip: str, rule_name: str = "HealingCore_Block") -> Tuple[bool, str]:
    return _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block",
        f"remoteip={ip}",
    ])


def reset_firewall() -> Tuple[bool, str]:
    return _run(["netsh", "advfirewall", "reset"])


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def restart_service(name: str) -> Tuple[bool, str]:
    ok1, d1 = _run(["net", "stop", name])
    time.sleep(2)
    ok2, d2 = _run(["net", "start", name])
    return ok2, f"stop={d1} | start={d2}"


def start_service(name: str) -> Tuple[bool, str]:
    return _run(["net", "start", name])


def stop_service(name: str) -> Tuple[bool, str]:
    return _run(["net", "stop", name])


def set_service_auto(name: str) -> Tuple[bool, str]:
    return _run(["sc", "config", name, "start=", "auto"])


def set_service_disabled(name: str) -> Tuple[bool, str]:
    return _run(["sc", "config", name, "start=", "disabled"])


def query_service(name: str) -> Tuple[bool, str]:
    return _run(["sc", "query", name])


def set_service_recovery(name: str) -> Tuple[bool, str]:
    """Set service to restart on failure (3 attempts, 60s reset)."""
    return _run([
        "sc", "failure", name,
        "reset=60", "actions=restart/5000/restart/10000/restart/30000"
    ])


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def kill_process(name: str) -> Tuple[bool, str]:
    return _run(["taskkill", "/IM", name, "/F"])


def kill_pid(pid: int) -> Tuple[bool, str]:
    return _run(["taskkill", "/PID", str(pid), "/F"])


def lower_process_priority(name: str) -> Tuple[bool, str]:
    return _ps(f'Get-Process -Name "{name}" | ForEach-Object {{ $_.PriorityClass = "BelowNormal" }}')


def get_high_cpu_processes(top: int = 5) -> Tuple[bool, str]:
    return _ps(
        f"Get-Process | Sort-Object CPU -Descending | Select-Object -First {top} | "
        "Format-Table Name,Id,CPU,WorkingSet -AutoSize | Out-String"
    )


def get_high_mem_processes(top: int = 5) -> Tuple[bool, str]:
    return _ps(
        f"Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First {top} | "
        "Format-Table Name,Id,WorkingSet,CPU -AutoSize | Out-String"
    )


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def clear_temp_files() -> Tuple[bool, str]:
    return _ps('Remove-Item -Path "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue')


def clear_disk_space(drive: str = "C") -> Tuple[bool, str]:
    """Run disk cleanup silently."""
    return _run(["cleanmgr", f"/d{drive}", "/sagerun:1"])


def drop_memory_cache() -> Tuple[bool, str]:
    """Request Windows to trim working sets of all processes."""
    return _ps(
        "Get-Process | ForEach-Object { "
        "try { $_.MinWorkingSet = $_.MinWorkingSet } catch {} }"
    )


def get_disk_usage(drive: str = "C") -> Tuple[bool, str]:
    return _ps(
        f"Get-Volume -DriveLetter {drive} | "
        "Select-Object DriveLetter, @{N='FreeGB';E={[math]::Round($_.SizeRemaining/1GB,2)}}, "
        "@{N='TotalGB';E={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize | Out-String"
    )


def get_memory_usage() -> Tuple[bool, str]:
    return _ps(
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object @{N='FreeGB';E={[math]::Round($_.FreePhysicalMemory/1MB,2)}}, "
        "@{N='TotalGB';E={[math]::Round($_.TotalVisibleMemorySize/1MB,2)}} | "
        "Format-List | Out-String"
    )


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY / AUTH PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def disable_account(username: str) -> Tuple[bool, str]:
    return _run(["net", "user", username, "/active:no"])


def enable_account(username: str) -> Tuple[bool, str]:
    return _run(["net", "user", username, "/active:yes"])


def unlock_account(username: str) -> Tuple[bool, str]:
    return _ps(f'Unlock-ADAccount -Identity "{username}"')


def reset_account_password(username: str, new_password: str) -> Tuple[bool, str]:
    return _run(["net", "user", username, new_password])


def add_firewall_exclusion(program_path: str) -> Tuple[bool, str]:
    return _ps(f'Set-MpPreference -ExclusionPath "{program_path}"')


def run_defender_scan(scan_type: str = "QuickScan") -> Tuple[bool, str]:
    return _ps(f'Start-MpScan -ScanType {scan_type}')


def remove_threats() -> Tuple[bool, str]:
    return _ps("Remove-MpThreat")


def update_av_signatures() -> Tuple[bool, str]:
    return _ps("Update-MpSignature")


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def restore_config_from_backup(src: str, dst: str) -> Tuple[bool, str]:
    return _run(["copy", "/Y", src, dst], timeout=60)


def reset_file_permissions(path: str) -> Tuple[bool, str]:
    return _run(["icacls", path, "/reset", "/T", "/C"])


def grant_file_permissions(path: str, user: str, rights: str = "(R,W)") -> Tuple[bool, str]:
    return _run(["icacls", path, "/grant", f"{user}:{rights}"])


def take_file_ownership(path: str) -> Tuple[bool, str]:
    return _run(["takeown", "/F", path, "/R", "/D", "Y"])


def restart_explorer() -> Tuple[bool, str]:
    ok1, _ = _run(["taskkill", "/IM", "explorer.exe", "/F"])
    time.sleep(1)
    ok2, d = _run(["explorer.exe"])
    return ok2, d


def repair_system_files() -> Tuple[bool, str]:
    return _run(["sfc", "/scannow"], timeout=300)


def dism_restore_health() -> Tuple[bool, str]:
    return _run(
        ["dism", "/online", "/cleanup-image", "/restorehealth"],
        timeout=600,
    )


# ══════════════════════════════════════════════════════════════════════════════
# REGISTRY PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def reg_query(key: str, value: str = "") -> Tuple[bool, str]:
    cmd = ["reg", "query", key]
    if value:
        cmd += ["/v", value]
    return _run(cmd)


def reg_set(key: str, value: str, data: str, reg_type: str = "REG_SZ") -> Tuple[bool, str]:
    return _run(["reg", "add", key, "/v", value, "/t", reg_type, "/d", data, "/f"])


def reg_delete(key: str, value: str = "") -> Tuple[bool, str]:
    cmd = ["reg", "delete", key, "/f"]
    if value:
        cmd += ["/v", value]
    return _run(cmd)


# ══════════════════════════════════════════════════════════════════════════════
# PRINT SPOOLER (from document)
# ══════════════════════════════════════════════════════════════════════════════

def clear_print_queue() -> Tuple[bool, str]:
    ok1, _ = stop_service("Spooler")
    time.sleep(1)
    ok2, _ = _ps('Remove-Item -Path "C:\\Windows\\System32\\spool\\PRINTERS\\*" -Force -ErrorAction SilentlyContinue')
    ok3, d = start_service("Spooler")
    return (ok1 and ok3), f"spooler cleared: {d}"


# ══════════════════════════════════════════════════════════════════════════════
# TIME SYNC
# ══════════════════════════════════════════════════════════════════════════════

def sync_time() -> Tuple[bool, str]:
    ok1, _ = _run(["net", "stop", "w32time"])
    ok2, _ = _run(["net", "start", "w32time"])
    ok3, d = _run(["w32tm", "/resync"])
    return ok3, d


def set_ntp_server(server: str = "pool.ntp.org") -> Tuple[bool, str]:
    ok1, d1 = _run(["w32tm", "/config", f"/manualpeerlist:{server}", "/syncfromflags:manual", "/update"])
    ok2, d2 = sync_time()
    return (ok1 and ok2), f"config={d1} | sync={d2}"

# ══════════════════════════════════════════════════════════════════════════════
# v0.7 ADDITIONS — functions referenced by primitives.py but missing
# ══════════════════════════════════════════════════════════════════════════════

def disable_service(name: str) -> Tuple[bool, str]:
    """sc config disabled + net stop."""
    ok1, _ = _run(["sc", "config", name, "start=", "disabled"])
    ok2, d = _run(["net", "stop", name])
    return ok2, d

def set_service_delayed(name: str) -> Tuple[bool, str]:
    """sc config delayed-auto."""
    return _run(["sc", "config", name, "start=", "delayed-auto"])

def set_process_priority(name: str, priority: str = "below normal") -> Tuple[bool, str]:
    """wmic process where name=X CALL setpriority."""
    return _run([
        "wmic", "process", "where", f"name='{name}'",
        "CALL", "setpriority", priority
    ])

def kill_high_cpu() -> Tuple[bool, str]:
    """Kill the top-CPU process via PowerShell."""
    return _ps(
        "$p = Get-Process | Sort-Object CPU -Descending | "
        "Where-Object {$_.Id -ne $PID -and $_.Id -ne 4} | "
        "Select-Object -First 1; "
        "if ($p) { Stop-Process -Id $p.Id -Force; Write-Host $p.Name } "
        "else { Write-Host 'no candidate' }"
    )

def reset_account_password(username: str, new_password: str = "") -> Tuple[bool, str]:
    """net user USERNAME * — generates random if not supplied."""
    if not new_password:
        import secrets, string
        new_password = "".join(secrets.choice(
            string.ascii_letters + string.digits) for _ in range(16))
    return _run(["net", "user", username, new_password])

def grant_logon_service_right(username: str) -> Tuple[bool, str]:
    """Grant SeServiceLogonRight via secedit (export, edit, import)."""
    if DryRun:
        log.info("[dry-run] would grant SeServiceLogonRight to %s", username)
        return True, "dry-run"
    import tempfile, os
    tmp = tempfile.mkdtemp()
    cfg = os.path.join(tmp, "logon_right.cfg")
    db  = os.path.join(tmp, "secedit.sdb")
    try:
        _run(["secedit", "/export", "/cfg", cfg])
        with open(cfg, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if "SeServiceLogonRight" in content:
            import re
            content = re.sub(
                r"(SeServiceLogonRight\s*=\s*)(.*)",
                lambda m: m.group(1) + m.group(2).rstrip() + f",{username}",
                content
            )
        else:
            content += f"\nSeServiceLogonRight = {username}\n"
        with open(cfg, "w", encoding="utf-8") as f:
            f.write(content)
        ok, d = _run(["secedit", "/configure", "/db", db, "/cfg", cfg, "/quiet"])
        return ok, d
    except Exception as exc:
        return False, str(exc)

def grant_smb_access(username: str, share: str = "") -> Tuple[bool, str]:
    """Grant-SmbShareAccess Full via PowerShell."""
    if not share:
        share = "C$"
    return _ps(
        f"Grant-SmbShareAccess -Name '{share}' -AccountName '{username}' "
        f"-AccessRight Full -Force"
    )

def update_group_policy() -> Tuple[bool, str]:
    """gpupdate /force."""
    return _run(["gpupdate", "/force"])

def add_av_exclusion(path: str) -> Tuple[bool, str]:
    """Add-MpPreference -ExclusionPath."""
    return _ps(f"Add-MpPreference -ExclusionPath '{path}'")

def grant_file_permissions(path: str, user: str,
                           rights: str = "(R,W)") -> Tuple[bool, str]:
    return _run(["icacls", path, "/grant", f"{user}:{rights}"])

def take_file_ownership(path: str) -> Tuple[bool, str]:
    return _run(["takeown", "/F", path, "/R", "/D", "Y"])

def restore_config_from_backup(src: str, dst: str = "") -> Tuple[bool, str]:
    if not dst:
        dst = src.replace(".bak", "") if src.endswith(".bak") else src + ".restored"
    return _run(["copy", "/Y", src, dst])

def update_driver(device_id: str) -> Tuple[bool, str]:
    """pnputil update — best effort."""
    return _ps(
        f"$dev = Get-PnpDevice | Where-Object {{$_.DeviceId -like '*{device_id}*'}}; "
        f"if ($dev) {{ $dev | Update-PnpSignedDriver -Confirm:$false }}"
    )

def rollback_driver(device_id: str) -> Tuple[bool, str]:
    """pnputil /revert-driver."""
    return _run(["pnputil", "/revert-driver", device_id])

def disable_device(device_id: str) -> Tuple[bool, str]:
    """Disable-PnpDevice."""
    return _ps(f"Disable-PnpDevice -InstanceId '{device_id}' -Confirm:$false")

def rollback_update(kb_or_name: str = "") -> Tuple[bool, str]:
    """wusa /uninstall or Remove-WindowsUpdate."""
    if kb_or_name.upper().startswith("KB"):
        return _run(["wusa", f"/KB:{kb_or_name.replace('KB','').replace('kb','')}",
                     "/uninstall", "/quiet", "/norestart"])
    return _ps(f"Get-HotFix | Where-Object {{$_.Description -like '*{kb_or_name}*'}} | "
               f"ForEach-Object {{ wusa /uninstall /KB:$($_.HotFixID) /quiet /norestart }}")

def chkdsk(drive: str = "C:") -> Tuple[bool, str]:
    """Schedule chkdsk on next reboot (can't run on mounted drive)."""
    return _run(["chkdsk", drive, "/f", "/scan"])

def reset_registry_perms(key: str = "") -> Tuple[bool, str]:
    """Reset registry key permissions via PowerShell."""
    if not key:
        return True, "no key specified"
    return _ps(
        f"$acl = Get-Acl 'Registry::{key}'; "
        f"$acl.SetAccessRuleProtection($false, $false); "
        f"Set-Acl 'Registry::{key}' $acl"
    )

def restore_registry(key: str = "") -> Tuple[bool, str]:
    """Restore a registry key from .reg backup."""
    if not key:
        return False, "no key specified"
    backup = f"C:\\HealingCore\\{key.replace('\\','_')}.reg"
    import os
    if not os.path.exists(backup):
        return False, f"backup not found: {backup}"
    return _run(["reg", "import", backup])

def set_execution_policy() -> Tuple[bool, str]:
    """Set PowerShell execution policy to RemoteSigned for CurrentUser."""
    return _ps("Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force")

def adjust_power_plan(plan: str = "balanced") -> Tuple[bool, str]:
    """powercfg /setactive for balanced/high/saver."""
    guids = {
        "balanced":    "381b4222-f694-41f0-9685-ff5bb260df2e",
        "performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
        "powersave":   "a1841308-3541-4fab-bc81-f71556f20b4a",
    }
    guid = guids.get(plan.lower(), guids["balanced"])
    return _run(["powercfg", "/setactive", guid])

def update_cert(cert_path: str = "") -> Tuple[bool, str]:
    """certutil -addstore or Update-TrustedRoots."""
    if cert_path:
        return _run(["certutil", "-addstore", "My", cert_path])
    return _ps("certutil -generateSSTFromWU sstemcert.sst -f")

def set_ntp_server(server: str = "pool.ntp.org") -> Tuple[bool, str]:
    return _run(["w32tm", "/config", f"/manualpeerlist:{server}",
                 "/syncfromflags:manual", "/update"])
