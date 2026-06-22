"""
drivers.windows_catalog
───────────────────────
Full Windows fault catalog — every scenario from the guide document
modeled as structured RemediationFix objects with exact commands.

Each FaultEntry maps to one or more RemediationFix objects.
Categories mirror the guide's top-level fault groupings.
"""
from __future__ import annotations

import logging
from typing import List

from healing_core.models import IncidentCategory, RemediationFix
from drivers.windows import (
    _run, _ps,
    restart_service, stop_service, start_service, set_service_auto,
    set_service_recovery, restart_wifi, connect_wifi, flush_dns, set_dns,
    reset_network_stack, release_renew_ip, allow_firewall_port,
    block_ip_firewall, reset_firewall, kill_process, kill_pid,
    lower_process_priority, get_high_cpu_processes, get_high_mem_processes,
    clear_temp_files, drop_memory_cache, get_disk_usage, get_memory_usage,
    disable_account, enable_account, reset_account_password,
    run_defender_scan, remove_threats, update_av_signatures,
    restore_config_from_backup, reset_file_permissions, grant_file_permissions,
    take_file_ownership, repair_system_files, dism_restore_health,
    reg_query, reg_set, reg_delete, clear_print_queue, sync_time, set_ntp_server,
)

log = logging.getLogger("healing_core.drivers.windows_catalog")


def _mk(name, cat, desc, steps, cost=0.3, impact=0.3):
    return RemediationFix(name=name, category=cat, description=desc,
                          steps=steps, cost=cost, impact=impact, source="catalog_windows")


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK — No Connection
# ══════════════════════════════════════════════════════════════════════════════

def wifi_interface_down_fixes() -> List[RemediationFix]:
    return [
        _mk("win_wifi_restart_adapter", IncidentCategory.NETWORK,
            "Restart Wi-Fi adapter via netsh",
            [lambda i: restart_wifi("Wi-Fi")], cost=0.2),

        _mk("win_wifi_connect_network", IncidentCategory.NETWORK,
            "Reconnect to a known SSID",
            [lambda i: connect_wifi("DefaultNetwork")], cost=0.2),

        _mk("win_network_stack_reset", IncidentCategory.NETWORK,
            "netsh winsock reset + ip reset (requires reboot to fully apply)",
            [lambda i: reset_network_stack()], cost=0.5, impact=0.5),
    ]


def dns_failure_fixes() -> List[RemediationFix]:
    return [
        _mk("win_dns_flush", IncidentCategory.NETWORK,
            "ipconfig /flushdns",
            [lambda i: flush_dns()], cost=0.1),

        _mk("win_dns_set_cloudflare", IncidentCategory.NETWORK,
            "Switch to Cloudflare DNS 1.1.1.1",
            [lambda i: set_dns("Wi-Fi", "1.1.1.1"),
             lambda i: flush_dns()], cost=0.2),

        _mk("win_dns_set_google", IncidentCategory.NETWORK,
            "Switch to Google DNS 8.8.8.8",
            [lambda i: set_dns("Wi-Fi", "8.8.8.8"),
             lambda i: flush_dns()], cost=0.2),
    ]


def gateway_unreachable_fixes() -> List[RemediationFix]:
    return [
        _mk("win_ip_release_renew", IncidentCategory.NETWORK,
            "ipconfig /release + /renew — request fresh DHCP lease",
            [lambda i: release_renew_ip()], cost=0.3),

        _mk("win_gateway_reset_stack", IncidentCategory.NETWORK,
            "Full network stack reset for gateway issues",
            [lambda i: reset_network_stack()], cost=0.5, impact=0.5),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK — Firewall Misconfiguration
# ══════════════════════════════════════════════════════════════════════════════

def firewall_block_fixes() -> List[RemediationFix]:
    return [
        _mk("win_fw_allow_port_80", IncidentCategory.NETWORK,
            "Allow inbound TCP 80 via Windows Firewall",
            [lambda i: allow_firewall_port(80, "TCP", "HealingCore_HTTP")], cost=0.3),

        _mk("win_fw_allow_port_443", IncidentCategory.NETWORK,
            "Allow inbound TCP 443 via Windows Firewall",
            [lambda i: allow_firewall_port(443, "TCP", "HealingCore_HTTPS")], cost=0.3),

        _mk("win_fw_reset_defaults", IncidentCategory.NETWORK,
            "Reset firewall to default rules (netsh advfirewall reset)",
            [lambda i: reset_firewall()], cost=0.6, impact=0.6),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK — Port Conflicts
# ══════════════════════════════════════════════════════════════════════════════

def port_conflict_fixes() -> List[RemediationFix]:
    return [
        _mk("win_port_find_conflict", IncidentCategory.NETWORK,
            "Identify process using conflicting port via netstat",
            [lambda i: _run(["netstat", "-ano"])], cost=0.1, impact=0.0),

        _mk("win_port_kill_blocker", IncidentCategory.SERVICE,
            "Kill process occupying the conflicting port",
            [lambda i: _ps(
                f'$pid = (Get-NetTCPConnection -LocalPort '
                f'{i.event.message.split(":")[-1].strip() if ":" in i.event.message else "8080"}'
                f' -ErrorAction SilentlyContinue).OwningProcess; '
                f'if ($pid) {{ Stop-Process -Id $pid -Force }}'
            )], cost=0.5, impact=0.6),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK — Congestion
# ══════════════════════════════════════════════════════════════════════════════

def network_congestion_fixes() -> List[RemediationFix]:
    return [
        _mk("win_net_kill_high_bandwidth", IncidentCategory.NETWORK,
            "Kill high-bandwidth processes causing congestion",
            [lambda i: _ps(
                "Get-NetTCPConnection | Group-Object OwningProcess | "
                "Sort-Object Count -Descending | Select-Object -First 1 | "
                "ForEach-Object { Stop-Process -Id $_.Name -Force }"
            )], cost=0.5, impact=0.6),

        _mk("win_net_reset_adapter", IncidentCategory.NETWORK,
            "Restart high-congestion network adapter",
            [lambda i: _ps('Restart-NetAdapter -Name "Ethernet" -Confirm:$false')], cost=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE — Dependency Failures
# ══════════════════════════════════════════════════════════════════════════════

def service_dependency_fixes() -> List[RemediationFix]:
    return [
        _mk("win_svc_restart_deps", IncidentCategory.SERVICE,
            "Restart failing service and its dependencies",
            [lambda i: restart_service(i.event.actor)], cost=0.3),

        _mk("win_svc_enable_auto", IncidentCategory.SERVICE,
            "Set service to auto-start to survive reboots",
            [lambda i: set_service_auto(i.event.actor)], cost=0.2),

        _mk("win_svc_set_recovery", IncidentCategory.SERVICE,
            "Configure automatic restart on service failure (3 attempts)",
            [lambda i: set_service_recovery(i.event.actor)], cost=0.2),

        _mk("win_svc_repair_sfc", IncidentCategory.SERVICE,
            "sfc /scannow to repair corrupted service files",
            [lambda i: repair_system_files()], cost=0.4, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE — Hung / Crash Loop
# ══════════════════════════════════════════════════════════════════════════════

def service_hung_fixes() -> List[RemediationFix]:
    return [
        _mk("win_svc_force_restart", IncidentCategory.SERVICE,
            "Force-stop then start hung service",
            [lambda i: _run(["taskkill", "/F", "/FI", f"SERVICES eq {i.event.actor}"]),
             lambda i: start_service(i.event.actor)], cost=0.4, impact=0.4),

        _mk("win_svc_increase_timeout", IncidentCategory.SERVICE,
            "Increase service pipe timeout in registry (60 seconds)",
            [lambda i: reg_set(
                r"HKLM\SYSTEM\CurrentControlSet\Control",
                "ServicesPipeTimeout", "60000", "REG_DWORD"
            )], cost=0.2, impact=0.2),

        _mk("win_svc_crash_loop_disable_autostart", IncidentCategory.SERVICE,
            "Disable crash-looping service temporarily",
            [lambda i: _run(["sc", "config", i.event.actor, "start=", "disabled"])],
            cost=0.5, impact=0.7),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE — Account / Permission
# ══════════════════════════════════════════════════════════════════════════════

def service_account_fixes() -> List[RemediationFix]:
    return [
        _mk("win_svc_enable_account", IncidentCategory.AUTHENTICATION,
            "Re-enable disabled service account",
            [lambda i: enable_account(i.event.actor)], cost=0.3, impact=0.4),

        _mk("win_svc_grant_logon_right", IncidentCategory.AUTHENTICATION,
            "Grant 'Log on as a service' right via Local Security Policy",
            [lambda i: _ps(
                f'$computerName = $env:COMPUTERNAME; '
                f'$username = "{i.event.actor}"; '
                f'secedit /export /cfg C:\\Temp\\sec.cfg 2>$null; '
                f'(Get-Content C:\\Temp\\sec.cfg) -replace '
                f'"SeServiceLogonRight =", "SeServiceLogonRight = $username," | '
                f'Set-Content C:\\Temp\\sec_new.cfg; '
                f'secedit /configure /db secedit.sdb /cfg C:\\Temp\\sec_new.cfg 2>$null'
            )], cost=0.5, impact=0.5),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE — Configuration Corruption
# ══════════════════════════════════════════════════════════════════════════════

def service_config_corrupt_fixes() -> List[RemediationFix]:
    return [
        _mk("win_svc_restore_config", IncidentCategory.CONFIGURATION,
            "Restore service config from backup",
            [lambda i: restore_config_from_backup(
                f"C:\\Backup\\{i.event.actor}.config",
                f"C:\\ProgramData\\{i.event.actor}\\app.config"
            )], cost=0.3),

        _mk("win_reg_restore_service", IncidentCategory.CONFIGURATION,
            "Restore service registry key from backup .reg file",
            [lambda i: _run([
                "reg", "restore",
                f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{i.event.actor}",
                f"C:\\Backup\\{i.event.actor}.reg"
            ])], cost=0.4, impact=0.4),

        _mk("win_sfc_dism_repair", IncidentCategory.CONFIGURATION,
            "Full SFC + DISM repair for deep system file corruption",
            [lambda i: repair_system_files(),
             lambda i: dism_restore_health()], cost=0.5, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE — Memory Depletion
# ══════════════════════════════════════════════════════════════════════════════

def memory_depletion_fixes() -> List[RemediationFix]:
    return [
        _mk("win_mem_kill_top_consumer", IncidentCategory.RESOURCE,
            "Kill process with highest memory usage",
            [lambda i: _ps(
                "Get-Process | Sort-Object WorkingSet -Descending | "
                "Select-Object -First 1 | Stop-Process -Force"
            )], cost=0.5, impact=0.7),

        _mk("win_mem_trim_working_sets", IncidentCategory.RESOURCE,
            "Trim all process working sets to release memory to OS",
            [lambda i: drop_memory_cache()], cost=0.3, impact=0.4),

        _mk("win_mem_clear_temp", IncidentCategory.RESOURCE,
            "Delete temp files to free disk and reduce paging pressure",
            [lambda i: clear_temp_files()], cost=0.1, impact=0.2),

        _mk("win_mem_increase_pagefile", IncidentCategory.RESOURCE,
            "Enable automatic managed pagefile for dynamic expansion",
            [lambda i: _run([
                "wmic", "computersystem",
                "where", f"name='{__import__('os').environ.get('COMPUTERNAME','%COMPUTERNAME%')}'",
                "set", "AutomaticManagedPagefile=True"
            ])], cost=0.3, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE — CPU Overload
# ══════════════════════════════════════════════════════════════════════════════

def cpu_overload_fixes() -> List[RemediationFix]:
    return [
        _mk("win_cpu_kill_top_process", IncidentCategory.RESOURCE,
            "Kill top CPU-consuming process",
            [lambda i: _ps(
                "Get-Process | Sort-Object CPU -Descending | "
                "Select-Object -First 1 | Stop-Process -Force"
            )], cost=0.5, impact=0.7),

        _mk("win_cpu_lower_priority", IncidentCategory.RESOURCE,
            "Lower priority of high-CPU process to BelowNormal",
            [lambda i: lower_process_priority(i.event.actor)], cost=0.2, impact=0.3),

        _mk("win_cpu_set_affinity", IncidentCategory.RESOURCE,
            "Limit high-CPU process to 2 CPU cores via processor affinity",
            [lambda i: _ps(
                f'$proc = Get-Process -Name "{i.event.actor}" -ErrorAction SilentlyContinue; '
                f'if ($proc) {{ $proc.ProcessorAffinity = [IntPtr]3 }}'
            )], cost=0.2, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE — Disk Full
# ══════════════════════════════════════════════════════════════════════════════

def disk_full_fixes() -> List[RemediationFix]:
    return [
        _mk("win_disk_clear_temp", IncidentCategory.RESOURCE,
            "Clear temp files from %TEMP% and system temp",
            [lambda i: clear_temp_files(),
             lambda i: _run(["cleanmgr", "/dC", "/sagerun:1"])], cost=0.2),

        _mk("win_disk_find_large_files", IncidentCategory.RESOURCE,
            "List top 10 largest files for manual review",
            [lambda i: _ps(
                "Get-ChildItem C:\\ -Recurse -File -ErrorAction SilentlyContinue | "
                "Sort-Object Length -Descending | Select-Object -First 10 | "
                "Format-Table FullName,@{N='SizeMB';E={[math]::Round($_.Length/1MB,1)}} | "
                "Out-String | Write-Host"
            )], cost=0.1, impact=0.0),

        _mk("win_disk_compress_logs", IncidentCategory.RESOURCE,
            "NTFS compress the Windows log directory to free space",
            [lambda i: _run(["compact", "/c", "/s:C:\\Windows\\Logs"])], cost=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY — Malware
# ══════════════════════════════════════════════════════════════════════════════

def malware_fixes() -> List[RemediationFix]:
    return [
        _mk("win_malware_quick_scan", IncidentCategory.MALWARE,
            "Windows Defender quick scan",
            [lambda i: run_defender_scan("QuickScan")], cost=0.2, impact=0.2),

        _mk("win_malware_full_scan", IncidentCategory.MALWARE,
            "Windows Defender full scan (slow but thorough)",
            [lambda i: run_defender_scan("FullScan")], cost=0.3, impact=0.3),

        _mk("win_malware_update_sigs", IncidentCategory.MALWARE,
            "Update Windows Defender signatures before scan",
            [lambda i: update_av_signatures(),
             lambda i: run_defender_scan("QuickScan")], cost=0.2),

        _mk("win_malware_remove_threats", IncidentCategory.MALWARE,
            "Remove all detected threats via Defender",
            [lambda i: remove_threats()], cost=0.4, impact=0.6),

        _mk("win_malware_isolate_network", IncidentCategory.MALWARE,
            "Disable network adapter to isolate infected machine",
            [lambda i: _ps('Disable-NetAdapter -Name "Ethernet" -Confirm:$false'),
             lambda i: run_defender_scan("FullScan")], cost=0.6, impact=0.9),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY — Process Hijack / Injection
# ══════════════════════════════════════════════════════════════════════════════

def process_hijack_fixes() -> List[RemediationFix]:
    return [
        _mk("win_inject_kill_rogue", IncidentCategory.SECURITY,
            "Kill suspicious process detected with injection indicators",
            [lambda i: kill_process(i.event.actor + ".exe"),
             lambda i: run_defender_scan("QuickScan")], cost=0.5, impact=0.6),

        _mk("win_inject_enable_mitigation", IncidentCategory.SECURITY,
            "Enable DEP + ASLR process mitigations for affected process",
            [lambda i: _ps(
                f'Set-ProcessMitigation -Name "{i.event.actor}.exe" '
                f'-Enable DEP,BottomUp -Confirm:$false 2>$null'
            )], cost=0.3, impact=0.4),

        _mk("win_inject_block_network", IncidentCategory.SECURITY,
            "Block outbound network for suspected injected process",
            [lambda i: _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=BlockInjected_{i.event.actor}", "dir=out", "action=block",
                f"program=C:\\Windows\\System32\\{i.event.actor}.exe"
            ])], cost=0.3, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION — Account Lockout / Credential Issues
# ══════════════════════════════════════════════════════════════════════════════

def auth_failure_fixes() -> List[RemediationFix]:
    return [
        _mk("win_auth_unlock_account", IncidentCategory.AUTHENTICATION,
            "Unlock locked-out user account (local)",
            [lambda i: _run(["net", "user", i.event.actor, "/active:yes"])], cost=0.3),

        _mk("win_auth_clear_cached_creds", IncidentCategory.AUTHENTICATION,
            "Clear Windows Credential Manager cached credentials",
            [lambda i: _ps(
                "cmdkey /list | ForEach-Object { "
                "if ($_ -match 'target=(.+)') { cmdkey /delete:$Matches[1] } }"
            )], cost=0.3, impact=0.4),

        _mk("win_auth_sync_time", IncidentCategory.AUTHENTICATION,
            "Sync time — Kerberos fails if clock drift > 5 minutes",
            [lambda i: sync_time()], cost=0.1),

        _mk("win_auth_block_brute_force_ip", IncidentCategory.AUTHENTICATION,
            "Block IP causing repeated auth failures via Windows Firewall",
            [lambda i: block_ip_firewall(
                i.event.message.split()[-1] if i.event.message else "0.0.0.0",
                f"HealingCore_BlockBruteForce_{i.event.actor}"
            )], cost=0.3, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION — Certificate Expiry
# ══════════════════════════════════════════════════════════════════════════════

def cert_expiry_fixes() -> List[RemediationFix]:
    return [
        _mk("win_cert_list_expired", IncidentCategory.AUTHENTICATION,
            "List all expired certificates in local machine store",
            [lambda i: _ps(
                "Get-ChildItem Cert:\\LocalMachine\\My | "
                "Where-Object {$_.NotAfter -lt (Get-Date)} | "
                "Select-Object Thumbprint,Subject,NotAfter | "
                "Format-Table -AutoSize | Out-String | Write-Host"
            )], cost=0.1, impact=0.0),

        _mk("win_cert_remove_expired", IncidentCategory.AUTHENTICATION,
            "Remove expired certificates from the store",
            [lambda i: _ps(
                "Get-ChildItem Cert:\\LocalMachine\\My | "
                "Where-Object {$_.NotAfter -lt (Get-Date)} | "
                "Remove-Item -Force 2>$null"
            )], cost=0.3, impact=0.3),

        _mk("win_cert_sync_time", IncidentCategory.AUTHENTICATION,
            "Sync time before cert validation (clock skew causes false expiry)",
            [lambda i: sync_time()], cost=0.1),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# HARDWARE — CPU Overheating / Thermal Throttling
# ══════════════════════════════════════════════════════════════════════════════

def cpu_overheat_fixes() -> List[RemediationFix]:
    return [
        _mk("win_thermal_kill_load", IncidentCategory.HARDWARE,
            "Kill top-CPU processes to reduce thermal load",
            [lambda i: _ps(
                "Get-Process | Sort-Object CPU -Descending | "
                "Select-Object -First 3 | Stop-Process -Force 2>$null"
            )], cost=0.5, impact=0.6),

        _mk("win_thermal_power_saver", IncidentCategory.HARDWARE,
            "Switch to Power Saver plan to reduce CPU frequency",
            [lambda i: _run([
                "powercfg", "/setactive", "381b4222-f694-41f0-9685-ff5bb260df2e"
            ])], cost=0.2, impact=0.3),

        _mk("win_thermal_report", IncidentCategory.HARDWARE,
            "Generate power/energy report for thermal diagnostics",
            [lambda i: _run(["powercfg", "/batteryreport",
                              "/output", "C:\\Temp\\batteryreport.html"])], cost=0.1, impact=0.0),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# HARDWARE — Disk Failure / SMART
# ══════════════════════════════════════════════════════════════════════════════

def disk_failure_fixes() -> List[RemediationFix]:
    return [
        _mk("win_disk_chkdsk", IncidentCategory.HARDWARE,
            "Schedule chkdsk on next reboot for /r bad-sector repair",
            [lambda i: _run(["chkdsk", "C:", "/f", "/r", "/x"])], cost=0.4, impact=0.3),

        _mk("win_disk_check_health", IncidentCategory.HARDWARE,
            "Check disk health via WMI",
            [lambda i: _ps(
                "Get-PhysicalDisk | Select-Object FriendlyName,OperationalStatus,"
                "HealthStatus,MediaType | Format-Table | Out-String | Write-Host"
            )], cost=0.1, impact=0.0),

        _mk("win_disk_backup_data", IncidentCategory.HARDWARE,
            "Robocopy data from failing drive to backup location",
            [lambda i: _run([
                "robocopy", "D:\\Data", "E:\\Backup", "/MIR", "/R:2", "/W:5"
            ], timeout=600)], cost=0.4, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# FILE SYSTEM — Access Denied / Permission Errors
# ══════════════════════════════════════════════════════════════════════════════

def file_access_denied_fixes() -> List[RemediationFix]:
    return [
        _mk("win_fs_reset_permissions", IncidentCategory.CONFIGURATION,
            "Reset file/folder ACLs to inherited defaults",
            [lambda i: reset_file_permissions(i.event.message.split()[-1])], cost=0.3),

        _mk("win_fs_grant_permissions", IncidentCategory.CONFIGURATION,
            "Grant read+write to the affected actor",
            [lambda i: grant_file_permissions(
                i.event.message.split()[-1], i.event.actor, "(R,W)"
            )], cost=0.3),

        _mk("win_fs_take_ownership", IncidentCategory.CONFIGURATION,
            "Take ownership of file/folder then grant access",
            [lambda i: take_file_ownership(i.event.message.split()[-1]),
             lambda i: grant_file_permissions(
                 i.event.message.split()[-1], "Administrators", ":(F)"
             )], cost=0.4, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# FILE SYSTEM — Corruption / Locks
# ══════════════════════════════════════════════════════════════════════════════

def file_system_corrupt_fixes() -> List[RemediationFix]:
    return [
        _mk("win_fs_sfc_repair", IncidentCategory.CONFIGURATION,
            "sfc /scannow to repair corrupted system files",
            [lambda i: repair_system_files()], cost=0.4, impact=0.3),

        _mk("win_fs_dism_restore", IncidentCategory.CONFIGURATION,
            "DISM /restorehealth for deeper component repair",
            [lambda i: dism_restore_health()], cost=0.5, impact=0.3),

        _mk("win_fs_kill_file_locker", IncidentCategory.CONFIGURATION,
            "Kill process holding file lock",
            [lambda i: kill_process(i.event.actor + ".exe")], cost=0.4, impact=0.5),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# REGISTRY — Corruption / Permission Errors
# ══════════════════════════════════════════════════════════════════════════════

def registry_fixes() -> List[RemediationFix]:
    return [
        _mk("win_reg_restore_key", IncidentCategory.CONFIGURATION,
            "Restore damaged registry key from backup .reg file",
            [lambda i: _run([
                "reg", "restore",
                f"HKLM\\SOFTWARE\\{i.event.actor}",
                f"C:\\Backup\\{i.event.actor}_registry.reg"
            ])], cost=0.4),

        _mk("win_reg_fix_service_key", IncidentCategory.CONFIGURATION,
            "Re-register core service DLL after registry damage",
            [lambda i: _run([
                "regsvr32", "/s", f"C:\\Windows\\System32\\{i.event.actor}.dll"
            ])], cost=0.3),

        _mk("win_reg_sfc_repair", IncidentCategory.CONFIGURATION,
            "SFC repair for registry-related system file corruption",
            [lambda i: repair_system_files()], cost=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# TIME SYNC
# ══════════════════════════════════════════════════════════════════════════════

def time_sync_fixes() -> List[RemediationFix]:
    return [
        _mk("win_time_resync", IncidentCategory.SYSTEMIC,
            "w32tm /resync to sync with configured NTP server",
            [lambda i: sync_time()], cost=0.1),

        _mk("win_time_set_pool_ntp", IncidentCategory.SYSTEMIC,
            "Configure pool.ntp.org as NTP source and resync",
            [lambda i: set_ntp_server("pool.ntp.org")], cost=0.2),

        _mk("win_time_restart_service", IncidentCategory.SYSTEMIC,
            "Restart Windows Time service",
            [lambda i: _run(["net", "stop", "w32time"]),
             lambda i: _run(["net", "start", "w32time"]),
             lambda i: sync_time()], cost=0.2),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# OS FREEZE — Blue Screen / Unresponsive Shell
# ══════════════════════════════════════════════════════════════════════════════

def os_freeze_fixes() -> List[RemediationFix]:
    return [
        _mk("win_os_restart_explorer", IncidentCategory.SERVICE,
            "Restart Windows Explorer to restore unresponsive shell",
            [lambda i: _run(["taskkill", "/IM", "explorer.exe", "/F"]),
             lambda i: _ps("Start-Process explorer.exe")], cost=0.3),

        _mk("win_os_list_crash_dumps", IncidentCategory.HARDWARE,
            "List recent minidumps for BSOD root-cause analysis",
            [lambda i: _ps(
                "Get-ChildItem C:\\Windows\\Minidump -ErrorAction SilentlyContinue | "
                "Sort-Object LastWriteTime -Descending | Select-Object -First 5 | "
                "Format-Table Name,LastWriteTime | Out-String | Write-Host"
            )], cost=0.1, impact=0.0),

        _mk("win_os_update_driver", IncidentCategory.DRIVER,
            "Disable problematic driver causing BSOD",
            [lambda i: _ps(
                f'$dev = Get-PnpDevice | Where-Object {{$_.Status -eq "Error"}} | '
                f'Select-Object -First 1; '
                f'if ($dev) {{ Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false }}'
            )], cost=0.4, impact=0.5),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# DRIVER — Incompatibility / Crash
# ══════════════════════════════════════════════════════════════════════════════

def driver_fixes() -> List[RemediationFix]:
    return [
        _mk("win_driver_list_errors", IncidentCategory.DRIVER,
            "List all devices with driver errors",
            [lambda i: _ps(
                'Get-PnpDevice | Where-Object {$_.Status -ne "OK"} | '
                "Select-Object Name,Status,Class | Format-Table | Out-String | Write-Host"
            )], cost=0.1, impact=0.0),

        _mk("win_driver_disable_faulty", IncidentCategory.DRIVER,
            "Disable first device with driver error",
            [lambda i: _ps(
                '$dev = Get-PnpDevice | Where-Object {$_.Status -eq "Error"} | '
                'Select-Object -First 1; '
                'if ($dev) { Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false }'
            )], cost=0.4, impact=0.5),

        _mk("win_driver_rollback", IncidentCategory.DRIVER,
            "Roll back most recently changed driver",
            [lambda i: _ps(
                '$dev = Get-PnpDevice | Where-Object {$_.Status -eq "Error"} | '
                'Select-Object -First 1; '
                'if ($dev) { pnputil /revert-driver $dev.InstanceId 2>$null }'
            )], cost=0.4, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# VIRTUALIZATION / CONTAINERS
# ══════════════════════════════════════════════════════════════════════════════

def virtualization_fixes() -> List[RemediationFix]:
    return [
        _mk("win_vm_restart", IncidentCategory.SERVICE,
            "Restart a named Hyper-V VM",
            [lambda i: _ps(f'Restart-VM -Name "{i.event.actor}" -Force 2>$null')], cost=0.4, impact=0.5),

        _mk("win_vm_remove_snapshot", IncidentCategory.SERVICE,
            "Remove corrupted VM snapshot",
            [lambda i: _ps(
                f'Get-VMSnapshot -VMName "{i.event.actor}" | '
                f'Sort-Object CreationTime | Select-Object -Last 1 | '
                f'Remove-VMSnapshot -Confirm:$false 2>$null'
            )], cost=0.4, impact=0.5),

        _mk("win_docker_restart", IncidentCategory.SERVICE,
            "Restart Docker Desktop service",
            [lambda i: restart_service("com.docker.service")], cost=0.3),

        _mk("win_container_prune", IncidentCategory.RESOURCE,
            "Docker system prune to free container/image disk space",
            [lambda i: _run(["docker", "system", "prune", "-f"])], cost=0.3, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# PRINTERS / PERIPHERALS
# ══════════════════════════════════════════════════════════════════════════════

def printer_fixes() -> List[RemediationFix]:
    return [
        _mk("win_printer_clear_queue", IncidentCategory.SERVICE,
            "Clear Windows print spooler queue",
            [lambda i: clear_print_queue()], cost=0.2),

        _mk("win_printer_restart_spooler", IncidentCategory.SERVICE,
            "Restart Print Spooler service only (no queue wipe)",
            [lambda i: restart_service("Spooler")], cost=0.2),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# ELEVATED PRIVILEGE / UAC
# ══════════════════════════════════════════════════════════════════════════════

def privilege_fixes() -> List[RemediationFix]:
    return [
        _mk("win_priv_add_to_admins", IncidentCategory.AUTHENTICATION,
            "Add account to local Administrators group",
            [lambda i: _run(["net", "localgroup", "Administrators",
                              i.event.actor, "/add"])], cost=0.5, impact=0.7),

        _mk("win_priv_grant_logon_service", IncidentCategory.AUTHENTICATION,
            "Export, edit, and reimport local security policy to grant SeServiceLogonRight",
            [lambda i: _run(["secedit", "/export", "/cfg", "C:\\Temp\\sec.cfg"]),
             lambda i: _run(["secedit", "/configure", "/db", "secedit.sdb",
                              "/cfg", "C:\\Temp\\sec.cfg"])], cost=0.4, impact=0.5),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# CLOUD INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════

def cloud_integration_fixes() -> List[RemediationFix]:
    return [
        _mk("win_cloud_test_endpoint", IncidentCategory.DEPENDENCY,
            "Test connectivity to cloud endpoint",
            [lambda i: _ps(
                f'Test-NetConnection -ComputerName api.example.com -Port 443 | '
                f'Select-Object TcpTestSucceeded | Format-List | Out-String | Write-Host'
            )], cost=0.1, impact=0.0),

        _mk("win_cloud_flush_dns_retry", IncidentCategory.DEPENDENCY,
            "Flush DNS and retry failed cloud API endpoint",
            [lambda i: flush_dns()], cost=0.1),

        _mk("win_cloud_reset_proxy", IncidentCategory.DEPENDENCY,
            "Reset WinHTTP proxy settings that may block cloud APIs",
            [lambda i: _run(["netsh", "winhttp", "reset", "proxy"])], cost=0.2),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# CATALOG REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

def all_fixes() -> List[RemediationFix]:
    """Return the complete Windows fault catalog."""
    catalog: List[RemediationFix] = []
    for fn in [
        wifi_interface_down_fixes, dns_failure_fixes, gateway_unreachable_fixes,
        firewall_block_fixes, port_conflict_fixes, network_congestion_fixes,
        service_dependency_fixes, service_hung_fixes, service_account_fixes,
        service_config_corrupt_fixes,
        memory_depletion_fixes, cpu_overload_fixes, disk_full_fixes,
        malware_fixes, process_hijack_fixes,
        auth_failure_fixes, cert_expiry_fixes,
        cpu_overheat_fixes, disk_failure_fixes,
        file_access_denied_fixes, file_system_corrupt_fixes,
        registry_fixes, time_sync_fixes,
        os_freeze_fixes, driver_fixes,
        virtualization_fixes, printer_fixes,
        privilege_fixes, cloud_integration_fixes,
    ]:
        try:
            catalog.extend(fn())
        except Exception as e:
            log.warning("catalog | error building %s: %s", fn.__name__, e)
    return catalog


def register_catalog(registry) -> None:
    """Register the entire Windows fault catalog into a PrimitivesRegistry."""
    fixes = all_fixes()
    for fix in fixes:
        registry.register(fix)
    log.info("windows_catalog | registered %d primitives", len(fixes))
