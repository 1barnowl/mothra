"""
drivers.macos_catalog
─────────────────────
Full macOS fault catalog — every scenario from the guide document
modeled as RemediationFix objects using macOS-native commands.

Mirrors linux_catalog.py / windows_catalog.py structure.
"""
from __future__ import annotations

import logging
from typing import List

from healing_core.models import IncidentCategory, RemediationFix
from drivers.macos import (
    restart_service, start_service, stop_service, reload_service,
    enable_service, disable_service, set_service_auto,
    restart_network_interface, flush_dns, set_dns, toggle_wifi, connect_wifi,
    release_renew_ip, reset_network_stack, set_gateway,
    kill_process, kill_pid, renice_process, purge_memory,
    get_high_cpu_processes, get_high_mem_processes,
    verify_disk, repair_disk, get_disk_usage, clear_temp_files,
    enable_firewall, disable_firewall, block_ip, allow_port, reset_firewall,
    disable_account, enable_account, reset_account_password,
    run_av_scan, update_av_signatures,
    sync_time, set_ntp_server,
    repair_system_files, restore_config_from_backup,
    reset_file_permissions, grant_file_permissions,
    run_software_update,
)

log = logging.getLogger("healing_core.drivers.macos_catalog")


def _mk(name, cat, desc, steps, cost=0.3, impact=0.3):
    return RemediationFix(name=name, category=cat, description=desc,
                          steps=steps, cost=cost, impact=impact,
                          source="catalog_macos")


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK
# ══════════════════════════════════════════════════════════════════════════════

def network_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_net_restart_iface", IncidentCategory.NETWORK,
            "Bring network interface en0 down then up",
            [lambda i: restart_network_interface("en0")], cost=0.3),

        _mk("mac_net_toggle_wifi_off_on", IncidentCategory.NETWORK,
            "Toggle Wi-Fi off then on via networksetup",
            [lambda i: (toggle_wifi(False) or None, toggle_wifi(True))[1]], cost=0.2),

        _mk("mac_net_flush_dns", IncidentCategory.NETWORK,
            "Flush DNS cache: dscacheutil + mDNSResponder HUP",
            [lambda i: flush_dns()], cost=0.1),

        _mk("mac_net_set_cloudflare_dns", IncidentCategory.NETWORK,
            "Set Cloudflare 1.1.1.1 as DNS for Wi-Fi",
            [lambda i: set_dns("1.1.1.1", "Wi-Fi")], cost=0.2),

        _mk("mac_net_release_renew_dhcp", IncidentCategory.NETWORK,
            "Release and renew DHCP lease on en0",
            [lambda i: release_renew_ip("en0")], cost=0.3),

        _mk("mac_net_reset_stack", IncidentCategory.NETWORK,
            "Run networksetup -detectnewhardware to reload network",
            [lambda i: reset_network_stack()], cost=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE
# ══════════════════════════════════════════════════════════════════════════════

def service_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_svc_restart", IncidentCategory.SERVICE,
            "Restart service via launchctl kickstart -k",
            [lambda i: restart_service(i.event.actor)], cost=0.3, impact=0.3),

        _mk("mac_svc_start", IncidentCategory.SERVICE,
            "Start a stopped launchd service",
            [lambda i: start_service(i.event.actor)], cost=0.2),

        _mk("mac_svc_reload", IncidentCategory.SERVICE,
            "Send HUP to reload service config",
            [lambda i: reload_service(i.event.actor)], cost=0.1),

        _mk("mac_svc_enable_auto", IncidentCategory.SERVICE,
            "Enable service auto-start at boot",
            [lambda i: set_service_auto(i.event.actor)], cost=0.2),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE
# ══════════════════════════════════════════════════════════════════════════════

def resource_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_res_kill_high_cpu", IncidentCategory.RESOURCE,
            "Kill the highest-CPU process",
            [lambda i: kill_process(i.event.actor or "unknown")], cost=0.5, impact=0.5),

        _mk("mac_res_renice_process", IncidentCategory.RESOURCE,
            "Renice high-CPU process to reduce priority",
            [lambda i: renice_process(i.event.actor, nice=10)], cost=0.2),

        _mk("mac_res_purge_memory", IncidentCategory.RESOURCE,
            "Purge inactive memory pages (requires sudo)",
            [lambda i: purge_memory()], cost=0.3, impact=0.3),

        _mk("mac_res_clear_temp", IncidentCategory.RESOURCE,
            "Clear /private/tmp and ~/Library/Caches",
            [lambda i: clear_temp_files()], cost=0.2),

        _mk("mac_res_disk_check", IncidentCategory.RESOURCE,
            "Verify boot volume via diskutil verifyVolume",
            [lambda i: verify_disk("/")], cost=0.2),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY / MALWARE
# ══════════════════════════════════════════════════════════════════════════════

def security_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_sec_block_ip", IncidentCategory.SECURITY,
            "Block suspicious IP via pf rule",
            [lambda i: block_ip(i.event.message.split()[-1])], cost=0.4, impact=0.4),

        _mk("mac_sec_disable_account", IncidentCategory.SECURITY,
            "Disable suspicious user account",
            [lambda i: disable_account(i.event.actor)], cost=0.5, impact=0.6),

        _mk("mac_sec_enable_fw", IncidentCategory.SECURITY,
            "Enable macOS Application Firewall",
            [lambda i: enable_firewall()], cost=0.2, impact=0.2),

        _mk("mac_sec_av_scan", IncidentCategory.MALWARE,
            "Run AV scan (XProtect MRT or ClamAV)",
            [lambda i: run_av_scan("/")], cost=0.3, impact=0.2),

        _mk("mac_sec_update_av_sigs", IncidentCategory.MALWARE,
            "Update XProtect/MRT signatures via softwareupdate",
            [lambda i: update_av_signatures()], cost=0.1),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def auth_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_auth_reset_password", IncidentCategory.AUTHENTICATION,
            "Reset user account password via dscl",
            [lambda i: reset_account_password(i.event.actor)], cost=0.5, impact=0.5),

        _mk("mac_auth_enable_account", IncidentCategory.AUTHENTICATION,
            "Re-enable a disabled user account",
            [lambda i: enable_account(i.event.actor)], cost=0.4, impact=0.4),

        _mk("mac_auth_flush_credentials", IncidentCategory.AUTHENTICATION,
            "Flush DNS + restart mDNSResponder (often fixes Kerberos issues)",
            [lambda i: flush_dns()], cost=0.1),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

def config_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_cfg_repair_permissions", IncidentCategory.CONFIGURATION,
            "Reset file permissions on affected path",
            [lambda i: reset_file_permissions("/usr/local")], cost=0.3),

        _mk("mac_cfg_restore_backup", IncidentCategory.CONFIGURATION,
            "Restore config from backup copy",
            [lambda i: restore_config_from_backup(
                i.event.message + ".bak", i.event.message
            )], cost=0.4, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# HARDWARE
# ══════════════════════════════════════════════════════════════════════════════

def hardware_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_hw_repair_disk", IncidentCategory.HARDWARE,
            "Run diskutil repairVolume on boot volume",
            [lambda i: repair_disk("/")], cost=0.4, impact=0.3),

        _mk("mac_hw_verify_disk", IncidentCategory.HARDWARE,
            "Verify boot volume integrity",
            [lambda i: verify_disk("/")], cost=0.2),

        _mk("mac_hw_repair_system", IncidentCategory.HARDWARE,
            "Run First Aid on boot volume",
            [lambda i: repair_system_files()], cost=0.4, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# TRANSIENT / SYSTEMIC
# ══════════════════════════════════════════════════════════════════════════════

def transient_fixes() -> List[RemediationFix]:
    return [
        _mk("mac_tr_sync_time", IncidentCategory.TRANSIENT,
            "Sync system clock via sntp",
            [lambda i: sync_time()], cost=0.1),

        _mk("mac_tr_restart_svc", IncidentCategory.TRANSIENT,
            "Restart the affected service",
            [lambda i: restart_service(i.event.actor)], cost=0.3),

        _mk("mac_tr_flush_dns", IncidentCategory.TRANSIENT,
            "Flush DNS to clear stale resolution entries",
            [lambda i: flush_dns()], cost=0.1),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# Registration
# ══════════════════════════════════════════════════════════════════════════════

def register_catalog(registry) -> None:
    """Register all macOS fixes into the PrimitivesRegistry."""
    all_fixes = (
        network_fixes()
        + service_fixes()
        + resource_fixes()
        + security_fixes()
        + auth_fixes()
        + config_fixes()
        + hardware_fixes()
        + transient_fixes()
    )
    for fix in all_fixes:
        registry.register(fix)
    log.info("macos_catalog | registered %d fixes", len(all_fixes))
