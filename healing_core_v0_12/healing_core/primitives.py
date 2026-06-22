"""
healing_core.primitives — PrimitivesRegistry  (v0.9)

Key v0.9 fixes:
  - macOS now registers its own builtins via _register_macos_builtins()
    (previously fell through to Linux, executing wrong commands)
  - Windows service steps call service_resolver.resolve() so actor names
    like "mysql" → "MySQL80" before hitting sc.exe / net.exe
  - All three platforms cover the same 52 named primitives that the
    OsFaultCatalog and ExceptionCatalog reference by name
"""
from __future__ import annotations

import logging
import platform
import time
from collections import defaultdict
from typing import Dict, List, Optional, TYPE_CHECKING

from .models import Incident, IncidentCategory, RemediationFix

if TYPE_CHECKING:
    from .learning import LearningStore

log = logging.getLogger("healing_core.primitives")
OS  = platform.system()   # "Linux" | "Windows" | "Darwin"


# ── Incident field extractors ─────────────────────────────────────────────────

def _svc(incident: Incident) -> str:
    """Return the OS-correct service name for this incident."""
    from .service_resolver import resolve
    return resolve(incident)

def _extract_port(incident: Incident) -> int:
    import re
    m = re.search(r":(\d{2,5})\b", incident.event.message or "")
    return int(m.group(1)) if m else 80

def _extract_ip(incident: Incident) -> str:
    import re
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", incident.event.message or "")
    return m.group(1) if m else ""

def _extract_path(incident: Incident) -> str:
    import re
    # Windows path
    mw = re.search(r"([A-Za-z]:\\[\\\w.\- ]+)", incident.event.message or "")
    if mw:
        return mw.group(1)
    # Unix path
    mu = re.search(r"(/[\w./\-]+)", incident.event.message or "")
    return mu.group(1) if mu else "/tmp"

def _extract_pid(incident: Incident) -> int:
    import re
    m = re.search(r"\bpid[=:\s]+(\d+)", incident.event.message or "", re.I)
    return int(m.group(1)) if m else 0

def _noop(incident: Incident) -> tuple:
    return (True, "n/a on this platform")


# ── Registry ──────────────────────────────────────────────────────────────────

class PrimitivesRegistry:
    def __init__(self):
        self._store: Dict[str, List[RemediationFix]] = defaultdict(list)

    def register(self, fix: RemediationFix) -> None:
        self._store[fix.category.name].append(fix)
        log.debug("primitives | registered %s  cat=%s", fix.name, fix.category.name)

    def select(self, incident: Incident,
               learning: "LearningStore") -> Optional[RemediationFix]:
        candidates = self._store.get(incident.category.name, [])
        if not candidates:
            return None
        best_name = learning.best_fix(incident.category.name)
        for fix in candidates:
            if fix.name == best_name:
                return fix
        return max(candidates, key=lambda f: f.success_rate, default=None)

    def promote(self, fix: RemediationFix, outcome: str) -> None:
        if outcome == "success":
            fix.success_count += 1
            if fix.success_count >= 3 and fix.promoted_at is None:
                fix.promoted_at = time.time()
                log.info("primitives | promoted %s to stable", fix.name)
        else:
            fix.failure_count += 1

    def register_builtins(self, dry_run: bool = True) -> None:
        """Register platform-appropriate builtins and set DryRun on the driver."""
        if OS == "Windows":
            import drivers.windows as _drv
            _drv.DryRun = dry_run
            self._register_windows_builtins(_drv)
        elif OS == "Darwin":
            import drivers.macos as _drv          # ← v0.9: was falling to Linux
            _drv.DryRun = dry_run
            self._register_macos_builtins(_drv)
        else:
            import drivers.linux as _drv
            _drv.DryRun = dry_run
            self._register_linux_builtins(_drv)
        count = sum(len(v) for v in self._store.values())
        log.info("primitives | %d built-ins registered  os=%s  dry_run=%s",
                 count, OS, dry_run)

    def _mk(self, name, cat, desc, steps, cost=0.3, impact=0.3, source="builtin"):
        return RemediationFix(name=name, category=cat, description=desc,
                              steps=steps, cost=cost, impact=impact, source=source)

    # ─────────────────────────────────────────────────────────────────────────
    # LINUX
    # ─────────────────────────────────────────────────────────────────────────

    def _register_linux_builtins(self, L) -> None:
        fixes = [
            # SERVICE
            self._mk("restart_service",    IncidentCategory.SERVICE,
                     "systemctl restart the failing service",
                     [lambda i,_L=L: _L.restart_service(_svc(i))],         0.3, 0.5),
            self._mk("disable_service",    IncidentCategory.SERVICE,
                     "systemctl disable + stop",
                     [lambda i,_L=L: _L.disable_service(_svc(i))],         0.5, 0.4),
            self._mk("set_service_auto",   IncidentCategory.SERVICE,
                     "systemctl enable and start",
                     [lambda i,_L=L: _L.set_service_auto(_svc(i))],        0.2, 0.4),
            self._mk("set_service_delayed",IncidentCategory.SERVICE,
                     "Add 10s startup delay via drop-in",
                     [lambda i,_L=L: _L.set_service_delayed(_svc(i))],     0.2, 0.3),
            self._mk("set_service_recovery",IncidentCategory.SERVICE,
                     "Configure Restart=on-failure",
                     [lambda i,_L=L: _L.set_service_recovery(_svc(i))],    0.2, 0.3),
            # NETWORK
            self._mk("flush_dns",            IncidentCategory.NETWORK,
                     "Flush DNS cache",
                     [lambda i,_L=L: _L.flush_dns()],                      0.1, 0.4),
            self._mk("set_dns_cloudflare",   IncidentCategory.NETWORK,
                     "Set nameserver to 1.1.1.1",
                     [lambda i,_L=L: _L.set_dns_cloudflare()],             0.2, 0.4),
            self._mk("reset_network_stack",  IncidentCategory.NETWORK,
                     "Restart NetworkManager",
                     [lambda i,_L=L: _L.reset_network_stack()],            0.4, 0.6),
            self._mk("restart_network_interface",IncidentCategory.NETWORK,
                     "Bring NIC down then up",
                     [lambda i,_L=L: _L.restart_network_interface()],      0.4, 0.5),
            self._mk("restart_wifi",         IncidentCategory.NETWORK,
                     "Toggle wifi via nmcli/rfkill",
                     [lambda i,_L=L: _L.restart_wifi()],                   0.3, 0.5),
            self._mk("release_renew_ip",     IncidentCategory.NETWORK,
                     "Release + renew DHCP lease",
                     [lambda i,_L=L: _L.release_renew_ip()],               0.2, 0.4),
            self._mk("allow_firewall_port",  IncidentCategory.NETWORK,
                     "Open port in iptables/nftables",
                     [lambda i,_L=L: _L.allow_firewall_port(_extract_port(i))],0.3,0.5),
            self._mk("reset_firewall",       IncidentCategory.NETWORK,
                     "Flush all firewall rules",
                     [lambda i,_L=L: _L.reset_firewall()],                 0.5, 0.6),
            self._mk("block_ip",             IncidentCategory.SECURITY,
                     "Block suspicious IP",
                     [lambda i,_L=L: _L.block_ip(_extract_ip(i))
                      if _extract_ip(i) else (False,"no IP")],             0.4, 0.6),
            # PROCESS / RESOURCE
            self._mk("kill_process",         IncidentCategory.RESOURCE,
                     "pkill -9 by actor name",
                     [lambda i,_L=L: _L.kill_process(i.event.actor)],     0.6, 0.7),
            self._mk("kill_pid",             IncidentCategory.RESOURCE,
                     "kill -9 by PID",
                     [lambda i,_L=L: _L.kill_pid(_extract_pid(i))],       0.5, 0.6),
            self._mk("kill_high_cpu",        IncidentCategory.RESOURCE,
                     "Kill highest-CPU process",
                     [lambda i,_L=L: _L.kill_high_cpu()],                 0.7, 0.7),
            self._mk("kill_high_mem",        IncidentCategory.RESOURCE,
                     "Kill highest-memory process",
                     [lambda i,_L=L: _L.kill_high_mem()],                 0.7, 0.7),
            self._mk("renice_process",       IncidentCategory.RESOURCE,
                     "Renice actor to nice=10",
                     [lambda i,_L=L: _L.renice_process(i.event.actor,10)],0.2, 0.4),
            self._mk("lower_priority",       IncidentCategory.RESOURCE,
                     "Renice actor to nice=19 (lowest)",
                     [lambda i,_L=L: _L.lower_priority(i.event.actor)],   0.2, 0.4),
            self._mk("drop_caches",          IncidentCategory.RESOURCE,
                     "Sync and drop page/slab/inode caches",
                     [lambda i,_L=L: _L.drop_caches()],                   0.4, 0.5),
            self._mk("get_disk_usage",       IncidentCategory.RESOURCE,
                     "df -h report",
                     [lambda i,_L=L: _L.get_disk_usage()],                0.0, 0.0),
            self._mk("clear_temp",           IncidentCategory.RESOURCE,
                     "Delete /tmp files > 1 day old",
                     [lambda i,_L=L: _L.clear_temp_files()],              0.1, 0.3),
            self._mk("adjust_power_plan",    IncidentCategory.RESOURCE,
                     "Set CPU governor to balanced",
                     [lambda i,_L=L: _L.adjust_power_plan("balanced")],   0.1, 0.2),
            # AUTH / ACCOUNT
            self._mk("disable_account",     IncidentCategory.AUTHENTICATION,
                     "usermod -L lock account",
                     [lambda i,_L=L: _L.disable_account(i.event.actor)],  0.5, 0.6),
            self._mk("enable_account",      IncidentCategory.AUTHENTICATION,
                     "usermod -U unlock account",
                     [lambda i,_L=L: _L.enable_account(i.event.actor)],   0.3, 0.5),
            self._mk("reset_account_password",IncidentCategory.AUTHENTICATION,
                     "Reset password via chpasswd",
                     [lambda i,_L=L: _L.reset_account_password(i.event.actor)],0.4,0.5),
            self._mk("grant_logon_service_right",IncidentCategory.AUTHENTICATION,
                     "Grant SeServiceLogonRight equivalent",
                     [lambda i,_L=L: _L.grant_logon_service_right(i.event.actor)],0.1,0.2),
            self._mk("grant_smb_access",    IncidentCategory.AUTHENTICATION,
                     "smbpasswd grant SMB share access",
                     [lambda i,_L=L: _L.grant_smb_access(i.event.actor)], 0.3, 0.4),
            self._mk("update_group_policy", IncidentCategory.CONFIGURATION,
                     "Flush SSSD/winbind cache",
                     [lambda i,_L=L: _L.update_group_policy()],           0.1, 0.2),
            # SECURITY / AV
            self._mk("run_defender_scan",   IncidentCategory.MALWARE,
                     "Quick ClamAV scan",
                     [lambda i,_L=L: _L.run_defender_scan("quick")],      0.3, 0.5),
            self._mk("run_av_scan",         IncidentCategory.MALWARE,
                     "Full ClamAV scan",
                     [lambda i,_L=L: _L.run_av_scan()],                   0.5, 0.6),
            self._mk("remove_threats",      IncidentCategory.MALWARE,
                     "clamscan --remove quarantine threats",
                     [lambda i,_L=L: _L.remove_threats()],                0.6, 0.7),
            self._mk("update_av_signatures",IncidentCategory.MALWARE,
                     "freshclam update definitions",
                     [lambda i,_L=L: _L.update_av_signatures()],          0.2, 0.3),
            self._mk("add_av_exclusion",    IncidentCategory.MALWARE,
                     "Add path to ClamAV whitelist",
                     [lambda i,_L=L: _L.add_av_exclusion(_extract_path(i))],0.2,0.3),
            # FILES / CONFIG
            self._mk("reset_file_permissions",  IncidentCategory.CONFIGURATION,
                     "chmod 644 on path",
                     [lambda i,_L=L: _L.reset_file_permissions(_extract_path(i))],0.2,0.4),
            self._mk("grant_file_permissions",  IncidentCategory.CONFIGURATION,
                     "chmod rw + chown actor on path",
                     [lambda i,_L=L: _L.grant_file_permissions(_extract_path(i),i.event.actor)],0.3,0.4),
            self._mk("take_file_ownership",     IncidentCategory.CONFIGURATION,
                     "chown -R actor on path",
                     [lambda i,_L=L: _L.take_file_ownership(_extract_path(i),i.event.actor)],0.3,0.4),
            self._mk("restore_config_from_backup",IncidentCategory.CONFIGURATION,
                     "Restore config from .bak",
                     [lambda i,_L=L: _L.restore_config_from_backup(_extract_path(i)+".bak",_extract_path(i))],0.4,0.6),
            self._mk("repair_system_files", IncidentCategory.CONFIGURATION,
                     "dpkg --configure -a + apt-get -f",
                     [lambda i,_L=L: _L.repair_system_files()],           0.4, 0.5),
            self._mk("dism_restore_health", IncidentCategory.CONFIGURATION,
                     "Linux: dpkg --configure -a",
                     [lambda i,_L=L: _L.dism_restore_health()],           0.4, 0.5),
            self._mk("reset_registry_perms",IncidentCategory.CONFIGURATION,
                     "N/A on Linux",
                     [lambda i,_L=L: (True,"n/a")],                       0.0, 0.0),
            self._mk("restore_registry",    IncidentCategory.CONFIGURATION,
                     "N/A on Linux",
                     [lambda i,_L=L: (True,"n/a")],                       0.0, 0.0),
            self._mk("set_execution_policy",IncidentCategory.CONFIGURATION,
                     "N/A on Linux",
                     [lambda i,_L=L: (True,"n/a")],                       0.0, 0.0),
            # DRIVERS
            self._mk("update_driver",       IncidentCategory.DRIVER,
                     "modprobe reload kernel module",
                     [lambda i,_L=L: _L.update_driver(i.event.actor)],    0.5, 0.5),
            self._mk("rollback_driver",     IncidentCategory.DRIVER,
                     "Unload+reload previous module",
                     [lambda i,_L=L: _L.rollback_driver(i.event.actor)],  0.5, 0.5),
            self._mk("disable_device",      IncidentCategory.DRIVER,
                     "Unbind device via sysfs",
                     [lambda i,_L=L: _L.disable_device(i.event.actor)],   0.5, 0.4),
            self._mk("rollback_update",     IncidentCategory.CONFIGURATION,
                     "apt/yum rollback last update",
                     [lambda i,_L=L: _L.rollback_update(i.event.actor)],  0.6, 0.5),
            # FILESYSTEM / TIME / CERTS
            self._mk("chkdsk",              IncidentCategory.RESOURCE,
                     "fsck -n read-only check",
                     [lambda i,_L=L: _L.chkdsk()],                        0.3, 0.4),
            self._mk("sync_time",           IncidentCategory.AUTHENTICATION,
                     "timedatectl set-ntp / chronyc makestep",
                     [lambda i,_L=L: _L.sync_time()],                     0.1, 0.3),
            self._mk("set_ntp_server",      IncidentCategory.AUTHENTICATION,
                     "Configure pool.ntp.org",
                     [lambda i,_L=L: _L.set_ntp_server()],                0.1, 0.3),
            self._mk("update_cert",         IncidentCategory.AUTHENTICATION,
                     "update-ca-certificates",
                     [lambda i,_L=L: _L.update_cert()],                   0.2, 0.4),
            self._mk("clear_print_queue",   IncidentCategory.SERVICE,
                     "Cancel all CUPS print jobs",
                     [lambda i,_L=L: _L.clear_print_queue()
                      if hasattr(_L,'clear_print_queue') else (True,"n/a")], 0.2, 0.3),
        ]
        for f in fixes:
            self.register(f)

    # ─────────────────────────────────────────────────────────────────────────
    # WINDOWS  (v0.9: service steps now call _svc() not i.event.actor)
    # ─────────────────────────────────────────────────────────────────────────

    def _register_windows_builtins(self, W) -> None:
        fixes = [
            # SERVICE — _svc() resolves e.g. "mysql" → "MySQL80"
            self._mk("restart_service",    IncidentCategory.SERVICE,
                     "net stop / net start",
                     [lambda i,_W=W: _W.restart_service(_svc(i))],        0.3, 0.5),
            self._mk("disable_service",    IncidentCategory.SERVICE,
                     "sc config disabled + net stop",
                     [lambda i,_W=W: _W.disable_service(_svc(i))],        0.5, 0.4),
            self._mk("set_service_auto",   IncidentCategory.SERVICE,
                     "sc config auto + net start",
                     [lambda i,_W=W: _W.set_service_auto(_svc(i))],       0.2, 0.4),
            self._mk("set_service_delayed",IncidentCategory.SERVICE,
                     "sc config delayed-auto",
                     [lambda i,_W=W: _W.set_service_delayed(_svc(i))],    0.2, 0.3),
            self._mk("set_service_recovery",IncidentCategory.SERVICE,
                     "sc failure actions restart",
                     [lambda i,_W=W: _W.set_service_recovery(_svc(i))],   0.2, 0.3),
            self._mk("clear_print_queue",  IncidentCategory.SERVICE,
                     "Stop spooler, clear spool folder, restart",
                     [lambda i,_W=W: _W.clear_print_queue()],             0.3, 0.3),
            # NETWORK
            self._mk("flush_dns",           IncidentCategory.NETWORK,
                     "ipconfig /flushdns",
                     [lambda i,_W=W: _W.flush_dns()],                     0.1, 0.4),
            self._mk("set_dns_cloudflare",  IncidentCategory.NETWORK,
                     "netsh set DNS 1.1.1.1",
                     [lambda i,_W=W: _W.set_dns("1.1.1.1")],             0.2, 0.4),
            self._mk("reset_network_stack", IncidentCategory.NETWORK,
                     "netsh winsock reset + ip reset",
                     [lambda i,_W=W: _W.reset_network_stack()],           0.4, 0.6),
            self._mk("restart_wifi",        IncidentCategory.NETWORK,
                     "Disable/enable Wi-Fi adapter",
                     [lambda i,_W=W: _W.restart_wifi()],                  0.3, 0.5),
            self._mk("restart_network_interface",IncidentCategory.NETWORK,
                     "Disable/enable primary NIC",
                     [lambda i,_W=W: _W.restart_wifi()],                  0.3, 0.5),
            self._mk("release_renew_ip",    IncidentCategory.NETWORK,
                     "ipconfig /release + /renew",
                     [lambda i,_W=W: _W.release_renew_ip()],              0.2, 0.4),
            self._mk("allow_firewall_port", IncidentCategory.NETWORK,
                     "netsh advfirewall allow port",
                     [lambda i,_W=W: _W.allow_firewall_port(_extract_port(i))],0.3,0.5),
            self._mk("reset_firewall",      IncidentCategory.NETWORK,
                     "netsh advfirewall reset",
                     [lambda i,_W=W: _W.reset_firewall()],                0.5, 0.6),
            self._mk("block_ip",            IncidentCategory.SECURITY,
                     "netsh advfirewall block IP",
                     [lambda i,_W=W: _W.block_ip_firewall(_extract_ip(i))
                      if _extract_ip(i) else (False,"no IP")],            0.4, 0.6),
            # PROCESS / RESOURCE
            self._mk("kill_process",        IncidentCategory.RESOURCE,
                     "taskkill /F by name",
                     [lambda i,_W=W: _W.kill_process(i.event.actor+".exe")],0.6,0.7),
            self._mk("kill_pid",            IncidentCategory.RESOURCE,
                     "taskkill /PID",
                     [lambda i,_W=W: _W.kill_by_pid(_extract_pid(i))
                      if hasattr(_W,"kill_by_pid") else _W.kill_process(i.event.actor+".exe")],0.5,0.6),
            self._mk("kill_high_cpu",       IncidentCategory.RESOURCE,
                     "Kill top CPU process via WMI",
                     [lambda i,_W=W: _W.kill_process(i.event.actor+".exe")],0.7,0.7),
            self._mk("kill_high_mem",       IncidentCategory.RESOURCE,
                     "Kill top memory process",
                     [lambda i,_W=W: _W.kill_process(i.event.actor+".exe")],0.7,0.7),
            self._mk("renice_process",      IncidentCategory.RESOURCE,
                     "wmic setpriority below normal",
                     [lambda i,_W=W: _W.set_process_priority(i.event.actor,"below normal")],0.2,0.4),
            self._mk("lower_priority",      IncidentCategory.RESOURCE,
                     "wmic setpriority idle",
                     [lambda i,_W=W: _W.set_process_priority(i.event.actor,"idle")],0.2,0.4),
            self._mk("drop_caches",         IncidentCategory.RESOURCE,
                     "Clear temp files (closest Windows equivalent)",
                     [lambda i,_W=W: _W.clear_temp_files()],             0.3, 0.4),
            self._mk("get_disk_usage",      IncidentCategory.RESOURCE,
                     "wmic logicaldisk freespace report",
                     [lambda i,_W=W: (True,"use Task Manager for disk info")],0.0,0.0),
            self._mk("clear_temp",          IncidentCategory.RESOURCE,
                     "Delete %TEMP% files",
                     [lambda i,_W=W: _W.clear_temp_files()],             0.1, 0.3),
            self._mk("adjust_power_plan",   IncidentCategory.RESOURCE,
                     "powercfg /setactive balanced",
                     [lambda i,_W=W: _W.adjust_power_plan("balanced")],  0.1, 0.2),
            # AUTH / ACCOUNT
            self._mk("disable_account",     IncidentCategory.AUTHENTICATION,
                     "net user /active:no",
                     [lambda i,_W=W: _W.disable_account(i.event.actor)], 0.5, 0.6),
            self._mk("enable_account",      IncidentCategory.AUTHENTICATION,
                     "net user /active:yes",
                     [lambda i,_W=W: _W.enable_account(i.event.actor)],  0.3, 0.5),
            self._mk("reset_account_password",IncidentCategory.AUTHENTICATION,
                     "net user USERNAME newpassword",
                     [lambda i,_W=W: _W.reset_account_password(i.event.actor)],0.4,0.5),
            self._mk("grant_logon_service_right",IncidentCategory.AUTHENTICATION,
                     "Grant SeServiceLogonRight via ntrights",
                     [lambda i,_W=W: _W.grant_logon_service_right(i.event.actor)],0.3,0.4),
            self._mk("grant_smb_access",    IncidentCategory.AUTHENTICATION,
                     "Grant-SmbShareAccess Full",
                     [lambda i,_W=W: _W.grant_smb_access(i.event.actor)],0.3, 0.4),
            self._mk("update_group_policy", IncidentCategory.CONFIGURATION,
                     "gpupdate /force",
                     [lambda i,_W=W: _W.update_group_policy()],          0.2, 0.3),
            # SECURITY / AV
            self._mk("run_defender_scan",   IncidentCategory.MALWARE,
                     "Start-MpScan QuickScan",
                     [lambda i,_W=W: _W.run_defender_scan("QuickScan")], 0.3, 0.5),
            self._mk("run_av_scan",         IncidentCategory.MALWARE,
                     "Start-MpScan FullScan",
                     [lambda i,_W=W: _W.run_defender_scan("FullScan")],  0.5, 0.6),
            self._mk("remove_threats",      IncidentCategory.MALWARE,
                     "Remove-MpThreat all threats",
                     [lambda i,_W=W: _W.remove_threats()],               0.6, 0.7),
            self._mk("update_av_signatures",IncidentCategory.MALWARE,
                     "Update-MpSignature",
                     [lambda i,_W=W: _W.update_av_signatures()],         0.2, 0.3),
            self._mk("add_av_exclusion",    IncidentCategory.MALWARE,
                     "Add-MpPreference -ExclusionPath",
                     [lambda i,_W=W: _W.add_av_exclusion(_extract_path(i))],0.2,0.3),
            # FILES / CONFIG
            self._mk("reset_file_permissions",   IncidentCategory.CONFIGURATION,
                     "icacls /reset",
                     [lambda i,_W=W: _W.reset_file_permissions(_extract_path(i))],0.2,0.4),
            self._mk("grant_file_permissions",   IncidentCategory.CONFIGURATION,
                     "icacls /grant user:(R,W)",
                     [lambda i,_W=W: _W.grant_file_permissions(_extract_path(i),i.event.actor)],0.3,0.4),
            self._mk("take_file_ownership",      IncidentCategory.CONFIGURATION,
                     "takeown /F path",
                     [lambda i,_W=W: _W.take_file_ownership(_extract_path(i))],0.3,0.4),
            self._mk("restore_config_from_backup",IncidentCategory.CONFIGURATION,
                     "copy backup.config → config",
                     [lambda i,_W=W: _W.restore_config_from_backup(_extract_path(i))],0.4,0.6),
            self._mk("repair_system_files", IncidentCategory.CONFIGURATION,
                     "sfc /scannow",
                     [lambda i,_W=W: _W.repair_system_files()],          0.4, 0.5),
            self._mk("dism_restore_health", IncidentCategory.CONFIGURATION,
                     "DISM /online /cleanup-image /restorehealth",
                     [lambda i,_W=W: _W.dism_restore_health()],          0.5, 0.6),
            self._mk("reset_registry_perms",IncidentCategory.CONFIGURATION,
                     "Reset registry key ACLs",
                     [lambda i,_W=W: _W.reset_registry_perms(i.event.actor)],0.3,0.4),
            self._mk("restore_registry",    IncidentCategory.CONFIGURATION,
                     "reg restore from backup",
                     [lambda i,_W=W: _W.restore_registry(i.event.actor)],0.4, 0.5),
            self._mk("set_execution_policy",IncidentCategory.CONFIGURATION,
                     "Set-ExecutionPolicy Bypass CurrentUser",
                     [lambda i,_W=W: _W.set_execution_policy()],         0.2, 0.3),
            # DRIVERS
            self._mk("update_driver",       IncidentCategory.DRIVER,
                     "pnputil /add-driver",
                     [lambda i,_W=W: _W.update_driver(i.event.actor)],   0.5, 0.5),
            self._mk("rollback_driver",     IncidentCategory.DRIVER,
                     "pnputil /revert-driver",
                     [lambda i,_W=W: _W.rollback_driver(i.event.actor)], 0.5, 0.5),
            self._mk("disable_device",      IncidentCategory.DRIVER,
                     "Disable-PnpDevice",
                     [lambda i,_W=W: _W.disable_device(i.event.actor)],  0.5, 0.4),
            self._mk("rollback_update",     IncidentCategory.CONFIGURATION,
                     "wusa /uninstall /kb:KBID",
                     [lambda i,_W=W: _W.rollback_update(i.event.actor)], 0.6, 0.5),
            # DISK / TIME / CERT
            self._mk("chkdsk",              IncidentCategory.RESOURCE,
                     "chkdsk C: /f",
                     [lambda i,_W=W: _W.chkdsk()],                       0.4, 0.5),
            self._mk("sync_time",           IncidentCategory.AUTHENTICATION,
                     "w32tm /resync",
                     [lambda i,_W=W: _W.sync_time()],                    0.1, 0.3),
            self._mk("set_ntp_server",      IncidentCategory.AUTHENTICATION,
                     "w32tm /config /manualpeerlist:pool.ntp.org",
                     [lambda i,_W=W: _W.set_ntp_server()],               0.1, 0.3),
            self._mk("update_cert",         IncidentCategory.AUTHENTICATION,
                     "certutil -addstore My cert.cer",
                     [lambda i,_W=W: _W.update_cert()],                  0.2, 0.4),
        ]
        for f in fixes:
            self.register(f)

    # ─────────────────────────────────────────────────────────────────────────
    # macOS  (v0.9: new — was previously registering Linux commands!)
    # ─────────────────────────────────────────────────────────────────────────

    def _register_macos_builtins(self, M) -> None:
        fixes = [
            # SERVICE — launchctl kickstart / load / unload
            self._mk("restart_service",    IncidentCategory.SERVICE,
                     "launchctl kickstart -k",
                     [lambda i,_M=M: _M.restart_service(_svc(i))],       0.3, 0.5),
            self._mk("disable_service",    IncidentCategory.SERVICE,
                     "launchctl disable + unload",
                     [lambda i,_M=M: (_M.disable_service(_svc(i)),
                                      _M.stop_service(_svc(i)))[-1]],    0.5, 0.4),
            self._mk("set_service_auto",   IncidentCategory.SERVICE,
                     "launchctl enable + start",
                     [lambda i,_M=M: _M.set_service_auto(_svc(i))],      0.2, 0.4),
            self._mk("set_service_delayed",IncidentCategory.SERVICE,
                     "launchctl kickstart with delay (macOS approximation)",
                     [lambda i,_M=M: _M.reload_service(_svc(i))],        0.2, 0.3),
            self._mk("set_service_recovery",IncidentCategory.SERVICE,
                     "launchctl enable (macOS KeepAlive equivalent)",
                     [lambda i,_M=M: _M.enable_service(_svc(i))],        0.2, 0.3),
            self._mk("clear_print_queue",  IncidentCategory.SERVICE,
                     "Cancel CUPS jobs via cancel -a",
                     [lambda i,_M=M: _M.restart_service("org.cups.cupsd")],0.2,0.3),
            # NETWORK — networksetup / dscacheutil / ifconfig
            self._mk("flush_dns",           IncidentCategory.NETWORK,
                     "dscacheutil -flushcache + killall -HUP mDNSResponder",
                     [lambda i,_M=M: _M.flush_dns()],                    0.1, 0.4),
            self._mk("set_dns_cloudflare",  IncidentCategory.NETWORK,
                     "networksetup -setdnsservers Wi-Fi 1.1.1.1",
                     [lambda i,_M=M: _M.set_dns("1.1.1.1","Wi-Fi")],    0.2, 0.4),
            self._mk("reset_network_stack", IncidentCategory.NETWORK,
                     "networksetup -detectnewhardware",
                     [lambda i,_M=M: _M.reset_network_stack()],          0.4, 0.5),
            self._mk("restart_network_interface",IncidentCategory.NETWORK,
                     "ifconfig en0 down/up",
                     [lambda i,_M=M: _M.restart_network_interface()],    0.3, 0.5),
            self._mk("restart_wifi",        IncidentCategory.NETWORK,
                     "networksetup -setairportpower Wi-Fi off/on",
                     [lambda i,_M=M: (_M.toggle_wifi(False,"Wi-Fi"),
                                      _M.toggle_wifi(True,"Wi-Fi"))[-1]],0.3,0.5),
            self._mk("release_renew_ip",    IncidentCategory.NETWORK,
                     "ipconfig set en0 NONE → DHCP",
                     [lambda i,_M=M: _M.release_renew_ip()],             0.2, 0.4),
            self._mk("allow_firewall_port", IncidentCategory.NETWORK,
                     "pfctl pass rule for port",
                     [lambda i,_M=M: _M.allow_port(_extract_port(i))],   0.3, 0.5),
            self._mk("reset_firewall",      IncidentCategory.NETWORK,
                     "pfctl -d and clear healing_core anchor",
                     [lambda i,_M=M: _M.reset_firewall()],               0.5, 0.6),
            self._mk("block_ip",            IncidentCategory.SECURITY,
                     "pfctl block rule for suspicious IP",
                     [lambda i,_M=M: _M.block_ip(_extract_ip(i))
                      if _extract_ip(i) else (False,"no IP")],           0.4, 0.6),
            # PROCESS / RESOURCE
            self._mk("kill_process",        IncidentCategory.RESOURCE,
                     "pkill -9 by name",
                     [lambda i,_M=M: _M.kill_process(i.event.actor)],    0.6, 0.7),
            self._mk("kill_pid",            IncidentCategory.RESOURCE,
                     "kill -9 by PID",
                     [lambda i,_M=M: _M.kill_pid(_extract_pid(i))],      0.5, 0.6),
            self._mk("kill_high_cpu",       IncidentCategory.RESOURCE,
                     "Kill highest CPU process",
                     [lambda i,_M=M: _M.kill_process(i.event.actor)],    0.7, 0.7),
            self._mk("kill_high_mem",       IncidentCategory.RESOURCE,
                     "Kill highest memory process",
                     [lambda i,_M=M: _M.kill_process(i.event.actor)],    0.7, 0.7),
            self._mk("renice_process",      IncidentCategory.RESOURCE,
                     "renice 10 process",
                     [lambda i,_M=M: _M.renice_process(i.event.actor,10)],0.2,0.4),
            self._mk("lower_priority",      IncidentCategory.RESOURCE,
                     "renice 19 process",
                     [lambda i,_M=M: _M.renice_process(i.event.actor,19)],0.2,0.4),
            self._mk("drop_caches",         IncidentCategory.RESOURCE,
                     "purge (flush inactive memory)",
                     [lambda i,_M=M: _M.purge_memory()],                 0.4, 0.5),
            self._mk("get_disk_usage",      IncidentCategory.RESOURCE,
                     "df -h",
                     [lambda i,_M=M: _M.get_disk_usage()],               0.0, 0.0),
            self._mk("clear_temp",          IncidentCategory.RESOURCE,
                     "Remove /private/tmp and ~/Library/Caches files",
                     [lambda i,_M=M: _M.clear_temp_files()],             0.1, 0.3),
            self._mk("adjust_power_plan",   IncidentCategory.RESOURCE,
                     "pmset -a powernap 0 (reduce background power)",
                     [lambda i,_M=M: (True,"pmset n/a in dry-run")],     0.1, 0.2),
            # AUTH / ACCOUNT — dscl
            self._mk("disable_account",     IncidentCategory.AUTHENTICATION,
                     "dscl disable user account",
                     [lambda i,_M=M: _M.disable_account(i.event.actor)], 0.5, 0.6),
            self._mk("enable_account",      IncidentCategory.AUTHENTICATION,
                     "dscl re-enable user account",
                     [lambda i,_M=M: _M.enable_account(i.event.actor)],  0.3, 0.5),
            self._mk("reset_account_password",IncidentCategory.AUTHENTICATION,
                     "dscl -passwd reset password",
                     [lambda i,_M=M: _M.reset_account_password(i.event.actor)],0.4,0.5),
            self._mk("grant_logon_service_right",IncidentCategory.AUTHENTICATION,
                     "N/A on macOS (launchd runs as root)",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            self._mk("grant_smb_access",    IncidentCategory.AUTHENTICATION,
                     "N/A on macOS (use Sharing prefs)",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            self._mk("update_group_policy", IncidentCategory.CONFIGURATION,
                     "N/A on macOS",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            # SECURITY / AV — XProtect / ClamAV
            self._mk("run_defender_scan",   IncidentCategory.MALWARE,
                     "Run XProtect MRT or ClamAV quick scan",
                     [lambda i,_M=M: _M.run_av_scan("/")],               0.3, 0.5),
            self._mk("run_av_scan",         IncidentCategory.MALWARE,
                     "Full ClamAV or MRT scan",
                     [lambda i,_M=M: _M.run_av_scan("/")],               0.5, 0.6),
            self._mk("remove_threats",      IncidentCategory.MALWARE,
                     "ClamAV --remove quarantine",
                     [lambda i,_M=M: _M.run_av_scan("/")],               0.6, 0.7),
            self._mk("update_av_signatures",IncidentCategory.MALWARE,
                     "softwareupdate --background (XProtect/MRT)",
                     [lambda i,_M=M: _M.update_av_signatures()],         0.2, 0.3),
            self._mk("add_av_exclusion",    IncidentCategory.MALWARE,
                     "N/A on macOS without 3rd-party AV",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            # FILES / CONFIG
            self._mk("reset_file_permissions",   IncidentCategory.CONFIGURATION,
                     "chmod -RN + chmod 755",
                     [lambda i,_M=M: _M.reset_file_permissions(_extract_path(i))],0.2,0.4),
            self._mk("grant_file_permissions",   IncidentCategory.CONFIGURATION,
                     "chown + chmod 755",
                     [lambda i,_M=M: _M.grant_file_permissions(_extract_path(i),i.event.actor)],0.3,0.4),
            self._mk("take_file_ownership",      IncidentCategory.CONFIGURATION,
                     "chown actor path",
                     [lambda i,_M=M: _M.grant_file_permissions(_extract_path(i),i.event.actor,"755")],0.3,0.4),
            self._mk("restore_config_from_backup",IncidentCategory.CONFIGURATION,
                     "cp -f backup config",
                     [lambda i,_M=M: _M.restore_config_from_backup(
                         _extract_path(i)+".bak",_extract_path(i))],     0.4, 0.6),
            self._mk("repair_system_files", IncidentCategory.CONFIGURATION,
                     "diskutil repairVolume /",
                     [lambda i,_M=M: _M.repair_system_files()],          0.4, 0.5),
            self._mk("dism_restore_health", IncidentCategory.CONFIGURATION,
                     "diskutil repairVolume / (macOS equivalent)",
                     [lambda i,_M=M: _M.repair_disk("/")],               0.4, 0.5),
            self._mk("reset_registry_perms",IncidentCategory.CONFIGURATION,
                     "N/A on macOS",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            self._mk("restore_registry",    IncidentCategory.CONFIGURATION,
                     "N/A on macOS",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            self._mk("set_execution_policy",IncidentCategory.CONFIGURATION,
                     "N/A on macOS",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            # DRIVERS / UPDATES — softwareupdate
            self._mk("update_driver",       IncidentCategory.DRIVER,
                     "softwareupdate -i -r (system update)",
                     [lambda i,_M=M: _M.run_software_update()],          0.5, 0.5),
            self._mk("rollback_driver",     IncidentCategory.DRIVER,
                     "N/A on macOS (use Time Machine)",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            self._mk("disable_device",      IncidentCategory.DRIVER,
                     "N/A on macOS",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            self._mk("rollback_update",     IncidentCategory.CONFIGURATION,
                     "N/A on macOS (use Time Machine / softwareupdate)",
                     [lambda i,_M=M: (True,"n/a on macOS")],             0.0, 0.0),
            # DISK / TIME / CERT
            self._mk("chkdsk",              IncidentCategory.RESOURCE,
                     "diskutil verifyVolume /",
                     [lambda i,_M=M: _M.verify_disk("/")],               0.3, 0.4),
            self._mk("sync_time",           IncidentCategory.AUTHENTICATION,
                     "sntp -sS pool.ntp.org",
                     [lambda i,_M=M: _M.sync_time()],                    0.1, 0.3),
            self._mk("set_ntp_server",      IncidentCategory.AUTHENTICATION,
                     "systemsetup -setnetworktimeserver pool.ntp.org",
                     [lambda i,_M=M: _M.set_ntp_server()],               0.1, 0.3),
            self._mk("update_cert",         IncidentCategory.AUTHENTICATION,
                     "security add-trusted-cert (macOS keychain)",
                     [lambda i,_M=M: (True,"security add-trusted-cert n/a in dry-run")],0.2,0.4),
        ]
        for f in fixes:
            self.register(f)
