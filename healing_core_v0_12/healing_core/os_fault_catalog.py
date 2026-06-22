"""
healing_core.os_fault_catalog
──────────────────────────────
Full OS / system fault taxonomy matching every scenario class in the guidance
document.  This is the *detection* layer — keyword + pattern matching maps a
raw event to one OsFaultEntry, which then names the ordered list of primitives
to try from the Windows / Linux catalogs.

The ExceptionCatalog covers Python-level exceptions (32 entries).
OsFaultCatalog covers OS / service / hardware fault scenarios (~150 entries).

Both catalogs are merged by the RobustExceptionHandler before
returning a recommendation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .models import IncidentCategory, Severity

# ── Entry ──────────────────────────────────────────────────────────────────────

@dataclass
class OsFaultEntry:
    fault_id:       str               # "no_connection.wifi_down"
    title:          str
    category:       IncidentCategory
    severity:       Severity
    keywords:       List[str]         # lowercased tokens for keyword matching
    patterns:       List[str]         # compiled regexes
    fix_primitives: List[str]         # ordered primitive names; first = most preferred
    platform:       str = "all"       # "all" | "windows" | "linux"
    description:    str = ""

_E = OsFaultEntry

# ── Abbreviations ──────────────────────────────────────────────────────────────
N  = IncidentCategory.NETWORK
S  = IncidentCategory.SERVICE
R  = IncidentCategory.RESOURCE
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


def _build_catalog() -> List[OsFaultEntry]:  # noqa: C901
    return [

        # ════════════════════════════════════════════════════════════════
        # NETWORK — No Connection
        # ════════════════════════════════════════════════════════════════
        _E("no_connection.wifi_down", "Wi-Fi Interface Down", N, HI,
           ["wifi","wlan","wireless","no_carrier","adapter","interface_down"],
           [r"wifi.*down", r"wlan.*down", r"no wireless", r"interface.*down",
            r"carrier.*lost"],
           ["restart_wifi","reset_network_stack","flush_dns"],
           platform="windows"),

        _E("no_connection.dns_failure", "DNS Resolution Failure", N, HI,
           ["dns","nxdomain","resolve","lookup","nameserver","domain_not_found"],
           [r"dns.*fail", r"nxdomain", r"name.*not.*known",
            r"getaddrinfo", r"no such host"],
           ["flush_dns","set_dns_cloudflare","reset_network_stack"]),

        _E("no_connection.gateway_unreachable", "Default Gateway Unreachable", N, HI,
           ["gateway","unreachable","dhcp","default_route","no_route"],
           [r"gateway.*unreachable", r"no route to host", r"dhcp.*fail",
            r"default.*gateway"],
           ["release_renew_ip","restart_wifi","reset_network_stack"]),

        # NETWORK — Congestion
        _E("network_congestion.high_packet_loss", "High Packet Loss", N, HI,
           ["packet_loss","packets_lost","jitter","retransmit","drop"],
           [r"packet.?loss", r"\d+% (loss|dropped)", r"retransmit"],
           ["restart_network_interface","flush_dns"]),

        _E("network_congestion.bandwidth_saturation", "Bandwidth Saturation", N, ME,
           ["bandwidth","saturated","throttle","congested","throughput_low"],
           [r"bandwidth.*sat", r"rate.*limit.*hit", r"egress.*full"],
           ["renice_process","kill_high_cpu"]),

        _E("network_congestion.latency_spikes", "Network Latency Spikes", N, ME,
           ["latency","spike","rtt","high_delay","slow_response"],
           [r"latency.*spike", r"rtt.*ms", r"high.*delay"],
           ["flush_dns","restart_network_interface"]),

        # NETWORK — Isolation
        _E("network_isolation.firewall_block", "Firewall Blocking Traffic", N, HI,
           ["firewall","blocked","iptables","nftables","drop_rule","deny"],
           [r"firewall.*block", r"connection.*blocked", r"iptables.*drop",
            r"port.*closed"],
           ["allow_firewall_port","reset_firewall","restart_service"]),

        _E("network_isolation.nat_failure", "NAT / Routing Failure", N, HI,
           ["nat","masquerade","routing","no_nat","forward"],
           [r"nat.*fail", r"masquerade.*error", r"routing.*broken"],
           ["restart_service","reset_network_stack"]),

        _E("network_isolation.proxy_restriction", "Proxy Restriction", N, ME,
           ["proxy","squid","http_proxy","connect_via_proxy"],
           [r"proxy.*error", r"connect.*via.*proxy", r"407"],
           ["reset_network_stack","flush_dns"]),

        # ════════════════════════════════════════════════════════════════
        # ANTIVIRUS / SECURITY BLOCKING
        # ════════════════════════════════════════════════════════════════
        _E("antivirus_blocking.process_quarantine", "Process Quarantined by AV", ML, HI,
           ["quarantine","antivirus","defender","av_block","threat_detected"],
           [r"quarantine", r"threat.*detected", r"antivirus.*block",
            r"defender.*removed"],
           ["add_av_exclusion","update_av_signatures"],
           platform="windows"),

        _E("antivirus_blocking.network_restrictions", "AV Network Restriction", ML, HI,
           ["av_network_block","firewall_av","ips_block","network_restriction"],
           [r"network.*blocked.*av", r"ips.*drop"],
           ["allow_firewall_port","add_av_exclusion"],
           platform="windows"),

        _E("antivirus_blocking.script_execution_blocked", "Script Execution Blocked", SC, ME,
           ["execution_policy","restricted","script_blocked","powershell_blocked"],
           [r"execution.*policy", r"script.*blocked", r"cannot.*execute.*script",
            r"PSSecurityException"],
           ["set_execution_policy"],
           platform="windows"),

        # ════════════════════════════════════════════════════════════════
        # NO DATA AVAILABLE
        # ════════════════════════════════════════════════════════════════
        _E("no_data.empty_log", "Log File Empty or Missing", C, ME,
           ["empty_log","log_missing","no_logs","log_file_not_found"],
           [r"log.*empty", r"no logs", r"log.*not found"],
           ["restart_service","restore_config_from_backup"]),

        _E("no_data.failed_api", "API Endpoint Returning Error", D, HI,
           ["api_error","http_500","http_503","api_down","bad_response"],
           [r"api.*error", r"HTTP 50[0-9]", r"upstream.*error",
            r"502 bad gateway", r"503 service"],
           ["flush_dns","restart_service"]),

        _E("no_data.db_query_timeout", "Database Query Timeout", S, HI,
           ["db_timeout","query_timeout","database_locked","sqlite_busy"],
           [r"database.*lock", r"query.*timeout", r"database is locked",
            r"deadlock.*detected"],
           ["restart_service","clear_temp"]),

        # ════════════════════════════════════════════════════════════════
        # SYSTEM LOCKDOWN
        # ════════════════════════════════════════════════════════════════
        _E("system_lockdown.unauthorized_account", "Unauthorized Account Detected", SC, CR,
           ["unauthorized_account","rogue_user","suspicious_logon","unknown_account"],
           [r"unauthorized.*account", r"rogue.*user", r"unknown.*logon"],
           ["disable_account","run_defender_scan"],
           platform="windows"),

        _E("system_lockdown.permission_errors", "System Permission Errors", C, HI,
           ["permission_denied","access_denied","icacls","acl_error"],
           [r"permission.*denied", r"access.*denied", r"EPERM",
            r"Operation not permitted"],
           ["reset_file_permissions","take_file_ownership"]),

        _E("system_lockdown.service_shutdown", "Critical Service Shut Down", S, CR,
           ["service_shutdown","critical_service_stop","service_killed"],
           [r"service.*shut.?down", r"critical.*service.*stop"],
           ["restart_service","set_service_auto"]),

        # ════════════════════════════════════════════════════════════════
        # RESOURCE STARVATION
        # ════════════════════════════════════════════════════════════════
        _E("resource_starvation.memory_depletion", "Memory Depletion", R, CR,
           ["memory_depletion","oom","out_of_memory","rss_limit","swap_full"],
           [r"out of memory", r"OOM", r"kill.*process.*oom",
            r"memory.*depleted", r"swap.*full"],
           ["drop_caches","kill_high_mem","restart_service"]),

        _E("resource_starvation.cpu_overload", "CPU Overload", R, HI,
           ["cpu_overload","cpu_100","cpu_spike","high_cpu","load_average"],
           [r"cpu.*100", r"load.*average.*\d{2,}", r"cpu.*overload",
            r"processor.*busy"],
           ["renice_process","kill_high_cpu","lower_priority"]),

        _E("resource_starvation.disk_full", "Disk Space Full", R, CR,
           ["disk_full","no_space","enospc","disk_usage_100","inode_exhausted"],
           [r"no space left", r"disk.*full", r"ENOSPC",
            r"disk.*usage.*9[5-9]%", r"inode.*exhausted"],
           ["clear_temp","get_disk_usage"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE DEPENDENCY FAILURE
        # ════════════════════════════════════════════════════════════════
        _E("service_dependency.missing_service", "Missing Dependent Service", S, HI,
           ["missing_dependency","service_not_found","dependency_missing"],
           [r"dependency.*missing", r"service.*not found", r"required.*service"],
           ["restart_service","set_service_auto"]),

        _E("service_dependency.wrong_config", "Incorrect Dependency Configuration", C, ME,
           ["wrong_dependency_config","dependency_misconfigured","sc_config"],
           [r"dependency.*misconfigured", r"wrong.*dependency"],
           ["restore_config_from_backup","restart_service"]),

        _E("service_dependency.dependent_crash", "Dependent Service Crashed", S, HI,
           ["dependent_crash","dependency_crashed","downstream_failure"],
           [r"dependent.*crash", r"dependency.*died", r"downstream.*fail"],
           ["restart_service","repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE ACCOUNT MISCONFIGURATION
        # ════════════════════════════════════════════════════════════════
        _E("svc_account.wrong_password", "Service Account Wrong Password", A, HI,
           ["wrong_password","bad_credentials","logon_failure","event4625"],
           [r"logon.*fail", r"wrong.*password", r"bad.*credentials",
            r"EventID.*4625"],
           ["reset_account_password","enable_account"],
           platform="windows"),

        _E("svc_account.insufficient_perms", "Service Account Insufficient Permissions", A, HI,
           ["seservicelogonright","logon_as_service","insufficient_rights"],
           [r"SeServiceLogonRight", r"logon.*service.*denied",
            r"insufficient.*privileges"],
           ["grant_logon_service_right","reset_file_permissions"],
           platform="windows"),

        _E("svc_account.account_disabled", "Service Account Disabled", A, HI,
           ["account_disabled","disabled_account","event4725"],
           [r"account.*disabled", r"EventID.*4725"],
           ["enable_account","reset_account_password"],
           platform="windows"),

        # ════════════════════════════════════════════════════════════════
        # SERVICE TIMEOUT
        # ════════════════════════════════════════════════════════════════
        _E("svc_timeout.insufficient_startup", "Service Startup Timeout", S, ME,
           ["startup_timeout","service_timeout","event7011"],
           [r"service.*timeout", r"startup.*timeout", r"EventID.*7011"],
           ["set_service_delayed","restart_service"],
           platform="windows"),

        _E("svc_timeout.resource_constraints", "Resource Constraints on Startup", R, HI,
           ["resource_timeout","low_resources","insufficient_resources"],
           [r"resource.*constrain", r"insufficient.*resource"],
           ["kill_high_cpu","drop_caches","restart_service"]),

        _E("svc_timeout.dependency_delays", "Dependency Startup Delays", S, ME,
           ["dependency_delay","startup_order","boot_order_wrong"],
           [r"dependency.*delay", r"waiting.*for.*service"],
           ["set_service_delayed","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE CRASH FROM RESOURCE EXHAUSTION
        # ════════════════════════════════════════════════════════════════
        _E("svc_crash_resource.memory", "Service Crash — Memory Exhaustion", S, CR,
           ["service_memory_crash","oom_killed","heap_exhausted"],
           [r"service.*crash.*memory", r"OOM.*service", r"heap.*exhausted"],
           ["restart_service","drop_caches"]),

        _E("svc_crash_resource.cpu", "Service Crash — CPU Exhaustion", S, HI,
           ["cpu_exhaustion","service_cpu_crash","spin_loop"],
           [r"service.*crash.*cpu", r"cpu.*spin", r"100%.*cpu.*service"],
           ["restart_service","renice_process"]),

        _E("svc_crash_resource.disk", "Service Crash — Disk Exhaustion", S, CR,
           ["disk_exhaustion","service_disk_crash","no_disk_space"],
           [r"service.*crash.*disk", r"disk.*exhaust"],
           ["clear_temp","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE PERMISSION DENIED
        # ════════════════════════════════════════════════════════════════
        _E("svc_perm_denied.file_perms", "Service — Insufficient File Permissions", C, HI,
           ["service_file_permission","access_denied_file","icacls_denied"],
           [r"access.*denied.*file", r"EACCES.*service"],
           ["reset_file_permissions","grant_file_permissions","take_file_ownership"]),

        _E("svc_perm_denied.registry", "Service — Registry Access Denied", C, HI,
           ["registry_denied","reg_access_denied","registry_permission"],
           [r"registry.*denied", r"reg.*access.*denied"],
           ["reset_registry_perms"],
           platform="windows"),

        _E("svc_perm_denied.network_resource", "Service — Network Resource Denied", N, HI,
           ["smb_denied","share_denied","network_access_denied"],
           [r"share.*access.*denied", r"smb.*denied"],
           ["grant_smb_access","allow_firewall_port"],
           platform="windows"),

        # ════════════════════════════════════════════════════════════════
        # SERVICE LOGON FAILURE
        # ════════════════════════════════════════════════════════════════
        _E("svc_logon_failure.invalid_creds", "Service Logon — Invalid Credentials", A, HI,
           ["invalid_credentials","logon_fail","wrong_pass"],
           [r"logon.*fail.*credent", r"invalid.*credentials"],
           ["reset_account_password","enable_account"]),

        _E("svc_logon_failure.account_disabled", "Service Logon — Account Disabled", A, HI,
           ["logon_account_disabled","svc_disabled"],
           [r"logon.*account.*disabled"],
           ["enable_account"]),

        _E("svc_logon_failure.permission_denied", "Service Logon — Permission Denied", A, HI,
           ["logon_permission_denied","no_logon_right"],
           [r"logon.*permission.*denied", r"SeServiceLogonRight.*missing"],
           ["grant_logon_service_right"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE HUNG STATE
        # ════════════════════════════════════════════════════════════════
        _E("svc_hung.resource_overuse", "Service Hung — Resource Overuse", S, HI,
           ["service_hung","hung_service","unresponsive_service"],
           [r"service.*hung", r"service.*unresponsive", r"stop_pending",
            r"service.*not.*respond"],
           ["restart_service","kill_high_cpu","drop_caches"]),

        _E("svc_hung.deadlock", "Service Hung — Deadlock", S, HI,
           ["deadlock","mutex_deadlock","thread_stuck","lock_contention"],
           [r"deadlock", r"mutex.*block", r"lock.*wait.*forever"],
           ["restart_service"]),

        _E("svc_hung.external_unavailable", "Service Hung — External Resource", S, HI,
           ["external_resource_hung","upstream_hang","db_hang"],
           [r"waiting.*external", r"external.*unavailable", r"upstream.*hang"],
           ["restart_service","flush_dns"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE CONFIGURATION CORRUPTION
        # ════════════════════════════════════════════════════════════════
        _E("svc_config_corrupt.config_file", "Corrupted Service Config File", C, HI,
           ["config_corrupt","config_file_corrupt","invalid_config"],
           [r"config.*corrupt", r"config.*invalid", r"parse.*config.*error",
            r"yaml.*error", r"json.*parse.*error"],
           ["restore_config_from_backup","restart_service"]),

        _E("svc_config_corrupt.registry", "Registry Configuration Damage", C, HI,
           ["registry_corrupt","registry_damage","hive_corrupt"],
           [r"registry.*corrupt", r"hive.*damage"],
           ["restore_registry","repair_system_files"],
           platform="windows"),

        _E("svc_config_corrupt.env_vars", "Environment Variable Misconfiguration", C, ME,
           ["env_var_missing","wrong_env","path_wrong","env_misconfigured"],
           [r"env.*misconfigured", r"PATH.*invalid", r"environment.*variable.*missing"],
           ["restore_config_from_backup"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE UPDATE INCOMPATIBILITY
        # ════════════════════════════════════════════════════════════════
        _E("svc_update_compat.driver_conflict", "Driver Update Conflict", DR, HI,
           ["driver_conflict","update_conflict","driver_incompatible"],
           [r"driver.*conflict", r"update.*incompatible", r"after.*update.*fail"],
           ["rollback_driver","update_driver"]),

        _E("svc_update_compat.patch_bug", "Service Patch Bug", S, HI,
           ["patch_bug","buggy_patch","patch_regression"],
           [r"patch.*bug", r"regression.*patch"],
           ["rollback_update","restart_service"],
           platform="windows"),

        _E("svc_update_compat.os_mismatch", "OS Upgrade Mismatch", S, HI,
           ["os_upgrade_mismatch","version_mismatch","api_mismatch"],
           [r"os.*mismatch", r"version.*incompatible", r"api.*not.*supported"],
           ["rollback_update","repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE PORT CONFLICT
        # ════════════════════════════════════════════════════════════════
        _E("svc_port_conflict.duplicate_port", "Duplicate Port Usage", N, HI,
           ["port_in_use","address_in_use","eaddrinuse","port_conflict"],
           [r"port.*in use", r"EADDRINUSE", r"address.*already.*bound",
            r"bind.*failed.*address"],
           ["kill_pid","restart_service"]),

        _E("svc_port_conflict.firewall_block", "Firewall Blocking Service Port", N, HI,
           ["port_blocked","firewall_port_block","port_not_accessible"],
           [r"port.*blocked", r"connection.*refused.*firewall"],
           ["allow_firewall_port","restart_service"]),

        _E("svc_port_conflict.adapter_conflict", "Network Adapter Port Conflict", N, ME,
           ["adapter_conflict","nic_conflict","adapter_port_issue"],
           [r"adapter.*conflict", r"NIC.*conflict"],
           ["restart_network_interface","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # MALWARE DISRUPTION
        # ════════════════════════════════════════════════════════════════
        _E("malware.rogue_process", "Rogue Process Spawned", ML, CR,
           ["rogue_process","spawn_loop","fork_bomb","suspicious_process"],
           [r"rogue.*process", r"fork.*bomb", r"suspicious.*process.*spawn"],
           ["kill_process","run_defender_scan","run_av_scan"]),

        _E("malware.suspicious_file", "Suspicious File Created", ML, CR,
           ["suspicious_file","malware_file","payload_dropped","file_drop"],
           [r"suspicious.*file", r"unknown.*executable", r"malware.*file"],
           ["run_defender_scan","remove_threats","run_av_scan"]),

        _E("malware.abnormal_network", "Abnormal Network Traffic (Malware)", ML, CR,
           ["c2_traffic","malware_network","exfiltration","beaconing","botnet"],
           [r"c2.*traffic", r"exfiltrat", r"beacon.*malware", r"botnet"],
           ["block_ip","run_defender_scan","reset_firewall"]),

        # ════════════════════════════════════════════════════════════════
        # SOFTWARE CRASH LOOP
        # ════════════════════════════════════════════════════════════════
        _E("crash_loop.repeated_app_failure", "Repeated Application Failure", S, HI,
           ["crash_loop","app_crash_loop","repeated_crash","restart_loop"],
           [r"crash.*loop", r"app.*restart.*loop", r"repeated.*crash",
            r"restarting.*too.*fast"],
           ["restart_service","repair_system_files","rollback_update"]),

        _E("crash_loop.service_restart_flood", "Service Restart Flood", S, HI,
           ["restart_flood","rapid_restart","service_bounce"],
           [r"restart.*flood", r"service.*restart.*\d+ times"],
           ["set_service_recovery","restart_service","disable_service"]),

        _E("crash_loop.driver_error_surge", "Driver Error Surge", DR, CR,
           ["driver_surge","driver_crash_loop","bsod_driver"],
           [r"driver.*error.*surge", r"BSOD.*driver", r"kernel.*driver.*crash"],
           ["rollback_driver","disable_device","update_driver"]),

        # ════════════════════════════════════════════════════════════════
        # AUTHENTICATION FAILURE
        # ════════════════════════════════════════════════════════════════
        _E("auth_failure.invalid_credential", "Invalid Credential Rejection", A, HI,
           ["invalid_credential","wrong_password","bad_auth","401"],
           [r"invalid.*credent", r"401 unauthorized", r"authentication.*failed",
            r"wrong.*password"],
           ["reset_account_password","sync_time"]),

        _E("auth_failure.token_expiry", "Authentication Token Expired", A, HI,
           ["token_expired","jwt_expired","kerberos_expired","ticket_expired"],
           [r"token.*expir", r"jwt.*expir", r"kerberos.*expir",
            r"ticket.*expir"],
           ["sync_time","restart_service"]),

        _E("auth_failure.account_lockout", "Account Locked Out", A, HI,
           ["account_lockout","locked_out","event4740","max_attempts"],
           [r"account.*lock", r"EventID.*4740", r"too many.*attempt"],
           ["enable_account","reset_account_password"]),

        # ════════════════════════════════════════════════════════════════
        # EXTERNAL SERVICE OUTAGE
        # ════════════════════════════════════════════════════════════════
        _E("external_outage.api_down", "External API Endpoint Down", D, HI,
           ["api_down","upstream_down","endpoint_unavailable","http503"],
           [r"api.*down", r"endpoint.*unavailable", r"upstream.*unavailable",
            r"503.*service.*unavailable"],
           ["flush_dns","restart_service"]),

        _E("external_outage.cloud_failure", "Cloud Provider Failure", D, CR,
           ["cloud_failure","provider_outage","aws_down","gcp_down","azure_down"],
           [r"cloud.*failure", r"provider.*outage", r"region.*unavailable"],
           ["flush_dns","restart_service"]),

        _E("external_outage.third_party_timeout", "Third-Party Service Timeout", D, ME,
           ["third_party_timeout","upstream_timeout","external_timeout"],
           [r"third.?party.*timeout", r"external.*timeout", r"upstream.*timeout"],
           ["flush_dns","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # CONFIGURATION CORRUPTION
        # ════════════════════════════════════════════════════════════════
        _E("config_corrupt.registry_key", "Registry Key Damaged", C, HI,
           ["registry_damage","registry_corrupt","hive_error"],
           [r"registry.*damage", r"hive.*corrupt", r"reg.*error"],
           ["restore_registry","repair_system_files"],
           platform="windows"),

        _E("config_corrupt.config_overwrite", "Config File Overwritten", C, HI,
           ["config_overwrite","config_clobbered","wrong_config"],
           [r"config.*overwritten", r"config.*clobbered"],
           ["restore_config_from_backup"]),

        _E("config_corrupt.path_misc", "Path Misconfiguration", C, ME,
           ["wrong_path","path_not_found","invalid_path"],
           [r"path.*not found", r"invalid.*path", r"wrong.*path"],
           ["restore_config_from_backup"]),

        # ════════════════════════════════════════════════════════════════
        # POWER SUPPLY / THERMAL
        # ════════════════════════════════════════════════════════════════
        _E("power.battery_drain", "Battery Drain", H, ME,
           ["battery_drain","low_battery","power_saver"],
           [r"battery.*drain", r"low.*battery", r"battery.*\d+%"],
           ["adjust_power_plan"]),

        _E("power.voltage_fluctuation", "Voltage Fluctuation", H, HI,
           ["voltage_fluctuation","power_instability","psu_unstable"],
           [r"voltage.*fluctuat", r"power.*unstable", r"PSU.*error"],
           ["repair_system_files"]),

        _E("power.power_event_failure", "Unexpected Power Event", H, CR,
           ["power_event","unexpected_shutdown","event41"],
           [r"unexpected.*shutdown", r"EventID.*41", r"power.*event.*fail"],
           ["repair_system_files","dism_restore_health"],
           platform="windows"),

        _E("power.sudden_shutdown", "Sudden Shutdown", H, CR,
           ["sudden_shutdown","abrupt_shutdown","power_cut"],
           [r"sudden.*shutdown", r"abrupt.*shutdown", r"power.*cut"],
           ["repair_system_files"]),

        _E("power.ups_disconnect", "UPS Disconnected", H, HI,
           ["ups_disconnect","ups_failure","battery_backup_lost"],
           [r"ups.*disconnect", r"UPS.*fail", r"battery.*backup.*lost"],
           ["adjust_power_plan","repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # FILE SYSTEM ERRORS
        # ════════════════════════════════════════════════════════════════
        _E("filesystem.corrupted_directory", "Corrupted Directory", R, HI,
           ["corrupted_dir","directory_corrupt","dir_error"],
           [r"directory.*corrupt", r"dir.*error", r"fsck.*error"],
           ["chkdsk","repair_system_files"]),

        _E("filesystem.inaccessible_drive", "Drive Inaccessible", R, CR,
           ["drive_inaccessible","drive_offline","disk_not_accessible"],
           [r"drive.*inaccessible", r"disk.*offline", r"drive.*not.*accessible"],
           ["chkdsk","restart_service"]),

        _E("filesystem.file_lock_conflict", "File Lock Conflict", S, ME,
           ["file_locked","file_in_use","lock_conflict","ebusy"],
           [r"file.*lock", r"file.*in use", r"EBUSY", r"sharing.*violation"],
           ["kill_process","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # UNAUTHORIZED PROCESS HIJACK
        # ════════════════════════════════════════════════════════════════
        _E("process_hijack.injection", "Process Injection Detected", SC, CR,
           ["process_injection","dll_injection","code_injection","shellcode"],
           [r"process.*inject", r"DLL.*inject", r"code.*inject"],
           ["kill_process","run_defender_scan"]),

        _E("process_hijack.thread_takeover", "Thread Takeover Detected", SC, CR,
           ["thread_takeover","thread_hijack","remote_thread"],
           [r"thread.*takeover", r"thread.*hijack", r"remote.*thread"],
           ["kill_process","run_defender_scan"]),

        _E("process_hijack.handle_manipulation", "Handle Manipulation", SC, HI,
           ["handle_manipulation","handle_hijack","object_hijack"],
           [r"handle.*manipulat", r"handle.*hijack"],
           ["kill_process","run_defender_scan"]),

        # ════════════════════════════════════════════════════════════════
        # TIME SYNC FAILURE
        # ════════════════════════════════════════════════════════════════
        _E("time_sync.clock_drift", "System Clock Drift", TR, ME,
           ["clock_drift","time_skew","ntp_drift","w32tm"],
           [r"clock.*drift", r"time.*skew", r"NTP.*drift", r"w32tm.*error"],
           ["sync_time","set_ntp_server"]),

        _E("time_sync.ntp_failure", "NTP Server Failure", N, HI,
           ["ntp_failure","ntp_server_down","time_server_fail"],
           [r"NTP.*fail", r"time.*server.*down", r"stratum.*unreachable"],
           ["set_ntp_server","sync_time"]),

        _E("time_sync.timestamp_mismatch", "Timestamp Mismatch", C, ME,
           ["timestamp_mismatch","time_mismatch","kerberos_skew"],
           [r"timestamp.*mismatch", r"kerberos.*clock.*skew",
            r"time.*differ.*too.*large"],
           ["sync_time"]),

        # ════════════════════════════════════════════════════════════════
        # MEMORY LEAK CASCADE
        # ════════════════════════════════════════════════════════════════
        _E("memory_leak.unreleased_handles", "Unreleased File Handles", R, HI,
           ["handle_leak","unreleased_handle","fd_leak","too_many_open_files"],
           [r"handle.*leak", r"too many open files", r"EMFILE",
            r"ENFILE", r"fd.*leak"],
           ["restart_service","kill_process"]),

        _E("memory_leak.heap_overflow", "Heap Overflow / Corruption", R, CR,
           ["heap_overflow","heap_corrupt","heap_exhausted","heap_fragmented"],
           [r"heap.*overflow", r"heap.*corrupt", r"heap.*exhausted"],
           ["restart_service","drop_caches"]),

        _E("memory_leak.gc_stall", "Garbage Collection Stall", R, HI,
           ["gc_stall","gc_pause","full_gc","stop_the_world"],
           [r"GC.*stall", r"full.*GC", r"stop.*the.*world", r"gc.*pause.*ms"],
           ["restart_service","drop_caches"]),

        # ════════════════════════════════════════════════════════════════
        # FIREWALL MISCONFIGURATION
        # ════════════════════════════════════════════════════════════════
        _E("firewall_misc.blocked_inbound", "Firewall Blocking Inbound Traffic", N, HI,
           ["inbound_blocked","firewall_inbound_block"],
           [r"inbound.*block", r"firewall.*drop.*inbound"],
           ["allow_firewall_port","reset_firewall"]),

        _E("firewall_misc.dropped_outbound", "Firewall Dropping Outbound Packets", N, HI,
           ["outbound_dropped","firewall_outbound_drop"],
           [r"outbound.*drop", r"firewall.*block.*outbound"],
           ["allow_firewall_port","reset_firewall"]),

        _E("firewall_misc.rule_overlap", "Firewall Rule Overlap / Conflict", C, ME,
           ["rule_overlap","firewall_conflict","rule_conflict"],
           [r"rule.*overlap", r"firewall.*conflict"],
           ["reset_firewall"]),

        # ════════════════════════════════════════════════════════════════
        # DRIVER INCOMPATIBILITY
        # ════════════════════════════════════════════════════════════════
        _E("driver_compat.kernel_panic", "Kernel Panic from Driver", DR, CR,
           ["kernel_panic","bsod","blue_screen","bugcheck","kernel_crash"],
           [r"kernel.*panic", r"BSOD", r"blue.*screen", r"bugcheck",
            r"KERNEL_DATA_INPAGE_ERROR"],
           ["rollback_driver","disable_device","repair_system_files"]),

        _E("driver_compat.outdated_driver", "Outdated Driver Crash", DR, HI,
           ["outdated_driver","old_driver","driver_version_old"],
           [r"outdated.*driver", r"driver.*version.*incompatible",
            r"old.*driver.*crash"],
           ["update_driver"]),

        _E("driver_compat.hardware_mismatch", "Hardware/Driver Mismatch", DR, HI,
           ["hardware_mismatch","driver_hardware_mismatch","wrong_driver"],
           [r"hardware.*mismatch", r"wrong.*driver", r"driver.*mismatch"],
           ["update_driver","rollback_driver"]),

        # ════════════════════════════════════════════════════════════════
        # HARDWARE FAILURE
        # ════════════════════════════════════════════════════════════════
        _E("hardware.cpu_overheating", "CPU Overheating", H, CR,
           ["cpu_overheat","thermal_throttle","high_temp","cpu_temp"],
           [r"cpu.*overheat", r"thermal.*throttl", r"temperature.*critical",
            r"TjMax.*exceeded"],
           ["lower_priority","kill_high_cpu"]),

        _E("hardware.disk_crash", "Disk Crash / Failure", H, CR,
           ["disk_crash","disk_failure","smart_error","bad_sectors","disk_dead"],
           [r"disk.*crash", r"disk.*fail", r"SMART.*error", r"bad.*sector",
            r"I/O.*error.*disk"],
           ["chkdsk"]),

        _E("hardware.ram_fault", "RAM Fault", H, CR,
           ["ram_fault","memory_fault","ecc_error","dimm_error"],
           [r"RAM.*fault", r"memory.*fault", r"ECC.*error", r"DIMM.*error",
            r"uncorrectable.*memory"],
           ["repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # OS FREEZE
        # ════════════════════════════════════════════════════════════════
        _E("os_freeze.blue_screen", "Blue Screen / Kernel Panic", H, CR,
           ["blue_screen","bsod","kernel_panic_os","stop_error"],
           [r"0x[0-9A-Fa-f]{8}", r"STOP.*0x", r"CRITICAL_PROCESS_DIED",
            r"kernel.*panic"],
           ["rollback_driver","repair_system_files","dism_restore_health"]),

        _E("os_freeze.unresponsive_shell", "Shell / Desktop Unresponsive", S, HI,
           ["shell_unresponsive","explorer_hang","desktop_freeze"],
           [r"explorer.*hang", r"shell.*unresponsive", r"desktop.*freeze"],
           ["restart_service"]),

        _E("os_freeze.kernel_lockup", "Kernel Lockup / NMI", H, CR,
           ["kernel_lockup","nmi_watchdog","softlockup","hardlockup"],
           [r"kernel.*lockup", r"NMI.*watchdog", r"soft.*lockup",
            r"hard.*lockup"],
           ["repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # CRITICAL SERVICE FAILURE
        # ════════════════════════════════════════════════════════════════
        _E("critical_svc.task_scheduler", "Task Scheduler Stopped", S, CR,
           ["task_scheduler_stop","scheduler_stopped","event7036_schedule"],
           [r"Task Scheduler.*stop", r"Schedule.*service.*stop"],
           ["restart_service"],
           platform="windows"),

        _E("critical_svc.network_service_crash", "Network Service Crash", N, CR,
           ["dns_crash","netman_crash","network_service_crashed"],
           [r"network.*service.*crash", r"DNS.*crash", r"Netlogon.*crash"],
           ["restart_service","reset_network_stack"]),

        _E("critical_svc.system_process_halt", "Critical System Process Halt", S, CR,
           ["svchost_halt","lsass_halt","system_process_stop","winlogon_halt"],
           [r"svchost.*halt", r"lsass.*stop", r"winlogon.*crash",
            r"critical.*process.*halt"],
           ["repair_system_files","dism_restore_health"]),

        # ════════════════════════════════════════════════════════════════
        # STORAGE INACCESSIBILITY
        # ════════════════════════════════════════════════════════════════
        _E("storage.drive_unmounted", "Drive Unmounted Unexpectedly", R, HI,
           ["drive_unmounted","volume_unmounted","disk_offline"],
           [r"drive.*unmount", r"volume.*unmount", r"disk.*offline"],
           ["chkdsk","restart_service"]),

        _E("storage.partition_corruption", "Partition Table Corruption", R, CR,
           ["partition_corrupt","mbr_corrupt","gpt_corrupt","partition_table_error"],
           [r"partition.*corrupt", r"MBR.*corrupt", r"GPT.*error",
            r"partition.*table.*damage"],
           ["chkdsk","repair_system_files"]),

        _E("storage.filesystem_lock", "File System Locked", R, HI,
           ["filesystem_lock","fs_readonly","remounted_readonly","readonly_mount"],
           [r"filesystem.*lock", r"mounted.*read.only", r"remounted.*ro"],
           ["restart_service","chkdsk"]),

        # ════════════════════════════════════════════════════════════════
        # NETWORK ISOLATION (extended)
        # ════════════════════════════════════════════════════════════════
        _E("network_isolation.firewall_block_deep", "Deep Firewall Block", N, HI,
           ["stateful_block","connection_track_fail","conntrack"],
           [r"conntrack.*full", r"stateful.*block"],
           ["reset_firewall","restart_network_interface"]),

        # ════════════════════════════════════════════════════════════════
        # PROCESS TERMINATION
        # ════════════════════════════════════════════════════════════════
        _E("process_termination.antivirus_kill", "Process Killed by Antivirus", ML, HI,
           ["av_kill","antivirus_terminate","defender_kill"],
           [r"antivirus.*kill", r"defender.*terminat", r"AV.*removed.*process"],
           ["add_av_exclusion","run_defender_scan"]),

        _E("process_termination.policy_block", "Process Blocked by Policy", SC, ME,
           ["policy_block","applocker_block","srp_block","gpo_block"],
           [r"AppLocker.*block", r"SRP.*block", r"policy.*restrict.*execut"],
           ["update_group_policy"],
           platform="windows"),

        # ════════════════════════════════════════════════════════════════
        # DATA TRANSMISSION BLOCK
        # ════════════════════════════════════════════════════════════════
        _E("data_tx_block.port_closure", "Port Closed / Not Listening", N, HI,
           ["port_closed","port_not_listening","refused_port"],
           [r"port.*closed", r"port.*not.*listen", r"refused.*port"],
           ["allow_firewall_port","restart_service"]),

        _E("data_tx_block.packet_filter", "Packet Filtering Dropping Data", N, HI,
           ["packet_filter","deep_inspection","dpi_block"],
           [r"packet.*filter.*drop", r"DPI.*block"],
           ["reset_firewall","allow_firewall_port"]),

        _E("data_tx_block.protocol_mismatch", "Protocol Version Mismatch", C, ME,
           ["protocol_mismatch","tls_mismatch","version_mismatch_proto"],
           [r"protocol.*mismatch", r"TLS.*version.*mismatch", r"SSL.*handshake.*version"],
           ["sync_time","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # AUTHENTICATION REJECTION
        # ════════════════════════════════════════════════════════════════
        _E("auth_rejection.credential_revocation", "Credentials Revoked", A, HI,
           ["credential_revoked","cred_revoked","access_revoked"],
           [r"credential.*revok", r"access.*revoked", r"token.*revoked"],
           ["reset_account_password","enable_account"]),

        _E("auth_rejection.oauth_failure", "OAuth Token Failure", A, HI,
           ["oauth_failure","bearer_expired","access_token_fail"],
           [r"oauth.*fail", r"bearer.*expired", r"access_token.*invalid"],
           ["sync_time","restart_service"]),

        _E("auth_rejection.cert_expiry", "TLS Certificate Expired", A, HI,
           ["cert_expired","certificate_expired","ssl_cert_expiry"],
           [r"certificate.*expir", r"SSL.*cert.*expir", r"x509.*expir",
            r"CERTIFICATE_VERIFY_FAILED"],
           ["sync_time","update_cert"]),

        # ════════════════════════════════════════════════════════════════
        # SOFTWARE DEPENDENCY CONFLICT
        # ════════════════════════════════════════════════════════════════
        _E("dep_conflict.lib_versions", "Incompatible Library Versions", D, HI,
           ["dll_conflict","lib_conflict","so_conflict","version_conflict_lib"],
           [r"dll.*conflict", r"library.*version.*conflict",
            r"\.so.*not found", r"incompatible.*library"],
           ["restore_config_from_backup","repair_system_files"]),

        _E("dep_conflict.runtime_mismatch", "Mismatched Runtime Environment", D, HI,
           ["runtime_mismatch",".net_version","java_version","python_version_wrong"],
           [r"runtime.*mismatch", r"\.NET.*version.*required",
            r"Python.*version.*required", r"JVM.*version.*mismatch"],
           ["restore_config_from_backup"]),

        _E("dep_conflict.module_conflict", "Conflicting Module Dependencies", D, HI,
           ["module_conflict","pip_conflict","npm_conflict","dependency_hell"],
           [r"module.*conflict", r"pip.*conflict", r"dependency.*hell",
            r"incompatible.*version.*requirement"],
           ["restore_config_from_backup"]),

        # ════════════════════════════════════════════════════════════════
        # VIRTUALIZATION / CONTAINERS
        # ════════════════════════════════════════════════════════════════
        _E("virt.vm_snapshot_corrupt", "VM Snapshot Corruption", C, HI,
           ["snapshot_corrupt","vm_snapshot_error","checkpoint_corrupt"],
           [r"snapshot.*corrupt", r"checkpoint.*fail", r"VM.*snapshot.*error"],
           ["restart_service"]),

        _E("virt.container_net_misc", "Container Network Misconfiguration", N, HI,
           ["container_network","docker_network_error","cni_error"],
           [r"container.*network.*error", r"CNI.*fail", r"docker.*network"],
           ["reset_network_stack","restart_service"]),

        _E("virt.resource_overload", "VM/Container Resource Overload", R, HI,
           ["vm_resource_overload","container_oom","pod_oom","evicted"],
           [r"container.*OOM", r"pod.*evicted", r"VM.*resource.*overload"],
           ["drop_caches","kill_high_mem","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # BIOS / FIRMWARE
        # ════════════════════════════════════════════════════════════════
        _E("bios.failed_update", "BIOS Update Failed", H, CR,
           ["bios_update_fail","firmware_flash_fail","uefi_update_fail"],
           [r"BIOS.*update.*fail", r"firmware.*flash.*fail", r"UEFI.*error"],
           ["repair_system_files"]),

        _E("bios.malware_firmware", "Malware-Induced Firmware Damage", ML, CR,
           ["firmware_malware","bootkitmalware","uefi_malware","bios_malware"],
           [r"firmware.*malware", r"bootkit", r"UEFI.*malware"],
           ["run_defender_scan","repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # EVENT LOG
        # ════════════════════════════════════════════════════════════════
        _E("event_log.clearing_attempt", "Event Log Clearing Attempt", SC, HI,
           ["log_cleared","event1102","log_clearing"],
           [r"log.*cleared", r"EventID.*1102", r"audit.*log.*cleared"],
           ["run_defender_scan"],
           platform="windows"),

        _E("event_log.flooding", "Event Log Flooding", R, ME,
           ["log_flood","event_storm","event_flooding"],
           [r"log.*flood", r"event.*storm", r"too many.*events"],
           ["restart_service"]),

        _E("event_log.corruption", "Event Log File Corrupted", C, HI,
           ["log_corrupt","evtx_corrupt","event_log_corrupt"],
           [r"event.*log.*corrupt", r"evtx.*error"],
           ["repair_system_files"],
           platform="windows"),

        # ════════════════════════════════════════════════════════════════
        # SYSTEM UPDATE FAILURE
        # ════════════════════════════════════════════════════════════════
        _E("sys_update.patch_stall", "Windows Update Patch Stall", S, ME,
           ["windows_update_stall","patch_stuck","update_hang"],
           [r"Windows Update.*stall", r"update.*stuck", r"patch.*hang"],
           ["restart_service","repair_system_files"],
           platform="windows"),

        _E("sys_update.download_error", "Update Download Error", N, ME,
           ["update_download_error","bits_error","wuauserv_download"],
           [r"update.*download.*error", r"BITS.*error", r"download.*update.*fail"],
           ["flush_dns","reset_network_stack"],
           platform="windows"),

        _E("sys_update.rollback_failure", "Update Rollback Failure", C, CR,
           ["update_rollback_fail","patch_rollback_error","wusa_rollback"],
           [r"update.*rollback.*fail", r"patch.*rollback.*error"],
           ["repair_system_files","dism_restore_health"],
           platform="windows"),

        # ════════════════════════════════════════════════════════════════
        # PERIPHERAL / DEVICE
        # ════════════════════════════════════════════════════════════════
        _E("peripheral.driver_conflict", "Peripheral Driver Conflict", DR, HI,
           ["peripheral_conflict","device_driver_conflict","pnp_error"],
           [r"peripheral.*conflict", r"PnP.*error", r"device.*driver.*conflict"],
           ["update_driver","rollback_driver","disable_device"]),

        _E("peripheral.hardware_malfunction", "Peripheral Hardware Malfunction", H, HI,
           ["device_malfunction","hardware_fail","device_error"],
           [r"device.*malfunction", r"hardware.*fail", r"device.*error.*\d"],
           ["disable_device","update_driver"]),

        # ════════════════════════════════════════════════════════════════
        # OVERCLOCKING / THERMAL
        # ════════════════════════════════════════════════════════════════
        _E("thermal.cpu_throttling", "CPU Thermal Throttling", H, HI,
           ["cpu_throttle","thermal_throttle_cpu","frequency_scaling"],
           [r"cpu.*throttl", r"thermal.*throttl", r"frequency.*scaling.*thermal"],
           ["lower_priority","kill_high_cpu"]),

        _E("thermal.gpu_throttling", "GPU Thermal Throttling", H, HI,
           ["gpu_throttle","gpu_thermal","gpu_temp_limit"],
           [r"GPU.*throttl", r"gpu.*thermal.*limit"],
           ["lower_priority","kill_process"]),

        # ════════════════════════════════════════════════════════════════
        # ACPI
        # ════════════════════════════════════════════════════════════════
        _E("acpi.driver_incompatibility", "ACPI Driver Incompatibility", DR, HI,
           ["acpi_error","acpi_driver_fail","acpi_incompatible"],
           [r"ACPI.*error", r"ACPI.*driver.*fail", r"ACPI_BIOS_ERROR"],
           ["rollback_driver","repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # FILE ACCESS DENIED
        # ════════════════════════════════════════════════════════════════
        _E("file_access_denied.incorrect_acl", "File ACL Incorrect", C, HI,
           ["acl_incorrect","wrong_acl","file_acl_error"],
           [r"ACL.*incorrect", r"wrong.*ACL", r"access.*denied.*ACL"],
           ["reset_file_permissions","grant_file_permissions"]),

        _E("file_access_denied.ownership_mismatch", "File Ownership Mismatch", C, HI,
           ["owner_mismatch","wrong_owner","takeown_needed"],
           [r"owner.*mismatch", r"wrong.*owner", r"takeown"],
           ["take_file_ownership","reset_file_permissions"]),

        # ════════════════════════════════════════════════════════════════
        # KEY MANAGEMENT
        # ════════════════════════════════════════════════════════════════
        _E("key_mgmt.compromise", "Cryptographic Key Compromised", SC, CR,
           ["key_compromise","cert_stolen","private_key_leak"],
           [r"key.*compromis", r"private.*key.*leak", r"cert.*stolen"],
           ["run_defender_scan","sync_time"]),

        _E("key_mgmt.rotation", "Key Rotation Required / Overdue", SC, ME,
           ["key_rotation","cert_expiry_soon","rotate_key"],
           [r"key.*rotation.*due", r"cert.*expir.*soon", r"rotate.*key"],
           ["update_cert","sync_time"]),

        # ════════════════════════════════════════════════════════════════
        # DISK SPACE / LOGS
        # ════════════════════════════════════════════════════════════════
        _E("disk_space.exceeds_threshold", "Disk Usage Exceeds Threshold", R, HI,
           ["disk_high","disk_90","disk_95","low_disk_space"],
           [r"disk.*usage.*9[0-9]%", r"low.*disk.*space", r"disk.*threshold"],
           ["clear_temp","get_disk_usage"]),

        _E("log_storage.log_size_limit", "Log File Size Limit Reached", R, ME,
           ["log_size_limit","log_full","log_max_size"],
           [r"log.*size.*limit", r"log.*full", r"max.*log.*size.*reached"],
           ["clear_temp","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # CACHE / QUEUE
        # ════════════════════════════════════════════════════════════════
        _E("cache.corruption", "Cache Corruption", C, HI,
           ["cache_corrupt","cache_error","cache_invalid"],
           [r"cache.*corrupt", r"cache.*error", r"cache.*invalid"],
           ["restart_service","clear_temp"]),

        _E("queue.overload", "Queue Overloaded / Backlog", R, HI,
           ["queue_overload","queue_backlog","queue_full","message_backlog"],
           [r"queue.*overload", r"queue.*backlog", r"queue.*full",
            r"consumer.*lag"],
           ["restart_service","renice_process"]),

        _E("queue.deadlock", "Queue Deadlock", S, HI,
           ["queue_deadlock","message_deadlock"],
           [r"queue.*deadlock", r"message.*deadlock"],
           ["restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # TRAFFIC OVERLOAD
        # ════════════════════════════════════════════════════════════════
        _E("traffic.request_rate_exceeded", "Request Rate Exceeded Capacity", R, HI,
           ["rate_exceeded","rps_too_high","overloaded_endpoint","ddos"],
           [r"rate.*exceeded", r"requests.*per.*second.*limit",
            r"endpoint.*overloaded"],
           ["restart_service","kill_high_cpu"]),

        _E("traffic.abusive_patterns", "Abusive / Attack Traffic Detected", SC, CR,
           ["abusive_traffic","attack_traffic","ddos_traffic","brute_force"],
           [r"abuse.*traffic", r"DDoS", r"brute.?force"],
           ["block_ip","reset_firewall"]),

        # ════════════════════════════════════════════════════════════════
        # SECURITY INCIDENTS
        # ════════════════════════════════════════════════════════════════
        _E("security.compromised_creds", "Compromised Credentials Detected", SC, CR,
           ["compromised_creds","stolen_password","credential_leak"],
           [r"compromised.*credent", r"stolen.*password", r"credential.*breach"],
           ["reset_account_password","run_defender_scan"]),

        _E("security.suspicious_ip", "Suspicious IP Activity", SC, HI,
           ["suspicious_ip","threat_ip","malicious_ip","blocked_ip"],
           [r"suspicious.*IP", r"threat.*actor.*IP", r"malicious.*IP"],
           ["block_ip","run_defender_scan"]),

        _E("security.vulnerable_package", "Vulnerable Package Detected", SC, HI,
           ["cve","vulnerability","security_patch_missing","unpatched"],
           [r"CVE-\d{4}", r"vulnerabilit", r"security.*patch.*missing"],
           ["update_av_signatures","repair_system_files"]),

        # ════════════════════════════════════════════════════════════════
        # MALWARE-INDUCED
        # ════════════════════════════════════════════════════════════════
        _E("malware_induced.ransomware", "Ransomware Encryption Detected", ML, CR,
           ["ransomware","encrypted_files","ransom_note","file_extension_changed"],
           [r"ransomware", r"files.*encrypted.*ransom", r"\.encrypted$",
            r"ransom.*note"],
           ["run_defender_scan","remove_threats","block_ip"]),

        _E("malware_induced.rootkit", "Rootkit Kernel Modification", ML, CR,
           ["rootkit","kernel_modify","boot_sector_modified","hidden_process"],
           [r"rootkit", r"kernel.*modif", r"boot.*sector.*modif", r"hidden.*process"],
           ["run_defender_scan","repair_system_files","dism_restore_health"]),

        _E("malware_induced.trojan", "Trojan Network Block", ML, CR,
           ["trojan","c2_call","command_control","trojan_network"],
           [r"trojan", r"C&C.*server", r"command.*control.*connection"],
           ["block_ip","run_defender_scan","reset_network_stack"]),

        # ════════════════════════════════════════════════════════════════
        # CLOUD INTEGRATION
        # ════════════════════════════════════════════════════════════════
        _E("cloud.api_key_expiry", "Cloud API Key Expired", A, HI,
           ["api_key_expired","cloud_key_expired","aws_key_expired"],
           [r"API.*key.*expired", r"cloud.*key.*expir", r"401.*API"],
           ["sync_time","restart_service"]),

        _E("cloud.endpoint_misc", "Cloud Endpoint Misconfiguration", D, ME,
           ["endpoint_wrong","cloud_endpoint_error","wrong_region"],
           [r"cloud.*endpoint.*error", r"region.*not.*found",
            r"wrong.*endpoint"],
           ["restart_service","flush_dns"]),

        _E("cloud.auth_protocol_mismatch", "Cloud Auth Protocol Mismatch", A, HI,
           ["iam_error","auth_method_mismatch","cloud_auth_fail"],
           [r"IAM.*error", r"auth.*method.*mismatch", r"cloud.*auth.*fail"],
           ["sync_time","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # STUCK / ZOMBIE PROCESSES
        # ════════════════════════════════════════════════════════════════
        _E("stuck_process.zombie", "Zombie / Defunct Process", S, ME,
           ["zombie","defunct","process_stuck","unkillable"],
           [r"zombie.*process", r"defunct", r"Z .*STAT", r"process.*stuck"],
           ["kill_process","restart_service"],
           platform="linux"),

        _E("stuck_process.health_probe_fail", "Process Failing Health Probes", S, HI,
           ["health_probe_fail","liveness_fail","readiness_fail"],
           [r"health.*probe.*fail", r"liveness.*fail", r"readiness.*fail"],
           ["restart_service"]),

        _E("stuck_process.child_spawning", "Excessive Child Process Spawning", S, HI,
           ["fork_bomb","child_spawn","too_many_processes","process_limit"],
           [r"fork.*bomb", r"too many.*process", r"EAGAIN.*fork",
            r"process.*limit.*exceeded"],
           ["kill_process","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # DATA CORRUPTION
        # ════════════════════════════════════════════════════════════════
        _E("data_corruption.file", "File Corruption Detected", R, HI,
           ["file_corrupt","data_corrupt","checksum_fail","crc_error"],
           [r"file.*corrupt", r"data.*corrupt", r"checksum.*fail",
            r"CRC.*error", r"md5.*mismatch"],
           ["chkdsk","repair_system_files"]),

        _E("data_corruption.database", "Database Corruption / Instability", S, CR,
           ["db_corrupt","database_corrupt","table_corrupt","innodb_corrupt"],
           [r"database.*corrupt", r"table.*corrupt", r"InnoDB.*corrupt",
            r"index.*corrupt"],
           ["restart_service","restore_config_from_backup"]),

        # ════════════════════════════════════════════════════════════════
        # SERVICE FAILOVER
        # ════════════════════════════════════════════════════════════════
        _E("failover.primary_unreachable", "Primary Instance Unreachable", S, CR,
           ["primary_unreachable","primary_down","primary_fail","leader_fail"],
           [r"primary.*unreachable", r"primary.*down", r"leader.*fail"],
           ["restart_service","flush_dns"]),

        _E("failover.heartbeat_failing", "Heartbeat Checks Failing", S, HI,
           ["heartbeat_fail","keepalive_fail","vrrp_fail","corosync_fail"],
           [r"heartbeat.*fail", r"keepalive.*fail", r"VRRP.*fail"],
           ["restart_service","reset_network_stack"]),

        # ════════════════════════════════════════════════════════════════
        # DEPENDENCY MANAGEMENT
        # ════════════════════════════════════════════════════════════════
        _E("dep_mgmt.problematic_dependency", "Problematic Dependency Causing Errors", D, HI,
           ["bad_dependency","dep_error","third_party_error"],
           [r"dependency.*error", r"third.?party.*error", r"upstream.*broken"],
           ["restart_service","flush_dns"]),

        _E("dep_mgmt.sla_breach", "SLA Breach Linked to Dependency", D, HI,
           ["sla_breach","sla_violation","latency_sla"],
           [r"SLA.*breach", r"SLA.*violat", r"latency.*SLA.*exceeded"],
           ["restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # PERFORMANCE
        # ════════════════════════════════════════════════════════════════
        _E("performance.high_latency", "High Latency in Critical Operations", S, HI,
           ["high_latency","slow_operations","response_time_high"],
           [r"high.*latency", r"slow.*response", r"latency.*ms.*above.*threshold"],
           ["renice_process","restart_service"]),

        _E("performance.resource_contention", "Resource Contention Impacting Workloads", R, HI,
           ["resource_contention","iops_contention","cpu_steal"],
           [r"resource.*contention", r"cpu.*steal", r"IOPS.*contention"],
           ["renice_process","lower_priority","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # FAULTY COMPONENT
        # ════════════════════════════════════════════════════════════════
        _E("faulty_component.repeated_crashes", "Component Repeated Crashes", S, CR,
           ["component_crash","module_crash","repeated_component_fail"],
           [r"component.*crash", r"module.*crash.*repeat"],
           ["restart_service","rollback_update"]),

        _E("faulty_component.security_compromise", "Component Security Compromise", SC, CR,
           ["component_compromised","module_infected","sidecar_infected"],
           [r"component.*compromis", r"module.*infect"],
           ["run_defender_scan","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # MAINTENANCE CONFLICT
        # ════════════════════════════════════════════════════════════════
        _E("maintenance.peak_load_overlap", "Maintenance During Peak Load", S, ME,
           ["maintenance_peak","scheduled_maintenance_conflict"],
           [r"maintenance.*peak.*load", r"maintenance.*conflict"],
           ["restart_service"]),

        _E("maintenance.emergency_throttling", "Emergency Maintenance Throttling", S, ME,
           ["emergency_throttle","maintenance_throttle"],
           [r"emergency.*maintenance.*throttl"],
           ["lower_priority","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # DATA RETENTION
        # ════════════════════════════════════════════════════════════════
        _E("data_retention.exceeds_period", "Data Exceeds Retention Period", C, ME,
           ["retention_exceeded","data_too_old","retention_violation"],
           [r"retention.*exceeded", r"data.*older.*than.*policy"],
           ["clear_temp"]),

        _E("data_retention.storage_critically_low", "Storage Critically Low Due to Stale Data", R, CR,
           ["stale_data_low_disk","old_data_full","retention_disk_full"],
           [r"stale.*data.*disk.*full", r"old.*data.*fill.*disk"],
           ["clear_temp","get_disk_usage"]),

        # ════════════════════════════════════════════════════════════════
        # ORPHANED RESOURCES
        # ════════════════════════════════════════════════════════════════
        _E("orphaned.capacity_consumption", "Orphaned Resources Consuming Capacity", R, ME,
           ["orphaned_resource","zombie_volume","dangling_container"],
           [r"orphaned.*resource", r"dangling.*container", r"zombie.*volume"],
           ["clear_temp","restart_service"]),

        # ════════════════════════════════════════════════════════════════
        # GENERIC FALLBACKS
        # ════════════════════════════════════════════════════════════════
        _E("generic.service_crash", "Generic Service Crash", S, CR,
           ["service_crash","crashed","segfault","killed","sigsegv","coredump",
            "core_dump","exited","service_killed","process_killed"],
           [r"service.*crash", r"segfault", r"SIGSEGV", r"core.*dump",
            r"killed.*signal", r"process.*crash", r"service.*exited",
            r"crash.*killed", r"crashed.*service"],
           ["restart_service","repair_system_files"]),

        _E("generic.service_error", "Generic Service Error", S, ME,
           ["service_error","svc_error","service_fail","service_stopped"],
           [r"service.*error", r"service.*fail", r"service.*stop"],
           ["restart_service"]),

        _E("generic.config_error", "Generic Configuration Error", C, ME,
           ["config_error","configuration_error"],
           [r"config.*error", r"configuration.*error"],
           ["restore_config_from_backup"]),

        _E("generic.network_error", "Generic Network Error", N, ME,
           ["network_error","network_fail"],
           [r"network.*error", r"network.*fail"],
           ["flush_dns","reset_network_stack"]),
    ]


# ── OsFaultCatalog ────────────────────────────────────────────────────────────

class OsFaultCatalog:
    """
    Matches raw event text against the full OS-level fault taxonomy
    from the guidance document (~150 entries, 85+ top-level categories).

    Integration point:
        from healing_core.os_fault_catalog import OsFaultCatalog
        cat = OsFaultCatalog()
        entry = cat.lookup("gateway unreachable after DHCP renewal")
        # → OsFaultEntry(fault_id="no_connection.gateway_unreachable", ...)
    """

    def __init__(self) -> None:
        self._entries: List[OsFaultEntry] = _build_catalog() + _build_windows_catalog()
        # Pre-compile regexes
        self._patterns: List[Tuple[re.Pattern, OsFaultEntry]] = [
            (re.compile(p, re.IGNORECASE), e)
            for e in self._entries
            for p in e.patterns
        ]
        # Keyword index: word → [entries]
        self._kw_index: Dict[str, List[OsFaultEntry]] = {}
        for e in self._entries:
            for kw in e.keywords:
                self._kw_index.setdefault(kw, []).append(e)

    # ── Public API ─────────────────────────────────────────────────────────

    def lookup(self, text: str, platform: Optional[str] = None) -> Optional[OsFaultEntry]:
        """
        Find the best matching OsFaultEntry for a symptom text.
        Returns None if no match above threshold.
        """
        text_lower = text.lower()

        # 1. Pattern scan (most specific)
        for rx, entry in self._patterns:
            if platform and entry.platform not in ("all", platform):
                continue
            if rx.search(text):
                return entry

        # 2. Keyword scoring
        tokens = set(re.findall(r'[a-z0-9_]{3,}', text_lower))
        scored: Dict[str, Tuple[int, OsFaultEntry]] = {}
        for tok in tokens:
            for entry in self._kw_index.get(tok, []):
                if platform and entry.platform not in ("all", platform):
                    continue
                key = entry.fault_id
                prev_score, _ = scored.get(key, (0, entry))
                scored[key] = (prev_score + 1, entry)

        if scored:
            best_id = max(scored, key=lambda k: scored[k][0])
            score, entry = scored[best_id]
            if score >= 1:
                return entry

        return None

    def lookup_by_id(self, fault_id: str) -> Optional[OsFaultEntry]:
        for e in self._entries:
            if e.fault_id == fault_id:
                return e
        return None

    def lookup_by_category(self, category: IncidentCategory) -> List[OsFaultEntry]:
        return [e for e in self._entries if e.category == category]

    def all_entries(self) -> List[OsFaultEntry]:
        return list(self._entries)

    def summary(self) -> Dict:
        from collections import Counter
        cats = Counter(e.category.name for e in self._entries)
        plats = Counter(e.platform for e in self._entries)
        return {
            "total_entries": len(self._entries),
            "by_category":   dict(cats),
            "by_platform":   dict(plats),
        }

    def enrich_event(self, event_dict: dict, platform: Optional[str] = None) -> dict:
        """
        Given an event dict, improve category + fix hints using OS fault matching.
        Returns the (possibly modified) dict.
        """
        text = f"{event_dict.get('error_type','')} {event_dict.get('message','')}"
        entry = self.lookup(text, platform=platform)
        if entry:
            event_dict.setdefault("_os_fault_id",        entry.fault_id)
            event_dict.setdefault("_os_fault_category",  entry.category.name)
            event_dict.setdefault("_os_fault_severity",  entry.severity.name)
            event_dict.setdefault("_os_fault_primitives", entry.fix_primitives[:2])
        return event_dict


# ═════════════════════════════════════════════════════════════════════════════
# Windows-specific OS fault entries
# Tagged platform="windows" with Event IDs, HRESULT, stop codes, Win32 names
# ═════════════════════════════════════════════════════════════════════════════

def _build_windows_catalog() -> List[OsFaultEntry]:
    N  = IncidentCategory.NETWORK
    S  = IncidentCategory.SERVICE
    R  = IncidentCategory.RESOURCE
    C  = IncidentCategory.CONFIGURATION
    SC = IncidentCategory.SECURITY
    A  = IncidentCategory.AUTHENTICATION
    H  = IncidentCategory.HARDWARE
    D  = IncidentCategory.DEPENDENCY
    TR = IncidentCategory.TRANSIENT
    DR = IncidentCategory.DRIVER
    ML = IncidentCategory.MALWARE

    LO = Severity.LOW
    ME = Severity.MEDIUM
    HI = Severity.HIGH
    CR = Severity.CRITICAL

    return [

        # ── SERVICE: Event ID 7034 / 7031 / 7023 ─────────────────────────────
        _E("win.svc.crash_7034", "Service Terminated Unexpectedly (7034)", S, CR,
           ["event 7034","eventid 7034","7034","terminated unexpectedly",
            "service reported","service.*terminated"],
           [r"EventID.?7034", r"Event\s+ID\s+7034",
            r"service.*terminated unexpectedly",
            r"The .+? service terminated unexpectedly"],
           ["restart_service","repair_system_files","dism_restore_health"],
           platform="windows"),

        _E("win.svc.crash_7031", "Service Exited Without Recovery (7031)", S, HI,
           ["event 7031","eventid 7031","7031","service exit","exhausted recovery"],
           [r"EventID.?7031", r"Event\s+ID\s+7031",
            r"service.*termination.*recovery.*exhausted"],
           ["restart_service","set_service_recovery"],
           platform="windows"),

        _E("win.svc.stop_7036", "Service State Changed (7036)", S, ME,
           ["event 7036","eventid 7036","7036","service entered","running state",
            "stopped state"],
           [r"EventID.?7036", r"Event\s+ID\s+7036",
            r"service.*entered.*running|service.*entered.*stopped"],
           ["restart_service","set_service_auto"],
           platform="windows"),

        _E("win.svc.start_fail_7000", "Service Failed to Start (7000)", S, HI,
           ["event 7000","eventid 7000","7000","failed to start","service could not",
            "error 1053","service did not respond"],
           [r"EventID.?7000", r"Event\s+ID\s+7000",
            r"service.*failed to start", r"0x80070000"],
           ["restart_service","set_service_delayed","repair_system_files"],
           platform="windows"),

        _E("win.svc.timeout_7009", "Service Start Timeout (7009)", S, HI,
           ["event 7009","eventid 7009","7009","service timeout","timed out waiting",
            "service not respond"],
           [r"EventID.?7009", r"Event\s+ID\s+7009",
            r"timed out waiting for .+ service"],
           ["set_service_delayed","restart_service"],
           platform="windows"),

        _E("win.svc.dependency_7001", "Service Dependency Failed (7001)", D, HI,
           ["event 7001","eventid 7001","7001","depends on","dependency",
            "failed to start due","depended service"],
           [r"EventID.?7001", r"Event\s+ID\s+7001",
            r"service depends on .+ which failed"],
           ["restart_service","set_service_auto"],
           platform="windows"),

        _E("win.svc.missing_dep_7003", "Service Missing Dependency (7003)", D, HI,
           ["event 7003","eventid 7003","7003","could not find","marked for deletion",
            "missing dependency"],
           [r"EventID.?7003", r"Event\s+ID\s+7003",
            r"service.*marked for deletion"],
           ["repair_system_files","dism_restore_health"],
           platform="windows"),

        _E("win.svc.logon_fail_7038", "Service Logon Failure (7038)", A, HI,
           ["event 7038","eventid 7038","7038","logon as a service","service account",
            "account does not have","logon right"],
           [r"EventID.?7038", r"Event\s+ID\s+7038",
            r"logon as a service right"],
           ["grant_logon_service_right","reset_account_password"],
           platform="windows"),

        _E("win.svc.hung_7011", "Service Hung / No Response (7011)", S, HI,
           ["event 7011","eventid 7011","7011","transaction timeout","hung",
            "no response","not respond"],
           [r"EventID.?7011", r"Event\s+ID\s+7011",
            r"transaction timeout.*service.*control"],
           ["restart_service","repair_system_files"],
           platform="windows"),

        # ── AUTHENTICATION: Event IDs ─────────────────────────────────────────
        _E("win.auth.logon_fail_4625", "Account Logon Failure (4625)", A, HI,
           ["event 4625","eventid 4625","4625","logon failure","bad password",
            "wrong password","invalid credentials"],
           [r"EventID.?4625", r"Event\s+ID\s+4625",
            r"logon.*failure", r"account.*failed.*log.?on",
            r"Status.*0xC000006D", r"Status.*0xC0000064"],
           ["enable_account","reset_account_password","sync_time"],
           platform="windows"),

        _E("win.auth.lockout_4740", "Account Locked Out (4740)", A, HI,
           ["event 4740","eventid 4740","4740","locked out","account lockout",
            "too many attempts"],
           [r"EventID.?4740", r"Event\s+ID\s+4740",
            r"account.*locked.?out", r"lockout.*threshold"],
           ["enable_account","reset_account_password"],
           platform="windows"),

        _E("win.auth.kerberos_fail_4771", "Kerberos Pre-Auth Failure (4771)", A, HI,
           ["event 4771","eventid 4771","4771","kerberos","pre-authentication",
            "KDC_ERR","kerberos failure"],
           [r"EventID.?4771", r"Event\s+ID\s+4771",
            r"Kerberos pre-authentication failed",
            r"KDC_ERR_PREAUTH_FAILED", r"KRB5KDC"],
           ["sync_time","reset_account_password","enable_account"],
           platform="windows"),

        _E("win.auth.disabled_4725", "Account Disabled (4725)", A, ME,
           ["event 4725","eventid 4725","4725","account disabled","user account disabled"],
           [r"EventID.?4725", r"Event\s+ID\s+4725",
            r"user account was disabled"],
           ["enable_account","update_group_policy"],
           platform="windows"),

        _E("win.auth.cert_fail", "Certificate Authentication Failure", A, HI,
           ["certificate expired","cert expired","0x8009","CERT_E_EXPIRED",
            "SEC_E_CERT_EXPIRED","ssl handshake","tls handshake"],
           [r"CERT_E_EXPIRED", r"SEC_E_CERT_EXPIRED", r"0x80090325",
            r"certificate.*expired", r"certificate.*invalid",
            r"certificate.*revoked", r"CRYPT_E_REVOKED"],
           ["update_cert","sync_time"],
           platform="windows"),

        # ── SECURITY: Event IDs ───────────────────────────────────────────────
        _E("win.sec.new_service_7045", "Unknown Service Installed (7045)", ML, CR,
           ["event 7045","eventid 7045","7045","new service","service was installed",
            "malicious service"],
           [r"EventID.?7045", r"Event\s+ID\s+7045",
            r"new service was installed"],
           ["run_defender_scan","disable_service","update_av_signatures"],
           platform="windows"),

        _E("win.sec.firewall_block_5157", "Firewall Blocked Connection (5157)", N, ME,
           ["event 5157","eventid 5157","5157","firewall blocked","connection prevented",
            "filtering platform blocked"],
           [r"EventID.?5157", r"Event\s+ID\s+5157",
            r"Windows Filtering Platform.*blocked",
            r"prevented a connection"],
           ["allow_firewall_port","reset_firewall"],
           platform="windows"),

        _E("win.sec.dcom_10016", "DCOM Permission Denied (10016)", C, ME,
           ["event 10016","eventid 10016","10016","dcom","launch permission",
            "access permission","machine default","local activation"],
           [r"EventID.?10016", r"Event\s+ID\s+10016",
            r"DCOM.*permission", r"machine-default permission",
            r"local activation.*not granted"],
           ["update_group_policy","reset_registry_perms"],
           platform="windows"),

        _E("win.sec.audit_log_cleared_1102", "Security Audit Log Cleared (1102)", ML, CR,
           ["event 1102","eventid 1102","1102","audit log cleared","security log cleared",
            "log was cleared"],
           [r"EventID.?1102", r"Event\s+ID\s+1102",
            r"audit log.*cleared", r"security log.*cleared"],
           ["run_defender_scan","update_av_signatures"],
           platform="windows"),

        _E("win.sec.privilege_4673", "Sensitive Privilege Use (4673)", SC, ME,
           ["event 4673","eventid 4673","4673","privilege use","sensitive privilege",
            "SeDebugPrivilege","SeTcbPrivilege"],
           [r"EventID.?4673", r"Event\s+ID\s+4673",
            r"sensitive privilege.*used", r"SeDebugPrivilege",
            r"SeTcbPrivilege"],
           ["run_defender_scan","disable_account"],
           platform="windows"),

        # ── HARDWARE / CRASH: Event IDs ───────────────────────────────────────
        _E("win.hw.bsod_41", "Unexpected Shutdown / BSOD (Event 41)", H, CR,
           ["event 41","eventid 41","41","unexpected shutdown","bsod","blue screen",
            "kernel power","bugcheck","stop code"],
           [r"EventID.?41\b", r"Event\s+ID\s+41\b",
            r"system.*restarted.*unexpectedly", r"BugcheckCode",
            r"STOP.?0x", r"0x0000007E", r"0x00000050",
            r"0x0000001E", r"0x000000EF", r"0x000000D1"],
           ["chkdsk","dism_restore_health","repair_system_files"],
           platform="windows"),

        _E("win.hw.disk_err_7", "Disk Controller Error (Event 7)", H, CR,
           ["event 7","eventid 7","disk error","controller error",
            "device.*had a bad block","disk.*error"],
           [r"EventID.?7\b", r"Event\s+ID\s+7\b.*disk",
            r"disk.*controller.*error", r"bad block",
            r"\\Device\\Harddisk"],
           ["chkdsk","dism_restore_health"],
           platform="windows"),

        _E("win.hw.disk_err_11", "Driver Detected Controller Error (Event 11)", H, HI,
           ["event 11","eventid 11","11","driver detected","controller error",
            "harddisk"],
           [r"EventID.?11\b", r"Event\s+ID\s+11\b",
            r"driver detected.*controller error"],
           ["chkdsk","rollback_driver"],
           platform="windows"),

        _E("win.hw.disk_err_51", "Disk Paging Error (Event 51)", H, HI,
           ["event 51","eventid 51","51","paging operation","paging error",
            "error detected during","disk paging"],
           [r"EventID.?51\b", r"Event\s+ID\s+51\b",
            r"error.*paging operation", r"paging.*error"],
           ["chkdsk","repair_system_files"],
           platform="windows"),

        # ── DRIVER: Event IDs ─────────────────────────────────────────────────
        _E("win.drv.load_fail_7026", "Driver Failed to Load (7026)", DR, HI,
           ["event 7026","eventid 7026","7026","failed to load","driver failed",
            "boot-start driver","system-start driver"],
           [r"EventID.?7026", r"Event\s+ID\s+7026",
            r"following boot.*driver.*failed", r"driver.*failed.*load"],
           ["rollback_driver","update_driver","repair_system_files"],
           platform="windows"),

        _E("win.drv.conflict_219", "Device Driver Conflict (Event 219)", DR, ME,
           ["event 219","eventid 219","219","driver conflict","code 10","code 43",
            "device manager","driver install","device cannot start"],
           [r"EventID.?219", r"Event\s+ID\s+219",
            r"driver.*conflict", r"Code\s+10\b", r"Code\s+43\b",
            r"device cannot start"],
           ["rollback_driver","update_driver","disable_device"],
           platform="windows"),

        # ── CONFIGURATION: Registry / Group Policy ─────────────────────────────
        _E("win.cfg.registry_4657", "Registry Key Modified (4657)", C, ME,
           ["event 4657","eventid 4657","4657","registry key","registry modified",
            "registry value","HKLM","HKCU"],
           [r"EventID.?4657", r"Event\s+ID\s+4657",
            r"registry.*key.*modified", r"HKEY_LOCAL_MACHINE",
            r"HKEY_CURRENT_USER"],
           ["restore_registry","reset_registry_perms","update_group_policy"],
           platform="windows"),

        _E("win.cfg.gpo_fail", "Group Policy Application Failure", C, ME,
           ["group policy","gpupdate","gpo failed","policy error","policy apply",
            "gpresult","computer policy","user policy","policy processing"],
           [r"Group Policy.*fail", r"gpupdate.*error", r"PolicyApplication",
            r"EventID.?1058", r"EventID.?1030",
            r"GPO.*cannot be applied", r"policy.*access.*denied"],
           ["update_group_policy","flush_dns","restart_service"],
           platform="windows"),

        _E("win.cfg.sfc_corrupt", "System File Corruption Detected", C, HI,
           ["sfc","system file","corrupt system","windows resource protection",
            "integrity violation","sfcdetails","dism","restorehealth"],
           [r"Windows Resource Protection.*corrupt",
            r"sfc.*scannow.*corrupt", r"Integrity.*violation",
            r"component store.*corrupt", r"DISM.*restorehealth",
            r"CBS\.log"],
           ["repair_system_files","dism_restore_health"],
           platform="windows"),

        _E("win.cfg.winsock_corrupt", "Winsock Catalog Corruption", N, HI,
           ["winsock","winsock reset","lsp","layered service provider",
            "winsock catalog","netsh winsock","catalog corrupt"],
           [r"Winsock.*corrupt", r"winsock.*reset",
            r"LSP.*invalid", r"netsh.*winsock.*reset"],
           ["reset_network_stack","repair_system_files"],
           platform="windows"),

        # ── RESOURCE: Windows-specific ────────────────────────────────────────
        _E("win.res.pagefile_exhaust", "Pagefile / Virtual Memory Exhausted", R, CR,
           ["pagefile","virtual memory","commit limit","paging file","swap",
            "no paging file","your computer is low on memory",
            "low on virtual memory","commit charge"],
           [r"pagefile.*exhaust", r"virtual memory.*low",
            r"commit.*limit.*reached", r"no paging.*space",
            r"your computer is low on memory",
            r"0xC0000017", r"0xC000012D",
            r"EventID.?2004"],
           ["clear_temp","kill_high_mem","adjust_power_plan"],
           platform="windows"),

        _E("win.res.disk_full_ntfs", "NTFS Volume Full", R, CR,
           ["disk full","no space","ntfs","volume full","insufficient disk",
            "drive is full","disk space","free space","0 bytes"],
           [r"disk.*full", r"no space left", r"NTFS.*insufficient",
            r"volume.*insufficient.*space",
            r"0x80070070",   # ERROR_DISK_FULL
            r"EventID.?2013"],
           ["clear_temp","get_disk_usage","chkdsk"],
           platform="windows"),

        _E("win.res.handle_leak", "Handle Leak / Too Many Handles", R, HI,
           ["handle leak","too many handles","handles exceeded","handle count",
            "open handles","handle exhaustion","nhandles"],
           [r"handle.*leak", r"too many open handles",
            r"handle.*count.*exceed", r"NHandles",
            r"EventID.?1801"],
           ["restart_service","kill_process"],
           platform="windows"),

        _E("win.res.pool_depletion", "Non-Paged / Paged Pool Depletion", R, CR,
           ["nonpaged pool","paged pool","pool depletion","pool tag",
            "pool.*exhaust","kernel pool","tag exhausted"],
           [r"NonPagedPool.*deplet", r"PagedPool.*deplet",
            r"kernel pool.*exhaust",
            r"EventID.?2019", r"EventID.?2020"],
           ["kill_high_mem","restart_service","dism_restore_health"],
           platform="windows"),

        # ── NETWORK: Windows-specific ─────────────────────────────────────────
        _E("win.net.wlan_autoconfig", "WLAN AutoConfig Service Failure", N, HI,
           ["wlan autoconfig","wlansvc","wlan service","wifi service","wireless service",
            "cannot connect to wifi","wlan.*fail"],
           [r"WLAN AutoConfig.*fail", r"Wlansvc.*stop",
            r"EventID.?11001", r"EventID.?11002",
            r"wireless.*association.*fail"],
           ["restart_service","restart_wifi","flush_dns"],
           platform="windows"),

        _E("win.net.nla_fail", "Network Location Awareness Failure", N, ME,
           ["nla","network location","location awareness","nla service",
            "network profile","public network","private network"],
           [r"NLA.*fail", r"Network Location Awareness",
            r"network profile.*fail", r"EventID.?4202"],
           ["restart_service","reset_network_stack"],
           platform="windows"),

        _E("win.net.dns_client_fail", "DNS Client Service Failure", N, HI,
           ["dns client","dnscache","dns service","dns resolver","resolution fail",
            "EventID 1014","dns.*not.*respond"],
           [r"DNS Client.*fail", r"Dnscache.*stop",
            r"EventID.?1014", r"DNS.*name.*not.*exist",
            r"DNS.*server.*not.*respond"],
           ["restart_service","flush_dns","set_dns_cloudflare"],
           platform="windows"),

        _E("win.net.port_exhaustion", "Ephemeral Port Exhaustion (EADDRINUSE)", N, CR,
           ["port exhaustion","ephemeral port","dynamic port","WSAEADDRINUSE",
            "no more endpoints","port range","tcp port","10048"],
           [r"WSAEADDRINUSE", r"port.*exhaust",
            r"no.*endpoint.*available", r"10048\b",
            r"netsh.*int.*ipv4.*set.*dynamicport"],
           ["restart_service","reset_network_stack"],
           platform="windows"),

        # ── MALWARE: Windows-specific ─────────────────────────────────────────
        _E("win.mal.defender_threat", "Windows Defender Threat Detected", ML, CR,
           ["defender threat","windows defender","mpssvc","threat detected",
            "quarantine","malware detected","virus detected","spyware",
            "threat found","defender scan","wdboot"],
           [r"Defender.*Threat", r"Windows Defender.*detect",
            r"EventID.?1116", r"EventID.?1117",
            r"MALWAREPROTECTION_STATE_MALWARE_DETECTED",
            r"Threat.*detected.*action"],
           ["run_defender_scan","remove_threats","update_av_signatures"],
           platform="windows"),

        _E("win.mal.ransomware_indicator", "Ransomware / Mass File Encryption", ML, CR,
           ["ransomware","mass encrypt","file extension changed","YOUR_FILES",
            "readme.txt ransom","decrypt","!!!!","ransom note","bitcoin",
            "vssadmin delete","shadow copy delete"],
           [r"ransomware", r"mass.*encrypt",
            r"vssadmin.*delete.*shadows",
            r"Shadow.*Copy.*deleted",
            r"\.encrypted\b", r"\.(locked|cry|crypt)\b"],
           ["run_defender_scan","remove_threats","update_av_signatures"],
           platform="windows"),

        _E("win.mal.process_injection", "Suspicious Process Injection Detected", ML, CR,
           ["process inject","code inject","dll inject","hollowing",
            "remote thread","WriteProcessMemory","VirtualAllocEx",
            "CreateRemoteThread","suspicious parent","anomalous process"],
           [r"process.*inject", r"dll.*inject",
            r"WriteProcessMemory", r"CreateRemoteThread",
            r"VirtualAllocEx.*suspicious",
            r"EventID.?4657.*inject"],
           ["run_defender_scan","kill_process","disable_account"],
           platform="windows"),

        # ── UPDATES: Windows-specific ─────────────────────────────────────────
        _E("win.upd.install_fail", "Windows Update Installation Failure", C, ME,
           ["windows update","wuauserv","update fail","kb install","update error",
            "SoftwareDistribution","update stuck","0x80070643","0x8024"],
           [r"Windows Update.*fail", r"KB\d+.*fail",
            r"0x80070643", r"0x80240017", r"0x8024200D",
            r"EventID.?20.*update", r"WSUS.*error",
            r"SoftwareDistribution.*corrupt"],
           ["restart_service","repair_system_files","dism_restore_health"],
           platform="windows"),

        _E("win.upd.rollback_fail", "Windows Update Rollback Failure", C, HI,
           ["rollback fail","update rollback","cannot rollback","undo update",
            "uninstall update","wusa","pending operations fail"],
           [r"rollback.*fail", r"update.*rollback.*fail",
            r"EventID.?1001.*rollback",
            r"pending.*operations.*fail"],
           ["rollback_update","dism_restore_health","repair_system_files"],
           platform="windows"),

        # ── PRINT SPOOLER: Windows-specific ───────────────────────────────────
        _E("win.svc.spooler_crash", "Print Spooler Service Crash", S, HI,
           ["spooler","print spooler","spoolsv","print queue","printer",
            "print job","spooler crash","spooler stop"],
           [r"Spooler.*crash", r"spoolsv\.exe.*terminate",
            r"Print.*Spooler.*stop",
            r"EventID.?7034.*Spooler",
            r"print.*queue.*corrupt"],
           ["restart_service","clear_print_queue","repair_system_files"],
           platform="windows"),

        # ── CERTIFICATE STORE ─────────────────────────────────────────────────
        _E("win.cfg.cert_store", "Certificate Store Issue", A, HI,
           ["certificate store","cert store","certutil","cert expired",
            "revoked certificate","invalid cert","untrusted root",
            "SSL certificate","TLS certificate"],
           [r"certificate.*store.*fail", r"certutil.*error",
            r"certificate.*revok", r"untrusted.*root",
            r"CERT_E_EXPIRED", r"CERT_E_UNTRUSTEDROOT",
            r"EventID.?64.*cert"],
           ["update_cert","sync_time"],
           platform="windows"),

        # ── TASK SCHEDULER ────────────────────────────────────────────────────
        _E("win.svc.taskschd_fail", "Task Scheduler Service Failure", S, ME,
           ["task scheduler","schedule service","scheduled task","schtasks",
            "task failed","task run fail","task trigger"],
           [r"Task Scheduler.*fail", r"Schedule.*service.*stop",
            r"EventID.?7036.*Schedule",
            r"Task.*failed to start", r"schtasks.*error"],
           ["restart_service","set_service_auto","update_group_policy"],
           platform="windows"),

        # ── WMI / WINMGMT ─────────────────────────────────────────────────────
        _E("win.svc.wmi_fail", "WMI / Windows Management Instrumentation Failure", S, HI,
           ["wmi","winmgmt","wbem","wmi query fail","wmi not available",
            "wmi corrupted","wmi repository"],
           [r"WMI.*fail", r"winmgmt.*stop", r"WBEM.*error",
            r"WMI.*repository.*corrupt",
            r"EventID.?10.*WMI", r"EventID.?4101"],
           ["restart_service","repair_system_files","dism_restore_health"],
           platform="windows"),

        # ── RPC ───────────────────────────────────────────────────────────────
        _E("win.svc.rpc_fail", "RPC Service Unavailable", N, CR,
           ["rpc","rpcss","rpc server unavailable","rpc failed",
            "rpc endpoint","1722","0x800706ba"],
           [r"RPC.*server.*unavailable", r"RPC.*fail",
            r"0x800706ba", r"1722\b",
            r"EventID.?1753", r"RPC_S_SERVER_UNAVAILABLE"],
           ["restart_service","allow_firewall_port","reset_network_stack"],
           platform="windows"),

        # ── EVENTLOG SERVICE ──────────────────────────────────────────────────
        _E("win.svc.eventlog_fail", "Event Log Service Failure", S, HI,
           ["event log","eventlog service","wevtsvc","log file corrupt",
            "event log corrupt","log cleared","1102"],
           [r"Event Log.*fail", r"EventLog.*stop",
            r"EventID.?104\b", r"EventID.?1102",
            r"log file.*corrupt", r"event log.*corrupt"],
           ["restart_service","repair_system_files"],
           platform="windows"),

        # ── POWER ─────────────────────────────────────────────────────────────
        _E("win.pwr.sleep_fail", "Sleep / Hibernate Failure", H, ME,
           ["sleep fail","hibernate fail","resume fail","power state",
            "s3 fail","s4 fail","wake fail","kernel power"],
           [r"sleep.*fail", r"hibernate.*fail",
            r"resume.*fail", r"EventID.?6008",
            r"EventID.?41.*kernel.power",
            r"S3.*transition.*fail"],
           ["update_driver","rollback_driver","adjust_power_plan"],
           platform="windows"),

        # ── VOLUME SHADOW COPY ────────────────────────────────────────────────
        _E("win.svc.vss_fail", "Volume Shadow Copy Service Failure", S, HI,
           ["vss","volume shadow copy","vssadmin","shadow copy fail",
            "writer error","provider error","shadow storage"],
           [r"VSS.*fail", r"Volume Shadow Copy.*fail",
            r"vssadmin.*error",
            r"EventID.?8193", r"EventID.?12289",
            r"shadow.*copy.*fail"],
           ["restart_service","chkdsk","dism_restore_health"],
           platform="windows"),
    ]


