"""
drivers.linux_catalog
─────────────────────
Full Linux + container fault catalog — every Linux/Docker/Kubernetes
scenario from the guide document modeled as RemediationFix objects.
"""
from __future__ import annotations

import logging
from typing import List

from healing_core.models import IncidentCategory, RemediationFix
from drivers.linux import (
    _run,
    restart_service, start_service, stop_service, reload_service,
    enable_service, disable_service, query_service,
    restart_network_interface, flush_dns, set_dns, reset_network_stack,
    release_renew_ip, block_ip, allow_port, reset_firewall,
    kill_process, kill_pid, renice_process,
    apply_cgroup_limits, release_cgroup,
    drop_caches, get_disk_usage, clear_temp_files,
    disable_account, enable_account, update_av_signatures, run_av_scan,
    restore_config_from_backup, reset_file_permissions, repair_system_files,
    sync_time, set_ntp_server,
)

log = logging.getLogger("healing_core.drivers.linux_catalog")


def _mk(name, cat, desc, steps, cost=0.3, impact=0.3):
    return RemediationFix(name=name, category=cat, description=desc,
                          steps=steps, cost=cost, impact=impact,
                          source="catalog_linux")


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK
# ══════════════════════════════════════════════════════════════════════════════

def network_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_net_restart_iface", IncidentCategory.NETWORK,
            "Bring network interface down then up",
            [lambda i: restart_network_interface("eth0")], cost=0.3),

        _mk("lin_net_restart_networkmanager", IncidentCategory.NETWORK,
            "Restart NetworkManager service",
            [lambda i: restart_service("NetworkManager")], cost=0.3),

        _mk("lin_net_flush_dns", IncidentCategory.NETWORK,
            "Flush systemd-resolve DNS cache",
            [lambda i: flush_dns()], cost=0.1),

        _mk("lin_net_set_cloudflare", IncidentCategory.NETWORK,
            "Set /etc/resolv.conf to Cloudflare 1.1.1.1",
            [lambda i: set_dns("1.1.1.1")], cost=0.2),

        _mk("lin_net_release_renew", IncidentCategory.NETWORK,
            "dhclient release + renew for fresh DHCP lease",
            [lambda i: release_renew_ip("eth0")], cost=0.3),

        _mk("lin_net_reset_iptables", IncidentCategory.NETWORK,
            "Flush all iptables rules to open state",
            [lambda i: reset_firewall()], cost=0.5, impact=0.6),

        _mk("lin_net_block_malicious_ip", IncidentCategory.SECURITY,
            "iptables block inbound from suspicious IP",
            [lambda i: block_ip(
                i.event.message.split()[-1] if i.event.message else "0.0.0.0"
            )], cost=0.3, impact=0.4),

        _mk("lin_net_open_port", IncidentCategory.NETWORK,
            "iptables allow inbound on blocked port",
            [lambda i: allow_port(
                int(i.event.message.split(":")[-1].strip())
                if ":" in i.event.message else 8080
            )], cost=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE (systemd)
# ══════════════════════════════════════════════════════════════════════════════

def service_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_svc_restart", IncidentCategory.SERVICE,
            "systemctl restart failing service",
            [lambda i: restart_service(i.event.actor)], cost=0.3),

        _mk("lin_svc_start", IncidentCategory.SERVICE,
            "systemctl start stopped service",
            [lambda i: start_service(i.event.actor)], cost=0.2),

        _mk("lin_svc_reload", IncidentCategory.SERVICE,
            "systemctl reload (SIGHUP config reload, no downtime)",
            [lambda i: reload_service(i.event.actor)], cost=0.1),

        _mk("lin_svc_enable", IncidentCategory.SERVICE,
            "systemctl enable so service survives reboots",
            [lambda i: enable_service(i.event.actor)], cost=0.1),

        _mk("lin_svc_status", IncidentCategory.SERVICE,
            "Query systemd service status for diagnostics (no mutation)",
            [lambda i: query_service(i.event.actor)], cost=0.0, impact=0.0),

        _mk("lin_svc_restart_with_deps", IncidentCategory.SERVICE,
            "Stop, re-enable, and start service with clean dependency order",
            [lambda i: stop_service(i.event.actor),
             lambda i: enable_service(i.event.actor),
             lambda i: start_service(i.event.actor)], cost=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# RESOURCE
# ══════════════════════════════════════════════════════════════════════════════

def resource_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_res_drop_caches", IncidentCategory.RESOURCE,
            "Drop page + slab caches (/proc/sys/vm/drop_caches=3)",
            [lambda i: drop_caches()], cost=0.4, impact=0.5),

        _mk("lin_res_kill_top_mem", IncidentCategory.RESOURCE,
            "Kill highest-memory process via pkill",
            [lambda i: kill_process(i.event.actor)], cost=0.5, impact=0.7),

        _mk("lin_res_renice_cpu_hog", IncidentCategory.RESOURCE,
            "Renice high-CPU process to +10 (lower priority)",
            [lambda i: renice_process(i.event.actor, nice=10)], cost=0.2, impact=0.3),

        _mk("lin_res_cgroup_quarantine", IncidentCategory.RESOURCE,
            "Apply cgroups v2 CPU 10% + 128MB memory limit",
            [lambda i: apply_cgroup_limits(i.event.actor, cpu_pct=10, mem_mb=128)],
            cost=0.3, impact=0.4),

        _mk("lin_res_clear_tmp", IncidentCategory.RESOURCE,
            "Delete temp files older than 1 day from /tmp",
            [lambda i: clear_temp_files()], cost=0.1),

        _mk("lin_res_disk_usage", IncidentCategory.RESOURCE,
            "Report disk usage on / for diagnostics (no mutation)",
            [lambda i: get_disk_usage("/")], cost=0.0, impact=0.0),

        _mk("lin_res_journal_vacuum", IncidentCategory.RESOURCE,
            "Vacuum systemd journal to free disk space (keep 1G)",
            [lambda i: _run(["journalctl", "--vacuum-size=1G"])], cost=0.2),

        _mk("lin_res_find_large_files", IncidentCategory.RESOURCE,
            "List top 10 largest files under / for manual review",
            [lambda i: _run([
                "bash", "-c",
                "find / -xdev -type f -printf '%s %p\\n' 2>/dev/null | "
                "sort -rn | head -10"
            ])], cost=0.1, impact=0.0),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY / MALWARE
# ══════════════════════════════════════════════════════════════════════════════

def security_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_sec_update_av_sigs", IncidentCategory.MALWARE,
            "Update ClamAV virus definitions via freshclam",
            [lambda i: update_av_signatures()], cost=0.2),

        _mk("lin_sec_av_scan", IncidentCategory.MALWARE,
            "ClamAV recursive scan of /home and /tmp",
            [lambda i: run_av_scan("/home"),
             lambda i: run_av_scan("/tmp")], cost=0.3, impact=0.3),

        _mk("lin_sec_block_ip_iptables", IncidentCategory.SECURITY,
            "Drop inbound traffic from suspicious IP via iptables",
            [lambda i: block_ip(
                i.event.message.split()[-1] if i.event.message else "0.0.0.0"
            )], cost=0.3, impact=0.4),

        _mk("lin_sec_disable_account", IncidentCategory.SECURITY,
            "Lock compromised account via usermod -L",
            [lambda i: disable_account(i.event.actor)], cost=0.4, impact=0.5),

        _mk("lin_sec_enable_account", IncidentCategory.AUTHENTICATION,
            "Unlock account via usermod -U",
            [lambda i: enable_account(i.event.actor)], cost=0.2, impact=0.3),

        _mk("lin_sec_fail2ban_restart", IncidentCategory.SECURITY,
            "Restart fail2ban to apply updated ban rules",
            [lambda i: restart_service("fail2ban")], cost=0.2),

        _mk("lin_sec_ssh_restart", IncidentCategory.AUTHENTICATION,
            "Restart sshd to apply config changes / clear hung sessions",
            [lambda i: restart_service("sshd")], cost=0.2, impact=0.3),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

def config_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_cfg_restore_from_backup", IncidentCategory.CONFIGURATION,
            "Restore config file from /backup",
            [lambda i: restore_config_from_backup(
                f"/backup{i.event.actor}", i.event.actor
            )], cost=0.3),

        _mk("lin_cfg_nginx_test_reload", IncidentCategory.CONFIGURATION,
            "Test nginx config then reload if valid",
            [lambda i: _run(["nginx", "-t"]),
             lambda i: reload_service("nginx")], cost=0.2),

        _mk("lin_cfg_apache_reload", IncidentCategory.CONFIGURATION,
            "Test Apache config then graceful restart",
            [lambda i: _run(["apachectl", "configtest"]),
             lambda i: _run(["apachectl", "graceful"])], cost=0.2),

        _mk("lin_cfg_reset_permissions", IncidentCategory.CONFIGURATION,
            "chmod 644 on misconfigured config file",
            [lambda i: reset_file_permissions(i.event.actor, "644")], cost=0.2),

        _mk("lin_cfg_env_check", IncidentCategory.CONFIGURATION,
            "Print environment for diagnostics (no mutation)",
            [lambda i: _run(["env"])], cost=0.0, impact=0.0),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# DOCKER / CONTAINERS
# ══════════════════════════════════════════════════════════════════════════════

def container_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_docker_restart_container", IncidentCategory.SERVICE,
            "docker restart the named container",
            [lambda i: _run(["docker", "restart", i.event.actor])], cost=0.3),

        _mk("lin_docker_stop_remove", IncidentCategory.SERVICE,
            "Force-stop and remove a crashed container",
            [lambda i: _run(["docker", "stop", i.event.actor]),
             lambda i: _run(["docker", "rm", "-f", i.event.actor])], cost=0.4, impact=0.5),

        _mk("lin_docker_prune", IncidentCategory.RESOURCE,
            "docker system prune -f to free disk from dangling images/volumes",
            [lambda i: _run(["docker", "system", "prune", "-f"])], cost=0.3, impact=0.3),

        _mk("lin_docker_volume_prune", IncidentCategory.RESOURCE,
            "docker volume prune -f to free orphaned volumes",
            [lambda i: _run(["docker", "volume", "prune", "-f"])], cost=0.3, impact=0.3),

        _mk("lin_docker_network_reset", IncidentCategory.NETWORK,
            "Remove and recreate a broken Docker network",
            [lambda i: _run(["docker", "network", "rm", i.event.actor]),
             lambda i: _run(["docker", "network", "create", i.event.actor])],
            cost=0.4, impact=0.5),

        _mk("lin_docker_restart_daemon", IncidentCategory.SERVICE,
            "Restart the Docker daemon",
            [lambda i: restart_service("docker")], cost=0.4, impact=0.6),

        _mk("lin_docker_logs_tail", IncidentCategory.SERVICE,
            "Tail last 50 lines of container logs for diagnostics",
            [lambda i: _run(["docker", "logs", "--tail", "50", i.event.actor])],
            cost=0.0, impact=0.0),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# KUBERNETES
# ══════════════════════════════════════════════════════════════════════════════

def kubernetes_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_k8s_rollout_restart", IncidentCategory.SERVICE,
            "kubectl rollout restart deployment",
            [lambda i: _run([
                "kubectl", "rollout", "restart",
                f"deployment/{i.event.actor}"
            ])], cost=0.3, impact=0.4),

        _mk("lin_k8s_delete_pod", IncidentCategory.SERVICE,
            "Delete crashed pod so it is recreated by the controller",
            [lambda i: _run([
                "kubectl", "delete", "pod", i.event.actor, "--grace-period=0"
            ])], cost=0.3, impact=0.4),

        _mk("lin_k8s_scale_up", IncidentCategory.RESOURCE,
            "Scale deployment up by 1 replica to handle load",
            [lambda i: _run([
                "kubectl", "scale", f"deployment/{i.event.actor}", "--replicas=3"
            ])], cost=0.3, impact=0.3),

        _mk("lin_k8s_drain_node", IncidentCategory.HARDWARE,
            "kubectl drain faulty node to migrate workloads",
            [lambda i: _run([
                "kubectl", "drain", i.event.actor,
                "--ignore-daemonsets", "--delete-emptydir-data"
            ])], cost=0.5, impact=0.7),

        _mk("lin_k8s_cordon_node", IncidentCategory.HARDWARE,
            "kubectl cordon node to prevent new scheduling",
            [lambda i: _run(["kubectl", "cordon", i.event.actor])], cost=0.3, impact=0.4),

        _mk("lin_k8s_describe_pod", IncidentCategory.SERVICE,
            "kubectl describe pod for diagnostics (no mutation)",
            [lambda i: _run(["kubectl", "describe", "pod", i.event.actor])],
            cost=0.0, impact=0.0),

        _mk("lin_k8s_get_events", IncidentCategory.SERVICE,
            "kubectl get events sorted by time for diagnostics",
            [lambda i: _run([
                "kubectl", "get", "events", "--sort-by=.metadata.creationTimestamp"
            ])], cost=0.0, impact=0.0),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE (Postgres / MySQL / SQLite stubs)
# ══════════════════════════════════════════════════════════════════════════════

def database_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_db_restart_postgres", IncidentCategory.SERVICE,
            "Restart PostgreSQL service",
            [lambda i: restart_service("postgresql")], cost=0.3, impact=0.4),

        _mk("lin_db_restart_mysql", IncidentCategory.SERVICE,
            "Restart MySQL/MariaDB service",
            [lambda i: restart_service("mysql")], cost=0.3, impact=0.4),

        _mk("lin_db_pg_reload_conf", IncidentCategory.CONFIGURATION,
            "pg_ctl reload to apply postgresql.conf changes without downtime",
            [lambda i: _run(["pg_ctl", "reload"])], cost=0.1),

        _mk("lin_db_check_connections", IncidentCategory.RESOURCE,
            "Report active DB connection count (no mutation)",
            [lambda i: _run([
                "bash", "-c",
                "psql -U postgres -c 'SELECT count(*) FROM pg_stat_activity;' 2>/dev/null || "
                "mysqladmin -u root status 2>/dev/null"
            ])], cost=0.0, impact=0.0),

        _mk("lin_db_kill_idle_connections", IncidentCategory.RESOURCE,
            "Terminate idle Postgres connections older than 10 minutes",
            [lambda i: _run([
                "bash", "-c",
                "psql -U postgres -c "
                "\"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE state='idle' AND query_start < NOW() - INTERVAL '10 minutes';\" 2>/dev/null"
            ])], cost=0.4, impact=0.5),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# LOG MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def log_management_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_log_rotate", IncidentCategory.RESOURCE,
            "Force logrotate run to archive and compress logs",
            [lambda i: _run(["logrotate", "-f", "/etc/logrotate.conf"])], cost=0.2),

        _mk("lin_log_journal_vacuum", IncidentCategory.RESOURCE,
            "Vacuum systemd journal: keep last 2 days only",
            [lambda i: _run(["journalctl", "--vacuum-time=2d"])], cost=0.2),

        _mk("lin_log_clear_old", IncidentCategory.RESOURCE,
            "Delete log files older than 30 days under /var/log",
            [lambda i: _run([
                "find", "/var/log", "-type", "f", "-mtime", "+30", "-delete"
            ])], cost=0.3),

        _mk("lin_log_compress_dir", IncidentCategory.RESOURCE,
            "gzip compress all uncompressed log files over 100MB",
            [lambda i: _run([
                "bash", "-c",
                "find /var/log -name '*.log' -size +100M "
                "! -name '*.gz' -exec gzip -f {} \\;"
            ])], cost=0.2),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# TIME SYNC
# ══════════════════════════════════════════════════════════════════════════════

def time_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_time_sync", IncidentCategory.SYSTEMIC,
            "ntpdate resync with pool.ntp.org",
            [lambda i: sync_time()], cost=0.1),

        _mk("lin_time_set_ntp", IncidentCategory.SYSTEMIC,
            "Enable systemd-timesyncd automatic NTP",
            [lambda i: set_ntp_server()], cost=0.1),

        _mk("lin_time_restart_timesyncd", IncidentCategory.SYSTEMIC,
            "Restart systemd-timesyncd to force re-sync",
            [lambda i: restart_service("systemd-timesyncd")], cost=0.1),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# STUCK PROCESS / ZOMBIE (guide: Stuck Process section)
# ══════════════════════════════════════════════════════════════════════════════

def stuck_process_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_proc_kill_zombie_parent", IncidentCategory.SERVICE,
            "Kill parent process to reap zombie children",
            [lambda i: _run([
                "bash", "-c",
                f"ppid=$(ps -o ppid= -p $(pgrep -f '{i.event.actor}' | head -1) 2>/dev/null); "
                f"[ -n \"$ppid\" ] && kill -9 $ppid"
            ])], cost=0.5, impact=0.6),

        _mk("lin_proc_service_restart_clean", IncidentCategory.SERVICE,
            "Restart service to clear all child/zombie processes",
            [lambda i: stop_service(i.event.actor),
             lambda i: _run(["sleep", "2"]),
             lambda i: start_service(i.event.actor)], cost=0.4),

        _mk("lin_proc_set_ulimits", IncidentCategory.RESOURCE,
            "Apply ulimit constraints to prevent excessive child spawning",
            [lambda i: _run([
                "bash", "-c",
                f"echo '{i.event.actor} hard nproc 200' >> /etc/security/limits.conf"
            ])], cost=0.2, impact=0.3),

        _mk("lin_proc_enable_core_dump", IncidentCategory.SERVICE,
            "Enable core dumps for stuck process analysis",
            [lambda i: _run([
                "bash", "-c",
                f"ulimit -c unlimited && "
                f"echo '/tmp/core_%e_%p' > /proc/sys/kernel/core_pattern"
            ])], cost=0.1, impact=0.0),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# DATA CORRUPTION (guide: Data Corruption section)
# ══════════════════════════════════════════════════════════════════════════════

def data_corruption_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_data_fsck", IncidentCategory.HARDWARE,
            "Run fsck on unmounted filesystem to repair corruption",
            [lambda i: _run(["fsck", "-y", "/dev/sda1"])], cost=0.5, impact=0.5),

        _mk("lin_data_restore_from_backup", IncidentCategory.CONFIGURATION,
            "rsync restore from backup location",
            [lambda i: _run([
                "rsync", "-avz", "--checksum",
                f"/backup/{i.event.actor}/",
                f"/data/{i.event.actor}/"
            ], timeout=300)], cost=0.4, impact=0.4),

        _mk("lin_data_verify_checksums", IncidentCategory.CONFIGURATION,
            "sha256sum verify all files in affected directory",
            [lambda i: _run([
                "bash", "-c",
                f"find /data/{i.event.actor} -type f -exec sha256sum {{}} \\;"
            ], timeout=120)], cost=0.2, impact=0.0),

        _mk("lin_data_db_repair", IncidentCategory.SERVICE,
            "mysqlcheck or pg_dump to check/repair DB tables",
            [lambda i: _run([
                "bash", "-c",
                "mysqlcheck --all-databases --auto-repair -u root 2>/dev/null || "
                "pg_dump -U postgres --schema-only template1 >/dev/null 2>&1 && echo 'pg ok'"
            ], timeout=120)], cost=0.4, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE DEGRADATION (guide: Performance Degradation section)
# ══════════════════════════════════════════════════════════════════════════════

def performance_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_perf_clear_cache", IncidentCategory.RESOURCE,
            "Drop page cache to recover memory for application use",
            [lambda i: drop_caches()], cost=0.3, impact=0.4),

        _mk("lin_perf_redis_flush", IncidentCategory.SERVICE,
            "Flush Redis cache (FLUSHDB) if cache corruption suspected",
            [lambda i: _run([
                "bash", "-c",
                "redis-cli FLUSHDB 2>/dev/null && echo 'flushed'"
            ])], cost=0.4, impact=0.5),

        _mk("lin_perf_rabbitmq_purge", IncidentCategory.SERVICE,
            "Purge RabbitMQ queue backlog to reduce processing latency",
            [lambda i: _run([
                "rabbitmqctl", "purge_queue", i.event.actor
            ])], cost=0.4, impact=0.5),

        _mk("lin_perf_tc_throttle", IncidentCategory.NETWORK,
            "Apply tc traffic shaping to limit bandwidth of runaway process",
            [lambda i: _run([
                "bash", "-c",
                "tc qdisc add dev eth0 root handle 1: htb default 1 2>/dev/null; "
                "tc class add dev eth0 parent 1: classid 1:1 htb rate 100mbit 2>/dev/null; "
                "echo 'throttle applied'"
            ])], cost=0.3, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# KEY MANAGEMENT (guide: Key Management Problems)
# ══════════════════════════════════════════════════════════════════════════════

def key_management_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_key_revoke_ssh", IncidentCategory.SECURITY,
            "Remove suspected-compromised SSH host key",
            [lambda i: _run(["ssh-keygen", "-R", i.event.actor])], cost=0.4, impact=0.5),

        _mk("lin_key_rotate_ssl", IncidentCategory.SECURITY,
            "certbot renew + nginx reload for SSL certificate rotation",
            [lambda i: _run(["certbot", "renew", "--quiet"]),
             lambda i: reload_service("nginx")], cost=0.3, impact=0.3),

        _mk("lin_key_regenerate_host_key", IncidentCategory.SECURITY,
            "Regenerate SSH host key (ed25519)",
            [lambda i: _run([
                "ssh-keygen", "-t", "ed25519",
                "-f", "/etc/ssh/ssh_host_ed25519_key", "-N", ""
            ]),
             lambda i: restart_service("sshd")], cost=0.4, impact=0.4),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# MAINTENANCE / ORPHANED RESOURCES
# ══════════════════════════════════════════════════════════════════════════════

def maintenance_fixes() -> List[RemediationFix]:
    return [
        _mk("lin_maint_orphan_cleanup", IncidentCategory.RESOURCE,
            "Find and delete orphaned files older than 7 days",
            [lambda i: _run([
                "find", "/tmp", "/var/tmp",
                "-type", "f", "-mtime", "+7", "-delete"
            ])], cost=0.2),

        _mk("lin_maint_apt_clean", IncidentCategory.RESOURCE,
            "apt-get clean + autoremove to free package cache disk",
            [lambda i: _run(["apt-get", "clean", "-y"]),
             lambda i: _run(["apt-get", "autoremove", "-y"])], cost=0.2),

        _mk("lin_maint_yum_clean", IncidentCategory.RESOURCE,
            "yum clean all to free package cache",
            [lambda i: _run(["yum", "clean", "all"])], cost=0.2),

        _mk("lin_maint_snap_refresh", IncidentCategory.SERVICE,
            "Remove old snap revisions to free disk",
            [lambda i: _run([
                "bash", "-c",
                "snap list --all | awk '/disabled/{print $1, $3}' | "
                "while read name rev; do snap remove $name --revision=$rev 2>/dev/null; done"
            ])], cost=0.2),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# CATALOG REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

def all_fixes() -> List[RemediationFix]:
    """Return the complete Linux fault catalog."""
    catalog: List[RemediationFix] = []
    for fn in [
        network_fixes, service_fixes, resource_fixes, security_fixes,
        config_fixes, container_fixes, kubernetes_fixes, database_fixes,
        log_management_fixes, time_fixes, stuck_process_fixes,
        data_corruption_fixes, performance_fixes, key_management_fixes,
        maintenance_fixes,
    ]:
        try:
            catalog.extend(fn())
        except Exception as e:
            log.warning("catalog | error building %s: %s", fn.__name__, e)
    return catalog


def register_catalog(registry) -> None:
    """Register the entire Linux fault catalog into a PrimitivesRegistry."""
    fixes = all_fixes()
    for fix in fixes:
        registry.register(fix)
    log.info("linux_catalog | registered %d primitives", len(fixes))
