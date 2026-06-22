"""
example_plugin.py — demonstrates the HealingCore plugin contract.
Drop any .py file in plugins/ and it auto-loads at startup (or on SIGHUP).
Expose: PLUGIN_NAME, PLUGIN_VERSION, and register(registry).
"""
import logging
from healing_core.models import IncidentCategory, RemediationFix

PLUGIN_NAME        = "example_plugin"
PLUGIN_VERSION     = "0.1.0"
PLUGIN_DESCRIPTION = "Custom redis restart + cache-clear primitive"
PLUGIN_AUTHOR      = "your-team"

log = logging.getLogger(PLUGIN_NAME)

def _restart_redis(incident):
    log.info("[plugin] restarting redis for inc=%.8s", incident.id)
    return True

def _clear_redis_cache(incident):
    log.info("[plugin] flushing redis cache for inc=%.8s", incident.id)
    return True

def register(registry) -> None:
    registry.register(RemediationFix(
        name        = "plugin_restart_redis",
        category    = IncidentCategory.SERVICE,
        description = "Restart Redis + flush cache (plugin example)",
        source      = "plugin",
        cost        = 0.3,
        impact      = 0.4,
        steps       = [_restart_redis, _clear_redis_cache],
    ))
    log.info("example_plugin | registered 1 primitive")
