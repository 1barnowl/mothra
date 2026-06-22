"""
healing_core.plugins
────────────────────
Plugin loader — discovers and loads healing primitive plugins at startup.

Plugin contract
───────────────
Each plugin is a .py file in the plugins/ directory that exposes:

    PLUGIN_NAME:    str              (required)
    PLUGIN_VERSION: str              (required)
    PLUGIN_DESCRIPTION: str = ""    (optional)
    PLUGIN_AUTHOR:  str = ""        (optional)

    def register(registry) -> None:
        # registry is the PrimitivesRegistry instance
        # Call registry.register(RemediationFix(...)) for each primitive
        pass

Errors in one plugin are isolated — they log a warning and continue.
Plugins can be reloaded at runtime (useful during development).
"""
from __future__ import annotations

import importlib.util
import logging
import os
import sys
from typing import List, TYPE_CHECKING

from .models import PluginManifest

if TYPE_CHECKING:
    from .primitives import PrimitivesRegistry

log = logging.getLogger("healing_core.plugins")


class PluginLoader:
    def __init__(self, plugins_dir: str = "plugins") -> None:
        self._dir      = plugins_dir
        self.manifests: List[PluginManifest] = []

    def load_all(self, registry: "PrimitivesRegistry") -> None:
        """Scan plugins_dir and load every .py file found."""
        if not os.path.isdir(self._dir):
            log.debug("plugins | directory not found: %s", self._dir)
            return

        files = [
            f for f in os.listdir(self._dir)
            if f.endswith(".py") and not f.startswith("_")
        ]
        log.info("plugins | found %d file(s) in %s", len(files), self._dir)
        for fname in sorted(files):
            self._load_one(os.path.join(self._dir, fname), registry)

    def reload_all(self, registry: "PrimitivesRegistry") -> None:
        """Re-load all plugins (useful after SIGHUP)."""
        self.manifests.clear()
        self.load_all(registry)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_one(self, path: str, registry: "PrimitivesRegistry") -> None:
        module_name = f"_hc_plugin_{os.path.basename(path)[:-3]}"
        manifest = PluginManifest(
            name    = module_name,
            version = "?",
            path    = path,
        )
        self.manifests.append(manifest)

        try:
            spec   = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)             # type: ignore
            spec.loader.exec_module(module)                            # type: ignore

            manifest.name        = getattr(module, "PLUGIN_NAME",        module_name)
            manifest.version     = getattr(module, "PLUGIN_VERSION",     "0.0.1")
            manifest.description = getattr(module, "PLUGIN_DESCRIPTION", "")
            manifest.author      = getattr(module, "PLUGIN_AUTHOR",      "")

            if not hasattr(module, "register"):
                raise AttributeError("missing register(registry) function")

            module.register(registry)
            manifest.loaded = True
            log.info("plugins | loaded %-30s  v%s", manifest.name, manifest.version)

        except Exception as exc:
            manifest.error = str(exc)
            log.warning("plugins | FAILED to load %s — %s", path, exc)
