"""
drivers
───────
OS-specific healing primitives.

Platform dispatch:
  Linux   → drivers.linux   + drivers.linux_catalog
  Windows → drivers.windows + drivers.windows_catalog
  macOS   → drivers.macos   + drivers.macos_catalog   ← NEW v0.8

DryRun is set globally by HealingCore at startup.
Each module exposes a module-level `DryRun: bool` flag.
"""
import platform, importlib, logging

log = logging.getLogger("healing_core.drivers")
_OS = platform.system()   # "Linux" | "Windows" | "Darwin"

def get_driver():
    """Return the active platform driver module."""
    _MAP = {"Linux": "drivers.linux", "Windows": "drivers.windows",
            "Darwin": "drivers.macos"}
    mod_path = _MAP.get(_OS, "drivers.linux")
    try:
        return importlib.import_module(mod_path)
    except ImportError as exc:
        log.warning("Could not import %s: %s", mod_path, exc)
        return None

def set_dry_run(dry: bool) -> None:
    """Propagate DryRun flag to all driver modules."""
    for path in ("drivers.linux", "drivers.windows", "drivers.macos"):
        try:
            m = importlib.import_module(path)
            m.DryRun = dry
        except ImportError:
            pass

PLATFORM = _OS
