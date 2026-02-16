"""Master killswitch — 4 activation methods, thread-safe."""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager

_lock = threading.Lock()
_programmatic: bool = False
_config_override: bool | None = None
_local = threading.local()


def is_active() -> bool:
    """Check if killswitch is active from any source.

    Sources checked (any one activates):
    1. Thread-local forced (via ``disabled()`` context manager)
    2. Environment variable ``AEGIS_KILLSWITCH=1``
    3. Programmatic ``activate()``
    4. Config file override via ``set_config_override(True)``
    """
    if getattr(_local, "forced", False):
        return True
    if os.environ.get("AEGIS_KILLSWITCH", "0") == "1":
        return True
    if _programmatic:
        return True
    if _config_override is True:
        return True
    return False


def activate() -> None:
    """Programmatically activate the killswitch (global)."""
    global _programmatic
    with _lock:
        _programmatic = True


def deactivate() -> None:
    """Programmatically deactivate the killswitch (global)."""
    global _programmatic
    with _lock:
        _programmatic = False


def set_config_override(value: bool | None) -> None:
    """Set killswitch state from config file.

    Args:
        value: ``True`` to activate, ``False`` to explicitly deactivate,
               ``None`` to clear the config override.
    """
    global _config_override
    with _lock:
        _config_override = value


@contextmanager
def disabled():
    """Context manager that activates killswitch for this thread only.

    Usage::

        with aegis.killswitch.disabled():
            # All AEGIS checks are bypassed in this thread
            ...
    """
    _local.forced = True
    try:
        yield
    finally:
        _local.forced = False


def _reset() -> None:
    """Reset all killswitch state. For testing only."""
    global _programmatic, _config_override
    with _lock:
        _programmatic = False
        _config_override = None
    _local.forced = False
