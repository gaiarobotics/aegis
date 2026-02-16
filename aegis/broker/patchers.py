"""Endpoint patchers that monkey-patch standard library and third-party I/O."""

from __future__ import annotations

import builtins
import subprocess
import time
import uuid
from typing import Any

from aegis.broker.actions import ActionDecision, ActionRequest

# Module-level dict to store originals for restoration
_originals: dict[str, Any] = {}


def _make_request(
    action_type: str,
    read_write: str,
    target: str,
    args: dict[str, Any] | None = None,
) -> ActionRequest:
    """Helper to build an ActionRequest."""
    return ActionRequest(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        source_provenance="trusted.system",
        action_type=action_type,
        read_write=read_write,
        target=target,
        args=args or {},
        risk_hints={},
    )


def patch_http(broker: Any) -> None:
    """Monkey-patch requests.Session.request if the requests library is available."""
    try:
        import requests  # type: ignore[import-untyped]
    except (ImportError, ModuleNotFoundError):
        return

    if requests is None:
        return

    if "http" not in _originals:
        _originals["http"] = requests.Session.request

    original_request = _originals["http"]

    def patched_request(self: Any, method: str, url: str, **kwargs: Any) -> Any:
        # Determine read/write: GET/HEAD/OPTIONS are reads, everything else is write
        rw = "read" if method.upper() in ("GET", "HEAD", "OPTIONS") else "write"
        action = _make_request(
            action_type="http_write",
            read_write=rw,
            target=url,
            args={"method": method, **kwargs},
        )
        response = broker.evaluate(action)
        if response.decision != ActionDecision.ALLOW:
            raise PermissionError(
                f"AEGIS Broker denied HTTP {method} to {url}: {response.reason}"
            )
        return original_request(self, method, url, **kwargs)

    requests.Session.request = patched_request  # type: ignore[assignment]


def patch_subprocess(broker: Any) -> None:
    """Monkey-patch subprocess.run and subprocess.Popen."""
    if "subprocess_run" not in _originals:
        _originals["subprocess_run"] = subprocess.run
    if "subprocess_popen" not in _originals:
        _originals["subprocess_popen"] = subprocess.Popen

    original_run = _originals["subprocess_run"]
    original_popen = _originals["subprocess_popen"]

    def patched_run(*args: Any, **kwargs: Any) -> Any:
        cmd_args = args[0] if args else kwargs.get("args", [])
        target = cmd_args[0] if isinstance(cmd_args, (list, tuple)) and cmd_args else str(cmd_args)
        action = _make_request(
            action_type="tool_call",
            read_write="write",
            target=target,
            args={"cmd": cmd_args},
        )
        response = broker.evaluate(action)
        if response.decision != ActionDecision.ALLOW:
            raise PermissionError(
                f"AEGIS Broker denied subprocess.run: {response.reason}"
            )
        return original_run(*args, **kwargs)

    class PatchedPopen(original_popen):  # type: ignore[misc]
        def __init__(self, args: Any = None, **kwargs: Any) -> None:
            cmd_args = args if args is not None else kwargs.get("args", [])
            target = (
                cmd_args[0]
                if isinstance(cmd_args, (list, tuple)) and cmd_args
                else str(cmd_args)
            )
            action = _make_request(
                action_type="tool_call",
                read_write="write",
                target=target,
                args={"cmd": cmd_args},
            )
            resp = broker.evaluate(action)
            if resp.decision != ActionDecision.ALLOW:
                raise PermissionError(
                    f"AEGIS Broker denied subprocess.Popen: {resp.reason}"
                )
            super().__init__(args, **kwargs)

    subprocess.run = patched_run  # type: ignore[assignment]
    subprocess.Popen = PatchedPopen  # type: ignore[misc]


def patch_filesystem(broker: Any) -> None:
    """Wrap builtins.open to intercept file writes."""
    if "open" not in _originals:
        _originals["open"] = builtins.open

    original_open = _originals["open"]

    # Write mode indicators
    _write_modes = {"w", "a", "x", "r+", "w+", "a+", "x+"}

    def patched_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        # Check if this is a write operation
        is_write = False
        for wm in _write_modes:
            if wm in mode:
                is_write = True
                break

        if is_write:
            action = _make_request(
                action_type="fs_write",
                read_write="write",
                target=str(file),
                args={"mode": mode},
            )
            response = broker.evaluate(action)
            if response.decision != ActionDecision.ALLOW:
                raise PermissionError(
                    f"AEGIS Broker denied file write to {file}: {response.reason}"
                )

        return original_open(file, mode, *args, **kwargs)

    builtins.open = patched_open  # type: ignore[assignment]


def unpatch_all() -> None:
    """Restore all monkey-patched functions to their originals."""
    if "http" in _originals:
        try:
            import requests  # type: ignore[import-untyped]

            requests.Session.request = _originals["http"]  # type: ignore[assignment]
        except (ImportError, ModuleNotFoundError):
            pass

    if "subprocess_run" in _originals:
        subprocess.run = _originals["subprocess_run"]  # type: ignore[assignment]

    if "subprocess_popen" in _originals:
        subprocess.Popen = _originals["subprocess_popen"]  # type: ignore[misc]

    if "open" in _originals:
        builtins.open = _originals["open"]  # type: ignore[assignment]

    _originals.clear()
