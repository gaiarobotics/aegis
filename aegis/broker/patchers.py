"""Endpoint patchers that monkey-patch standard library and third-party I/O."""

from __future__ import annotations

import builtins
import os
import pathlib
import subprocess
import time
import urllib.request
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
    """Patch common synchronous HTTP clients."""
    try:
        import requests  # type: ignore[import-untyped]
    except (ImportError, ModuleNotFoundError):
        requests = None  # type: ignore[assignment]

    if requests is not None:
        if "http" not in _originals:
            _originals["http"] = requests.Session.request
        original_request = _originals["http"]

        def patched_request(self: Any, method: str, url: str, **kwargs: Any) -> Any:
            rw = "read" if method.upper() in ("GET", "HEAD", "OPTIONS") else "write"
            action = _make_request("http_write", rw, url, {"method": method, **kwargs})
            response = broker.evaluate(action)
            if response.decision != ActionDecision.ALLOW:
                raise PermissionError(
                    f"AEGIS Broker denied HTTP {method} to {url}: {response.reason}"
                )
            return original_request(self, method, url, **kwargs)

        requests.Session.request = patched_request  # type: ignore[assignment]

    try:
        import httpx

        if "httpx_request" not in _originals:
            _originals["httpx_request"] = httpx.Client.request
        original_httpx_request = _originals["httpx_request"]

        def patched_httpx_request(self: Any, method: str, url: Any, **kwargs: Any) -> Any:
            rw = "read" if method.upper() in ("GET", "HEAD", "OPTIONS") else "write"
            action = _make_request("http_write", rw, str(url), {"method": method, **kwargs})
            if broker.evaluate(action).decision != ActionDecision.ALLOW:
                raise PermissionError(f"AEGIS Broker denied HTTP {method} to {url}")
            return original_httpx_request(self, method, url, **kwargs)

        httpx.Client.request = patched_httpx_request  # type: ignore[assignment]
    except (ImportError, ModuleNotFoundError):
        pass

    if "urllib_urlopen" not in _originals:
        _originals["urllib_urlopen"] = urllib.request.urlopen

    def patched_urlopen(url: Any, *args: Any, **kwargs: Any) -> Any:
        target = url.full_url if isinstance(url, urllib.request.Request) else str(url)
        method = url.get_method() if isinstance(url, urllib.request.Request) else "GET"
        rw = "read" if method.upper() in ("GET", "HEAD", "OPTIONS") else "write"
        action = _make_request("http_write", rw, target, {"method": method})
        if broker.evaluate(action).decision != ActionDecision.ALLOW:
            raise PermissionError(f"AEGIS Broker denied HTTP {method} to {target}")
        return _originals["urllib_urlopen"](url, *args, **kwargs)

    urllib.request.urlopen = patched_urlopen


def patch_subprocess(broker: Any) -> None:
    """Monkey-patch subprocess.run and subprocess.Popen."""
    if "subprocess_run" not in _originals:
        _originals["subprocess_run"] = subprocess.run
    if "subprocess_popen" not in _originals:
        _originals["subprocess_popen"] = subprocess.Popen
    if "os_system" not in _originals:
        _originals["os_system"] = os.system
    if "os_popen" not in _originals:
        _originals["os_popen"] = os.popen

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
            raise PermissionError(f"AEGIS Broker denied subprocess.run: {response.reason}")
        return original_run(*args, **kwargs)

    class PatchedPopen(original_popen):  # type: ignore[misc]
        def __init__(self, args: Any = None, **kwargs: Any) -> None:
            cmd_args = args if args is not None else kwargs.get("args", [])
            target = (
                cmd_args[0] if isinstance(cmd_args, (list, tuple)) and cmd_args else str(cmd_args)
            )
            action = _make_request(
                action_type="tool_call",
                read_write="write",
                target=target,
                args={"cmd": cmd_args},
            )
            resp = broker.evaluate(action)
            if resp.decision != ActionDecision.ALLOW:
                raise PermissionError(f"AEGIS Broker denied subprocess.Popen: {resp.reason}")
            super().__init__(args, **kwargs)

    subprocess.run = patched_run  # type: ignore[assignment]
    subprocess.Popen = PatchedPopen  # type: ignore[misc]

    def patched_system(command: str) -> int:
        action = _make_request(
            "tool_call", "write", command.split()[0] if command else "", {"cmd": command}
        )
        if broker.evaluate(action).decision != ActionDecision.ALLOW:
            raise PermissionError("AEGIS Broker denied os.system")
        return _originals["os_system"](command)

    def patched_os_popen(command: str, mode: str = "r", buffering: int = -1):
        action = _make_request(
            "tool_call", "write", command.split()[0] if command else "", {"cmd": command}
        )
        if broker.evaluate(action).decision != ActionDecision.ALLOW:
            raise PermissionError("AEGIS Broker denied os.popen")
        return _originals["os_popen"](command, mode, buffering)

    os.system = patched_system
    os.popen = patched_os_popen


def patch_filesystem(broker: Any) -> None:
    """Wrap builtins.open to intercept file writes."""
    if "open" not in _originals:
        _originals["open"] = builtins.open
    if "os_open" not in _originals:
        _originals["os_open"] = os.open
    if "path_open" not in _originals:
        _originals["path_open"] = pathlib.Path.open

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

    def patched_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
        if flags & write_flags:
            action = _make_request("fs_write", "write", str(path), {"flags": flags})
            if broker.evaluate(action).decision != ActionDecision.ALLOW:
                raise PermissionError(f"AEGIS Broker denied file write to {path}")
        return _originals["os_open"](path, flags, *args, **kwargs)

    def patched_path_open(self: pathlib.Path, mode: str = "r", *args: Any, **kwargs: Any):
        if any(marker in mode for marker in _write_modes):
            action = _make_request("fs_write", "write", str(self), {"mode": mode})
            if broker.evaluate(action).decision != ActionDecision.ALLOW:
                raise PermissionError(f"AEGIS Broker denied file write to {self}")
        return _originals["path_open"](self, mode, *args, **kwargs)

    os.open = patched_os_open
    pathlib.Path.open = patched_path_open


def unpatch_all() -> None:
    """Restore all monkey-patched functions to their originals."""
    if "http" in _originals:
        try:
            import requests  # type: ignore[import-untyped]

            requests.Session.request = _originals["http"]  # type: ignore[assignment]
        except (ImportError, ModuleNotFoundError):
            pass

    if "httpx_request" in _originals:
        try:
            import httpx

            httpx.Client.request = _originals["httpx_request"]  # type: ignore[assignment]
        except (ImportError, ModuleNotFoundError):
            pass

    if "urllib_urlopen" in _originals:
        urllib.request.urlopen = _originals["urllib_urlopen"]

    if "subprocess_run" in _originals:
        subprocess.run = _originals["subprocess_run"]  # type: ignore[assignment]

    if "subprocess_popen" in _originals:
        subprocess.Popen = _originals["subprocess_popen"]  # type: ignore[misc]

    if "os_system" in _originals:
        os.system = _originals["os_system"]
    if "os_popen" in _originals:
        os.popen = _originals["os_popen"]

    if "open" in _originals:
        builtins.open = _originals["open"]  # type: ignore[assignment]
    if "os_open" in _originals:
        os.open = _originals["os_open"]
    if "path_open" in _originals:
        pathlib.Path.open = _originals["path_open"]

    _originals.clear()
