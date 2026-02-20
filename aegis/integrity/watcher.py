"""Linux inotify file watcher via ctypes.

Provides real-time notification of model file changes on Linux.
Raises ``ImportError`` on non-Linux platforms for graceful degradation.

Usage::

    from aegis.integrity.watcher import InotifyWatcher

    watcher = InotifyWatcher(callback=my_callback, stop_event=stop_event)
    watcher.start()
    watcher.add_watch("/path/to/model.bin", "llama3")
    # ... later ...
    watcher.stop()
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import platform
import struct
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform gate — ImportError on non-Linux
# ---------------------------------------------------------------------------

if platform.system() != "Linux":
    raise ImportError("inotify is only available on Linux")

# Load libc
_libc_name = ctypes.util.find_library("c")
if _libc_name is None:
    raise ImportError("Could not find libc")

_libc = ctypes.CDLL(_libc_name, use_errno=True)

# Verify required functions exist
for _func_name in ("inotify_init1", "inotify_add_watch", "inotify_rm_watch"):
    if not hasattr(_libc, _func_name):
        raise ImportError(f"libc missing {_func_name}")

# inotify constants
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ATTRIB = 0x00000004

IN_NONBLOCK = 0x00000800  # O_NONBLOCK for inotify_init1

# Combined mask for model file monitoring
_WATCH_MASK = IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF | IN_ATTRIB

# inotify_event struct: int wd, uint32_t mask, uint32_t cookie, uint32_t len
_EVENT_HEADER_SIZE = struct.calcsize("iIII")


class InotifyWatcher:
    """Watches files for changes using Linux inotify.

    Args:
        callback: Called as ``callback(file_path, model_name)`` on events.
        stop_event: A ``threading.Event`` signaling shutdown.
    """

    def __init__(
        self,
        callback: Callable[[str, str], Any],
        stop_event: threading.Event,
    ) -> None:
        self._callback = callback
        self._stop_event = stop_event

        # Create inotify instance (non-blocking)
        self._fd = _libc.inotify_init1(IN_NONBLOCK)
        if self._fd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"inotify_init1 failed: {os.strerror(errno)}")

        self._lock = threading.Lock()
        # wd -> (file_path, model_name)
        self._watches: dict[int, tuple[str, str]] = {}
        # file_path -> wd (for cleanup)
        self._path_to_wd: dict[str, int] = {}

        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the background read loop."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._read_loop,
            name="aegis-inotify",
            daemon=True,
        )
        self._thread.start()

    def add_watch(self, file_path: str, model_name: str) -> None:
        """Add an inotify watch on a file.

        Raises OSError if the watch cannot be added.
        """
        path_bytes = file_path.encode("utf-8")
        wd = _libc.inotify_add_watch(self._fd, path_bytes, _WATCH_MASK)
        if wd < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"inotify_add_watch failed for {file_path}: {os.strerror(errno)}")

        with self._lock:
            self._watches[wd] = (file_path, model_name)
            self._path_to_wd[file_path] = wd

    def stop(self) -> None:
        """Stop the watcher and clean up resources."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        # Remove all watches and close fd
        with self._lock:
            for wd in list(self._watches.keys()):
                try:
                    _libc.inotify_rm_watch(self._fd, wd)
                except Exception:
                    pass
            self._watches.clear()
            self._path_to_wd.clear()

        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    def _read_loop(self) -> None:
        """Background thread reading inotify events."""
        buf_size = 4096
        while not self._stop_event.is_set():
            try:
                data = os.read(self._fd, buf_size)
            except BlockingIOError:
                # No events available (non-blocking mode)
                self._stop_event.wait(timeout=0.5)
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                logger.debug("inotify read error", exc_info=True)
                self._stop_event.wait(timeout=1.0)
                continue

            if not data:
                self._stop_event.wait(timeout=0.5)
                continue

            self._parse_events(data)

    def _parse_events(self, data: bytes) -> None:
        """Parse raw inotify event data and invoke callbacks."""
        offset = 0
        while offset + _EVENT_HEADER_SIZE <= len(data):
            wd, mask, _cookie, name_len = struct.unpack_from(
                "iIII", data, offset,
            )
            offset += _EVENT_HEADER_SIZE + name_len

            with self._lock:
                watch_info = self._watches.get(wd)

            if watch_info is None:
                continue

            file_path, model_name = watch_info
            try:
                self._callback(file_path, model_name)
            except Exception:
                logger.debug(
                    "inotify callback error for %s", file_path, exc_info=True,
                )
