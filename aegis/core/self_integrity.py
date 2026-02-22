"""Self-integrity monitoring for AEGIS package files and config.

Detects runtime tampering of AEGIS source code and configuration by
periodically computing SHA256 hashes and comparing against baselines
established at startup.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


class SelfIntegrityWatcher:
    """Monitors AEGIS package files and config for runtime tampering.

    Computes SHA256 baselines at construction time, then periodically
    re-checks all watched files from a background daemon thread.

    Args:
        config: A ``SelfIntegrityConfig`` instance.
        package_dir: Root directory of the aegis package.
        config_path: Absolute path to the config file (may be empty).
        on_tamper: Callback invoked with the changed file path on tamper.
    """

    def __init__(
        self,
        config: Any,
        package_dir: Path,
        config_path: str = "",
        on_tamper: Callable[[str], None] | None = None,
    ) -> None:
        self._config = config
        self._on_tamper = on_tamper
        self._interval = config.check_interval_seconds
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        # Build baselines
        self._baselines: dict[str, str] = {}
        if config.watch_package:
            self._baselines.update(self._scan_package(package_dir))
        if config.watch_config and config_path:
            p = Path(config_path)
            if p.is_file():
                digest = self._hash_file(str(p))
                if digest:
                    self._baselines[str(p)] = digest

    def _scan_package(self, package_dir: Path) -> dict[str, str]:
        """Discover all .py files under package_dir and compute their SHA256."""
        baselines: dict[str, str] = {}
        try:
            for py_file in sorted(package_dir.rglob("*.py")):
                if not py_file.is_file():
                    continue
                digest = self._hash_file(str(py_file))
                if digest:
                    baselines[str(py_file)] = digest
        except OSError:
            logger.debug("Failed to scan package dir: %s", package_dir, exc_info=True)
        return baselines

    @staticmethod
    def _hash_file(path: str) -> str:
        """Compute SHA256 hex digest of a file. Returns empty string on error."""
        try:
            from aegis.integrity.monitor import _compute_sha256
            return _compute_sha256(path)
        except Exception:
            return ""

    @property
    def baselines(self) -> dict[str, str]:
        """Return a copy of the current baselines (for testing)."""
        with self._lock:
            return dict(self._baselines)

    def start(self) -> None:
        """Start background daemon thread for periodic checks."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._check_loop,
            name="aegis-self-integrity",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop background thread."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=self._interval + 2)

    def _check_loop(self) -> None:
        """Periodically check all watched files against baselines."""
        while not self._stop_event.wait(timeout=self._interval):
            self._check_once()

    def _check_once(self) -> None:
        """Single check pass over all baselined files."""
        with self._lock:
            snapshot = dict(self._baselines)

        for path, expected_hash in snapshot.items():
            if self._stop_event.is_set():
                return

            if not os.path.isfile(path):
                # File deleted — tamper
                logger.warning("Self-integrity: file deleted: %s", path)
                if self._on_tamper:
                    self._on_tamper(path)
                return  # One tamper is enough

            current_hash = self._hash_file(path)
            if not current_hash:
                continue  # Can't read — skip this cycle

            if current_hash != expected_hash:
                logger.warning("Self-integrity: file modified: %s", path)
                if self._on_tamper:
                    self._on_tamper(path)
                return  # One tamper is enough
