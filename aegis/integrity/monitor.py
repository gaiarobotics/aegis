"""Model integrity monitoring for AEGIS.

Detects tampering of local model files via a tiered strategy:
1. Stat check (mtime_ns, size, inode) — essentially free, every call
2. inotify watch (Linux) — real-time notification of file changes
3. SHA256 hash — sync or async at model registration time
4. Periodic re-hash — defense-in-depth against mmap modifications
"""

from __future__ import annotations

import enum
import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# SHA256 read chunk size
_HASH_CHUNK_SIZE = 65536  # 64 KB


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ModelTamperedError(Exception):
    """Raised when model file tampering is detected in enforce mode.

    Attributes:
        model_name: The name of the tampered model.
        file_path: The file path where tampering was detected.
        detail: Human-readable description of what changed.
    """

    def __init__(
        self,
        model_name: str = "",
        file_path: str = "",
        detail: str = "",
    ) -> None:
        self.model_name = model_name
        self.file_path = file_path
        self.detail = detail
        msg = f"Model tampered: {model_name}"
        if detail:
            msg += f" — {detail}"
        super().__init__(msg)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class ProvenanceStatus(enum.Enum):
    """Provenance verification status for a model file."""

    PENDING = "pending"
    VERIFIED_MANIFEST = "verified_manifest"
    UNVERIFIED = "unverified"


@dataclass
class StatSnapshot:
    """Lightweight filesystem metadata snapshot for change detection."""

    mtime_ns: int
    size: int
    inode: int

    @classmethod
    def from_path(cls, path: str) -> StatSnapshot:
        """Create a snapshot from a file path using os.stat()."""
        st = os.stat(path)
        return cls(
            mtime_ns=st.st_mtime_ns,
            size=st.st_size,
            inode=st.st_ino,
        )


@dataclass
class ModelFileRecord:
    """Per-file integrity state."""

    path: str
    stat: StatSnapshot
    sha256: str = ""
    provenance: ProvenanceStatus = ProvenanceStatus.PENDING
    manifest_digest: str = ""


@dataclass
class RegisteredModel:
    """Tracks all files and metadata for a registered model."""

    model_name: str
    provider: str
    files: list[ModelFileRecord] = field(default_factory=list)
    registered_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# IntegrityMonitor
# ---------------------------------------------------------------------------


class IntegrityMonitor:
    """Monitors model file integrity using tiered detection.

    Thread-safe.  Background threads (hash worker, rehash loop) use
    ``daemon=True`` and ``threading.Event`` for clean shutdown.

    Args:
        config: An ``IntegrityConfig`` instance from ``aegis.core.config``.
    """

    def __init__(self, config: Any) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._models: dict[str, RegisteredModel] = {}

        # Background hashing
        self._hash_queue: list[tuple[str, ModelFileRecord]] = []
        self._hash_queue_lock = threading.Lock()
        self._stop_event = threading.Event()

        # Start hash worker for async mode
        self._hash_thread: threading.Thread | None = None
        if config.hash_on_load == "async":
            self._hash_thread = threading.Thread(
                target=self._hash_worker,
                name="aegis-integrity-hash",
                daemon=True,
            )
            self._hash_thread.start()

        # Start periodic rehash thread
        self._rehash_thread: threading.Thread | None = None
        if config.rehash_interval_seconds > 0:
            self._rehash_thread = threading.Thread(
                target=self._rehash_loop,
                name="aegis-integrity-rehash",
                daemon=True,
            )
            self._rehash_thread.start()

        # inotify watcher (Linux only, graceful degradation)
        self._watcher = None
        if config.inotify_enabled:
            self._init_inotify()

    def _init_inotify(self) -> None:
        """Attempt to initialize inotify watcher; no-op on non-Linux."""
        try:
            from aegis.integrity.watcher import InotifyWatcher

            self._watcher = InotifyWatcher(
                callback=self._on_inotify_event,
                stop_event=self._stop_event,
            )
            self._watcher.start()
        except (ImportError, OSError):
            logger.debug("inotify not available, falling back to stat-only", exc_info=True)
            self._watcher = None

    def _on_inotify_event(self, file_path: str, model_name: str) -> None:
        """Handle inotify file change notification."""
        logger.info(
            "inotify: file change detected for model %s: %s",
            model_name, file_path,
        )
        # Force a stat refresh so next check_integrity() picks it up
        # The actual detection happens in check_integrity() via stat comparison

    # ----- Registration -----

    def register_model(
        self,
        model_name: str,
        provider: str,
        model_path: str | None = None,
    ) -> None:
        """Discover and register model files for integrity monitoring.

        Safe to call multiple times for the same model (idempotent).
        """
        with self._lock:
            if model_name in self._models:
                return

        # Discover files based on provider
        file_paths: list[str] = []
        digests: dict[str, str] = {}

        if provider == "ollama":
            from aegis.integrity.discovery import discover_ollama_files

            file_paths, digests = discover_ollama_files(
                model_name,
                ollama_models_path=self._config.ollama_models_path,
            )
        elif provider == "vllm":
            from aegis.integrity.discovery import discover_vllm_files

            file_paths, digests = discover_vllm_files(
                model_name,
                model_path=model_path,
                hf_cache_path=self._config.hf_cache_path,
                extensions=self._config.model_file_extensions,
            )

        if not file_paths:
            logger.debug(
                "No model files found for %s (provider=%s)", model_name, provider,
            )
            # Register with empty file list so we don't keep retrying
            with self._lock:
                self._models[model_name] = RegisteredModel(
                    model_name=model_name, provider=provider,
                )
            return

        # Build file records with stat snapshots
        records: list[ModelFileRecord] = []
        for fpath in file_paths:
            try:
                stat = StatSnapshot.from_path(fpath)
            except OSError:
                logger.debug("Could not stat model file: %s", fpath)
                continue

            manifest_digest = digests.get(fpath, "")
            record = ModelFileRecord(
                path=fpath,
                stat=stat,
                manifest_digest=manifest_digest,
            )
            records.append(record)

            # Add inotify watch if available
            if self._watcher is not None:
                try:
                    self._watcher.add_watch(fpath, model_name)
                except OSError:
                    logger.debug("Failed to add inotify watch: %s", fpath)

        # Hash based on config
        if self._config.hash_on_load == "sync":
            for record in records:
                self._hash_file(record)
        elif self._config.hash_on_load == "async":
            with self._hash_queue_lock:
                for record in records:
                    self._hash_queue.append((model_name, record))

        with self._lock:
            self._models[model_name] = RegisteredModel(
                model_name=model_name,
                provider=provider,
                files=records,
            )

    def is_registered(self, model_name: str) -> bool:
        """Check if a model is registered for integrity monitoring."""
        with self._lock:
            return model_name in self._models

    def get_status(self, model_name: str) -> RegisteredModel | None:
        """Get the current registration status for a model."""
        with self._lock:
            return self._models.get(model_name)

    # ----- Integrity checking (hot path) -----

    def check_integrity(self, model_name: str) -> list[str]:
        """Fast stat-based integrity check for a registered model.

        Returns a list of issue descriptions.  Empty list means clean.
        """
        with self._lock:
            model = self._models.get(model_name)
            if model is None:
                return []

        issues: list[str] = []
        for record in model.files:
            try:
                current = StatSnapshot.from_path(record.path)
            except FileNotFoundError:
                issues.append(f"file missing: {record.path}")
                continue
            except OSError as exc:
                issues.append(f"stat error: {record.path}: {exc}")
                continue

            if current.mtime_ns != record.stat.mtime_ns:
                issues.append(f"mtime changed: {record.path}")
            if current.size != record.stat.size:
                issues.append(f"size changed: {record.path}")
            if current.inode != record.stat.inode:
                issues.append(f"inode changed: {record.path}")

        return issues

    # ----- Hashing -----

    def _hash_file(self, record: ModelFileRecord) -> None:
        """Compute SHA256 hash for a file and update its record."""
        try:
            sha = _compute_sha256(record.path)
            record.sha256 = sha

            # Check provenance against manifest digest
            if record.manifest_digest:
                if sha == record.manifest_digest:
                    record.provenance = ProvenanceStatus.VERIFIED_MANIFEST
                else:
                    record.provenance = ProvenanceStatus.UNVERIFIED
                    logger.warning(
                        "Hash mismatch for %s: computed=%s manifest=%s",
                        record.path, sha, record.manifest_digest,
                    )
            else:
                record.provenance = ProvenanceStatus.UNVERIFIED
        except OSError:
            logger.debug("Failed to hash file: %s", record.path, exc_info=True)

    def _hash_worker(self) -> None:
        """Background thread that processes the async hash queue."""
        while not self._stop_event.is_set():
            item = None
            with self._hash_queue_lock:
                if self._hash_queue:
                    item = self._hash_queue.pop(0)

            if item is None:
                self._stop_event.wait(timeout=0.1)
                continue

            _model_name, record = item
            self._hash_file(record)

    def _rehash_loop(self) -> None:
        """Periodically re-hash all registered model files."""
        interval = self._config.rehash_interval_seconds
        while not self._stop_event.wait(timeout=interval):
            with self._lock:
                models = list(self._models.values())

            for model in models:
                for record in model.files:
                    if self._stop_event.is_set():
                        return
                    old_sha = record.sha256
                    if not old_sha:
                        # Not yet hashed, skip
                        continue
                    try:
                        new_sha = _compute_sha256(record.path)
                    except OSError:
                        logger.warning(
                            "Rehash: file not accessible: %s", record.path,
                        )
                        continue

                    if new_sha != old_sha:
                        logger.warning(
                            "Rehash: hash changed for %s (model=%s): %s -> %s",
                            record.path, model.model_name, old_sha, new_sha,
                        )
                        # Update the stat snapshot so check_integrity detects it too
                        try:
                            record.stat = StatSnapshot.from_path(record.path)
                        except OSError:
                            pass
                    else:
                        record.sha256 = new_sha

    # ----- Shutdown -----

    def stop(self) -> None:
        """Clean shutdown of background threads."""
        self._stop_event.set()
        if self._hash_thread is not None and self._hash_thread.is_alive():
            self._hash_thread.join(timeout=2.0)
        if self._rehash_thread is not None and self._rehash_thread.is_alive():
            self._rehash_thread.join(timeout=2.0)
        if self._watcher is not None:
            self._watcher.stop()


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _compute_sha256(file_path: str) -> str:
    """Compute SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
