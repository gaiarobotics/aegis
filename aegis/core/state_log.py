"""HMAC-chained append-only event log for tamper-proof state persistence.

Each entry is HMAC-SHA256 signed and includes a chain hash linking to
the previous entry's signature.  Tampering with any entry (insertion,
deletion, or modification) breaks the chain and is detected on load.

The signing key is read from the ``AEGIS_STATE_KEY`` environment variable
or generated ephemerally.  It is never written to disk.

Filesystem ``O_APPEND`` and ``chattr +a`` protections are applied
best-effort when available.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import struct
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel for the first entry in the chain
_GENESIS_CHAIN = "0" * 64


@dataclass
class StateEvent:
    """A single event in the append-only state log.

    Attributes:
        event_type: Categorical event name (e.g. ``trust_interaction``).
        data: Arbitrary JSON-serialisable payload.
        timestamp: Unix timestamp of the event.
        sequence: Monotonic sequence number within the log.
        chain_hash: SHA-256 hex digest of the previous entry's signature.
        signature: HMAC-SHA256 hex digest over the canonical representation.
    """

    event_type: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    sequence: int = 0
    chain_hash: str = _GENESIS_CHAIN
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Build the canonical byte representation for signing.

        Includes all fields except ``signature`` itself.  The ``data``
        dict is serialised with sorted keys for determinism.
        """
        parts = [
            self.event_type,
            json.dumps(self.data, sort_keys=True, separators=(",", ":")),
            f"{self.timestamp:.6f}",
            str(self.sequence),
            self.chain_hash,
        ]
        return "|".join(parts).encode("utf-8")


def _hmac_sign(data: bytes, key: bytes) -> str:
    """Return HMAC-SHA256 hex digest."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _hmac_verify(data: bytes, signature_hex: str, key: bytes) -> bool:
    """Verify HMAC-SHA256 hex signature."""
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)


def _sha256_hex(data: str) -> str:
    """SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _try_set_append_only(path: Path) -> bool:
    """Best-effort: set the filesystem append-only attribute.

    Uses ``chattr +a`` on Linux.  Returns True if successful.
    """
    try:
        result = subprocess.run(
            ["chattr", "+a", str(path)],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            logger.debug("Set append-only attribute on %s", path)
            return True
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    return False


def _try_open_append(path: Path) -> Any:
    """Open a file with O_APPEND where available.

    Falls back to normal append mode on platforms that don't support
    ``os.O_APPEND``.  Returns a file object opened for text writing.
    """
    try:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        fd = os.open(str(path), flags, 0o644)
        return os.fdopen(fd, "a", encoding="utf-8")
    except (AttributeError, OSError):
        return open(path, "a", encoding="utf-8")


def resolve_state_key() -> bytes:
    """Resolve the HMAC signing key for the state log.

    Resolution order:
    1. ``AEGIS_STATE_KEY`` environment variable (hex-encoded)
    2. ``AEGIS_STATE_KEY`` environment variable (raw UTF-8)
    3. Generate an ephemeral 32-byte random key (logs a warning)

    Returns:
        32-byte signing key.
    """
    env_key = os.environ.get("AEGIS_STATE_KEY", "")
    if env_key:
        # Try hex decode first
        try:
            decoded = bytes.fromhex(env_key)
            if len(decoded) >= 16:
                return decoded[:32].ljust(32, b"\x00")
        except ValueError:
            pass
        # Fall back to hashing the raw value
        return hashlib.sha256(env_key.encode("utf-8")).digest()

    logger.warning(
        "AEGIS_STATE_KEY not set — using ephemeral key. "
        "State log signatures will not survive daemon restart."
    )
    return os.urandom(32)


class StateLog:
    """HMAC-chained append-only event log.

    Thread-safe.  Entries are written as JSONL, each signed and chained
    to the previous entry.

    Args:
        path: Path to the log file.
        key: HMAC signing key (32 bytes).  If ``None``, resolved via
            :func:`resolve_state_key`.
        apply_fs_protection: Whether to attempt filesystem-level append
            protections (``O_APPEND``, ``chattr +a``).
    """

    def __init__(
        self,
        path: str | Path,
        key: bytes | None = None,
        apply_fs_protection: bool = True,
    ) -> None:
        self._path = Path(path)
        self._key = key if key is not None else resolve_state_key()
        self._lock = threading.Lock()
        self._sequence: int = 0
        self._last_signature: str = _GENESIS_CHAIN
        self._apply_fs_protection = apply_fs_protection
        self._fs_protected = False

    @property
    def path(self) -> Path:
        return self._path

    @property
    def sequence(self) -> int:
        with self._lock:
            return self._sequence

    @property
    def last_signature(self) -> str:
        with self._lock:
            return self._last_signature

    def _ensure_file(self) -> None:
        """Create the log file and parent directories if needed."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch(mode=0o644)
        if self._apply_fs_protection and not self._fs_protected:
            self._fs_protected = _try_set_append_only(self._path)

    def append(self, event_type: str, **data: Any) -> StateEvent:
        """Append a signed event to the log.

        Args:
            event_type: Event category name.
            **data: Arbitrary event payload (must be JSON-serialisable).

        Returns:
            The signed :class:`StateEvent` that was written.
        """
        with self._lock:
            self._ensure_file()

            event = StateEvent(
                event_type=event_type,
                data=data,
                timestamp=time.time(),
                sequence=self._sequence,
                chain_hash=_sha256_hex(self._last_signature),
            )
            event.signature = _hmac_sign(event.canonical_bytes(), self._key)

            line = json.dumps(
                {
                    "event_type": event.event_type,
                    "data": event.data,
                    "timestamp": event.timestamp,
                    "sequence": event.sequence,
                    "chain_hash": event.chain_hash,
                    "signature": event.signature,
                },
                sort_keys=True,
                separators=(",", ":"),
            )

            try:
                f = _try_open_append(self._path)
                try:
                    f.write(line + "\n")
                    f.flush()
                    os.fsync(f.fileno())
                finally:
                    f.close()
            except OSError:
                logger.error("Failed to write state log entry", exc_info=True)
                raise

            self._sequence += 1
            self._last_signature = event.signature

            return event

    def load_and_verify(self) -> list[StateEvent]:
        """Load all entries and verify the HMAC chain.

        Returns:
            List of verified :class:`StateEvent` instances.

        Raises:
            TamperDetectedError: If any entry fails signature or chain
                verification.
            FileNotFoundError: If the log file does not exist.
        """
        if not self._path.exists():
            return []

        events: list[StateEvent] = []
        expected_chain = _sha256_hex(_GENESIS_CHAIN)

        with open(self._path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise TamperDetectedError(
                        f"Line {line_num}: invalid JSON — {exc}"
                    )

                event = StateEvent(
                    event_type=raw["event_type"],
                    data=raw.get("data", {}),
                    timestamp=raw["timestamp"],
                    sequence=raw["sequence"],
                    chain_hash=raw["chain_hash"],
                    signature=raw["signature"],
                )

                # Verify chain continuity
                if event.chain_hash != expected_chain:
                    raise TamperDetectedError(
                        f"Line {line_num}: chain break — "
                        f"expected {expected_chain[:16]}…, "
                        f"got {event.chain_hash[:16]}…"
                    )

                # Verify HMAC signature
                if not _hmac_verify(
                    event.canonical_bytes(), event.signature, self._key
                ):
                    raise TamperDetectedError(
                        f"Line {line_num}: invalid signature for "
                        f"event '{event.event_type}' seq={event.sequence}"
                    )

                # Verify sequence monotonicity
                expected_seq = len(events)
                if event.sequence != expected_seq:
                    raise TamperDetectedError(
                        f"Line {line_num}: sequence gap — "
                        f"expected {expected_seq}, got {event.sequence}"
                    )

                events.append(event)
                expected_chain = _sha256_hex(event.signature)

        # Update internal state to continue appending after the last entry
        with self._lock:
            self._sequence = len(events)
            if events:
                self._last_signature = events[-1].signature
            else:
                self._last_signature = _GENESIS_CHAIN

        return events

    def write_checkpoint(self, state: dict[str, Any], path: str | Path) -> None:
        """Write a signed state snapshot for fast startup.

        The checkpoint contains the full reconstructed state plus chain
        metadata, signed with the same HMAC key.

        Args:
            state: The reconstructed state dict to checkpoint.
            path: Path to write the checkpoint file.
        """
        checkpoint_path = Path(path)
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            payload = {
                "state": state,
                "sequence": self._sequence,
                "last_signature": self._last_signature,
                "timestamp": time.time(),
            }

        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        sig = _hmac_sign(canonical, self._key)

        envelope = {
            "payload": payload,
            "signature": sig,
        }

        # Atomic write via temp + rename
        import tempfile

        dir_name = str(checkpoint_path.parent)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(envelope, f, sort_keys=True, separators=(",", ":"))
            os.replace(tmp_path, str(checkpoint_path))
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load_checkpoint(self, path: str | Path) -> dict[str, Any] | None:
        """Load and verify a signed state checkpoint.

        Returns:
            The checkpoint payload dict, or ``None`` if the file does
            not exist or verification fails.
        """
        checkpoint_path = Path(path)
        if not checkpoint_path.exists():
            return None

        try:
            with open(checkpoint_path, "r", encoding="utf-8") as f:
                envelope = json.load(f)
        except (json.JSONDecodeError, OSError):
            logger.warning("Checkpoint file unreadable: %s", checkpoint_path)
            return None

        payload = envelope.get("payload")
        sig = envelope.get("signature", "")

        if payload is None:
            return None

        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        if not _hmac_verify(canonical, sig, self._key):
            logger.warning(
                "Checkpoint signature verification failed: %s — "
                "ignoring checkpoint and rebuilding from log",
                checkpoint_path,
            )
            return None

        # Restore internal state from checkpoint
        with self._lock:
            self._sequence = payload.get("sequence", 0)
            self._last_signature = payload.get(
                "last_signature", _GENESIS_CHAIN
            )

        return payload


class TamperDetectedError(Exception):
    """Raised when the state log integrity check fails.

    Attributes:
        detail: Human-readable description of the tampering detected.
    """

    def __init__(self, detail: str = ""):
        self.detail = detail
        super().__init__(f"State log tamper detected: {detail}")
