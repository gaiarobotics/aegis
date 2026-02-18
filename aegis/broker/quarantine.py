"""Quarantine mode for the AEGIS Broker."""

from __future__ import annotations

import threading

from aegis.core.config import AegisConfig


class QuarantineManager:
    """Thread-safe quarantine manager for read-only lockdown mode."""

    def __init__(
        self,
        config: AegisConfig | None = None,
        exit_token: str | None = None,
    ) -> None:
        if config is None:
            config = AegisConfig()

        triggers = config.broker.get("quarantine_triggers", {})
        self._threshold_denied_writes: int = triggers.get("repeated_denied_writes", 5)
        self._threshold_new_domain_burst: int = triggers.get("new_domain_burst", 3)
        self._threshold_drift_score: float = triggers.get("drift_score_threshold", 3.0)

        self._exit_token: str | None = exit_token
        self._lock = threading.Lock()
        self._quarantined: bool = False
        self._reason: str | None = None

    def enter_quarantine(self, reason: str) -> None:
        """Activate read-only quarantine mode."""
        with self._lock:
            self._quarantined = True
            self._reason = reason

    def exit_quarantine(self, token: str | None = None) -> None:
        """Deactivate quarantine mode.

        Args:
            token: If an exit_token was configured, this must match it.

        Raises:
            ValueError: If an exit_token was configured and the provided
                token does not match.
        """
        with self._lock:
            if self._exit_token is not None and token != self._exit_token:
                raise ValueError("Invalid exit token")
            self._quarantined = False
            self._reason = None

    def is_quarantined(self) -> bool:
        """Check whether quarantine mode is active."""
        with self._lock:
            return self._quarantined

    @property
    def reason(self) -> str | None:
        """Return the reason quarantine was activated, or None."""
        with self._lock:
            return self._reason

    def check_triggers(
        self,
        denied_count: int,
        new_domain_count: int,
        drift_score: float | None = None,
    ) -> None:
        """Auto-enter quarantine if any threshold is exceeded.

        Args:
            denied_count: Number of denied write attempts.
            new_domain_count: Number of new domains contacted.
            drift_score: Current behavioral drift score, or None.
        """
        if denied_count >= self._threshold_denied_writes:
            self.enter_quarantine(
                f"Repeated denied writes: {denied_count} >= {self._threshold_denied_writes}"
            )
            return

        if new_domain_count >= self._threshold_new_domain_burst:
            self.enter_quarantine(
                f"New domain burst: {new_domain_count} >= {self._threshold_new_domain_burst}"
            )
            return

        if drift_score is not None and drift_score >= self._threshold_drift_score:
            self.enter_quarantine(
                f"Drift score exceeded: {drift_score} >= {self._threshold_drift_score}"
            )
            return
