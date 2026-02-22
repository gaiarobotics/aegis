"""Quarantine mode for the AEGIS Broker."""

from __future__ import annotations

import threading
import time

from aegis.core.config import AegisConfig


# Severity tiers determine cooldown behavior:
# - "low": auto-release after short cooldown (e.g., denied writes from tool discovery)
# - "medium": auto-release after longer cooldown (e.g., new domain burst)
# - "high": requires manual release (e.g., behavioral drift anomaly)
_REASON_SEVERITY: dict[str, str] = {
    "denied_writes": "low",
    "new_domain_burst": "medium",
    "drift_score": "high",
}

_COOLDOWN_SECONDS: dict[str, float] = {
    "low": 60.0,
    "medium": 300.0,
}


def _classify_severity(reason: str) -> str:
    """Classify quarantine severity from the reason string."""
    reason_lower = reason.lower()
    if "denied" in reason_lower and "write" in reason_lower:
        return "low"
    if "domain" in reason_lower:
        return "medium"
    if "drift" in reason_lower:
        return "high"
    return "medium"  # Default to medium for unknown reasons


class QuarantineManager:
    """Thread-safe quarantine manager for read-only lockdown mode."""

    def __init__(
        self,
        config: AegisConfig | None = None,
        exit_token: str | None = None,
    ) -> None:
        if config is None:
            config = AegisConfig()

        self._threshold_denied_writes: int = config.broker.quarantine_triggers.repeated_denied_writes
        self._threshold_new_domain_burst: int = config.broker.quarantine_triggers.new_domain_burst
        self._threshold_drift_score: float = config.broker.quarantine_triggers.drift_score_threshold

        self._exit_token: str | None = exit_token
        self._lock = threading.Lock()
        self._quarantined: bool = False
        self._reason: str | None = None
        self._severity: str = "low"
        self._quarantine_time: float | None = None

    def enter_quarantine(self, reason: str) -> None:
        """Activate read-only quarantine mode."""
        with self._lock:
            self._quarantined = True
            self._reason = reason
            self._severity = _classify_severity(reason)
            self._quarantine_time = time.monotonic()

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
            self._severity = "low"
            self._quarantine_time = None

    def is_quarantined(self) -> bool:
        """Check whether quarantine mode is active.

        Automatically releases quarantine if the cooldown has expired
        for low/medium severity quarantines.
        """
        with self._lock:
            if not self._quarantined:
                return False
            # Check cooldown for auto-release
            if self._quarantine_time is not None and self._severity in _COOLDOWN_SECONDS:
                elapsed = time.monotonic() - self._quarantine_time
                if elapsed >= _COOLDOWN_SECONDS[self._severity]:
                    self._quarantined = False
                    self._reason = None
                    self._severity = "low"
                    self._quarantine_time = None
                    return False
            return self._quarantined

    @property
    def reason(self) -> str | None:
        """Return the reason quarantine was activated, or None."""
        with self._lock:
            return self._reason

    @property
    def severity(self) -> str:
        """Return the severity tier of the current quarantine."""
        with self._lock:
            return self._severity

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
