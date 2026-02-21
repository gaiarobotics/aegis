"""Recovery quarantine module for AEGIS."""

import threading
from typing import Any, Optional

from aegis.core.config import RecoveryConfig


class RecoveryQuarantine:
    """Manages quarantine state for the AEGIS recovery system.

    Thread-safe quarantine management with support for automatic
    quarantine based on NK verdicts and drift detection results.
    """

    def __init__(
        self,
        config: RecoveryConfig | None = None,
        exit_token: Optional[str] = None,
    ) -> None:
        self._config = config or RecoveryConfig()
        self._exit_token: Optional[str] = exit_token
        self._quarantined = False
        self._reason: Optional[str] = None
        self._read_only = False
        self._lock = threading.Lock()

    def enter(self, reason: str, read_only: bool = True) -> None:
        """Activate quarantine with a given reason.

        Args:
            reason: The reason for entering quarantine.
            read_only: Whether quarantine is read-only mode.
        """
        with self._lock:
            self._quarantined = True
            self._reason = reason
            self._read_only = read_only

    def exit(self, token: Optional[str] = None) -> None:
        """Deactivate quarantine.

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
            self._read_only = False

    def is_quarantined(self) -> bool:
        """Check if currently quarantined.

        Returns:
            True if quarantine is active, False otherwise.
        """
        with self._lock:
            return self._quarantined

    def get_reason(self) -> Optional[str]:
        """Get the reason for quarantine.

        Returns:
            The quarantine reason string, or None if not quarantined.
        """
        with self._lock:
            return self._reason

    def auto_quarantine(
        self,
        nk_verdict: Any = None,
        drift_result: Any = None,
    ) -> bool:
        """Automatically enter quarantine based on verdict or drift results.

        Args:
            nk_verdict: An object with a `verdict` attribute.
            drift_result: An object with `is_drifting` and `max_sigma` attributes.

        Returns:
            True if quarantine was entered, False otherwise.
        """
        if not self._config.auto_quarantine:
            return False

        # Check NK verdict
        if nk_verdict is not None:
            if (
                self._config.quarantine_on_hostile_nk
                and getattr(nk_verdict, "verdict", None) == "hostile"
            ):
                self.enter(reason="Auto-quarantine: hostile NK verdict detected")
                return True

        # Check drift result
        if drift_result is not None:
            if (
                getattr(drift_result, "is_drifting", False)
                and getattr(drift_result, "max_sigma", 0.0)
                > self._config.drift_sigma_threshold
            ):
                sigma = getattr(drift_result, "max_sigma", 0.0)
                self.enter(
                    reason=f"Auto-quarantine: drift detected (max_sigma={sigma})"
                )
                return True

        return False
