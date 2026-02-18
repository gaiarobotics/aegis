"""Recovery quarantine module for AEGIS."""

import threading
from typing import Any, Optional


_DEFAULT_CONFIG = {
    "auto_quarantine": True,
    "quarantine_on_hostile_nk": True,
    "drift_sigma_threshold": 3.0,
}


class RecoveryQuarantine:
    """Manages quarantine state for the AEGIS recovery system.

    Thread-safe quarantine management with support for automatic
    quarantine based on NK verdicts and drift detection results.
    """

    def __init__(self, config: Optional[dict] = None) -> None:
        self._config = {**_DEFAULT_CONFIG}
        if config is not None:
            self._config.update(config)
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

    def exit(self) -> None:
        """Deactivate quarantine."""
        with self._lock:
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
        if not self._config.get("auto_quarantine", True):
            return False

        # Check NK verdict
        if nk_verdict is not None:
            if (
                self._config.get("quarantine_on_hostile_nk", True)
                and getattr(nk_verdict, "verdict", None) == "hostile"
            ):
                self.enter(reason="Auto-quarantine: hostile NK verdict detected")
                return True

        # Check drift result
        if drift_result is not None:
            if (
                getattr(drift_result, "is_drifting", False)
                and getattr(drift_result, "max_sigma", 0.0)
                > self._config.get("drift_sigma_threshold", 3.0)
            ):
                sigma = getattr(drift_result, "max_sigma", 0.0)
                self.enter(
                    reason=f"Auto-quarantine: drift detected (max_sigma={sigma})"
                )
                return True

        return False
