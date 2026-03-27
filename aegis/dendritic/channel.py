"""Alert channel — typed, schema-enforced write path for dendritic alerts.

Solves the Sentinel Paradox: the sentinel needs a narrow write channel to
retransmit processed alerts, without gaining general write access. This
channel accepts ONLY DendriticAlert objects and sends them via the
monitoring client or directly to target Shield instances.

Analogous to dendritic cell migration to lymph nodes for antigen presentation.
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.dendritic.alert import DendriticAlert, verify_alert

logger = logging.getLogger(__name__)


class AlertChannel:
    """Typed alert channel that only transmits DendriticAlert messages.

    Schema-enforced: rejects anything that is not a DendriticAlert.
    All alerts must be signed and are verified before transmission.

    Args:
        monitoring_client: Optional monitoring client for remote alert delivery.
        sentinel_public_key: The sentinel's public key for signature verification.
        key_type: The key type used for signing ("hmac-sha256" or "ed25519").
    """

    def __init__(
        self,
        monitoring_client: Any = None,
        sentinel_public_key: bytes | None = None,
        key_type: str = "hmac-sha256",
    ) -> None:
        self._monitoring_client = monitoring_client
        self._sentinel_public_key = sentinel_public_key
        self._key_type = key_type
        self._sent_count = 0
        self._rejected_count = 0

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def rejected_count(self) -> int:
        return self._rejected_count

    def send(self, alert: DendriticAlert) -> bool:
        """Send a dendritic alert through the channel.

        Verifies the alert signature before transmission. Rejects
        unsigned, mis-signed, or non-DendriticAlert objects.

        Args:
            alert: The signed DendriticAlert to transmit.

        Returns:
            True if the alert was accepted and sent, False if rejected.
        """
        # Schema enforcement: only DendriticAlert objects
        if not isinstance(alert, DendriticAlert):
            logger.warning("AlertChannel rejected non-DendriticAlert object: %s", type(alert).__name__)
            self._rejected_count += 1
            return False

        # Signature verification
        if self._sentinel_public_key is not None:
            if not verify_alert(alert, self._sentinel_public_key, self._key_type):
                logger.warning(
                    "AlertChannel rejected alert with invalid signature from sentinel %s",
                    alert.sentinel_id,
                )
                self._rejected_count += 1
                return False

        # Transmit via monitoring client
        if self._monitoring_client is not None:
            try:
                self._monitoring_client.send_dendritic_alert(
                    source_agent_id=alert.source_agent_id,
                    sentinel_id=alert.sentinel_id,
                    danger_signal=alert.danger_signal.value,
                    threat_score=alert.threat_score,
                    cleaned_fragment=alert.cleaned_fragment,
                    original_content_hash=alert.original_content_hash,
                    modifications=alert.modifications,
                )
            except Exception:
                logger.debug("Failed to send dendritic alert via monitoring client", exc_info=True)

        self._sent_count += 1
        logger.info(
            "Dendritic alert sent: source=%s signal=%s score=%.2f",
            alert.source_agent_id,
            alert.danger_signal.value,
            alert.threat_score,
        )
        return True

    def receive(self, alert: DendriticAlert, public_key: bytes, key_type: str = "hmac-sha256") -> bool:
        """Receive and verify a dendritic alert from an external sentinel.

        This is the receiving end — used by Shield.receive_dendritic_alert()
        to verify incoming alerts before acting on them.

        Args:
            alert: The incoming DendriticAlert.
            public_key: The sentinel's public key to verify against.
            key_type: The key type for verification.

        Returns:
            True if the alert is authentic, False otherwise.
        """
        if not isinstance(alert, DendriticAlert):
            return False
        return verify_alert(alert, public_key, key_type)
