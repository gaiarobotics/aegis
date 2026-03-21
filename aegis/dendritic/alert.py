"""Danger signal and alert message construction for dendritic processing.

Maps to MHC-II loading and T-cell co-stimulation: the processed fragment
is tagged with a danger signal and signed by the sentinel's attestation key.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any


class DangerSignal(str, Enum):
    """Danger signals that co-stimulate the receiving agent's response.

    Analogous to DAMPs/PAMPs in immunology — without a danger signal,
    antigen presentation leads to tolerance, not activation.
    """

    STOP_AND_ALERT_HUMAN = "stop_and_alert_human"
    ELEVATED_SCRUTINY = "elevated_scrutiny"
    QUARANTINE_RECOMMENDED = "quarantine_recommended"


@dataclass
class DendriticAlert:
    """A signed alert carrying a processed injection fragment and danger signal.

    Analogous to a dendritic cell presenting antigen on MHC-II to T-helper cells.
    The signature prevents spoofing — only authenticated sentinels can emit alerts.
    """

    cleaned_fragment: str
    danger_signal: DangerSignal
    source_agent_id: str
    sentinel_id: str
    threat_score: float
    original_content_hash: str
    timestamp: float
    signature: bytes
    modifications: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for transport."""
        return {
            "cleaned_fragment": self.cleaned_fragment,
            "danger_signal": self.danger_signal.value,
            "source_agent_id": self.source_agent_id,
            "sentinel_id": self.sentinel_id,
            "threat_score": self.threat_score,
            "original_content_hash": self.original_content_hash,
            "timestamp": self.timestamp,
            "signature": self.signature.hex(),
            "modifications": self.modifications,
        }


def _canonical_alert_repr(alert: DendriticAlert) -> bytes:
    """Build canonical byte representation for signing (excludes signature)."""
    parts = [
        alert.cleaned_fragment,
        alert.danger_signal.value,
        alert.source_agent_id,
        alert.sentinel_id,
        str(alert.threat_score),
        alert.original_content_hash,
        str(alert.timestamp),
    ]
    return "|".join(parts).encode("utf-8")


def sign_alert(alert: DendriticAlert, key: bytes, key_type: str = "hmac-sha256") -> bytes:
    """Sign a dendritic alert with the sentinel's key."""
    data = _canonical_alert_repr(alert)
    if key_type == "hmac-sha256":
        return hmac.new(key, data, hashlib.sha256).digest()
    elif key_type == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.from_private_bytes(key)
        return private_key.sign(data)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")


def verify_alert(alert: DendriticAlert, public_key: bytes, key_type: str = "hmac-sha256") -> bool:
    """Verify a dendritic alert's signature."""
    data = _canonical_alert_repr(alert)
    if key_type == "hmac-sha256":
        expected = hmac.new(public_key, data, hashlib.sha256).digest()
        return hmac.compare_digest(alert.signature, expected)
    elif key_type == "ed25519":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(public_key)
            pub.verify(alert.signature, data)
            return True
        except Exception:
            return False
    else:
        return False


def build_alert(
    cleaned_fragment: str,
    danger_signal: DangerSignal,
    source_agent_id: str,
    sentinel_id: str,
    threat_score: float,
    original_content_hash: str,
    modifications: list[dict[str, Any]],
    signing_key: bytes,
    key_type: str = "hmac-sha256",
) -> DendriticAlert:
    """Build and sign a DendriticAlert.

    Args:
        cleaned_fragment: The sanitized text with injection payload removed.
        danger_signal: The danger signal level to co-stimulate the response.
        source_agent_id: The agent that produced the original injected content.
        sentinel_id: The sentinel that performed the dendritic processing.
        threat_score: Scanner threat score from the original detection.
        original_content_hash: SHA-256 hash of the original content before processing.
        modifications: List of modifications made during sanitization.
        signing_key: The sentinel's private/shared key for signing.
        key_type: Key type ("hmac-sha256" or "ed25519").

    Returns:
        A signed DendriticAlert ready for transmission.
    """
    alert = DendriticAlert(
        cleaned_fragment=cleaned_fragment,
        danger_signal=danger_signal,
        source_agent_id=source_agent_id,
        sentinel_id=sentinel_id,
        threat_score=threat_score,
        original_content_hash=original_content_hash,
        timestamp=time.time(),
        signature=b"",
        modifications=modifications,
    )
    alert.signature = sign_alert(alert, signing_key, key_type)
    return alert
