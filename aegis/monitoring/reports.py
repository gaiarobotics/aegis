"""Monitoring report data structures.

Shared by the SDK client and monitor server.  Privacy guarantee is structural:
no ``content`` or ``text`` fields exist in any report type.
"""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ReportBase:
    """Common fields for all monitoring reports."""

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    operator_id: str = ""
    timestamp: float = field(default_factory=time.time)
    report_type: str = ""
    signature: bytes = b""
    key_type: str = "hmac-sha256"

    def sign(self, keypair: Any) -> None:
        """Sign this report using the given KeyPair.

        Re-uses the attestation module's signing functions so that the
        same key material works for both attestations and reports.
        """
        from aegis.identity.attestation import _sign_hmac

        data = self._canonical_bytes()
        if keypair.key_type == "hmac-sha256":
            self.signature = _sign_hmac(data, keypair.private_key)
            self.key_type = keypair.key_type
        elif keypair.key_type == "ed25519":
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PrivateKey,
                )

                private_key = Ed25519PrivateKey.from_private_bytes(keypair.private_key)
                self.signature = private_key.sign(data)
                self.key_type = keypair.key_type
            except ImportError:
                raise ValueError("Ed25519 signing requires the 'cryptography' package.")
        else:
            raise ValueError(f"Unsupported key type: {keypair.key_type}")

    def verify(self, public_key: bytes) -> bool:
        """Verify the signature on this report."""
        from aegis.identity.attestation import _verify_hmac

        data = self._canonical_bytes()
        if self.key_type == "hmac-sha256":
            return _verify_hmac(data, self.signature, public_key)
        elif self.key_type == "ed25519":
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PublicKey,
                )

                pub_key = Ed25519PublicKey.from_public_bytes(public_key)
                try:
                    pub_key.verify(self.signature, data)
                    return True
                except Exception:
                    return False
            except ImportError:
                raise ValueError(
                    "Ed25519 verification requires the 'cryptography' package."
                )
        return False

    @staticmethod
    def _esc(s: str) -> str:
        """Escape backslash and pipe in a field before joining with ``|``."""
        return s.replace("\\", "\\\\").replace("|", "\\|")

    def _canonical_bytes(self) -> bytes:
        """Build a canonical byte representation for signing.

        Includes all fields except ``signature``.
        Each field is escaped to prevent separator confusion.
        """
        parts = [
            self._esc(self.report_id),
            self._esc(self.agent_id),
            self._esc(self.operator_id),
            self._esc(str(self.timestamp)),
            self._esc(self.report_type),
            self._esc(self.key_type),
        ]
        parts.extend(self._esc(p) for p in self._extra_canonical_parts())
        return "|".join(parts).encode("utf-8")

    def _extra_canonical_parts(self) -> list[str]:
        """Subclass hook — return additional canonical parts."""
        return []

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        d = asdict(self)
        # Convert signature bytes to base64 string for JSON transport
        d["signature"] = base64.b64encode(self.signature).decode("ascii")
        return d

    _VALID_KEY_TYPES = {"hmac-sha256", "ed25519"}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportBase":
        """Deserialize from a dictionary.

        Raises:
            ValueError: If key_type is not a supported type.
        """
        data = dict(data)  # shallow copy
        if "signature" in data and isinstance(data["signature"], str):
            data["signature"] = base64.b64decode(data["signature"])
        key_type = data.get("key_type", "hmac-sha256")
        if key_type not in cls._VALID_KEY_TYPES:
            raise ValueError(f"Unsupported key_type: {key_type!r}")
        return cls(**data)


@dataclass
class CompromiseReport(ReportBase):
    """Reports that an agent has been detected as compromised."""

    report_type: str = "compromise"
    compromised_agent_id: str = ""
    source: str = ""
    nk_score: float = 0.0
    nk_verdict: str = ""
    recommended_action: str = "quarantine"

    def _extra_canonical_parts(self) -> list[str]:
        return [
            self.compromised_agent_id,
            self.source,
            str(self.nk_score),
            self.nk_verdict,
            self.recommended_action,
        ]


@dataclass
class TrustReport(ReportBase):
    """Periodic trust state update for an agent."""

    report_type: str = "trust"
    target_agent_id: str = ""
    trust_score: float = 0.0
    trust_tier: int = 0
    clean_interactions: int = 0
    total_interactions: int = 0
    anomaly_count: int = 0
    voucher_count: int = 0

    def _extra_canonical_parts(self) -> list[str]:
        return [
            self.target_agent_id,
            str(self.trust_score),
            str(self.trust_tier),
            str(self.clean_interactions),
            str(self.total_interactions),
            str(self.anomaly_count),
            str(self.voucher_count),
        ]


@dataclass
class ThreatEventReport(ReportBase):
    """Reports a detected threat event (metadata only — no input text)."""

    report_type: str = "threat_event"
    threat_score: float = 0.0
    is_threat: bool = False
    scanner_match_count: int = 0
    nk_score: float = 0.0
    nk_verdict: str = ""

    def _extra_canonical_parts(self) -> list[str]:
        return [
            str(self.threat_score),
            str(self.is_threat),
            str(self.scanner_match_count),
            str(self.nk_score),
            self.nk_verdict,
        ]


@dataclass
class AgentHeartbeat(ReportBase):
    """Periodic heartbeat with graph edge information."""

    report_type: str = "heartbeat"
    trust_tier: int = 0
    trust_score: float = 0.0
    is_quarantined: bool = False
    edges: list[dict[str, Any]] = field(default_factory=list)
    style_hash: str = ""      # 32-char hex, always present when behavior enabled
    content_hash: str = ""    # 32-char hex, present when embeddings installed
    topic_velocity: float = 0.0  # [0.0, 1.0] — rate of topic change between messages

    def _extra_canonical_parts(self) -> list[str]:
        edge_repr = ";".join(
            f"{e.get('target_agent_id', '')}:{e.get('direction', '')}:"
            f"{e.get('last_seen', '')}:{e.get('message_count', 0)}"
            for e in self.edges
        )
        return [
            str(self.trust_tier),
            str(self.trust_score),
            str(self.is_quarantined),
            edge_repr,
            self.style_hash,
            self.content_hash,
            str(self.topic_velocity),
        ]
