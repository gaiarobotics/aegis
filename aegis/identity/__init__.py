"""AEGIS Identity module -- attestation, trust management, and NK cell analysis."""

from aegis.identity.attestation import (
    Attestation,
    KeyPair,
    create_attestation,
    generate_keypair,
    verify_attestation,
)
from aegis.identity.nkcell import AgentContext, NKCell, NKVerdict
from aegis.identity.trust import TrustManager, TrustRecord

__all__ = [
    "Attestation",
    "KeyPair",
    "create_attestation",
    "generate_keypair",
    "verify_attestation",
    "TrustManager",
    "TrustRecord",
    "AgentContext",
    "NKCell",
    "NKVerdict",
]
