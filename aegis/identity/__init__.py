"""AEGIS Identity module -- attestation, trust management, NK cell analysis, speaker classification, and identity resolution."""

from aegis.identity.attestation import (
    Attestation,
    KeyPair,
    create_attestation,
    generate_keypair,
    verify_attestation,
)
from aegis.identity.nkcell import AgentContext, NKCell, NKVerdict
from aegis.identity.resolver import IdentityResolver
from aegis.identity.speaker import ExtractionResult, SpeakerInfo, extract_speakers
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
    "ExtractionResult",
    "IdentityResolver",
    "SpeakerInfo",
    "extract_speakers",
]
