"""Attestation module for agent identity verification.

Provides cryptographic attestation for AI agents, binding an agent's identity
to its operator, purpose, and declared capabilities.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class KeyPair:
    """A cryptographic key pair for signing attestations."""

    public_key: bytes
    private_key: bytes
    key_type: str


@dataclass
class Attestation:
    """A signed attestation binding an agent to its operator and purpose."""

    agent_id: str
    operator_id: str
    purpose_hash: str
    declared_capabilities: list[str]
    ttl: int
    nonce: str
    signature: bytes
    timestamp: float
    key_type: str


def generate_keypair(key_type: str = "hmac-sha256") -> KeyPair:
    """Generate a cryptographic key pair.

    Args:
        key_type: The key type. "hmac-sha256" uses a random 32-byte shared key.
                  "ed25519" uses the cryptography library if available.

    Returns:
        A KeyPair instance.

    Raises:
        ValueError: If key_type is unsupported or required library is missing.
    """
    if key_type == "hmac-sha256":
        # HMAC uses a symmetric shared secret — public_key and private_key
        # hold the same value.  This is correct for HMAC-based auth: the
        # "public key" is really the shared secret exchanged out-of-band.
        key = os.urandom(32)
        return KeyPair(public_key=key, private_key=key, key_type=key_type)
    elif key_type == "ed25519":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            private_bytes = private_key.private_bytes_raw()
            public_bytes = public_key.public_bytes_raw()
            return KeyPair(
                public_key=public_bytes,
                private_key=private_bytes,
                key_type=key_type,
            )
        except ImportError:
            raise ValueError(
                "Ed25519 key generation requires the 'cryptography' package. "
                "Install it with: pip install cryptography>=41.0"
            )
    else:
        raise ValueError(f"Unsupported key type: {key_type}")


MAX_TTL_SECONDS = 7 * 24 * 3600  # 1 week


def _esc(s: str) -> str:
    """Escape backslash and pipe in a field before joining with ``|``."""
    return s.replace("\\", "\\\\").replace("|", "\\|")


def _canonical_repr(attestation: Attestation) -> bytes:
    """Build a canonical byte representation of an attestation for signing.

    The representation includes all fields except the signature itself.
    Each field is escaped to prevent separator confusion.
    """
    parts = [
        _esc(attestation.agent_id),
        _esc(attestation.operator_id),
        _esc(attestation.purpose_hash),
        _esc(",".join(attestation.declared_capabilities)),
        _esc(str(attestation.ttl)),
        _esc(attestation.nonce),
        _esc(str(attestation.timestamp)),
        _esc(attestation.key_type),
    ]
    return "|".join(parts).encode("utf-8")


def _sign_hmac(data: bytes, key: bytes) -> bytes:
    """Sign data using HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _verify_hmac(data: bytes, signature: bytes, key: bytes) -> bool:
    """Verify an HMAC-SHA256 signature."""
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(signature, expected)


def create_attestation(
    keypair: KeyPair,
    operator_id: str,
    model: str,
    system_prompt: str,
    capabilities: list[str],
    ttl_seconds: int = 86400,
) -> Attestation:
    """Create a signed attestation for an agent.

    Args:
        keypair: The key pair to sign with.
        operator_id: Identifier for the operator deploying the agent.
        model: The model identifier, used as the agent_id.
        system_prompt: The agent's system prompt (will be hashed, never stored raw).
        capabilities: List of declared capabilities.
        ttl_seconds: Time-to-live in seconds (default: 24 hours).

    Returns:
        A signed Attestation instance.
    """
    ttl_seconds = min(ttl_seconds, MAX_TTL_SECONDS)
    purpose_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
    nonce = str(uuid.uuid4())
    timestamp = time.time()

    # Create attestation with empty signature first for canonical repr
    attestation = Attestation(
        agent_id=model,
        operator_id=operator_id,
        purpose_hash=purpose_hash,
        declared_capabilities=list(capabilities),
        ttl=ttl_seconds,
        nonce=nonce,
        signature=b"",
        timestamp=timestamp,
        key_type=keypair.key_type,
    )

    data = _canonical_repr(attestation)

    if keypair.key_type == "hmac-sha256":
        signature = _sign_hmac(data, keypair.private_key)
    elif keypair.key_type == "ed25519":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            private_key = Ed25519PrivateKey.from_private_bytes(keypair.private_key)
            signature = private_key.sign(data)
        except ImportError:
            raise ValueError("Ed25519 signing requires the 'cryptography' package.")
    else:
        raise ValueError(f"Unsupported key type: {keypair.key_type}")

    attestation.signature = signature
    return attestation


class AttestationVerifier:
    """Verifies attestations with nonce replay protection.

    Maintains a bounded set of seen nonces to prevent replay attacks.
    """

    def __init__(self, max_nonce_cache: int = 100_000) -> None:
        self._seen_nonces: set[str] = set()
        self._max_cache = max_nonce_cache

    def verify(self, attestation: Attestation, public_key: bytes) -> bool:
        """Verify an attestation, rejecting replayed nonces.

        Returns False if the nonce has been seen before, the signature
        is invalid, or the attestation has expired.
        """
        if attestation.nonce in self._seen_nonces:
            return False
        result = verify_attestation(attestation, public_key)
        if result:
            if len(self._seen_nonces) >= self._max_cache:
                # Evict a random nonce to keep cache bounded
                self._seen_nonces.pop()
            self._seen_nonces.add(attestation.nonce)
        return result


def verify_attestation(attestation: Attestation, public_key: bytes) -> bool:
    """Verify an attestation's signature and check TTL expiry.

    Args:
        attestation: The attestation to verify.
        public_key: The public key to verify against.

    Returns:
        True if the attestation is valid and not expired, False otherwise.
    """
    # Check TTL expiry
    if time.time() > attestation.timestamp + attestation.ttl:
        return False

    # Build canonical repr (with empty signature for verification)
    data = _canonical_repr(
        Attestation(
            agent_id=attestation.agent_id,
            operator_id=attestation.operator_id,
            purpose_hash=attestation.purpose_hash,
            declared_capabilities=attestation.declared_capabilities,
            ttl=attestation.ttl,
            nonce=attestation.nonce,
            signature=b"",
            timestamp=attestation.timestamp,
            key_type=attestation.key_type,
        )
    )

    if attestation.key_type == "hmac-sha256":
        return _verify_hmac(data, attestation.signature, public_key)
    elif attestation.key_type == "ed25519":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            pub_key = Ed25519PublicKey.from_public_bytes(public_key)
            try:
                pub_key.verify(attestation.signature, data)
                return True
            except Exception:
                return False
        except ImportError:
            raise ValueError("Ed25519 verification requires the 'cryptography' package.")
    else:
        return False
