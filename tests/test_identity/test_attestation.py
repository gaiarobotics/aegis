"""Tests for aegis.identity.attestation module."""

import hashlib
import time

import pytest

from aegis.identity.attestation import (
    Attestation,
    KeyPair,
    create_attestation,
    generate_keypair,
    verify_attestation,
)


class TestGenerateKeypair:
    """Tests for generate_keypair."""

    def test_generate_keypair_hmac(self):
        kp = generate_keypair(key_type="hmac-sha256")
        assert isinstance(kp, KeyPair)
        assert kp.key_type == "hmac-sha256"
        assert len(kp.public_key) == 32
        assert len(kp.private_key) == 32
        # HMAC uses same key for both
        assert kp.public_key == kp.private_key

    def test_generate_keypair_default_is_hmac(self):
        kp = generate_keypair()
        assert kp.key_type == "hmac-sha256"

    def test_generate_keypair_unique(self):
        kp1 = generate_keypair()
        kp2 = generate_keypair()
        assert kp1.public_key != kp2.public_key


class TestCreateAttestation:
    """Tests for create_attestation."""

    def test_create_hmac_attestation(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="operator-1",
            model="gpt-4",
            system_prompt="You are a helpful assistant.",
            capabilities=["read", "write"],
            ttl_seconds=3600,
        )
        assert isinstance(att, Attestation)
        assert att.agent_id == "gpt-4"
        assert att.operator_id == "operator-1"
        assert att.declared_capabilities == ["read", "write"]
        assert att.ttl == 3600
        assert att.key_type == "hmac-sha256"
        assert len(att.signature) > 0
        assert len(att.nonce) > 0
        assert att.timestamp > 0

    def test_purpose_hash_not_raw_prompt(self):
        """The purpose_hash should be a SHA-256 hex digest, not the raw prompt."""
        kp = generate_keypair()
        prompt = "You are a helpful assistant."
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt=prompt,
            capabilities=[],
        )
        expected_hash = hashlib.sha256(prompt.encode()).hexdigest()
        assert att.purpose_hash == expected_hash
        assert prompt not in att.purpose_hash

    def test_nonce_uniqueness(self):
        kp = generate_keypair()
        nonces = set()
        for _ in range(100):
            att = create_attestation(
                keypair=kp,
                operator_id="op",
                model="m",
                system_prompt="prompt",
                capabilities=[],
            )
            nonces.add(att.nonce)
        assert len(nonces) == 100


class TestVerifyAttestation:
    """Tests for verify_attestation."""

    def test_verify_valid(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=["read"],
        )
        assert verify_attestation(att, kp.public_key) is True

    def test_verify_invalid_key(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=["read"],
        )
        wrong_kp = generate_keypair()
        assert verify_attestation(att, wrong_kp.public_key) is False

    def test_verify_expired(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=[],
            ttl_seconds=0,
        )
        # Force expiration by setting timestamp in the past
        # We need to re-sign with the old timestamp
        import dataclasses
        expired_att = dataclasses.replace(att, timestamp=time.time() - 100, ttl=1)
        # This should fail because timestamp + ttl < now
        assert verify_attestation(expired_att, kp.public_key) is False

    def test_verify_tampered_signature(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=[],
        )
        import dataclasses
        tampered = dataclasses.replace(att, signature=b"tampered")
        assert verify_attestation(tampered, kp.public_key) is False
