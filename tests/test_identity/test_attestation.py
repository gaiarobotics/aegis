"""Tests for aegis.identity.attestation module."""

import hashlib
import time

import pytest

from aegis.identity.attestation import (
    Attestation,
    AttestationVerifier,
    KeyPair,
    MAX_TTL_SECONDS,
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


class TestUnsupportedKeyType:
    def test_generate_unsupported_key_type_raises(self):
        with pytest.raises(ValueError, match="Unsupported key type"):
            generate_keypair(key_type="rsa-2048")

    def test_create_attestation_unsupported_key_type_raises(self):
        kp = KeyPair(public_key=b"fake", private_key=b"fake", key_type="unknown")
        with pytest.raises(ValueError, match="Unsupported key type"):
            create_attestation(
                keypair=kp,
                operator_id="op",
                model="m",
                system_prompt="prompt",
                capabilities=[],
            )

    def test_verify_unsupported_key_type_returns_false(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=[],
        )
        import dataclasses
        unknown_att = dataclasses.replace(att, key_type="unknown")
        assert verify_attestation(unknown_att, kp.public_key) is False


class TestTTLCap:
    """TTL must be capped at MAX_TTL_SECONDS."""

    def test_ttl_capped_at_max(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=[],
            ttl_seconds=MAX_TTL_SECONDS * 10,
        )
        assert att.ttl == MAX_TTL_SECONDS

    def test_ttl_within_cap_unchanged(self):
        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=[],
            ttl_seconds=3600,
        )
        assert att.ttl == 3600


class TestNonceReplayProtection:
    """AttestationVerifier must reject replayed nonces."""

    def test_first_verification_succeeds(self):
        kp = generate_keypair()
        att = create_attestation(keypair=kp, operator_id="op", model="m",
                                  system_prompt="prompt", capabilities=[])
        verifier = AttestationVerifier()
        assert verifier.verify(att, kp.public_key) is True

    def test_replay_rejected(self):
        kp = generate_keypair()
        att = create_attestation(keypair=kp, operator_id="op", model="m",
                                  system_prompt="prompt", capabilities=[])
        verifier = AttestationVerifier()
        assert verifier.verify(att, kp.public_key) is True
        # Same attestation (same nonce) should be rejected
        assert verifier.verify(att, kp.public_key) is False

    def test_different_nonces_both_accepted(self):
        kp = generate_keypair()
        att1 = create_attestation(keypair=kp, operator_id="op", model="m",
                                   system_prompt="prompt", capabilities=[])
        att2 = create_attestation(keypair=kp, operator_id="op", model="m",
                                   system_prompt="prompt", capabilities=[])
        verifier = AttestationVerifier()
        assert verifier.verify(att1, kp.public_key) is True
        assert verifier.verify(att2, kp.public_key) is True

    def test_cache_eviction(self):
        verifier = AttestationVerifier(max_nonce_cache=5)
        kp = generate_keypair()
        for _ in range(10):
            att = create_attestation(keypair=kp, operator_id="op", model="m",
                                      system_prompt="prompt", capabilities=[])
            assert verifier.verify(att, kp.public_key) is True
        # Cache should not have grown beyond 5
        assert len(verifier._seen_nonces) <= 5


class TestCanonicalEscape:
    """Fields with pipe chars must be escaped in canonical repr."""

    def test_pipe_in_agent_id(self):
        kp = generate_keypair()
        att = create_attestation(keypair=kp, operator_id="op|evil", model="m|evil",
                                  system_prompt="prompt", capabilities=[])
        assert verify_attestation(att, kp.public_key) is True


class TestEd25519Paths:
    """Test Ed25519 paths with mocking (cryptography package may not be installed)."""

    def test_generate_ed25519_without_cryptography_raises(self):
        """If cryptography is not installed, Ed25519 keygen should raise ValueError."""
        import unittest.mock as mock

        # Mock the import to fail
        original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

        def mock_import(name, *args, **kwargs):
            if "cryptography" in name:
                raise ImportError("mocked")
            return original_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(ValueError, match="cryptography"):
                generate_keypair(key_type="ed25519")

    def test_create_attestation_ed25519_without_cryptography_raises(self):
        """If cryptography is not installed, Ed25519 signing should raise ValueError."""
        import unittest.mock as mock

        kp = KeyPair(
            public_key=b"fake_pub_key_32bytesxxxxxxxxxx",
            private_key=b"fake_priv_key_32bytesxxxxxxxxx",
            key_type="ed25519",
        )

        def mock_import(name, *args, **kwargs):
            if "cryptography" in name:
                raise ImportError("mocked")
            return __import__(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(ValueError, match="cryptography"):
                create_attestation(
                    keypair=kp,
                    operator_id="op",
                    model="m",
                    system_prompt="prompt",
                    capabilities=[],
                )

    def test_verify_attestation_ed25519_without_cryptography_raises(self):
        """If cryptography is not installed, Ed25519 verification should raise ValueError."""
        import dataclasses
        import unittest.mock as mock

        kp = generate_keypair()
        att = create_attestation(
            keypair=kp,
            operator_id="op",
            model="m",
            system_prompt="prompt",
            capabilities=[],
        )
        # Change key_type to ed25519
        ed_att = dataclasses.replace(att, key_type="ed25519")

        def mock_import(name, *args, **kwargs):
            if "cryptography" in name:
                raise ImportError("mocked")
            return __import__(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(ValueError, match="cryptography"):
                verify_attestation(ed_att, kp.public_key)
