"""Tests for EdDSA-25519-BLAKE2b algorithm."""

import pytest

from mebuki_sign.algorithms.eddsa_25519_blake2b import EdDSA25519BLAKE2bAlgorithm
from mebuki_sign.errors import InvalidKeyError


class TestEdDSA25519BLAKE2bAlgorithm:
    """Tests for EdDSA-25519-BLAKE2b signature algorithm."""

    def test_generate_keypair(self):
        """Test keypair generation."""
        private_key, public_key = EdDSA25519BLAKE2bAlgorithm.generate_keypair()

        assert len(private_key) == 32
        assert len(public_key) == 32
        assert private_key != public_key

    def test_sign_verify_success(self):
        """Test successful signing and verification."""
        private_key, public_key = EdDSA25519BLAKE2bAlgorithm.generate_keypair()
        message = b"test message"

        signature = EdDSA25519BLAKE2bAlgorithm.sign(private_key, message)
        assert len(signature) == 64

        valid = EdDSA25519BLAKE2bAlgorithm.verify(public_key, message, signature)
        assert valid is True

    def test_verify_wrong_message(self):
        """Test verification with wrong message."""
        private_key, public_key = EdDSA25519BLAKE2bAlgorithm.generate_keypair()
        message = b"test message"

        signature = EdDSA25519BLAKE2bAlgorithm.sign(private_key, message)

        valid = EdDSA25519BLAKE2bAlgorithm.verify(public_key, b"wrong message", signature)
        assert valid is False

    def test_verify_wrong_signature(self):
        """Test verification with tampered signature."""
        private_key, public_key = EdDSA25519BLAKE2bAlgorithm.generate_keypair()
        message = b"test message"

        signature = EdDSA25519BLAKE2bAlgorithm.sign(private_key, message)
        tampered_sig = bytes([signature[0] ^ 0xFF]) + signature[1:]

        valid = EdDSA25519BLAKE2bAlgorithm.verify(public_key, message, tampered_sig)
        assert valid is False

    def test_sign_invalid_key(self):
        """Test signing with invalid key."""
        with pytest.raises(InvalidKeyError):
            EdDSA25519BLAKE2bAlgorithm.sign(b"invalid_key", b"message")

    def test_verify_invalid_key(self):
        """Test verification with invalid key."""
        with pytest.raises(InvalidKeyError):
            EdDSA25519BLAKE2bAlgorithm.verify(b"invalid_key", b"message", b"X" * 64)

    def test_algorithm_constants(self):
        """Test algorithm metadata."""
        assert EdDSA25519BLAKE2bAlgorithm.name == "eddsa-25519-blake2b"
        assert EdDSA25519BLAKE2bAlgorithm.public_key_size == 32
        assert EdDSA25519BLAKE2bAlgorithm.signature_size == 64

    def test_multiple_messages(self):
        """Test signing and verification of multiple different messages."""
        private_key, public_key = EdDSA25519BLAKE2bAlgorithm.generate_keypair()

        messages = [
            b"message 1",
            b"another message",
            b"",
            b"\x00\x01\x02\x03",
            b"x" * 1000,
        ]

        for message in messages:
            signature = EdDSA25519BLAKE2bAlgorithm.sign(private_key, message)
            assert EdDSA25519BLAKE2bAlgorithm.verify(public_key, message, signature)
            # Verify it doesn't validate for wrong message
            assert not EdDSA25519BLAKE2bAlgorithm.verify(public_key, b"wrong", signature)

    def test_deterministic_signing(self):
        """Test that same key and message produce same signature."""
        private_key, _ = EdDSA25519BLAKE2bAlgorithm.generate_keypair()
        message = b"deterministic test"

        sig1 = EdDSA25519BLAKE2bAlgorithm.sign(private_key, message)
        sig2 = EdDSA25519BLAKE2bAlgorithm.sign(private_key, message)

        assert sig1 == sig2
