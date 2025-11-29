"""Tests for Ed25519 algorithm."""

import pytest

from mebuki_sign.algorithms.ed25519 import Ed25519Algorithm
from mebuki_sign.errors import InvalidKeyError


class TestEd25519Algorithm:
    """Tests for Ed25519 signature algorithm."""

    def test_generate_keypair(self):
        """Test keypair generation."""
        private_key, public_key = Ed25519Algorithm.generate_keypair()

        assert len(private_key) == 32
        assert len(public_key) == 32
        assert private_key != public_key

    def test_sign_verify_success(self):
        """Test successful signing and verification."""
        private_key, public_key = Ed25519Algorithm.generate_keypair()
        message = b"test message"

        signature = Ed25519Algorithm.sign(private_key, message)
        assert len(signature) == 64

        valid = Ed25519Algorithm.verify(public_key, message, signature)
        assert valid is True

    def test_verify_wrong_message(self):
        """Test verification with wrong message."""
        private_key, public_key = Ed25519Algorithm.generate_keypair()
        message = b"test message"

        signature = Ed25519Algorithm.sign(private_key, message)

        valid = Ed25519Algorithm.verify(public_key, b"wrong message", signature)
        assert valid is False

    def test_verify_wrong_signature(self):
        """Test verification with tampered signature."""
        private_key, public_key = Ed25519Algorithm.generate_keypair()
        message = b"test message"

        signature = Ed25519Algorithm.sign(private_key, message)
        tampered_sig = bytes([signature[0] ^ 0xFF]) + signature[1:]

        valid = Ed25519Algorithm.verify(public_key, message, tampered_sig)
        assert valid is False

    def test_sign_invalid_key(self):
        """Test signing with invalid key."""
        with pytest.raises(InvalidKeyError):
            Ed25519Algorithm.sign(b"invalid_key", b"message")

    def test_verify_invalid_key(self):
        """Test verification with invalid key."""
        # Ed25519 with short key returns False instead of raising
        result = Ed25519Algorithm.verify(b"invalid_key", b"message", b"X" * 64)
        assert result is False

    def test_algorithm_constants(self):
        """Test algorithm metadata."""
        assert Ed25519Algorithm.name == "ed25519"
        assert Ed25519Algorithm.public_key_size == 32
        assert Ed25519Algorithm.signature_size == 64
