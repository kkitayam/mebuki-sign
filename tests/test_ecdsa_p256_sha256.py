"""Tests for ECDSA P-256 + SHA-256 algorithm."""

import pytest

from mebuki_sign.algorithms.ecdsa_p256_sha256 import ECDSAP256SHA256Algorithm
from mebuki_sign.errors import InvalidKeyError


class TestECDSAP256SHA256Algorithm:
    """Tests for ECDSA P-256 + SHA-256 signature algorithm."""

    def test_generate_keypair(self):
        """Test keypair generation."""
        private_key, public_key = ECDSAP256SHA256Algorithm.generate_keypair()

        assert len(private_key) == 32
        assert len(public_key) == 65
        assert public_key[0] == 0x04

    def test_sign_verify_success(self):
        """Test successful signing and verification."""
        private_key, public_key = ECDSAP256SHA256Algorithm.generate_keypair()
        message = b"test message"

        signature = ECDSAP256SHA256Algorithm.sign(private_key, message)
        assert len(signature) == 64

        valid = ECDSAP256SHA256Algorithm.verify(public_key, message, signature)
        assert valid is True

    def test_verify_wrong_message(self):
        """Test verification with wrong message."""
        private_key, public_key = ECDSAP256SHA256Algorithm.generate_keypair()
        message = b"test message"

        signature = ECDSAP256SHA256Algorithm.sign(private_key, message)

        valid = ECDSAP256SHA256Algorithm.verify(public_key, b"wrong message", signature)
        assert valid is False

    def test_verify_wrong_signature(self):
        """Test verification with tampered signature."""
        private_key, public_key = ECDSAP256SHA256Algorithm.generate_keypair()
        message = b"test message"

        signature = ECDSAP256SHA256Algorithm.sign(private_key, message)
        tampered_sig = bytes([signature[0] ^ 0xFF]) + signature[1:]

        valid = ECDSAP256SHA256Algorithm.verify(public_key, message, tampered_sig)
        assert valid is False

    def test_sign_invalid_key(self):
        """Test signing with invalid key."""
        with pytest.raises(InvalidKeyError):
            ECDSAP256SHA256Algorithm.sign(b"invalid_key", b"message")

    def test_verify_invalid_key(self):
        """Test verification with invalid key."""
        with pytest.raises(InvalidKeyError):
            ECDSAP256SHA256Algorithm.verify(b"invalid_key", b"message", b"X" * 64)

    def test_algorithm_constants(self):
        """Test algorithm metadata."""
        assert ECDSAP256SHA256Algorithm.name == "ecdsa-p256-sha256"
        assert ECDSAP256SHA256Algorithm.public_key_size == 65
        assert ECDSAP256SHA256Algorithm.signature_size == 64

    def test_verify_svl_known_vector(self):
        """Test compatibility with mebuki-svl-ecdsa-p256-sha256 known vector."""
        message = b"Hello, Mebuki ECDSA!"
        public_key = bytes(
            [
                0x04,
                0x2E,
                0x2A,
                0xD1,
                0x1C,
                0xB4,
                0x6B,
                0xB9,
                0x1B,
                0x94,
                0xF3,
                0x52,
                0xE3,
                0x4C,
                0xCD,
                0xDE,
                0x07,
                0x65,
                0xB8,
                0x2B,
                0xB2,
                0x9B,
                0x21,
                0x5E,
                0x9D,
                0xD6,
                0x42,
                0x9C,
                0x2B,
                0xBC,
                0x1E,
                0xD1,
                0x96,
                0xD7,
                0x0C,
                0xAD,
                0xA7,
                0xB7,
                0xB1,
                0x0D,
                0x11,
                0x28,
                0x07,
                0xE7,
                0xBD,
                0x0F,
                0x77,
                0x26,
                0xBD,
                0x21,
                0x8D,
                0xB9,
                0xC5,
                0x5C,
                0x75,
                0x90,
                0x6D,
                0x38,
                0xFB,
                0xFD,
                0x5F,
                0xAA,
                0x97,
                0xAB,
                0xEB,
            ]
        )
        signature = bytes(
            [
                0x15,
                0x58,
                0xDE,
                0x2A,
                0x77,
                0x68,
                0xDC,
                0x7C,
                0xA2,
                0xAB,
                0x5F,
                0x9F,
                0x77,
                0xEC,
                0x7D,
                0x14,
                0xF4,
                0x44,
                0x23,
                0x87,
                0xD8,
                0xB1,
                0x4C,
                0x3E,
                0x8D,
                0x70,
                0x35,
                0x22,
                0x7E,
                0x32,
                0x0E,
                0x39,
                0x6D,
                0x69,
                0x30,
                0x73,
                0x7D,
                0x17,
                0xD6,
                0xCA,
                0xB5,
                0xD2,
                0xF8,
                0x55,
                0x81,
                0xB8,
                0xA6,
                0x0D,
                0x2F,
                0x78,
                0x1E,
                0x38,
                0x7A,
                0xFB,
                0x1E,
                0x14,
                0x1A,
                0x59,
                0x4C,
                0x9B,
                0x74,
                0x83,
                0x01,
                0x15,
            ]
        )

        assert ECDSAP256SHA256Algorithm.verify(public_key, message, signature) is True
