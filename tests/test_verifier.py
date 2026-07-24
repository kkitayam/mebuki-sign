"""Tests for verifier behavior with mbk_header_t layout."""

import pytest

from mebuki_sign.algorithms import ECDSAP256SHA256Algorithm as ECDSAAlgorithm
from mebuki_sign.binary import Header, SignedBinary
from mebuki_sign.errors import InvalidBinaryError
from mebuki_sign.verifier import verify_signature


def make_signed_binary(software: bytes = b"payload") -> tuple[Header, bytes, bytes, bytes]:
    """Create a self-signed binary for testing."""
    private_key, public_key = ECDSAAlgorithm.generate_keypair()
    header = Header(
        security_version=1,
        key_generation=1,
        invalidation_flag=0xFF,
        software_size=len(software),
    )
    message = header.pack() + software
    signature = ECDSAAlgorithm.sign(private_key, message)
    return header, software, signature, public_key


def test_verify_signature_success():
    """Verify succeeds when header and payload are consistent."""
    header, software, signature, public_key = make_signed_binary()
    signed = SignedBinary(header=header, software=software, signature=signature)

    assert verify_signature(signed, public_key, "ecdsa-p256-sha256") is True


def test_verify_signature_software_size_mismatch():
    """Verifier rejects when header-software size differs."""
    header, software, signature, public_key = make_signed_binary()
    bad_header = Header(
        security_version=header.security_version,
        key_generation=header.key_generation,
        invalidation_flag=header.invalidation_flag,
        software_size=header.software_size + 1,
    )
    signed = SignedBinary(header=bad_header, software=software, signature=signature)

    with pytest.raises(InvalidBinaryError, match="Software size mismatch"):
        verify_signature(signed, public_key, "ecdsa-p256-sha256")


def test_verify_signature_invalid_signature_size():
    """Verifier rejects signatures that do not match algorithm size."""
    header, software, signature, public_key = make_signed_binary()
    short_signature = signature[:-1]
    signed = SignedBinary(header=header, software=software, signature=short_signature)

    with pytest.raises(InvalidBinaryError, match="Invalid signature size"):
        verify_signature(signed, public_key, "ecdsa-p256-sha256")
