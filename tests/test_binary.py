"""Tests for binary format handling."""

import pytest

from mebuki_sign.binary import Header, SignedBinary
from mebuki_sign.errors import InvalidBinaryError


class TestHeader:
    """Tests for Header class."""

    def test_pack_unpack_roundtrip(self):
        """Test header packing and unpacking."""
        header = Header(security_version=100, key_generation=5, software_size=1234)
        packed = header.pack()

        assert len(packed) == 8
        unpacked = Header.unpack(packed)

        assert unpacked.security_version == 100
        assert unpacked.key_generation == 5
        assert unpacked.invalidation_flag == 0xFF
        assert unpacked.software_size == 1234

    def test_invalid_security_version(self):
        """Test header with invalid security version."""
        header = Header(security_version=0xFFFF, key_generation=0, software_size=0)

        with pytest.raises(InvalidBinaryError, match="security_version"):
            header.pack()

    def test_invalid_key_generation(self):
        """Test header with invalid key generation."""
        header = Header(security_version=0, key_generation=0xFF, software_size=0)

        with pytest.raises(InvalidBinaryError, match="key_generation"):
            header.pack()

    def test_invalid_invalidation_flag(self):
        """Test header with invalid invalidation flag."""
        header = Header(security_version=0, key_generation=0, invalidation_flag=0x00, software_size=0)

        with pytest.raises(InvalidBinaryError, match="invalidation_flag"):
            header.pack()

    def test_invalid_software_size(self):
        """Test header with invalid software size."""
        header = Header(security_version=0, key_generation=0, software_size=0x1_0000_0000)

        with pytest.raises(InvalidBinaryError, match="software_size"):
            header.pack()

    def test_unpack_short_data(self):
        """Test unpacking data that's too short."""
        with pytest.raises(InvalidBinaryError, match="too short"):
            Header.unpack(b"\x00" * 4)


class TestSignedBinary:
    """Tests for SignedBinary class."""

    def test_pack_unpack_roundtrip(self):
        """Test signed binary packing and unpacking."""
        software = b"test software binary"
        header = Header(
            security_version=42,
            key_generation=3,
            invalidation_flag=0xFF,
            software_size=len(software),
        )
        software = b"test software binary"
        signature = b"fake_signature_data_64bytes" + b"\x00" * 37  # 64 bytes total

        signed = SignedBinary(header=header, software=software, signature=signature)
        packed = signed.pack()

        unpacked = SignedBinary.unpack(packed, signature_size=64)

        assert unpacked.header.security_version == 42
        assert unpacked.header.key_generation == 3
        assert unpacked.software == software
        assert unpacked.signature == signature

    def test_unpack_too_short(self):
        """Test unpacking binary that's too short."""
        with pytest.raises(InvalidBinaryError, match="too short"):
            SignedBinary.unpack(b"\x00" * 10, signature_size=64)

    def test_unpack_wrong_signature_size(self):
        """Test unpacking with mismatched signature size."""
        software = b"test"
        header = Header(
            security_version=0,
            key_generation=0,
            invalidation_flag=0xFF,
            software_size=len(software),
        )
        signature = b"X" * 32  # 32 bytes

        signed = SignedBinary(header=header, software=software, signature=signature)
        packed = signed.pack()

        # Expect 64-byte signature but only 32 bytes present
        # This will fail with "Binary too short" error
        with pytest.raises(InvalidBinaryError, match="too short"):
            SignedBinary.unpack(packed, signature_size=64)

    def test_unpack_software_size_mismatch(self):
        """Test unpacking when header software_size does not match payload."""
        software = b"abcd"
        header = Header(
            security_version=1,
            key_generation=1,
            invalidation_flag=0xFF,
            software_size=len(software) + 1,  # deliberately wrong
        )
        signature = b"Y" * 64

        signed = SignedBinary(header=header, software=software, signature=signature)
        packed = signed.pack()

        with pytest.raises(InvalidBinaryError, match="Software size mismatch"):
            SignedBinary.unpack(packed, signature_size=64)
