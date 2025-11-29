"""Binary format handling for libmebuki firmware.

Binary format:
- Header (8 bytes)
- Software binary (variable)
- Signature (algorithm-dependent)
"""

import struct
from dataclasses import dataclass
from typing import BinaryIO

from .errors import InvalidBinaryError


@dataclass
class Header:
    """Firmware binary header (8 bytes).

    Layout:
        uint32_t magic;             // 0x4D42454B ("MBEK")
        uint16_t security_version;  // 0-0xFFFE (0xFFFF = uninitialized)
        uint8_t  key_generation;    // 0-0xFE (0xFF = uninitialized)
        uint8_t  reserved;          // Must be 0xFF
    """

    magic: int = 0x4D42454B  # "MBEK"
    security_version: int = 0
    key_generation: int = 0
    reserved: int = 0xFF

    MAGIC = 0x4D42454B
    SIZE = 8
    FORMAT = "<IHBB"  # Little-endian: uint32, uint16, uint8, uint8

    def pack(self) -> bytes:
        """Serialize header to bytes.

        Returns:
            8-byte header

        Raises:
            InvalidBinaryError: If header values are invalid
        """
        if self.magic != self.MAGIC:
            raise InvalidBinaryError(f"Invalid magic: 0x{self.magic:08X}")
        if not (0 <= self.security_version <= 0xFFFE):
            raise InvalidBinaryError(
                f"Invalid security_version: {self.security_version} (must be 0-0xFFFE)"
            )
        if not (0 <= self.key_generation <= 0xFE):
            raise InvalidBinaryError(
                f"Invalid key_generation: {self.key_generation} (must be 0-0xFE)"
            )

        return struct.pack(
            self.FORMAT, self.magic, self.security_version, self.key_generation, self.reserved
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Header":
        """Deserialize header from bytes.

        Args:
            data: At least 8 bytes

        Returns:
            Header object

        Raises:
            InvalidBinaryError: If data is invalid
        """
        if len(data) < cls.SIZE:
            raise InvalidBinaryError(f"Header too short: {len(data)} bytes (expected {cls.SIZE})")

        try:
            magic, security_version, key_generation, reserved = struct.unpack(
                cls.FORMAT, data[: cls.SIZE]
            )
        except struct.error as e:
            raise InvalidBinaryError(f"Failed to unpack header: {e}") from e

        if magic != cls.MAGIC:
            raise InvalidBinaryError(f"Invalid magic: 0x{magic:08X} (expected 0x{cls.MAGIC:08X})")

        return cls(
            magic=magic,
            security_version=security_version,
            key_generation=key_generation,
            reserved=reserved,
        )


@dataclass
class SignedBinary:
    """Complete signed firmware binary.

    Layout:
        - Header (8 bytes)
        - Software binary (variable)
        - Signature (variable, algorithm-dependent)
    """

    header: Header
    software: bytes
    signature: bytes

    def pack(self) -> bytes:
        """Serialize to complete binary.

        Returns:
            Complete signed binary
        """
        return self.header.pack() + self.software + self.signature

    @classmethod
    def unpack(cls, data: bytes, signature_size: int) -> "SignedBinary":
        """Deserialize from complete binary.

        Args:
            data: Complete binary data
            signature_size: Expected signature size in bytes

        Returns:
            SignedBinary object

        Raises:
            InvalidBinaryError: If binary is invalid
        """
        min_size = Header.SIZE + signature_size
        if len(data) < min_size:
            raise InvalidBinaryError(
                f"Binary too short: {len(data)} bytes (minimum {min_size})"
            )

        # Parse header
        header = Header.unpack(data)

        # Extract software and signature
        software_end = len(data) - signature_size
        software = data[Header.SIZE : software_end]
        signature = data[software_end:]

        if len(signature) != signature_size:
            raise InvalidBinaryError(
                f"Invalid signature size: {len(signature)} bytes (expected {signature_size})"
            )

        return cls(header=header, software=software, signature=signature)

    @classmethod
    def from_file(cls, file: BinaryIO, signature_size: int) -> "SignedBinary":
        """Load from file.

        Args:
            file: Binary file object
            signature_size: Expected signature size

        Returns:
            SignedBinary object
        """
        from .errors import FileOperationError

        try:
            data = file.read()
            return cls.unpack(data, signature_size)
        except OSError as e:
            raise FileOperationError(f"Failed to read binary: {e}") from e

    def to_file(self, file: BinaryIO) -> None:
        """Save to file.

        Args:
            file: Binary file object to write to
        """
        from .errors import FileOperationError

        try:
            file.write(self.pack())
        except OSError as e:
            raise FileOperationError(f"Failed to write binary: {e}") from e


def read_unsigned_binary(file: BinaryIO) -> bytes:
    """Read unsigned firmware binary from file.

    Args:
        file: Binary file object

    Returns:
        Raw binary data

    Raises:
        FileOperationError: If read fails
    """
    from .errors import FileOperationError

    try:
        return file.read()
    except OSError as e:
        raise FileOperationError(f"Failed to read unsigned binary: {e}") from e
