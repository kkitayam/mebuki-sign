"""Firmware signing functionality."""

from typing import BinaryIO

from .algorithms import get_algorithm
from .binary import Header, SignedBinary, read_unsigned_binary
from .keygen import load_key


def sign_firmware(
    unsigned_binary: bytes,
    private_key: bytes,
    algorithm_name: str,
    security_version: int,
    key_generation: int,
) -> SignedBinary:
    """Sign firmware binary.

    Args:
        unsigned_binary: Raw firmware binary (without header)
        private_key: Private key as raw bytes
        algorithm_name: Signature algorithm name
        security_version: Security version (0-0xFFFE)
        key_generation: Key generation (0-0xFE)

    Returns:
        Signed binary with header

    Raises:
        InvalidAlgorithmError: If algorithm is not supported
        InvalidKeyError: If private key is invalid
        InvalidBinaryError: If header values are invalid
    """
    algorithm = get_algorithm(algorithm_name)

    # Create header
    header = Header(
        security_version=security_version,
        key_generation=key_generation,
        invalidation_flag=0xFF,
        software_size=len(unsigned_binary),
    )

    # Sign: header + software
    message = header.pack() + unsigned_binary
    signature = algorithm.sign(private_key, message)

    return SignedBinary(header=header, software=unsigned_binary, signature=signature)


def sign_file(
    input_file: BinaryIO,
    output_file: BinaryIO,
    key_file: BinaryIO,
    algorithm_name: str,
    security_version: int,
    key_generation: int,
    key_format: str = "binary",
) -> None:
    """Sign firmware file.

    Args:
        input_file: Unsigned firmware binary file
        output_file: Output signed binary file
        key_file: Private key file
        algorithm_name: Signature algorithm name
        security_version: Security version (0-0xFFFE)
        key_generation: Key generation (0-0xFE)
        key_format: Key file format ("binary" or "pem")

    Raises:
        InvalidAlgorithmError: If algorithm is not supported
        InvalidKeyError: If private key is invalid
        InvalidBinaryError: If header values are invalid
        FileOperationError: If file operations fail
    """
    # Read inputs
    unsigned_binary = read_unsigned_binary(input_file)
    private_key = load_key(key_file, key_format)

    # Sign
    signed = sign_firmware(
        unsigned_binary, private_key, algorithm_name, security_version, key_generation
    )

    # Write output
    signed.to_file(output_file)
