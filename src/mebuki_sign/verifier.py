"""Signature verification functionality."""

from typing import BinaryIO

from .algorithms import get_algorithm
from .binary import SignedBinary
from .keygen import load_key


def verify_signature(
    signed_binary: SignedBinary,
    public_key: bytes,
    algorithm_name: str,
) -> bool:
    """Verify firmware signature.

    Args:
        signed_binary: Signed binary with header
        public_key: Public key as raw bytes
        algorithm_name: Signature algorithm name

    Returns:
        True if signature is valid, False otherwise

    Raises:
        InvalidAlgorithmError: If algorithm is not supported
        InvalidKeyError: If public key is invalid
    """
    algorithm = get_algorithm(algorithm_name)

    # Reconstruct message: header + software
    message = signed_binary.header.pack() + signed_binary.software

    # Verify signature
    return algorithm.verify(public_key, message, signed_binary.signature)


def verify_file(
    signed_file: BinaryIO,
    key_file: BinaryIO,
    algorithm_name: str,
    key_format: str = "binary",
) -> tuple[bool, SignedBinary]:
    """Verify signed firmware file.

    Args:
        signed_file: Signed firmware binary file
        key_file: Public key file
        algorithm_name: Signature algorithm name
        key_format: Key file format ("binary" or "pem")

    Returns:
        Tuple of (verification_result, signed_binary)

    Raises:
        InvalidAlgorithmError: If algorithm is not supported
        InvalidKeyError: If public key is invalid
        InvalidBinaryError: If binary format is invalid
        FileOperationError: If file operations fail
    """
    # Get signature size for this algorithm
    algorithm = get_algorithm(algorithm_name)
    signature_size = algorithm.signature_size

    # Read inputs
    signed_binary = SignedBinary.from_file(signed_file, signature_size)
    public_key = load_key(key_file, key_format)

    # Verify
    valid = verify_signature(signed_binary, public_key, algorithm_name)

    return valid, signed_binary
