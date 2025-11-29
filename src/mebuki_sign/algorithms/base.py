"""Base signature algorithm interface."""

from typing import Protocol


class SignatureAlgorithm(Protocol):
    """Protocol defining the signature algorithm interface.

    All signature algorithms must implement this interface.
    """

    name: str
    """Algorithm name (lowercase, hyphen-separated)."""

    public_key_size: int
    """Public key size in bytes."""

    signature_size: int
    """Signature size in bytes."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate a new keypair.

        Returns:
            Tuple of (private_key, public_key) as raw bytes
        """
        ...

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign a message.

        Args:
            private_key: Private key as raw bytes
            message: Message to sign

        Returns:
            Signature as raw bytes

        Raises:
            InvalidKeyError: If private key is invalid
        """
        ...

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature.

        Args:
            public_key: Public key as raw bytes
            message: Original message
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise

        Raises:
            InvalidKeyError: If public key is invalid
        """
        ...
