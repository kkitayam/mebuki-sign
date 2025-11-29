"""Ed25519 signature algorithm implementation."""

from cryptography.hazmat.primitives.asymmetric import ed25519

from ..errors import InvalidKeyError


class Ed25519Algorithm:
    """Ed25519 signature algorithm (EdDSA with Curve25519).

    - Public key size: 32 bytes
    - Signature size: 64 bytes
    - Security level: ~128-bit
    """

    name = "ed25519"
    public_key_size = 32
    signature_size = 64

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate Ed25519 keypair.

        Returns:
            Tuple of (private_key, public_key) as raw bytes
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return private_bytes, public_bytes

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign message with Ed25519.

        Args:
            private_key: 32-byte Ed25519 private key
            message: Message to sign

        Returns:
            64-byte signature

        Raises:
            InvalidKeyError: If private key is invalid
        """
        try:
            key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
            return key.sign(message)
        except Exception as e:
            raise InvalidKeyError(f"Invalid Ed25519 private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify Ed25519 signature.

        Args:
            public_key: 32-byte Ed25519 public key
            message: Original message
            signature: 64-byte signature

        Returns:
            True if valid, False otherwise

        Raises:
            InvalidKeyError: If public key is invalid
        """
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, message)
            return True
        except ValueError as e:
            if "invalid" in str(e).lower() or "malformed" in str(e).lower():
                raise InvalidKeyError(f"Invalid Ed25519 public key: {e}") from e
            # Verification failed
            return False
        except Exception:
            # Verification failed
            return False


# Import after class definition to avoid circular imports
from cryptography.hazmat.primitives import serialization
