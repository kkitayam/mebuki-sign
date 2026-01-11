"""EdDSA-25519-BLAKE2b signature algorithm implementation.

Uses Ed25519 digital signature system with BLAKE2b hash function instead of SHA512.
This variant is compatible with Monocypher and NANO cryptocurrency.

- Public key size: 32 bytes
- Signature size: 64 bytes
- Security level: ~128-bit
"""

import ed25519_blake2b

from ..errors import InvalidKeyError


class EdDSA25519BLAKE2bAlgorithm:
    """EdDSA-25519-BLAKE2b signature algorithm.

    EdDSA with Curve25519 using BLAKE2b hash function instead of SHA512.
    Compatible with Monocypher's Ed25519-BLAKE2b implementation.

    - Public key size: 32 bytes
    - Signature size: 64 bytes
    - Security level: ~128-bit
    """

    name = "eddsa-25519-blake2b"
    public_key_size = 32
    signature_size = 64

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate EdDSA-25519-BLAKE2b keypair.

        Returns:
            Tuple of (private_key, public_key) as raw bytes.
            Private key is 32-byte seed, public key is 32-byte verifying key.
        """
        signing_key, verifying_key = ed25519_blake2b.create_keypair()

        # Convert to raw bytes
        private_bytes = signing_key.to_seed()
        public_bytes = verifying_key.to_bytes()

        return private_bytes, public_bytes

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign message with EdDSA-25519-BLAKE2b.

        Args:
            private_key: 32-byte seed (EdDSA-25519-BLAKE2b private key)
            message: Message to sign

        Returns:
            64-byte signature

        Raises:
            InvalidKeyError: If private key is invalid
        """
        try:
            signing_key = ed25519_blake2b.SigningKey(private_key)
            return signing_key.sign(message)
        except Exception as e:
            raise InvalidKeyError(f"Invalid EdDSA-25519-BLAKE2b private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify EdDSA-25519-BLAKE2b signature.

        Args:
            public_key: 32-byte public key (verifying key)
            message: Original message
            signature: 64-byte signature

        Returns:
            True if valid, False otherwise

        Raises:
            InvalidKeyError: If public key is invalid
        """
        try:
            verifying_key = ed25519_blake2b.VerifyingKey(public_key)
            verifying_key.verify(signature, message)
            return True
        except ed25519_blake2b.BadSignatureError:
            # Signature verification failed
            return False
        except Exception as e:
            raise InvalidKeyError(f"Invalid EdDSA-25519-BLAKE2b public key: {e}") from e
