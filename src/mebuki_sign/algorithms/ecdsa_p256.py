"""ECDSA with P-256 curve signature algorithm implementation."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..errors import InvalidKeyError


class ECDSAP256Algorithm:
    """ECDSA with NIST P-256 curve and SHA-256.

    - Public key size: 64 bytes (uncompressed, without 0x04 prefix)
    - Signature size: 64 bytes (raw R||S format)
    - Security level: ~128-bit
    """

    name = "ecdsa-p256"
    public_key_size = 64
    signature_size = 64

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate ECDSA P-256 keypair.

        Returns:
            Tuple of (private_key, public_key) as raw bytes
            - private_key: 32-byte scalar
            - public_key: 64-byte uncompressed point (x||y, no prefix)
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Private key: extract the private number as 32 bytes
        private_numbers = private_key.private_numbers()
        private_bytes = private_numbers.private_value.to_bytes(32, byteorder="big")

        # Public key: 65 bytes (0x04 || x || y), strip the 0x04 prefix
        public_bytes_full = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        public_bytes = public_bytes_full[1:]  # Remove 0x04 prefix

        return private_bytes, public_bytes

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign message with ECDSA P-256.

        Args:
            private_key: 32-byte ECDSA private key
            message: Message to sign

        Returns:
            64-byte signature in raw R||S format

        Raises:
            InvalidKeyError: If private key is invalid
        """
        try:
            key = ec.derive_private_key(
                int.from_bytes(private_key, byteorder="big"),
                ec.SECP256R1(),
            )
            # Sign and get DER-encoded signature
            der_signature = key.sign(message, ec.ECDSA(hashes.SHA256()))

            # Decode DER to extract R and S
            from cryptography.hazmat.primitives.asymmetric.utils import (
                decode_dss_signature,
            )

            r, s = decode_dss_signature(der_signature)

            # Convert to raw R||S format (32 bytes each)
            r_bytes = r.to_bytes(32, byteorder="big")
            s_bytes = s.to_bytes(32, byteorder="big")

            return r_bytes + s_bytes
        except Exception as e:
            raise InvalidKeyError(f"Invalid ECDSA-P256 private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify ECDSA P-256 signature.

        Args:
            public_key: 64-byte public key (x||y, no prefix)
            message: Original message
            signature: 64-byte signature in R||S format

        Returns:
            True if valid, False otherwise

        Raises:
            InvalidKeyError: If public key is invalid
        """
        try:
            # Add 0x04 prefix for uncompressed point
            public_bytes_full = b"\x04" + public_key
            key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), public_bytes_full
            )

            # Convert raw R||S to DER format
            r = int.from_bytes(signature[:32], byteorder="big")
            s = int.from_bytes(signature[32:], byteorder="big")

            from cryptography.hazmat.primitives.asymmetric.utils import (
                encode_dss_signature,
            )

            der_signature = encode_dss_signature(r, s)

            # Verify
            key.verify(der_signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except ValueError as e:
            if "invalid" in str(e).lower() or "malformed" in str(e).lower():
                raise InvalidKeyError(f"Invalid ECDSA-P256 public key: {e}") from e
            # Verification failed
            return False
        except Exception:
            # Verification failed
            return False
