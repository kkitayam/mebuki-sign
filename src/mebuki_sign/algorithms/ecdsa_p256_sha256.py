"""ECDSA P-256 + SHA-256 signature algorithm implementation."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..errors import InvalidKeyError

_SECP256R1_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
)


class ECDSAP256SHA256Algorithm:
    """ECDSA over secp256r1 (P-256) using SHA-256.

    - Public key size: 65 bytes (uncompressed SEC1 point: 0x04 || X || Y)
    - Signature size: 64 bytes (raw r || s)
    """

    name = "ecdsa-p256-sha256"
    public_key_size = 65
    signature_size = 64

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate ECDSA P-256 keypair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_value = private_key.private_numbers().private_value

        private_bytes = private_value.to_bytes(32, "big")
        public_bytes = private_key.public_key().public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint,
        )

        return private_bytes, public_bytes

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign message with ECDSA P-256 + SHA-256."""
        if len(private_key) != 32:
            raise InvalidKeyError(
                f"Invalid ECDSA P-256 private key size: {len(private_key)} (expected 32)"
            )

        private_value = int.from_bytes(private_key, "big")
        if not (1 <= private_value < _SECP256R1_ORDER):
            raise InvalidKeyError("Invalid ECDSA P-256 private key scalar")

        try:
            key = ec.derive_private_key(private_value, ec.SECP256R1())
            signature_der = key.sign(message, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            raise InvalidKeyError(f"Invalid ECDSA P-256 private key: {e}") from e

        r, s = decode_dss_signature(signature_der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify ECDSA P-256 + SHA-256 signature."""
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
        except ValueError as e:
            raise InvalidKeyError(f"Invalid ECDSA P-256 public key: {e}") from e

        if len(signature) != 64:
            return False

        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        if r == 0 or s == 0:
            return False

        try:
            signature_der = encode_dss_signature(r, s)
            key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except ValueError:
            return False
