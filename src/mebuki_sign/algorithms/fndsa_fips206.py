"""FN-DSA (FIPS 206) algorithm using py-fn-dsa."""

from py_fn_dsa import LOGN_512, SigningKey, VerifyKey, keygen, sign, verify
from ..errors import InvalidKeyError


class FNDSA512Algorithm:
    """FN-DSA with logn=9 (fndsa512, FIPS 206).

    - Public key size: 897 bytes
    - Signature size: 666 bytes
    - Security level: NIST Level 1 (~128-bit)
    """

    name = "fndsa512"
    public_key_size = 897
    signature_size = 666
    _logn = LOGN_512
    _private_key_size = 1345

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate FN-DSA keypair."""
        verify_key, signing_key = keygen(FNDSA512Algorithm._logn)
        return signing_key.key_data, verify_key.key_data

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign with FN-DSA (FIPS 206)."""
        if len(private_key) != FNDSA512Algorithm._private_key_size:
            raise InvalidKeyError(
                f"Invalid FN-DSA private key size: {len(private_key)} bytes "
                f"(expected {FNDSA512Algorithm._private_key_size})"
            )

        try:
            signing_key = SigningKey.from_bytes(FNDSA512Algorithm._logn, private_key)
            signature = bytes(sign(signing_key, message))
            if len(signature) != FNDSA512Algorithm.signature_size:
                raise InvalidKeyError(
                    f"Invalid FN-DSA signature size: {len(signature)} bytes "
                    f"(expected {FNDSA512Algorithm.signature_size})"
                )
            return signature
        except (RuntimeError, TypeError, ValueError) as e:
            raise InvalidKeyError(f"Invalid FN-DSA private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify FN-DSA (FIPS 206) signature."""
        if len(public_key) != FNDSA512Algorithm.public_key_size:
            return False
        if len(signature) != FNDSA512Algorithm.signature_size:
            return False

        try:
            verify_key = VerifyKey.from_bytes(FNDSA512Algorithm._logn, public_key)
            return bool(verify(verify_key, signature, message))
        except (RuntimeError, TypeError, ValueError):
            return False
