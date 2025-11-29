"""Post-Quantum Cryptography (PQC) signature algorithms.

Requires liboqs-python to be installed:
    pip install mebuki-sign[pqc]
"""

try:
    import oqs
except ImportError as e:
    raise ImportError(
        "liboqs-python is required for PQC algorithms. "
        "Install with: pip install mebuki-sign[pqc]"
    ) from e

from ..errors import InvalidKeyError


class MLDSA44Algorithm:
    """ML-DSA-44 (FIPS 204, formerly Dilithium2).

    - Public key size: 1312 bytes
    - Signature size: 2420 bytes
    - Security level: NIST Level 2 (~128-bit)
    """

    name = "mldsa44"
    public_key_size = 1312
    signature_size = 2420
    _oqs_name = "Dilithium2"

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate ML-DSA-44 keypair."""
        with oqs.Signature(MLDSA44Algorithm._oqs_name) as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            return private_key, public_key

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign with ML-DSA-44."""
        try:
            with oqs.Signature(MLDSA44Algorithm._oqs_name, private_key) as sig:
                return sig.sign(message)
        except Exception as e:
            raise InvalidKeyError(f"Invalid ML-DSA-44 private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify ML-DSA-44 signature."""
        try:
            with oqs.Signature(MLDSA44Algorithm._oqs_name) as sig:
                return sig.verify(message, signature, public_key)
        except Exception:
            return False


class MLDSA65Algorithm:
    """ML-DSA-65 (FIPS 204, formerly Dilithium3).

    - Public key size: 1952 bytes
    - Signature size: 3293 bytes
    - Security level: NIST Level 3 (~192-bit)
    """

    name = "mldsa65"
    public_key_size = 1952
    signature_size = 3293
    _oqs_name = "Dilithium3"

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate ML-DSA-65 keypair."""
        with oqs.Signature(MLDSA65Algorithm._oqs_name) as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            return private_key, public_key

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign with ML-DSA-65."""
        try:
            with oqs.Signature(MLDSA65Algorithm._oqs_name, private_key) as sig:
                return sig.sign(message)
        except Exception as e:
            raise InvalidKeyError(f"Invalid ML-DSA-65 private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify ML-DSA-65 signature."""
        try:
            with oqs.Signature(MLDSA65Algorithm._oqs_name) as sig:
                return sig.verify(message, signature, public_key)
        except Exception:
            return False


class MLDSA87Algorithm:
    """ML-DSA-87 (FIPS 204, formerly Dilithium5).

    - Public key size: 2592 bytes
    - Signature size: 4595 bytes
    - Security level: NIST Level 5 (~256-bit)
    """

    name = "mldsa87"
    public_key_size = 2592
    signature_size = 4595
    _oqs_name = "Dilithium5"

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate ML-DSA-87 keypair."""
        with oqs.Signature(MLDSA87Algorithm._oqs_name) as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            return private_key, public_key

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign with ML-DSA-87."""
        try:
            with oqs.Signature(MLDSA87Algorithm._oqs_name, private_key) as sig:
                return sig.sign(message)
        except Exception as e:
            raise InvalidKeyError(f"Invalid ML-DSA-87 private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify ML-DSA-87 signature."""
        try:
            with oqs.Signature(MLDSA87Algorithm._oqs_name) as sig:
                return sig.verify(message, signature, public_key)
        except Exception:
            return False


class FNDSAAlgorithm:
    """FN-DSA (FIPS 205, SPHINCS+-SHAKE-128f-simple).

    - Public key size: 32 bytes
    - Signature size: 7856 bytes
    - Security level: NIST Level 1 (~128-bit)
    - Note: Stateless hash-based signature (slower than ML-DSA)
    """

    name = "fndsa"
    public_key_size = 32
    signature_size = 7856
    _oqs_name = "SPHINCS+-SHAKE-128f-simple"

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate FN-DSA keypair."""
        with oqs.Signature(FNDSAAlgorithm._oqs_name) as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()
            return private_key, public_key

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign with FN-DSA."""
        try:
            with oqs.Signature(FNDSAAlgorithm._oqs_name, private_key) as sig:
                return sig.sign(message)
        except Exception as e:
            raise InvalidKeyError(f"Invalid FN-DSA private key: {e}") from e

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify FN-DSA signature."""
        try:
            with oqs.Signature(FNDSAAlgorithm._oqs_name) as sig:
                return sig.verify(message, signature, public_key)
        except Exception:
            return False
