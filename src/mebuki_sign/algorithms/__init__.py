"""Signature algorithm implementations."""

from .base import SignatureAlgorithm
from .ed25519 import Ed25519Algorithm
from .ecdsa_p256_sha256 import ECDSAP256SHA256Algorithm
from .eddsa_25519_blake2b import EdDSA25519BLAKE2bAlgorithm

# Algorithm registry
ALGORITHMS: dict[str, type[SignatureAlgorithm]] = {
    "ed25519": Ed25519Algorithm,
    "ecdsa-p256-sha256": ECDSAP256SHA256Algorithm,
    "eddsa-25519-blake2b": EdDSA25519BLAKE2bAlgorithm,
}

PQC_AVAILABLE = False
FNDSA_AVAILABLE = False

# Try to import PQC algorithms if liboqs is available
try:
    from .pqc import (
        MLDSA44Algorithm,
        MLDSA65Algorithm,
        MLDSA87Algorithm,
        SLHDSAShake128fSimpleAlgorithm,
    )

    ALGORITHMS.update(
        {
            "mldsa44": MLDSA44Algorithm,
            "mldsa65": MLDSA65Algorithm,
            "mldsa87": MLDSA87Algorithm,
            "slh-dsa-shake-128f-simple": SLHDSAShake128fSimpleAlgorithm,
        }
    )
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

try:
    from .fndsa_fips206 import FNDSA512Algorithm

    ALGORITHMS.update(
        {
            "fndsa512": FNDSA512Algorithm,
        }
    )
    FNDSA_AVAILABLE = True
except ImportError:
    FNDSA_AVAILABLE = False

def get_algorithm(name: str) -> type[SignatureAlgorithm]:
    """Get algorithm by name.

    Args:
        name: Algorithm name (case-insensitive)

    Returns:
        Algorithm class

    Raises:
        InvalidAlgorithmError: If algorithm is not supported
    """
    from ..errors import InvalidAlgorithmError

    name_lower = name.lower()
    if name_lower not in ALGORITHMS:
        available = ", ".join(sorted(ALGORITHMS.keys()))
        raise InvalidAlgorithmError(
            f"Algorithm '{name}' is not supported. Available algorithms: {available}"
        )
    return ALGORITHMS[name_lower]

__all__ = [
    "SignatureAlgorithm",
    "Ed25519Algorithm",
    "ECDSAP256SHA256Algorithm",
    "EdDSA25519BLAKE2bAlgorithm",
    "ALGORITHMS",
    "PQC_AVAILABLE",
    "FNDSA_AVAILABLE",
    "get_algorithm",
]
