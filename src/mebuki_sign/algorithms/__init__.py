"""Signature algorithm implementations."""

from .base import SignatureAlgorithm
from .ed25519 import Ed25519Algorithm
from .eddsa_25519_blake2b import EdDSA25519BLAKE2bAlgorithm

# Algorithm registry
ALGORITHMS: dict[str, type[SignatureAlgorithm]] = {
    "ed25519": Ed25519Algorithm,
    "eddsa-25519-blake2b": EdDSA25519BLAKE2bAlgorithm,
}

# Try to import PQC algorithms if liboqs is available
try:
    from .pqc import MLDSA44Algorithm, MLDSA65Algorithm, MLDSA87Algorithm, FNDSAAlgorithm

    ALGORITHMS.update(
        {
            "mldsa44": MLDSA44Algorithm,
            "mldsa65": MLDSA65Algorithm,
            "mldsa87": MLDSA87Algorithm,
            "fndsa": FNDSAAlgorithm,
        }
    )
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False


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
    "EdDSA25519BLAKE2bAlgorithm",
    "ALGORITHMS",
    "PQC_AVAILABLE",
    "get_algorithm",
]
