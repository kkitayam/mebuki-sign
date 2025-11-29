"""Signature algorithm implementations."""

from .base import SignatureAlgorithm
from .ed25519 import Ed25519Algorithm
from .ecdsa_p256 import ECDSAP256Algorithm

# Algorithm registry
ALGORITHMS: dict[str, type[SignatureAlgorithm]] = {
    "ed25519": Ed25519Algorithm,
    "ecdsa-p256": ECDSAP256Algorithm,
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
    "ECDSAP256Algorithm",
    "ALGORITHMS",
    "PQC_AVAILABLE",
    "get_algorithm",
]
