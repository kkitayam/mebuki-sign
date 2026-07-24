"""Signature algorithm implementations."""

from .base import SignatureAlgorithm
from .ecdsa_p256_sha256 import ECDSAP256SHA256Algorithm
from .eddsa_25519_blake2b import EdDSA25519BLAKE2bAlgorithm
from .fndsa_fips206 import FNDSA512Algorithm

# Algorithm registry
ALGORITHMS: dict[str, type[SignatureAlgorithm]] = {
    "ecdsa-p256-sha256": ECDSAP256SHA256Algorithm,
    "eddsa-25519-blake2b": EdDSA25519BLAKE2bAlgorithm,
    "fndsa512": FNDSA512Algorithm,
}

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
    "ECDSAP256SHA256Algorithm",
    "EdDSA25519BLAKE2bAlgorithm",
    "ALGORITHMS",
    "get_algorithm",
]
