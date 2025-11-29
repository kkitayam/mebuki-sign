"""mebuki-sign: Firmware signing tool for libmebuki secure boot library.

This package provides tools for signing, verifying, and managing firmware binaries
for use with the libmebuki secure boot library.
"""

__version__ = "0.1.0"

from .errors import (
    MebukiSignError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidBinaryError,
    FileOperationError,
)

__all__ = [
    "__version__",
    "MebukiSignError",
    "InvalidAlgorithmError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidBinaryError",
    "FileOperationError",
]
