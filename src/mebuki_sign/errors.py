"""Custom exceptions for mebuki-sign."""


class MebukiSignError(Exception):
    """Base exception for all mebuki-sign errors."""

    exit_code = 1


class InvalidAlgorithmError(MebukiSignError):
    """Raised when an unsupported or invalid algorithm is specified."""

    exit_code = 2


class InvalidKeyError(MebukiSignError):
    """Raised when a key is invalid or cannot be loaded."""

    exit_code = 3


class InvalidSignatureError(MebukiSignError):
    """Raised when signature verification fails."""

    exit_code = 4


class InvalidBinaryError(MebukiSignError):
    """Raised when binary format is invalid."""

    exit_code = 5


class FileOperationError(MebukiSignError):
    """Raised when file I/O operations fail."""

    exit_code = 6
