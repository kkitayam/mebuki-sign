"""Key generation utilities."""

from pathlib import Path
from typing import BinaryIO

from .algorithms import get_algorithm
from .errors import FileOperationError


def generate_keypair(
    algorithm_name: str,
) -> tuple[bytes, bytes]:
    """Generate a keypair for the specified algorithm.

    Args:
        algorithm_name: Algorithm name (e.g., "ed25519", "ecdsa-p256")

    Returns:
        Tuple of (private_key, public_key) as raw bytes

    Raises:
        InvalidAlgorithmError: If algorithm is not supported
    """
    algorithm = get_algorithm(algorithm_name)
    return algorithm.generate_keypair()


def save_key(
    key_data: bytes,
    output_file: BinaryIO,
    format: str = "binary",
) -> None:
    """Save key to file.

    Args:
        key_data: Raw key bytes
        output_file: Output file object
        format: Output format ("binary", "pem", "c-array")

    Raises:
        FileOperationError: If write fails
        ValueError: If format is invalid
    """
    try:
        if format == "binary":
            output_file.write(key_data)
        elif format == "pem":
            # PEM format (Base64-encoded with headers)
            import base64

            b64_data = base64.b64encode(key_data).decode("ascii")
            # Split into 64-character lines
            lines = [b64_data[i : i + 64] for i in range(0, len(b64_data), 64)]
            pem_data = "-----BEGIN KEY-----\n" + "\n".join(lines) + "\n-----END KEY-----\n"
            output_file.write(pem_data.encode("ascii"))
        elif format == "c-array":
            # C array format for ROM embedding
            hex_bytes = ", ".join(f"0x{b:02X}" for b in key_data)
            # Format with line breaks every 12 bytes
            lines = []
            bytes_list = hex_bytes.split(", ")
            for i in range(0, len(bytes_list), 12):
                line = ", ".join(bytes_list[i : i + 12])
                lines.append(f"    {line}")
            c_data = "const uint8_t key[] = {\n" + ",\n".join(lines) + "\n};\n"
            output_file.write(c_data.encode("ascii"))
        else:
            raise ValueError(f"Invalid format: {format}")
    except OSError as e:
        raise FileOperationError(f"Failed to write key: {e}") from e


def load_key(input_file: BinaryIO, format: str = "binary") -> bytes:
    """Load key from file.

    Args:
        input_file: Input file object
        format: Input format ("binary", "pem")

    Returns:
        Raw key bytes

    Raises:
        FileOperationError: If read fails
        ValueError: If format is invalid
    """
    try:
        if format == "binary":
            return input_file.read()
        elif format == "pem":
            # Parse PEM format
            import base64

            pem_data = input_file.read().decode("ascii")
            # Remove headers and whitespace
            lines = pem_data.strip().split("\n")
            b64_lines = [line for line in lines if not line.startswith("-----")]
            b64_data = "".join(b64_lines)
            return base64.b64decode(b64_data)
        else:
            raise ValueError(f"Invalid format: {format}")
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise FileOperationError(f"Failed to read key: {e}") from e


def generate_multiple_keys(
    algorithm_name: str,
    num_generations: int,
    output_dir: Path,
    key_format: str = "binary",
) -> None:
    """Generate multiple key generations.

    Args:
        algorithm_name: Algorithm name
        num_generations: Number of key generations to create
        output_dir: Output directory
        key_format: Output format for keys

    Raises:
        FileOperationError: If file operations fail
        ValueError: If num_generations is invalid
    """
    if not (1 <= num_generations <= 255):
        raise ValueError(f"num_generations must be 1-255, got {num_generations}")

    output_dir.mkdir(parents=True, exist_ok=True)

    for gen in range(num_generations):
        private_key, public_key = generate_keypair(algorithm_name)

        # Save private key
        private_path = output_dir / f"private_key_gen{gen}.key"
        with open(private_path, "wb") as f:
            save_key(private_key, f, key_format)

        # Save public key
        public_path = output_dir / f"public_key_gen{gen}.pub"
        with open(public_path, "wb") as f:
            save_key(public_key, f, key_format)

        # Set restrictive permissions on private key (Unix-like systems)
        try:
            private_path.chmod(0o600)
        except (OSError, NotImplementedError):
            # Windows or other systems that don't support chmod
            pass
