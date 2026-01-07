"""Key generation utilities."""

from pathlib import Path
from typing import BinaryIO, Iterable, Optional

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
            # Legacy single-array format (kept for backward-compat single-key use)
            hex_bytes = ", ".join(f"0x{b:02X}" for b in key_data)
            bytes_list = hex_bytes.split(", ")
            # 12 bytes per line as before
            lines = [
                "    " + ", ".join(bytes_list[i : i + 12])
                for i in range(0, len(bytes_list), 12)
            ]
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
    *,
    private_key_format: str = "pem",
    emit_macros_header: Optional[str] = None,
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

    public_keys: list[bytes] = []

    for gen in range(num_generations):
        private_key, public_key = generate_keypair(algorithm_name)

        # Save private key (consistent: default PEM)
        private_ext = ".pem" if private_key_format.lower() == "pem" else ".key"
        private_path = output_dir / f"private_key_gen{gen}{private_ext}"
        with open(private_path, "wb") as f:
            save_key(private_key, f, private_key_format)

        # Collect public key for header emission when c-array is selected
        public_keys.append(public_key)

        # Set restrictive permissions on private key (Unix-like systems)
        try:
            private_path.chmod(0o600)
        except (OSError, NotImplementedError):
            # Windows or other systems that don't support chmod
            pass

    # If c-array is requested, write aggregated public_keys.h
    if key_format.lower() == "c-array":
        header_path = output_dir / "public_keys.h"
        with open(header_path, "wb") as f:
            generate_public_keys_header(public_keys, f)

        # Optionally emit macros header (file path or '-')
        if emit_macros_header is not None:
            emit_macros_header_file(emit_macros_header)
    else:
        # Non c-array: also save individual public keys in requested format
        for gen, pub in enumerate(public_keys):
            public_path = output_dir / f"public_key_gen{gen}.pub"
            with open(public_path, "wb") as f:
                save_key(pub, f, key_format)


def _format_bytes_as_c_lines(data: bytes, *, bytes_per_line: int = 8, indent: int = 8) -> str:
    hex_bytes = [f"0x{b:02X}" for b in data]
    lines = []
    for i in range(0, len(hex_bytes), bytes_per_line):
        chunk = ", ".join(hex_bytes[i : i + bytes_per_line])
        lines.append(" " * indent + chunk)
    return ",\n".join(lines)


def generate_public_keys_header(public_keys: Iterable[bytes], out: BinaryIO) -> None:
    """Generate a public_keys.h compatible header containing only the array definition.

    The definition uses unsized first dimension and MBK_SVL_PUBKEY_SIZE for the
    second dimension, to avoid emitting config macros in this header.
    """
    try:
        gens = list(public_keys)
        header_lines: list[str] = []
        header_lines.append("/* Auto-generated by mebuki-sign: public_keys.h */")
        header_lines.append("/* Contains the definition of 'public_keys' array. */")
        header_lines.append("/* This header is intended to be included by a single .c file. */")
        header_lines.append("")
        header_lines.append(
            "const uint8_t public_keys[][MBK_SVL_PUBKEY_SIZE] = {"
        )
        for idx, key in enumerate(gens):
            header_lines.append(f"    /* Generation {idx} */ {{")
            header_lines.append(_format_bytes_as_c_lines(key, bytes_per_line=8, indent=8))
            header_lines.append("    },")
        if gens:
            # Replace trailing comma on last entry for cleaner C syntax (optional but neat)
            header_lines[-1] = header_lines[-1].rstrip(',')
        header_lines.append("};")
        header_lines.append("")
        out.write("\n".join(header_lines).encode("ascii"))
    except OSError as e:
        raise FileOperationError(f"Failed to write header: {e}") from e


def emit_macros_header_file(path_or_dash: str) -> None:
    """Emit minimal macro header for integration (file path or '-' for stdout)."""
    content = (
        "/* Auto-generated by mebuki-sign: macros header */\n"
        "#ifndef MBK_SVL_PUBLIC_KEYS_HEADER\n"
        "#define MBK_SVL_PUBLIC_KEYS_HEADER \"public_keys.h\"\n"
        "#endif\n"
    )
    if path_or_dash == "-":
        import sys

        sys.stdout.write(content)
        return
    p = Path(path_or_dash)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(content, encoding="utf-8")
    except OSError as e:
        raise FileOperationError(f"Failed to write macros header: {e}") from e
