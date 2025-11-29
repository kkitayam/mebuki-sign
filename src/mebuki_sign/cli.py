"""Command-line interface for mebuki-sign."""

import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .algorithms import ALGORITHMS, PQC_AVAILABLE
from .errors import MebukiSignError


@click.group()
@click.version_option(version=__version__, prog_name="mebuki-sign")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Firmware signing tool for libmebuki secure boot library.

    Supports multiple signature algorithms including Ed25519, ECDSA-P256,
    and post-quantum algorithms (ML-DSA, FN-DSA).
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@main.command()
@click.option(
    "-i",
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Unsigned firmware binary file",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Output signed binary file",
)
@click.option(
    "-k",
    "--key",
    "key_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Private key file",
)
@click.option(
    "-v",
    "--security-version",
    type=click.IntRange(0, 0xFFFE),
    required=True,
    help="Security version (0-65534)",
)
@click.option(
    "-g",
    "--key-generation",
    type=click.IntRange(0, 0xFE),
    required=True,
    help="Key generation (0-254)",
)
@click.option(
    "--algorithm",
    type=click.Choice(list(ALGORITHMS.keys()), case_sensitive=False),
    default="ed25519",
    show_default=True,
    help="Signature algorithm",
)
@click.option(
    "--key-format",
    type=click.Choice(["binary", "pem"], case_sensitive=False),
    default="binary",
    show_default=True,
    help="Private key format",
)
@click.pass_context
def sign(
    ctx: click.Context,
    input_path: Path,
    output_path: Path,
    key_path: Path,
    security_version: int,
    key_generation: int,
    algorithm: str,
    key_format: str,
) -> None:
    """Sign firmware binary."""
    from .signer import sign_file

    verbose = ctx.obj["verbose"]

    try:
        if verbose:
            click.echo(f"Algorithm: {algorithm}")
            click.echo(f"Security version: {security_version}")
            click.echo(f"Key generation: {key_generation}")
            click.echo(f"Input: {input_path}")
            click.echo(f"Output: {output_path}")

        with open(input_path, "rb") as input_file, open(
            output_path, "wb"
        ) as output_file, open(key_path, "rb") as key_file:
            sign_file(
                input_file,
                output_file,
                key_file,
                algorithm,
                security_version,
                key_generation,
                key_format,
            )

        click.secho("✓ Firmware signed successfully", fg="green")

    except MebukiSignError as e:
        click.secho(f"✗ Error: {e}", fg="red", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(e.exit_code)


@main.command()
@click.option(
    "--algorithm",
    type=click.Choice(list(ALGORITHMS.keys()), case_sensitive=False),
    required=True,
    help="Signature algorithm",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    help="Output key file (without extension). Creates .key and .pub files.",
)
@click.option(
    "--generations",
    type=click.IntRange(1, 255),
    default=1,
    show_default=True,
    help="Number of key generations to create",
)
@click.option(
    "--format",
    "key_format",
    type=click.Choice(["binary", "pem", "c-array"], case_sensitive=False),
    default="binary",
    show_default=True,
    help="Output format",
)
@click.pass_context
def keygen(
    ctx: click.Context,
    algorithm: str,
    output_path: Optional[Path],
    generations: int,
    key_format: str,
) -> None:
    """Generate cryptographic keypair(s)."""
    from .keygen import generate_keypair, save_key

    verbose = ctx.obj["verbose"]

    try:
        if verbose:
            click.echo(f"Algorithm: {algorithm}")
            click.echo(f"Generations: {generations}")
            click.echo(f"Format: {key_format}")

        if generations == 1:
            # Single keypair
            private_key, public_key = generate_keypair(algorithm)

            if output_path:
                # Save to files
                private_path = output_path.with_suffix(".key")
                public_path = output_path.with_suffix(".pub")

                with open(private_path, "wb") as f:
                    save_key(private_key, f, key_format)
                with open(public_path, "wb") as f:
                    save_key(public_key, f, key_format)

                # Set restrictive permissions
                try:
                    private_path.chmod(0o600)
                except (OSError, NotImplementedError):
                    pass

                click.secho(f"✓ Keys generated:", fg="green")
                click.echo(f"  Private: {private_path}")
                click.echo(f"  Public:  {public_path}")
            else:
                # Output to stdout (binary only)
                if key_format != "binary":
                    click.secho(
                        "Warning: stdout output only supports binary format", fg="yellow"
                    )
                click.echo("Private key:", err=True)
                sys.stdout.buffer.write(private_key)
                click.echo("\nPublic key:", err=True)
                sys.stdout.buffer.write(public_key)

        else:
            # Multiple generations
            if not output_path:
                raise click.UsageError("--output is required for multiple generations")

            from .keygen import generate_multiple_keys

            output_dir = output_path
            generate_multiple_keys(algorithm, generations, output_dir, key_format)

            click.secho(
                f"✓ Generated {generations} key generation(s) in {output_dir}", fg="green"
            )

    except MebukiSignError as e:
        click.secho(f"✗ Error: {e}", fg="red", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(e.exit_code)


@main.command()
@click.option(
    "-i",
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Signed firmware binary file",
)
@click.option(
    "-k",
    "--key",
    "key_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Public key file",
)
@click.option(
    "--algorithm",
    type=click.Choice(list(ALGORITHMS.keys()), case_sensitive=False),
    required=True,
    help="Signature algorithm",
)
@click.option(
    "--key-format",
    type=click.Choice(["binary", "pem"], case_sensitive=False),
    default="binary",
    show_default=True,
    help="Public key format",
)
@click.pass_context
def verify(
    ctx: click.Context,
    input_path: Path,
    key_path: Path,
    algorithm: str,
    key_format: str,
) -> None:
    """Verify firmware signature."""
    from .verifier import verify_file

    verbose = ctx.obj["verbose"]

    try:
        if verbose:
            click.echo(f"Algorithm: {algorithm}")
            click.echo(f"Input: {input_path}")

        with open(input_path, "rb") as signed_file, open(key_path, "rb") as key_file:
            valid, signed_binary = verify_file(signed_file, key_file, algorithm, key_format)

        if valid:
            click.secho("✓ Signature is valid", fg="green")
            if verbose:
                click.echo(f"Security version: {signed_binary.header.security_version}")
                click.echo(f"Key generation: {signed_binary.header.key_generation}")
                click.echo(f"Software size: {len(signed_binary.software)} bytes")
            sys.exit(0)
        else:
            click.secho("✗ Signature is INVALID", fg="red", err=True)
            sys.exit(4)  # InvalidSignatureError exit code

    except MebukiSignError as e:
        click.secho(f"✗ Error: {e}", fg="red", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(e.exit_code)


@main.command()
@click.option(
    "-i",
    "--input",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Signed firmware binary file",
)
@click.option(
    "--algorithm",
    type=click.Choice(list(ALGORITHMS.keys()), case_sensitive=False),
    required=True,
    help="Signature algorithm (needed for parsing)",
)
@click.pass_context
def info(ctx: click.Context, input_path: Path, algorithm: str) -> None:
    """Display firmware binary information."""
    from .algorithms import get_algorithm
    from .binary import SignedBinary

    verbose = ctx.obj["verbose"]

    try:
        algo = get_algorithm(algorithm)

        with open(input_path, "rb") as f:
            signed = SignedBinary.from_file(f, algo.signature_size)

        click.echo(f"File: {input_path}")
        click.echo(f"Magic: 0x{signed.header.magic:08X}")
        click.echo(f"Security version: {signed.header.security_version}")
        click.echo(f"Key generation: {signed.header.key_generation}")
        click.echo(f"Software size: {len(signed.software)} bytes")
        click.echo(f"Signature size: {len(signed.signature)} bytes")
        click.echo(f"Total size: {len(signed.pack())} bytes")

        if verbose:
            click.echo(f"\nAlgorithm: {algorithm}")
            click.echo(f"Expected signature size: {algo.signature_size} bytes")

    except MebukiSignError as e:
        click.secho(f"✗ Error: {e}", fg="red", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(e.exit_code)


if __name__ == "__main__":
    main()
