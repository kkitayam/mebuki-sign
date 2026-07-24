"""Tests for c-array header generation and PEM outputs in keygen."""

from pathlib import Path

from mebuki_sign.keygen import (
    emit_macros_header_file,
    generate_multiple_keys,
)


def test_generate_multiple_keys_c_array_creates_header_and_pem(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"

    generate_multiple_keys(
        "ecdsa-p256-sha256",
        num_generations=2,
        output_dir=out_dir,
        key_format="c-array",
        private_key_format="pem",
    )

    header = out_dir / "public_keys.h"
    priv0 = out_dir / "private_key_gen0.pem"
    priv1 = out_dir / "private_key_gen1.pem"

    assert header.is_file()
    assert priv0.is_file()
    assert priv1.is_file()

    content = header.read_text(encoding="ascii")
    assert "const uint8_t public_keys[][MBK_SVL_PUBKEY_SIZE]" in content
    assert "/* Generation 0 */" in content
    assert "/* Generation 1 */" in content

    # Ensure 8 bytes per line formatting exists by sampling a line with commas
    lines = [line.strip() for line in content.splitlines() if line.strip().startswith("0x")]
    assert any(line.count("0x") == 8 for line in lines)


def test_emit_macros_header_file_path_and_stdout(tmp_path: Path, capsys) -> None:
    macros_path = tmp_path / "macros.h"

    emit_macros_header_file(str(macros_path))
    data = macros_path.read_text(encoding="utf-8")
    assert "MBK_SVL_PUBLIC_KEYS_HEADER" in data
    assert "public_keys.h" in data

    emit_macros_header_file("-")
    captured = capsys.readouterr()
    assert "MBK_SVL_PUBLIC_KEYS_HEADER" in captured.out
    assert "public_keys.h" in captured.out