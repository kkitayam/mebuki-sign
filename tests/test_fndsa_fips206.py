"""Tests for FN-DSA (FIPS 206) algorithm."""

import importlib.util

import pytest

from mebuki_sign.algorithms import ALGORITHMS


class TestFNDSA512Algorithm:
    """Tests for FN-DSA (fndsa512) signature algorithm."""

    def test_registry_with_optional_dependency(self):
        """Algorithm is registered only when py-fn-dsa is importable."""
        has_py_fn_dsa = importlib.util.find_spec("py_fn_dsa") is not None
        if has_py_fn_dsa:
            assert "fndsa512" in ALGORITHMS
        else:
            assert "fndsa512" not in ALGORITHMS

    def test_generate_keypair(self):
        """Test keypair generation."""
        py_fn_dsa = pytest.importorskip("py_fn_dsa")
        _ = py_fn_dsa

        from mebuki_sign.algorithms.fndsa_fips206 import FNDSA512Algorithm

        private_key, public_key = FNDSA512Algorithm.generate_keypair()

        assert len(private_key) == 1345
        assert len(public_key) == 897
        assert private_key != public_key

    def test_sign_verify_success(self):
        """Test successful signing and verification."""
        py_fn_dsa = pytest.importorskip("py_fn_dsa")
        _ = py_fn_dsa

        from mebuki_sign.algorithms.fndsa_fips206 import FNDSA512Algorithm

        private_key, public_key = FNDSA512Algorithm.generate_keypair()
        message = b"test message"

        signature = FNDSA512Algorithm.sign(private_key, message)
        assert len(signature) == 666

        valid = FNDSA512Algorithm.verify(public_key, message, signature)
        assert valid is True

    def test_verify_wrong_message(self):
        """Test verification with wrong message."""
        py_fn_dsa = pytest.importorskip("py_fn_dsa")
        _ = py_fn_dsa

        from mebuki_sign.algorithms.fndsa_fips206 import FNDSA512Algorithm

        private_key, public_key = FNDSA512Algorithm.generate_keypair()
        message = b"test message"

        signature = FNDSA512Algorithm.sign(private_key, message)

        valid = FNDSA512Algorithm.verify(public_key, b"wrong message", signature)
        assert valid is False

    def test_verify_wrong_signature(self):
        """Test verification with tampered signature."""
        py_fn_dsa = pytest.importorskip("py_fn_dsa")
        _ = py_fn_dsa

        from mebuki_sign.algorithms.fndsa_fips206 import FNDSA512Algorithm

        private_key, public_key = FNDSA512Algorithm.generate_keypair()
        message = b"test message"

        signature = FNDSA512Algorithm.sign(private_key, message)
        tampered_sig = bytes([signature[0] ^ 0xFF]) + signature[1:]

        valid = FNDSA512Algorithm.verify(public_key, message, tampered_sig)
        assert valid is False

    def test_sign_invalid_key(self):
        """Test signing with invalid key."""
        py_fn_dsa = pytest.importorskip("py_fn_dsa")
        _ = py_fn_dsa

        from mebuki_sign.algorithms.fndsa_fips206 import FNDSA512Algorithm
        from mebuki_sign.errors import InvalidKeyError

        with pytest.raises(InvalidKeyError):
            FNDSA512Algorithm.sign(b"invalid_key", b"message")

    def test_verify_invalid_key(self):
        """Test verification with invalid key."""
        py_fn_dsa = pytest.importorskip("py_fn_dsa")
        _ = py_fn_dsa

        from mebuki_sign.algorithms.fndsa_fips206 import FNDSA512Algorithm

        result = FNDSA512Algorithm.verify(b"invalid_key", b"message", b"X" * 666)
        assert result is False

    def test_algorithm_constants(self):
        """Test algorithm metadata."""
        py_fn_dsa = pytest.importorskip("py_fn_dsa")
        _ = py_fn_dsa

        from mebuki_sign.algorithms.fndsa_fips206 import FNDSA512Algorithm

        assert FNDSA512Algorithm.name == "fndsa512"
        assert FNDSA512Algorithm.public_key_size == 897
        assert FNDSA512Algorithm.signature_size == 666
