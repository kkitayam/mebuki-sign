# mebuki-sign

This tool is used to sign firmware for the [mebuki](https://github.com/kkitayam/mebuki) secure boot library.

## Build & Test Commands

Use [uv](https://docs.astral.sh/uv/)

## Architecture

```
CLI (cli.py)  →  signer.py / verifier.py / keygen.py
                       ↓
              algorithms/get_algorithm(name)
                       ↓
              Algorithm implementation (e.g., ecdsa_p256_sha256.py)
                       ↓
              binary.py (SignedBinary / Header)
```

**Module Roles:**
| Module | Role |
|---|---|
| `algorithms/base.py` | Defines the `SignatureAlgorithm` Protocol |
| `algorithms/__init__.py` | Algorithm registry `ALGORITHMS` and `get_algorithm()` |
| `binary.py` | Serialization of `Header` (8B) and `SignedBinary` |
| `signer.py` | `sign_firmware()` — signs header\|\|software |
| `verifier.py` | `verify_signature()` / `verify_file()` |
| `keygen.py` | Key generation and format conversion (binary/PEM/C array) |
| `cli.py` | Click CLI: `sign`, `keygen`, `verify`, `info` |
| `errors.py` | Custom exception hierarchy |

## Binary Format

```
[0x0000] uint16_t LE  security_version   (0–0xFFFE)
[0x0002] uint8_t      key_generation     (0–0xFE)
[0x0003] uint8_t      invalidation_flag  (0xFF=valid, 0x00=invalid)
[0x0004] uint32_t LE  software_size
[0x0008] bytes        software_body      (firmware)
[0x0008+N] bytes      signature          (algorithm-dependent size)

Signed message: [8 Bytes header] || [software_body]
```

## Adding a New Algorithm

1. Create `src/mebuki_sign/algorithms/new_algo.py`:
   ```python
   class NewAlgorithm:
       name = "new-algo"           # lowercase, hyphen-separated
       public_key_size: int = ...
       signature_size: int = ...
   
       @staticmethod
       def generate_keypair() -> tuple[bytes, bytes]: ...  # (private, public)
   
       @staticmethod
       def sign(private_key: bytes, message: bytes) -> bytes: ...
   
       @staticmethod
       def verify(public_key: bytes, message: bytes, signature: bytes) -> bool: ...
   ```

2. Register it in the `ALGORITHMS` dictionary in `src/mebuki_sign/algorithms/__init__.py`.

3. If it has optional dependencies, add a dependency group in `pyproject.toml` and use the pattern of catching `ImportError` in `algorithms/__init__.py` and raising `MissingDependencyError`.

## Test Conventions

- Test class naming: `Test{AlgorithmName}Algorithm`
- Required test methods (see [test_ecdsa_p256_sha256.py](tests/test_ecdsa_p256_sha256.py)):
  - `test_generate_keypair` — check key sizes
  - `test_sign_verify_success` — success case
  - `test_verify_wrong_message` — tampering detection
  - `test_verify_wrong_signature` — signature tampering
  - `test_sign_invalid_key` — invalid private key
  - `test_verify_invalid_key` — invalid public key
  - `test_algorithm_constants` — `public_key_size`, `signature_size`, `name`

## Known Issues & Notes

- For MCU-targeted C array output, a uint8_t array + alignment (`_Alignas`) may be required (to prevent HardFaults).
- The maximum value of `security_version` is 0xFFFE (0xFFFF is reserved). The maximum value of `key_generation` is 0xFE.
