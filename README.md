# mebuki-sign

Firmware signing tool for [mebuki](https://github.com/kkitayam/mebuki) secure boot library.

## Features

- **Multiple signature algorithms**: ECDSA-P256-SHA256, FN-DSA (FIPS 206)
- **Simple CLI**: Sign, verify, and generate keys with a single command
- **Multiple output formats**: Binary, PEM, C array (for ROM embedding)
- **Key generation management**: Support for multiple key generations (0-254)

## Installation

### Basic installation (ECDSA-P256-SHA256, FN-DSA)

```bash
pip install mebuki-sign
```

### Development installation

```bash
git clone https://github.com/kkitayam/mebuki-sign.git
cd mebuki-sign
pip install -e .[dev]
```

## Quick Start

### 1. Generate keypair

```bash
# ECDSA P-256 + SHA-256 (default)
mebuki-sign keygen --algorithm ecdsa-p256-sha256 -o mykey

# Post-quantum
mebuki-sign keygen --algorithm fndsa512 -o mykey
```

This creates `mykey.key` (private) and `mykey.pub` (public).

### 2. Sign firmware

```bash
mebuki-sign sign \
  -i firmware.bin \
  -o firmware_signed.bin \
  -k mykey.key \
  --algorithm ecdsa-p256-sha256 \
  --security-version 1 \
  --key-generation 0
```

### 3. Verify signature

```bash
mebuki-sign verify \
  -i firmware_signed.bin \
  -k mykey.pub \
  --algorithm ecdsa-p256-sha256
```

### 4. Display binary information

```bash
mebuki-sign info -i firmware_signed.bin --algorithm ecdsa-p256-sha256
```

## Supported Algorithms

| Algorithm | Public Key | Signature | Security Level | PQC |
|-----------|-----------|-----------|----------------|-----|
| `ecdsa-p256-sha256` | 65 B | 64 B | ~128-bit | No |
| `fndsa512` | 897 B | 666 B | NIST L1 (~128-bit) | Yes |

## Binary Format

```
+-------------------------+
| Header (8 bytes)        |
|   [0-1]   security_version (uint16_t)
|   [2]     key_generation (uint8_t)
|   [3]     invalidation_flag (uint8_t)
|   [4-7]   software_size (uint32_t)
+-------------------------+
| Software binary         |
| (variable size)         |
+-------------------------+
| Signature               |
| (algorithm-dependent)   |
+-------------------------+

**Header fields:**
- `security_version`: Monotonically increasing value (0-0xFFFE) to prevent rollback attacks
- `key_generation`: Current key generation number (0-254) for key rotation
- `invalidation_flag`: Firmware validity flag (0xFF = valid, 0x00 = invalid)
- `software_size`: Size of the software binary in bytes
```

## Advanced Usage

### Generate multiple key generations

```bash
# Generate 8 key generations for key rotation
mebuki-sign keygen \
  --algorithm ecdsa-p256-sha256 \
  --generations 8 \
  -o keys/
```

This creates:
- `keys/private_key_gen0.key`, `keys/public_key_gen0.pub`
- `keys/private_key_gen1.key`, `keys/public_key_gen1.pub`
- ...
- `keys/private_key_gen7.key`, `keys/public_key_gen7.pub`

### Generate keys in C array format (ROM embedding)

```bash
mebuki-sign keygen \
  --algorithm ecdsa-p256-sha256 \
  --format c-array \
  -o rom_keys
```

Output (`rom_keys.pub`):
```c
const uint8_t key[] = {
    0x3A, 0x2F, 0x41, 0x5C, 0x6B, 0x7D, 0x8E, 0x9F, 0xA1, 0xB2, 0xC3, 0xD4,
    // ... (32 bytes total)
};
```

### Sign with PEM-format key

```bash
# Generate in PEM format
mebuki-sign keygen --algorithm ecdsa-p256-sha256 --format pem -o mykey

# Sign using PEM key
mebuki-sign sign \
  -i firmware.bin \
  -o firmware_signed.bin \
  -k mykey.key \
  --key-format pem \
  --algorithm ecdsa-p256-sha256 \
  -v 1 -g 0
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error |
| 2 | Invalid algorithm |
| 3 | Invalid key |
| 4 | Invalid signature (verification failed) |
| 5 | Invalid binary format |
| 6 | File operation error |

## Security Considerations

- **Private key protection**: Generated private keys have `0600` permissions on Unix-like systems
- **Security versions**: Use monotonically increasing values to prevent rollback attacks
- **Key generations**: Support up to 255 generations (0-254) for key rotation

## License

MIT License. See [LICENSE](LICENSE) for details.
