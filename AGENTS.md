# mebuki-sign — Agent Instructions

MCU ファームウェア署名ツール。[mebuki](https://github.com/kkitayam/mebuki) セキュアブートライブラリ向けにファームウェアに署名する。

## ビルド・テスト コマンド

uv を使う

## アーキテクチャ

```
CLI (cli.py)  →  signer.py / verifier.py / keygen.py
                       ↓
              algorithms/get_algorithm(name)
                       ↓
              Algorithm実装 (ed25519.py など)
                       ↓
              binary.py (SignedBinary / Header)
```

**モジュール役割:**
| モジュール | 役割 |
|---|---|
| `algorithms/base.py` | `SignatureAlgorithm` Protocol 定義 |
| `algorithms/__init__.py` | アルゴリズムレジストリ `ALGORITHMS` と `get_algorithm()` |
| `binary.py` | `Header` (8B) と `SignedBinary` のシリアライズ |
| `signer.py` | `sign_firmware()` — header\|\|software に署名 |
| `verifier.py` | `verify_signature()` / `verify_file()` |
| `keygen.py` | 鍵生成・フォーマット変換（binary/PEM/C配列） |
| `cli.py` | Click CLI: `sign`, `keygen`, `verify`, `info` |
| `errors.py` | カスタム例外階層 |

## バイナリフォーマット

```
[0x0000] uint16_t LE  security_version   (0–0xFFFE)
[0x0002] uint8_t      key_generation     (0–0xFE)
[0x0003] uint8_t      invalidation_flag  (0xFF=valid, 0x00=invalid)
[0x0004] uint32_t LE  software_size
[0x0008] bytes        software_body      (firmware)
[0x0008+N] bytes      signature          (アルゴリズム依存サイズ)

署名対象: [8B ヘッダ] || [software_body]
```

## 新アルゴリズムの追加方法

1. `src/mebuki_sign/algorithms/new_algo.py` を作成:
   ```python
   class NewAlgorithm:
       name = "new-algo"           # 小文字・ハイフン区切り
       public_key_size: int = ...
       signature_size: int = ...
   
       @staticmethod
       def generate_keypair() -> tuple[bytes, bytes]: ...  # (private, public)
   
       @staticmethod
       def sign(private_key: bytes, message: bytes) -> bytes: ...
   
       @staticmethod
       def verify(public_key: bytes, message: bytes, signature: bytes) -> bool: ...
   ```

2. `src/mebuki_sign/algorithms/__init__.py` の `ALGORITHMS` 辞書に登録。

3. オプション依存なら `pyproject.toml` に依存グループを追加し、`algorithms/__init__.py` で `ImportError` を捕捉して `MissingDependencyError` を送出するパターンを使う。

## テスト規約

- テストクラス命名: `Test{AlgorithmName}Algorithm`
- 必須テストメソッド（[test_ecdsa_p256_sha256.py](tests/test_ecdsa_p256_sha256.py) を参照）:
  - `test_generate_keypair` — 鍵サイズの確認
  - `test_sign_verify_success` — 正常系
  - `test_verify_wrong_message` — 改ざん検知
  - `test_verify_wrong_signature` — 署名改ざん
  - `test_sign_invalid_key` — 不正な秘密鍵
  - `test_verify_invalid_key` — 不正な公開鍵
  - `test_algorithm_constants` — `public_key_size`, `signature_size`, `name`

## 既知の問題・注意点

- MCU 向け C 配列出力では uint8_t 配列 + アライメント (`_Alignas`) が必要になる場合がある（HardFault 対策）。
- `security_version` の最大値は 0xFFFE（0xFFFF は予約済み）。`key_generation` 最大値は 0xFE。
