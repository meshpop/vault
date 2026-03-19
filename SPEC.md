# SV01 Binary Format Specification

**SecureVault Encrypted Blob Format — Version 1**

## Overview

SV01 is sv-vault's encrypted data storage format. Serializes AES-256-GCM authenticated-encrypted data into a single binary file. Designed so other implementations can achieve compatibility from this spec alone.

## Binary Layout

```
Offset  Size    Type        Field           Description
──────  ────    ────        ─────           ───────────
0       4       bytes       magic           magic number "SV01" (0x53 0x56 0x30 0x31)
4       1       uint8       version         format version (currently 1)
5       32      bytes       salt            Argon2id KDF salt
37      12      bytes       nonce           AES-256-GCM nonce
49      2       uint16 BE   ctx_len         context string length
51      N       utf-8       context         encryption context (e.g. "master-key", "vault-export")
51+N    2       uint16 BE   ts_len          timestamp string length
53+N    M       utf-8       created_at      ISO 8601 timestamp
53+N+M  4       uint32 BE   cipher_len      ciphertext length
57+N+M  L       bytes       ciphertext      AES-256-GCM ciphertext + 16-byte auth tag
```

## Total size

`57 + ctx_len + ts_len + cipher_len` bytes

## Cryptographic Parameters

### Key Derivation — Argon2id

| Parameter   | Value   | Note                       |
|-------------|---------|----------------------------|
| Algorithm   | Argon2id | Hybrid (side-channel + GPU resistant) |
| Time cost   | 3       | iterations                 |
| Memory cost | 65536   | 64 MB                      |
| Parallelism | 4       | threads                    |
| Hash length | 32      | AES-256 key size           |
| Salt        | 32 bytes | random, stored in blob    |

Password → `argon2id(password, salt, t=3, m=64MB, p=4)` → 32-byte key

In direct key mode (`encrypt_with_key`), KDF is skipped and salt is filled with zeros.

### Encryption — AES-256-GCM

| Parameter   | Value   | Note                       |
|-------------|---------|----------------------------|
| Algorithm   | AES-256-GCM | Authenticated Encryption |
| Key size    | 256 bits (32 bytes) |                  |
| Nonce       | 96 bits (12 bytes) | random           |
| Tag size    | 128 bits (16 bytes) | appended to ciphertext |

GCM auth tag is automatically appended to the ciphertext (default behavior of the cryptography library).

### AAD (Additional Authenticated Data)

Optional. When used, the same AAD must be passed during decryption. AAD is not stored in the blob — managed by the caller.

## Shamir's Secret Sharing

Split master key (32 bytes) into N shares; K shares needed to recover.

| Parameter       | Value           |
|-----------------|-----------------|
| Field           | GF(2^8)         |
| Irreducible polynomial | 0x11D (x^8+x^4+x^3+x^2+1) |
| Generator       | 2 (primitive root, order 255) |
| Share index     | 1-based (x=1,2,...,N) |
| Per-byte        | independent polynomial |

**Note**: Different from AES's 0x11B. In 0x11B, order of 2 is 51, which is unsuitable for Shamir.

### Share Format

Each share is an `(index: int, data: bytes)` pair. data length = original secret length (32 bytes for master key).

## File Extensions

| Extension | Content |
|-----------|---------|
| `.vault`  | SV01 encrypted blob (file/secret) |
| `.bin`    | Shamir share (raw bytes) |

## Vault Directory Structure

```
~/.sv-vault/
├── vault.meta.json      # metadata (vault_id, shamir config, share map)
├── vault.data           # SV01 blob — secret DB encrypted with master key
├── vault.key.enc        # SV01 blob — master key encrypted with password
└── audit.jsonl          # audit log (append-only)
```

## vault.meta.json Schema

```json
{
  "vault_id": "26f0d008921c",
  "version": 2,
  "shamir_n": 5,
  "shamir_k": 3,
  "share_map": [
    {
      "share_index": 1,
      "node": "worker2",
      "remote_path": "/opt/sv-vault/shares/share_26f0d008921c_1.bin",
      "stored_at": "2026-03-14T08:00:00+00:00",
      "verified": true,
      "hash": "8bfd47a2878aa1b7"
    }
  ],
  "entry_count": 7,
  "backup_targets": ["storage1", "storage2"],
  "created_at": "2026-03-14T08:00:00+00:00",
  "last_modified": "2026-03-14T08:00:00+00:00"
}
```

## Security Properties

1. **Authenticated encryption** — GCM provides confidentiality + integrity + authentication simultaneously. No CBC+HMAC needed.
2. **Memory-hard KDF** — Argon2id 64MB. Maximizes cost of GPU brute-force.
3. **Information-theoretic security** — Shamir SSS: k-1 shares reveal zero information about the secret.
4. **Transport-agnostic** — shares transferred via vssh (Wire/Tailscale/LAN agnostic). No SSH fallback.
5. **Rule-based only** — AI/LLM makes no security decisions. Password locations decided by humans.

## Compatibility Notes

- Python 3.9+ required
- `cryptography` >= 41.0 (AES-GCM)
- `argon2-cffi` >= 23.1 (Argon2id)
- Big-endian (network byte order) for multi-byte integers
- UTF-8 for all strings
- No padding — GCM does not require padding
