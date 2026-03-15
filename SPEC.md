# SV01 Binary Format Specification

**SecureVault Encrypted Blob Format — Version 1**

## Overview

SV01은 sv-vault의 암호화 데이터 저장 포맷이다. AES-256-GCM 인증 암호화된 데이터를 단일 바이너리 파일로 직렬화한다. 다른 구현체가 이 스펙만 보고 호환 가능하도록 설계.

## Binary Layout

```
Offset  Size    Type        Field           Description
──────  ────    ────        ─────           ───────────
0       4       bytes       magic           매직 넘버 "SV01" (0x53 0x56 0x30 0x31)
4       1       uint8       version         포맷 버전 (현재 1)
5       32      bytes       salt            Argon2id KDF salt
37      12      bytes       nonce           AES-256-GCM nonce
49      2       uint16 BE   ctx_len         context 문자열 길이
51      N       utf-8       context         암호화 컨텍스트 (예: "master-key", "vault-export")
51+N    2       uint16 BE   ts_len          timestamp 문자열 길이
53+N    M       utf-8       created_at      ISO 8601 타임스탬프
53+N+M  4       uint32 BE   cipher_len      ciphertext 길이
57+N+M  L       bytes       ciphertext      AES-256-GCM 암호문 + 16바이트 auth tag
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

패스워드 → `argon2id(password, salt, t=3, m=64MB, p=4)` → 32-byte key

Direct key mode (`encrypt_with_key`)에서는 KDF를 건너뛰고 salt는 0으로 채움.

### Encryption — AES-256-GCM

| Parameter   | Value   | Note                       |
|-------------|---------|----------------------------|
| Algorithm   | AES-256-GCM | Authenticated Encryption |
| Key size    | 256 bits (32 bytes) |                  |
| Nonce       | 96 bits (12 bytes) | random           |
| Tag size    | 128 bits (16 bytes) | appended to ciphertext |

GCM auth tag는 ciphertext 끝에 자동 포함됨 (cryptography 라이브러리 기본 동작).

### AAD (Additional Authenticated Data)

선택적. 사용 시 복호화에도 동일한 AAD를 전달해야 한다. AAD는 blob에 저장되지 않음 — 호출자가 관리.

## Shamir's Secret Sharing

마스터 키 (32 bytes)를 N개 share로 분할, K개면 복원 가능.

| Parameter       | Value           |
|-----------------|-----------------|
| Field           | GF(2^8)         |
| Irreducible polynomial | 0x11D (x^8+x^4+x^3+x^2+1) |
| Generator       | 2 (primitive root, order 255) |
| Share index     | 1-based (x=1,2,...,N) |
| Per-byte        | 독립 다항식     |

**주의**: AES의 0x11B와 다르다. 0x11B에서 2의 order는 51로 Shamir에 부적합.

### Share Format

각 share는 `(index: int, data: bytes)` 쌍. data 길이 = 원본 secret 길이 (32 bytes for master key).

## File Extensions

| Extension | Content |
|-----------|---------|
| `.vault`  | SV01 encrypted blob (파일/시크릿) |
| `.bin`    | Shamir share (raw bytes) |

## Vault Directory Structure

```
~/.sv-vault/
├── vault.meta.json      # 메타데이터 (vault_id, shamir 설정, share 맵)
├── vault.data           # SV01 blob — 마스터 키로 암호화된 시크릿 DB
├── vault.key.enc        # SV01 blob — 패스워드로 암호화된 마스터 키
└── audit.jsonl          # 감사 로그 (append-only)
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
      "node": "d2",
      "remote_path": "/opt/sv-vault/shares/share_26f0d008921c_1.bin",
      "stored_at": "2026-03-14T08:00:00+00:00",
      "verified": true,
      "hash": "8bfd47a2878aa1b7"
    }
  ],
  "entry_count": 7,
  "backup_targets": ["s1", "s2"],
  "created_at": "2026-03-14T08:00:00+00:00",
  "last_modified": "2026-03-14T08:00:00+00:00"
}
```

## Security Properties

1. **인증 암호화** — GCM은 기밀성 + 무결성 + 인증을 동시에 제공. CBC+HMAC 불필요.
2. **메모리 하드 KDF** — Argon2id 64MB. GPU brute-force 비용 극대화.
3. **정보 이론적 보안** — Shamir SSS는 k-1개 share로는 secret에 대해 아무 정보도 얻을 수 없음.
4. **Transport-agnostic** — vssh (Wire/Tailscale/LAN 무관)로 share 전송. SSH fallback 없음.
5. **룰 기반 전용** — AI/LLM이 보안 결정 안 함. 패스워드 위치는 사람이 정함.

## Compatibility Notes

- Python 3.9+ 필요
- `cryptography` >= 41.0 (AES-GCM)
- `argon2-cffi` >= 23.1 (Argon2id)
- Big-endian (network byte order) for multi-byte integers
- UTF-8 for all strings
- No padding — GCM은 패딩 불필요
