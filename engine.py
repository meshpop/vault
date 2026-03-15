"""
SecureVault Encryption Engine (sv-vault)
AES-256-GCM + Argon2id — 현대적 인증 암호화

CBC/PBKDF2 사용하지 않음.
- GCM: 무결성 검증 포함 (인증 암호화)
- Argon2id: GPU 브루트포스 저항 (메모리 하드 KDF)
"""

import os
import json
import struct
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# ─── 상수 ────────────────────────────────────────────────────
VAULT_MAGIC = b"SV01"  # SecureVault v1 파일 매직
KEY_SIZE = 32           # AES-256 = 32 bytes
NONCE_SIZE = 12         # GCM 표준 nonce = 12 bytes
SALT_SIZE = 32          # Argon2 salt
TAG_SIZE = 16           # GCM auth tag (자동 포함)

# Argon2id 파라미터 — OWASP 권장 기준
ARGON2_TIME_COST = 3        # iterations
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4      # threads


@dataclass
class EncryptedBlob:
    """암호화된 데이터 컨테이너"""
    magic: bytes        # SV01
    version: int        # 1
    salt: bytes         # Argon2 salt (32 bytes)
    nonce: bytes        # GCM nonce (12 bytes)
    ciphertext: bytes   # 암호화된 데이터 + GCM tag
    created_at: str     # ISO 8601 timestamp
    context: str        # 암호화 컨텍스트 (예: "backup", "secret", "memo")

    def to_bytes(self) -> bytes:
        """직렬화: 파일 저장용 바이너리 포맷"""
        ctx_bytes = self.context.encode("utf-8")
        ts_bytes = self.created_at.encode("utf-8")

        # 포맷: MAGIC(4) + VERSION(1) + SALT(32) + NONCE(12)
        #        + CTX_LEN(2) + CTX + TS_LEN(2) + TS
        #        + CIPHER_LEN(4) + CIPHERTEXT
        buf = bytearray()
        buf += self.magic
        buf += struct.pack("B", self.version)
        buf += self.salt
        buf += self.nonce
        buf += struct.pack("!H", len(ctx_bytes))
        buf += ctx_bytes
        buf += struct.pack("!H", len(ts_bytes))
        buf += ts_bytes
        buf += struct.pack("!I", len(self.ciphertext))
        buf += self.ciphertext
        return bytes(buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedBlob":
        """역직렬화: 바이너리 → EncryptedBlob"""
        pos = 0

        magic = data[pos:pos + 4]; pos += 4
        if magic != VAULT_MAGIC:
            raise ValueError(f"잘못된 Vault 파일 (magic={magic!r})")

        version = struct.unpack("B", data[pos:pos + 1])[0]; pos += 1
        if version != 1:
            raise ValueError(f"지원하지 않는 버전: {version}")

        salt = data[pos:pos + SALT_SIZE]; pos += SALT_SIZE
        nonce = data[pos:pos + NONCE_SIZE]; pos += NONCE_SIZE

        ctx_len = struct.unpack("!H", data[pos:pos + 2])[0]; pos += 2
        context = data[pos:pos + ctx_len].decode("utf-8"); pos += ctx_len

        ts_len = struct.unpack("!H", data[pos:pos + 2])[0]; pos += 2
        created_at = data[pos:pos + ts_len].decode("utf-8"); pos += ts_len

        cipher_len = struct.unpack("!I", data[pos:pos + 4])[0]; pos += 4
        ciphertext = data[pos:pos + cipher_len]

        return cls(
            magic=magic, version=version,
            salt=salt, nonce=nonce,
            ciphertext=ciphertext,
            created_at=created_at, context=context,
        )

    def to_dict(self) -> dict:
        """JSON 직렬화용"""
        import base64
        return {
            "version": self.version,
            "salt": base64.b64encode(self.salt).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "created_at": self.created_at,
            "context": self.context,
        }


class VaultEngine:
    """SecureVault 핵심 암호화 엔진

    모든 암호화/복호화는 이 클래스를 통해서만 수행.
    CBC/PBKDF2 사용하지 않음 — GCM + Argon2id만 사용.
    """

    def __init__(
        self,
        argon2_time_cost: int = ARGON2_TIME_COST,
        argon2_memory_cost: int = ARGON2_MEMORY_COST,
        argon2_parallelism: int = ARGON2_PARALLELISM,
    ):
        self.argon2_time_cost = argon2_time_cost
        self.argon2_memory_cost = argon2_memory_cost
        self.argon2_parallelism = argon2_parallelism

    # ─── KDF ─────────────────────────────────────────────────

    def derive_key(self, password: str | bytes, salt: bytes) -> bytes:
        """Argon2id로 패스워드에서 AES-256 키 파생

        Args:
            password: 마스터 패스워드 또는 키 바이트
            salt: 32바이트 랜덤 salt

        Returns:
            32바이트 AES-256 키
        """
        if isinstance(password, str):
            password = password.encode("utf-8")

        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=self.argon2_time_cost,
            memory_cost=self.argon2_memory_cost,
            parallelism=self.argon2_parallelism,
            hash_len=KEY_SIZE,
            type=Type.ID,  # Argon2id — side-channel + GPU 저항
        )

    # ─── 암호화 ──────────────────────────────────────────────

    def encrypt(
        self,
        data: bytes,
        password: str | bytes,
        context: str = "default",
        aad: Optional[bytes] = None,
    ) -> EncryptedBlob:
        """데이터를 AES-256-GCM으로 암호화

        Args:
            data: 평문 데이터
            password: 패스워드 (Argon2id로 키 파생)
            context: 암호화 컨텍스트 (메타데이터)
            aad: Additional Authenticated Data (선택)

        Returns:
            EncryptedBlob
        """
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = self.derive_key(password, salt)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, aad)

        return EncryptedBlob(
            magic=VAULT_MAGIC,
            version=1,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            created_at=datetime.now(timezone.utc).isoformat(),
            context=context,
        )

    def decrypt(
        self,
        blob: EncryptedBlob,
        password: str | bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """EncryptedBlob을 복호화

        Args:
            blob: 암호화된 데이터
            password: 패스워드
            aad: 암호화 시 사용한 AAD (동일해야 함)

        Returns:
            복호화된 평문

        Raises:
            InvalidTag: 패스워드 틀리거나 데이터 변조됨
        """
        key = self.derive_key(password, blob.salt)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(blob.nonce, blob.ciphertext, aad)

    # ─── 키 직접 사용 (Shamir 복구 후) ───────────────────────

    def encrypt_with_key(
        self,
        data: bytes,
        key: bytes,
        context: str = "default",
        aad: Optional[bytes] = None,
    ) -> EncryptedBlob:
        """이미 파생된 키로 직접 암호화 (Shamir 복구 키 등)"""
        if len(key) != KEY_SIZE:
            raise ValueError(f"키 길이 오류: {len(key)} (필요: {KEY_SIZE})")

        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, aad)

        return EncryptedBlob(
            magic=VAULT_MAGIC,
            version=1,
            salt=b"\x00" * SALT_SIZE,  # KDF 안 씀 — salt 비움
            nonce=nonce,
            ciphertext=ciphertext,
            created_at=datetime.now(timezone.utc).isoformat(),
            context=context,
        )

    def decrypt_with_key(
        self,
        blob: EncryptedBlob,
        key: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """이미 파생된 키로 직접 복호화"""
        if len(key) != KEY_SIZE:
            raise ValueError(f"키 길이 오류: {len(key)} (필요: {KEY_SIZE})")

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(blob.nonce, blob.ciphertext, aad)

    # ─── 파일 I/O ────────────────────────────────────────────

    def encrypt_file(
        self,
        src_path: str,
        dst_path: str,
        password: str | bytes,
        context: str = "file",
    ) -> EncryptedBlob:
        """파일을 암호화하여 .vault 파일로 저장"""
        with open(src_path, "rb") as f:
            data = f.read()

        # AAD에 원본 파일명 해시 포함 (무결성)
        aad = hashlib.sha256(os.path.basename(src_path).encode()).digest()
        blob = self.encrypt(data, password, context=context, aad=aad)

        with open(dst_path, "wb") as f:
            f.write(blob.to_bytes())

        return blob

    def decrypt_file(
        self,
        src_path: str,
        dst_path: str,
        password: str | bytes,
        original_filename: Optional[str] = None,
    ) -> bytes:
        """암호화된 .vault 파일을 복호화"""
        with open(src_path, "rb") as f:
            blob = EncryptedBlob.from_bytes(f.read())

        aad = None
        if original_filename:
            aad = hashlib.sha256(original_filename.encode()).digest()

        plaintext = self.decrypt(blob, password, aad=aad)

        with open(dst_path, "wb") as f:
            f.write(plaintext)

        return plaintext

    # ─── 유틸리티 ────────────────────────────────────────────

    @staticmethod
    def generate_key() -> bytes:
        """랜덤 AES-256 키 생성"""
        return os.urandom(KEY_SIZE)

    @staticmethod
    def generate_salt() -> bytes:
        """랜덤 salt 생성"""
        return os.urandom(SALT_SIZE)

    def info(self) -> dict:
        """현재 엔진 설정 정보"""
        return {
            "cipher": "AES-256-GCM",
            "kdf": "Argon2id",
            "argon2_time_cost": self.argon2_time_cost,
            "argon2_memory_cost": f"{self.argon2_memory_cost // 1024} MB",
            "argon2_parallelism": self.argon2_parallelism,
            "key_size": f"{KEY_SIZE * 8} bits",
            "nonce_size": f"{NONCE_SIZE * 8} bits",
            "salt_size": f"{SALT_SIZE * 8} bits",
            "deprecated": ["AES-CBC", "PBKDF2", "SHA1"],
        }
