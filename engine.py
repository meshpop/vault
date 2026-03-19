"""
SecureVault Encryption Engine (sv-vault)
AES-256-GCM + Argon2id — modern authenticated encryption

CBC/PBKDF2 not used.
- GCM: integrity verification included (authenticated encryption)
- Argon2id: GPU brute-force resistant (memory-hard KDF)
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

# ─── Constants ────────────────────────────────────────────────────
VAULT_MAGIC = b"SV01"  # SecureVault v1 file magic
KEY_SIZE = 32           # AES-256 = 32 bytes
NONCE_SIZE = 12         # GCM standard nonce = 12 bytes
SALT_SIZE = 32          # Argon2 salt
TAG_SIZE = 16           # GCM auth tag (included automatically)

# Argon2id parameters — OWASP recommended baseline
ARGON2_TIME_COST = 3        # iterations
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4      # threads


@dataclass
class EncryptedBlob:
    """Encrypted data container"""
    magic: bytes        # SV01
    version: int        # 1
    salt: bytes         # Argon2 salt (32 bytes)
    nonce: bytes        # GCM nonce (12 bytes)
    ciphertext: bytes   # encrypted data + GCM tag
    created_at: str     # ISO 8601 timestamp
    context: str        # encryption context (e.g. "backup", "secret", "memo")

    def to_bytes(self) -> bytes:
        """Serialize to binary format for file storage"""
        ctx_bytes = self.context.encode("utf-8")
        ts_bytes = self.created_at.encode("utf-8")

        # Format: MAGIC(4) + VERSION(1) + SALT(32) + NONCE(12)
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
        """Deserialize: binary → EncryptedBlob"""
        pos = 0

        magic = data[pos:pos + 4]; pos += 4
        if magic != VAULT_MAGIC:
            raise ValueError(f"Invalid Vault file (magic={magic!r})")

        version = struct.unpack("B", data[pos:pos + 1])[0]; pos += 1
        if version != 1:
            raise ValueError(f"Unsupported version: {version}")

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
        """For JSON serialization"""
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
    """SecureVault core encryption engine

    All encryption/decryption is performed through this class only.
    CBC/PBKDF2 not used — GCM + Argon2id only.
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
        """Derive AES-256 key from password using Argon2id

        Args:
            password: master password or key bytes
            salt: 32-byte random salt

        Returns:
            32-byte AES-256 key
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
            type=Type.ID,  # Argon2id — side-channel + GPU resistant
        )

    # ─── Encryption ──────────────────────────────────────────────

    def encrypt(
        self,
        data: bytes,
        password: str | bytes,
        context: str = "default",
        aad: Optional[bytes] = None,
    ) -> EncryptedBlob:
        """Encrypt data with AES-256-GCM

        Args:
            data: plaintext data
            password: password (key derived via Argon2id)
            context: encryption context (metadata)
            aad: Additional Authenticated Data (optional)

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
        """Decrypt an EncryptedBlob

        Args:
            blob: encrypted data
            password: password
            aad: AAD used during encryption (must match)

        Returns:
            decrypted plaintext

        Raises:
            InvalidTag: wrong password or data tampered
        """
        key = self.derive_key(password, blob.salt)
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(blob.nonce, blob.ciphertext, aad)
        except Exception as tag_err:
            # InvalidTag has empty str() — raise with explicit message
            if not str(tag_err).strip():
                raise ValueError("Wrong password or corrupted file (GCM auth tag mismatch)") from tag_err
            raise

    # ─── Direct key use (after Shamir recovery) ───────────────────────

    def encrypt_with_key(
        self,
        data: bytes,
        key: bytes,
        context: str = "default",
        aad: Optional[bytes] = None,
    ) -> EncryptedBlob:
        """Encrypt directly with a pre-derived key (e.g. Shamir recovered key)"""
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key length error: {len(key)} (required: {KEY_SIZE})")

        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, aad)

        return EncryptedBlob(
            magic=VAULT_MAGIC,
            version=1,
            salt=b"\x00" * SALT_SIZE,  # no KDF — empty salt
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
        """Decrypt directly with a pre-derived key"""
        if len(key) != KEY_SIZE:
            raise ValueError(f"Key length error: {len(key)} (required: {KEY_SIZE})")

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(blob.nonce, blob.ciphertext, aad)

    # ─── File I/O ────────────────────────────────────────────

    def encrypt_file(
        self,
        src_path: str,
        dst_path: str,
        password: str | bytes,
        context: str = "file",
    ) -> EncryptedBlob:
        """Encrypt a file and save as .vault file"""
        with open(src_path, "rb") as f:
            data = f.read()

        # Include original filename hash in AAD (integrity)
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
        """Decrypt an encrypted .vault file"""
        with open(src_path, "rb") as f:
            blob = EncryptedBlob.from_bytes(f.read())

        aad = None
        if original_filename:
            aad = hashlib.sha256(original_filename.encode()).digest()

        plaintext = self.decrypt(blob, password, aad=aad)

        with open(dst_path, "wb") as f:
            f.write(plaintext)

        return plaintext

    # ─── Utilities ────────────────────────────────────────────

    @staticmethod
    def generate_key() -> bytes:
        """Generate a random AES-256 key"""
        return os.urandom(KEY_SIZE)

    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt"""
        return os.urandom(SALT_SIZE)

    def info(self) -> dict:
        """Current engine configuration info"""
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
