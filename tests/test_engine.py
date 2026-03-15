#!/usr/bin/env python3
"""
SecureVault Engine 테스트

테스트 항목:
1. AES-256-GCM 암호화/복호화
2. Argon2id KDF
3. 틀린 패스워드 → 실패
4. 데이터 변조 → 실패
5. EncryptedBlob 직렬화/역직렬화
6. AAD (Additional Authenticated Data)
7. 직접 키 사용 (Shamir 복구 후)
8. 파일 암호화/복호화
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import VaultEngine, EncryptedBlob, VAULT_MAGIC


@pytest.fixture
def engine():
    # 테스트용 빠른 Argon2 파라미터
    return VaultEngine(
        argon2_time_cost=1,
        argon2_memory_cost=8192,  # 8MB (테스트용)
        argon2_parallelism=1,
    )


class TestEncryption:
    """암호화/복호화 기본 테스트"""

    def test_encrypt_decrypt(self, engine):
        """기본 암호화/복호화"""
        data = b"Hello SecureVault!"
        password = "test_password_123"

        blob = engine.encrypt(data, password)
        result = engine.decrypt(blob, password)

        assert result == data

    def test_encrypt_decrypt_unicode(self, engine):
        """한글 데이터 암호화/복호화"""
        data = "비밀번호 관리 시스템 SecureVault 테스트".encode("utf-8")
        password = "한글패스워드도됩니다"

        blob = engine.encrypt(data, password)
        result = engine.decrypt(blob, password)

        assert result == data

    def test_encrypt_decrypt_large(self, engine):
        """큰 데이터 암호화/복호화 (1MB)"""
        data = os.urandom(1024 * 1024)  # 1MB
        password = "large_file_test"

        blob = engine.encrypt(data, password)
        result = engine.decrypt(blob, password)

        assert result == data

    def test_encrypt_decrypt_empty(self, engine):
        """빈 데이터 암호화/복호화"""
        data = b""
        password = "empty_test"

        blob = engine.encrypt(data, password)
        result = engine.decrypt(blob, password)

        assert result == data

    def test_wrong_password_fails(self, engine):
        """틀린 패스워드 → 복호화 실패"""
        data = b"secret data"
        blob = engine.encrypt(data, "correct_password")

        with pytest.raises(Exception):  # InvalidTag
            engine.decrypt(blob, "wrong_password")

    def test_different_encryptions_different_ciphertext(self, engine):
        """같은 데이터/패스워드도 매번 다른 암호문 (랜덤 nonce+salt)"""
        data = b"same data"
        password = "same password"

        blob1 = engine.encrypt(data, password)
        blob2 = engine.encrypt(data, password)

        assert blob1.ciphertext != blob2.ciphertext
        assert blob1.salt != blob2.salt
        assert blob1.nonce != blob2.nonce


class TestBlobSerialization:
    """EncryptedBlob 직렬화 테스트"""

    def test_to_bytes_from_bytes(self, engine):
        """바이너리 직렬화/역직렬화"""
        data = b"serialization test"
        password = "serial_test"

        blob = engine.encrypt(data, password)
        raw = blob.to_bytes()

        # 매직 바이트 확인
        assert raw[:4] == VAULT_MAGIC

        # 역직렬화
        restored = EncryptedBlob.from_bytes(raw)

        assert restored.magic == blob.magic
        assert restored.version == blob.version
        assert restored.salt == blob.salt
        assert restored.nonce == blob.nonce
        assert restored.ciphertext == blob.ciphertext
        assert restored.context == blob.context

        # 복호화 가능한지
        result = engine.decrypt(restored, password)
        assert result == data

    def test_invalid_magic(self):
        """잘못된 매직 바이트"""
        bad_data = b"XXXX" + b"\x00" * 100

        with pytest.raises(ValueError, match="잘못된 Vault 파일"):
            EncryptedBlob.from_bytes(bad_data)

    def test_to_dict(self, engine):
        """JSON 직렬화"""
        blob = engine.encrypt(b"json test", "pass")
        d = blob.to_dict()

        assert "version" in d
        assert "salt" in d
        assert "nonce" in d
        assert "ciphertext" in d
        assert "created_at" in d
        assert "context" in d


class TestAAD:
    """Additional Authenticated Data 테스트"""

    def test_aad_match(self, engine):
        """AAD 일치 시 복호화 성공"""
        data = b"aad test"
        password = "aad_pass"
        aad = b"file_hash_12345"

        blob = engine.encrypt(data, password, aad=aad)
        result = engine.decrypt(blob, password, aad=aad)

        assert result == data

    def test_aad_mismatch_fails(self, engine):
        """AAD 불일치 시 복호화 실패"""
        data = b"aad test"
        password = "aad_pass"

        blob = engine.encrypt(data, password, aad=b"correct_aad")

        with pytest.raises(Exception):
            engine.decrypt(blob, password, aad=b"wrong_aad")

    def test_aad_missing_fails(self, engine):
        """암호화 시 AAD 사용, 복호화 시 AAD 누락 → 실패"""
        data = b"aad test"
        password = "aad_pass"

        blob = engine.encrypt(data, password, aad=b"some_aad")

        with pytest.raises(Exception):
            engine.decrypt(blob, password, aad=None)


class TestDirectKey:
    """직접 키 사용 테스트 (Shamir 복구 후)"""

    def test_encrypt_with_key(self, engine):
        """직접 키로 암호화/복호화"""
        key = engine.generate_key()
        data = b"direct key test"

        blob = engine.encrypt_with_key(data, key)
        result = engine.decrypt_with_key(blob, key)

        assert result == data

    def test_wrong_key_fails(self, engine):
        """틀린 키 → 실패"""
        key1 = engine.generate_key()
        key2 = engine.generate_key()
        data = b"key test"

        blob = engine.encrypt_with_key(data, key1)

        with pytest.raises(Exception):
            engine.decrypt_with_key(blob, key2)

    def test_invalid_key_size(self, engine):
        """잘못된 키 크기"""
        with pytest.raises(ValueError, match="키 길이"):
            engine.encrypt_with_key(b"data", b"short_key")


class TestFileEncryption:
    """파일 암호화/복호화 테스트"""

    def test_file_encrypt_decrypt(self, engine):
        """파일 암호화 → 복호화"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"file content for encryption test")
            src = f.name

        dst_enc = src + ".vault"
        dst_dec = src + ".decrypted"

        try:
            engine.encrypt_file(src, dst_enc, "file_pass", context="test_file")

            assert os.path.isfile(dst_enc)
            assert os.path.getsize(dst_enc) > os.path.getsize(src)

            engine.decrypt_file(
                dst_enc, dst_dec, "file_pass",
                original_filename=os.path.basename(src),
            )

            with open(dst_dec, "rb") as f:
                assert f.read() == b"file content for encryption test"
        finally:
            for p in [src, dst_enc, dst_dec]:
                if os.path.exists(p):
                    os.remove(p)


class TestKDF:
    """KDF (Argon2id) 테스트"""

    def test_derive_key_deterministic(self, engine):
        """같은 패스워드+salt → 같은 키"""
        salt = engine.generate_salt()
        key1 = engine.derive_key("password", salt)
        key2 = engine.derive_key("password", salt)

        assert key1 == key2

    def test_derive_key_different_salt(self, engine):
        """다른 salt → 다른 키"""
        key1 = engine.derive_key("password", engine.generate_salt())
        key2 = engine.derive_key("password", engine.generate_salt())

        assert key1 != key2

    def test_derive_key_length(self, engine):
        """키 길이 = 32바이트 (AES-256)"""
        key = engine.derive_key("password", engine.generate_salt())
        assert len(key) == 32


class TestEngineInfo:
    """엔진 정보 테스트"""

    def test_info(self, engine):
        info = engine.info()
        assert info["cipher"] == "AES-256-GCM"
        assert info["kdf"] == "Argon2id"
        assert "AES-CBC" in info["deprecated"]
        assert "PBKDF2" in info["deprecated"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
