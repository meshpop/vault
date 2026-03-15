#!/usr/bin/env python3
"""
SecureVault 통합 테스트

전체 플로우: 설정 초기화 → 키 생성 → Shamir 분할 → 암호화 → 백업 → 복원 → 검증
"""

import os
import sys
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import VaultEngine
from keymanager import KeyManager
from config import ConfigManager
from backup import SecureBackup


@pytest.fixture
def test_dir():
    """테스트용 임시 디렉토리"""
    d = tempfile.mkdtemp(prefix="sv_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def engine():
    return VaultEngine(argon2_time_cost=1, argon2_memory_cost=8192, argon2_parallelism=1)


class TestFullFlow:
    """전체 플로우 통합 테스트"""

    def test_init_encrypt_backup_restore(self, test_dir, engine):
        """초기화 → 암호화 → 백업 → 복원"""
        config_dir = os.path.join(test_dir, ".sv-vault")
        password = "integration_test_password"

        # 1. 설정 초기화
        cm = ConfigManager(config_dir=config_dir)
        cm.init()
        cm.load()

        assert os.path.isfile(cm.config_path)
        assert os.path.isdir(cm.vault_dir)
        assert os.path.isdir(cm.backup_dir)

        # 2. 테스트 소스 파일 생성 (secrets.enc 모사)
        secrets_data = b'{"db_password": "super_secret_123", "api_key": "sk-abc-def"}'
        secrets_path = os.path.join(test_dir, "secrets.enc")
        with open(secrets_path, "wb") as f:
            f.write(secrets_data)

        # 3. 백업 (이중 암호화 → 로컬 테스트 모드)
        sb = SecureBackup(config=cm, engine=engine, transport=None)
        record = sb.backup(secrets_path, password)

        assert record.source_file == "secrets.enc"
        assert record.vault_file.endswith(".vault")
        assert all(v is True for v in record.results.values())

        # 4. 상태 확인
        status = sb.status()
        assert status["local_vault_count"] >= 1
        assert status["latest_local"] is not None

        # 5. 로컬 백업에서 복원
        restored_path = os.path.join(test_dir, "secrets.enc.restored")
        vault_path = os.path.join(cm.backup_dir, status["latest_local"])
        sb.restore(vault_path, password, restored_path)

        with open(restored_path, "rb") as f:
            restored_data = f.read()

        assert restored_data == secrets_data

    def test_shamir_key_flow(self, test_dir, engine):
        """마스터 키 생성 → Shamir 분할 → 복구 → 암호화/복호화"""
        meta_path = os.path.join(test_dir, "keys.json")

        # 1. 키 매니저 초기화
        km = KeyManager(metadata_path=meta_path)

        # 2. 마스터 키 생성
        master_key = km.generate_master_key()
        assert len(master_key) == 32

        # 3. Shamir 분할 (5조각, 3개로 복구)
        key_id, shares = km.split_key(
            master_key, n=5, k=3,
            key_type="master",
            locations=["맥북", "s1", "s2", "USB", "종이"],
        )

        assert len(shares) == 5

        # 4. 키 ID 검증
        assert KeyManager.verify_key(master_key, key_id)

        # 5. 3개 조각으로 복구
        recovered = km.recover_key([shares[0], shares[2], shares[4]])
        assert recovered == master_key

        # 6. 복구된 키로 암호화/복호화
        data = b"Shamir flow test data"
        blob = engine.encrypt_with_key(data, recovered)
        result = engine.decrypt_with_key(blob, master_key)
        assert result == data

    def test_node_key_derivation(self):
        """노드별 HMAC 키 파생 플로우"""
        km = KeyManager()

        # 1. 마스터 HMAC 키 생성
        master_hmac = km.generate_hmac_key()

        # 2. 노드별 키 파생
        nodes = ["v1", "g1", "g2", "s1", "s2", "d1"]
        node_keys = {}
        for node in nodes:
            node_keys[node] = km.derive_node_key(master_hmac, node)

        # 3. 모두 다른 키
        unique_keys = set(k.hex() for k in node_keys.values())
        assert len(unique_keys) == len(nodes)

        # 4. 재현 가능
        for node in nodes:
            assert km.derive_node_key(master_hmac, node) == node_keys[node]

    def test_config_principles_validation(self, test_dir):
        """원칙 위반 시 에러"""
        config_dir = os.path.join(test_dir, ".sv-vault-bad")
        cm = ConfigManager(config_dir=config_dir)
        cm.init()

        # SSH fallback 활성화 시도 → 에러
        cm.config.transport.ssh_fallback = True
        with pytest.raises(ValueError, match="원칙 위반"):
            cm._validate_principles()

        # AI 결정권 부여 시도 → 에러
        cm.config.transport.ssh_fallback = False
        cm.config.monitor.ai_decision_authority = True
        with pytest.raises(ValueError, match="원칙 위반"):
            cm._validate_principles()

    def test_backup_verify_flow(self, test_dir, engine):
        """백업 → 검증 (로컬 모드)"""
        config_dir = os.path.join(test_dir, ".sv-vault-verify")
        password = "verify_test"

        cm = ConfigManager(config_dir=config_dir)
        cm.init()
        cm.load()

        # 소스 생성
        src = os.path.join(test_dir, "test_secrets.enc")
        with open(src, "wb") as f:
            f.write(b"verify test data")

        # 백업
        sb = SecureBackup(config=cm, engine=engine, transport=None)
        sb.backup(src, password)

        # 검증
        results = sb.verify(password)

        for target, result in results.items():
            assert result["ok"] is True
            assert result["context"].startswith("backup:")

    def test_multiple_backups_and_cleanup(self, test_dir, engine):
        """다중 백업 + 정리"""
        config_dir = os.path.join(test_dir, ".sv-vault-multi")
        password = "multi_test"

        cm = ConfigManager(config_dir=config_dir)
        cm.init()
        cm.load()
        cm.config.backup.max_versions = 3

        src = os.path.join(test_dir, "multi_secrets.enc")
        with open(src, "wb") as f:
            f.write(b"multi backup test")

        sb = SecureBackup(config=cm, engine=engine, transport=None)

        # 5번 백업
        for _ in range(5):
            sb.backup(src, password)

        # 로컬에 max_versions 이하만 남아야
        vaults = [f for f in os.listdir(cm.backup_dir)
                   if f.endswith(".vault") and not f.startswith(".")]
        assert len(vaults) <= cm.config.backup.max_versions


class TestProductReady:
    """제품화 준비 테스트"""

    def test_engine_no_deprecated(self, engine):
        """구식 알고리즘 사용 안 함"""
        info = engine.info()
        assert info["cipher"] == "AES-256-GCM"
        assert info["kdf"] == "Argon2id"
        assert "AES-CBC" in info["deprecated"]
        assert "PBKDF2" in info["deprecated"]

    def test_blob_format_stable(self, engine):
        """바이너리 포맷 안정성 — 버전 1"""
        blob = engine.encrypt(b"format test", "pass")
        raw = blob.to_bytes()

        # 매직: SV01
        assert raw[:4] == b"SV01"
        # 버전: 1
        assert raw[4] == 1

    def test_config_defaults_are_safe(self):
        """기본 설정이 안전한지"""
        cm = ConfigManager()
        c = cm.config

        assert c.encryption.cipher == "AES-256-GCM"
        assert c.encryption.kdf == "Argon2id"
        assert not c.transport.ssh_fallback
        assert c.monitor.ai_role == "monitor_only"
        assert not c.monitor.ai_decision_authority
        assert c.principles["rule_based_only"] is True
        assert c.principles["human_decides"] is True
        assert c.backup.targets == ["s1", "s2"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
