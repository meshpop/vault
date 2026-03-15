"""
SecureVault Manager 테스트 — CRUD + Shamir + 감사 로그
"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vault import SecureVaultManager, SecretEntry


@pytest.fixture
def vault_dir():
    d = tempfile.mkdtemp(prefix="sv_vault_test_")
    yield d
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def vault(vault_dir):
    vm = SecureVaultManager(vault_dir)
    vm.init("test-master-password-2026")
    return vm


class TestInit:
    def test_init_creates_files(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        result = vm.init("mypassword", shamir_n=5, shamir_k=3)

        assert os.path.exists(os.path.join(vault_dir, "vault.meta.json"))
        assert os.path.exists(os.path.join(vault_dir, "vault.data"))
        assert os.path.exists(os.path.join(vault_dir, "vault.key.enc"))
        assert result["vault_id"]
        assert result["shamir"] == "3-of-5"
        assert len(result["shares"]) == 5

    def test_init_duplicate_raises(self, vault):
        with pytest.raises(FileExistsError):
            vault.init("another-password")

    def test_init_shares_valid(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        result = vm.init("pw", shamir_n=7, shamir_k=4)
        assert len(result["shares"]) == 7
        assert result["shamir"] == "4-of-7"
        for idx, share in result["shares"]:
            assert isinstance(idx, int)
            assert len(share) == 32  # 마스터 키 크기


class TestUnlockLock:
    def test_unlock_correct_password(self, vault):
        vault.lock()
        assert not vault.is_unlocked
        assert vault.unlock("test-master-password-2026")
        assert vault.is_unlocked

    def test_unlock_wrong_password(self, vault):
        vault.lock()
        assert not vault.unlock("wrong-password")
        assert not vault.is_unlocked

    def test_unlock_shamir(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        result = vm.init("pw123", shamir_n=5, shamir_k=3)
        shares = result["shares"]

        # 시크릿 추가
        vm.add("test", "secret_value")
        vm.lock()

        # 3개 share로 복원
        assert vm.unlock_shamir(shares[:3])
        assert vm.is_unlocked
        entry = vm.get("test")
        assert entry.value == "secret_value"

    def test_unlock_shamir_insufficient(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        result = vm.init("pw123", shamir_n=5, shamir_k=3)
        shares = result["shares"]
        vm.lock()

        # 2개만으로는 실패
        assert not vm.unlock_shamir(shares[:2])

    def test_lock_clears_memory(self, vault):
        vault.add("secret1", "value1")
        assert vault.is_unlocked
        vault.lock()
        assert not vault.is_unlocked
        with pytest.raises(PermissionError):
            vault.get("secret1")


class TestCRUD:
    def test_add_and_get(self, vault):
        entry = vault.add("db_password", "super_secret", category="database")
        assert entry.name == "db_password"
        assert entry.value == "super_secret"
        assert entry.category == "database"

        retrieved = vault.get("db_password")
        assert retrieved.value == "super_secret"

    def test_add_duplicate_raises(self, vault):
        vault.add("key1", "val1")
        with pytest.raises(KeyError):
            vault.add("key1", "val2")

    def test_update(self, vault):
        vault.add("api_key", "old_key")
        updated = vault.update("api_key", value="new_key", category="api")
        assert updated.value == "new_key"
        assert updated.category == "api"

        retrieved = vault.get("api_key")
        assert retrieved.value == "new_key"

    def test_update_nonexistent_raises(self, vault):
        with pytest.raises(KeyError):
            vault.update("nonexistent", value="x")

    def test_delete(self, vault):
        vault.add("temp_key", "temp_value")
        assert vault.delete("temp_key")
        assert vault.get("temp_key") is None

    def test_delete_nonexistent(self, vault):
        assert not vault.delete("nonexistent")

    def test_list_secrets(self, vault):
        vault.add("s1", "v1", category="db")
        vault.add("s2", "v2", category="api")
        vault.add("s3", "v3", category="db")

        all_list = vault.list_secrets()
        assert len(all_list) == 3
        # 값이 노출되지 않음
        for item in all_list:
            assert "value" not in item

        db_list = vault.list_secrets(category="db")
        assert len(db_list) == 2

    def test_search(self, vault):
        vault.add("mysql_prod", "pw1", tags=["production", "mysql"])
        vault.add("redis_staging", "pw2", tags=["staging", "redis"])
        vault.add("postgres_prod", "pw3", tags=["production", "postgres"])

        results = vault.search("prod")
        assert len(results) == 2  # mysql_prod, postgres_prod

        results = vault.search("staging")
        assert len(results) == 1

    def test_crud_while_locked_raises(self, vault):
        vault.lock()
        with pytest.raises(PermissionError):
            vault.add("x", "y")
        with pytest.raises(PermissionError):
            vault.list_secrets()


class TestPersistence:
    def test_data_survives_lock_unlock(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        vm.init("pw")
        vm.add("secret1", "value1")
        vm.add("secret2", "value2", category="api", tags=["prod"])
        vm.lock()

        # 새 인스턴스로 열기
        vm2 = SecureVaultManager(vault_dir)
        vm2.unlock("pw")
        assert vm2.get("secret1").value == "value1"
        s2 = vm2.get("secret2")
        assert s2.value == "value2"
        assert s2.category == "api"
        assert "prod" in s2.tags

    def test_meta_entry_count(self, vault):
        vault.add("a", "1")
        vault.add("b", "2")
        vault.add("c", "3")
        vault.delete("b")

        status = vault.status()
        assert status["entry_count"] == 2


class TestExportImport:
    def test_export_import(self, vault_dir):
        # 원본 vault
        vm1 = SecureVaultManager(vault_dir)
        vm1.init("pw1")
        vm1.add("key1", "val1")
        vm1.add("key2", "val2")

        exported = vm1.export_encrypted("export-password")
        vm1.lock()

        # 새 vault에 가져오기
        new_dir = vault_dir + "_new"
        os.makedirs(new_dir, exist_ok=True)
        vm2 = SecureVaultManager(new_dir)
        vm2.init("pw2")

        count = vm2.import_encrypted(exported, "export-password")
        assert count == 2
        assert vm2.get("key1").value == "val1"

        import shutil
        shutil.rmtree(new_dir, ignore_errors=True)

    def test_import_wrong_password(self, vault):
        exported = vault.export_encrypted("correct")
        vault2_dir = vault.vault_dir + "_imp"
        os.makedirs(vault2_dir, exist_ok=True)
        vm2 = SecureVaultManager(vault2_dir)
        vm2.init("pw")

        with pytest.raises(Exception):
            vm2.import_encrypted(exported, "wrong")

        import shutil
        shutil.rmtree(vault2_dir, ignore_errors=True)


class TestRekey:
    def test_rekey_preserves_secrets(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        vm.init("old_pw")
        vm.add("secret1", "value1")
        vm.add("secret2", "value2")

        result = vm.rekey("new_pw")
        assert result["new_key_hash"]
        assert len(result["shares"]) == 5
        assert result["warning"]

        # 새 키로 시크릿 접근 가능
        assert vm.get("secret1").value == "value1"
        assert vm.get("secret2").value == "value2"

    def test_rekey_old_password_fails(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        vm.init("old_pw")
        vm.add("s", "v")
        vm.rekey("new_pw")
        vm.lock()

        assert not vm.unlock("old_pw")  # 옛 패스워드 안 됨
        assert vm.unlock("new_pw")       # 새 패스워드 OK
        assert vm.get("s").value == "v"

    def test_rekey_new_shamir_works(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        vm.init("pw")
        vm.add("key", "val")

        result = vm.rekey("new_pw")
        new_shares = result["shares"]
        vm.lock()

        # 새 share로 잠금 해제
        assert vm.unlock_shamir(new_shares[:3])
        assert vm.get("key").value == "val"

    def test_rekey_old_shamir_fails(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        result_init = vm.init("pw")
        old_shares = result_init["shares"]

        vm.rekey("new_pw")
        vm.lock()

        # 옛 share로는 안 됨
        assert not vm.unlock_shamir(old_shares[:3])

    def test_rekey_invalidates_share_map(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        vm.init("pw")
        vm.rekey("new_pw")

        status = vm.status()
        assert status["share_nodes"] == []  # share 맵 비워짐


class TestAudit:
    def test_audit_log_created(self, vault):
        vault.add("s1", "v1")
        vault.get("s1")
        vault.update("s1", value="v2")
        vault.delete("s1")

        log = vault.get_audit_log()
        actions = [e["action"] for e in log]
        assert "init" in actions
        assert "add" in actions
        assert "read" in actions
        assert "update" in actions
        assert "delete" in actions

    def test_audit_log_persists(self, vault_dir):
        vm = SecureVaultManager(vault_dir)
        vm.init("pw")
        vm.add("x", "y")
        vm.lock()

        vm2 = SecureVaultManager(vault_dir)
        log = vm2.get_audit_log()
        assert len(log) >= 2  # init + add + lock


class TestStatus:
    def test_status_uninitalized(self):
        vm = SecureVaultManager("/tmp/nonexistent_vault_test")
        assert vm.status() == {"initialized": False}

    def test_status_initialized(self, vault):
        status = vault.status()
        assert status["initialized"]
        assert status["unlocked"]
        assert status["vault_id"]
        assert status["shamir"] == "3-of-5"
