#!/usr/bin/env python3
"""
SecureVault KeyManager 테스트

테스트 항목:
1. Shamir's Secret Sharing — 분할/복구
2. 다양한 n/k 조합
3. 임계값 미달 시 복구 실패
4. 랜덤 키 생성
5. 노드별 HMAC 키 파생
6. 키 메타데이터 관리
"""

import os
import sys
import json
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keymanager import KeyManager, ShamirSecret
from engine import KEY_SIZE


class TestShamirSecret:
    """Shamir's Secret Sharing 테스트"""

    def test_split_recover_3_of_5(self):
        """3-of-5: 5조각 생성, 3조각으로 복구"""
        secret = os.urandom(32)
        shares = ShamirSecret.split(secret, n=5, k=3)

        assert len(shares) == 5

        # 아무 3조각으로 복구
        recovered = ShamirSecret.recover(shares[:3])
        assert recovered == secret

        recovered = ShamirSecret.recover(shares[2:5])
        assert recovered == secret

        recovered = ShamirSecret.recover([shares[0], shares[2], shares[4]])
        assert recovered == secret

    def test_split_recover_2_of_3(self):
        """2-of-3: Vault 키용"""
        secret = os.urandom(32)
        shares = ShamirSecret.split(secret, n=3, k=2)

        assert len(shares) == 3

        recovered = ShamirSecret.recover([shares[0], shares[1]])
        assert recovered == secret

        recovered = ShamirSecret.recover([shares[1], shares[2]])
        assert recovered == secret

    def test_split_recover_all_shares(self):
        """전체 조각으로 복구"""
        secret = os.urandom(32)
        shares = ShamirSecret.split(secret, n=5, k=3)

        recovered = ShamirSecret.recover(shares)
        assert recovered == secret

    def test_split_recover_exact_threshold(self):
        """정확히 k개로 복구"""
        secret = os.urandom(32)
        shares = ShamirSecret.split(secret, n=10, k=5)

        recovered = ShamirSecret.recover(shares[:5])
        assert recovered == secret

    def test_below_threshold_wrong_result(self):
        """임계값 미달 → 다른 결과 (복구 실패는 아니지만 틀린 값)"""
        secret = os.urandom(32)
        shares = ShamirSecret.split(secret, n=5, k=3)

        # 2조각만으로 "복구" 시도 → 틀린 값
        wrong = ShamirSecret.recover(shares[:2])
        assert wrong != secret

    def test_split_recover_small_secret(self):
        """작은 시크릿 (1바이트)"""
        secret = b"\x42"
        shares = ShamirSecret.split(secret, n=3, k=2)

        recovered = ShamirSecret.recover(shares[:2])
        assert recovered == secret

    def test_split_recover_large_secret(self):
        """큰 시크릿 (256바이트)"""
        secret = os.urandom(256)
        shares = ShamirSecret.split(secret, n=5, k=3)

        recovered = ShamirSecret.recover(shares[:3])
        assert recovered == secret

    def test_invalid_params(self):
        """잘못된 파라미터"""
        with pytest.raises(ValueError):
            ShamirSecret.split(b"test", n=1, k=1)

        with pytest.raises(ValueError):
            ShamirSecret.split(b"test", n=3, k=4)  # k > n

    def test_different_share_combinations(self):
        """모든 3조각 조합으로 복구 가능"""
        import itertools

        secret = os.urandom(32)
        shares = ShamirSecret.split(secret, n=5, k=3)

        for combo in itertools.combinations(shares, 3):
            recovered = ShamirSecret.recover(list(combo))
            assert recovered == secret


class TestKeyManager:
    """KeyManager 테스트"""

    def test_generate_master_key(self):
        km = KeyManager()
        key = km.generate_master_key()
        assert len(key) == KEY_SIZE

    def test_generate_vault_key(self):
        km = KeyManager()
        key = km.generate_vault_key()
        assert len(key) == KEY_SIZE

    def test_generate_session_key(self):
        km = KeyManager()
        key = km.generate_session_key()
        assert len(key) == KEY_SIZE

    def test_split_and_recover(self):
        """키 분할 + 복구"""
        km = KeyManager()
        key = km.generate_master_key()

        key_id, shares = km.split_key(key, n=5, k=3, key_type="master")

        assert len(shares) == 5
        assert len(key_id) == 16

        recovered = km.recover_key(shares[:3])
        assert recovered == key

    def test_verify_key(self):
        """키 검증"""
        km = KeyManager()
        key = km.generate_master_key()

        key_id, _ = km.split_key(key, n=3, k=2, key_type="test")

        assert KeyManager.verify_key(key, key_id)
        assert not KeyManager.verify_key(os.urandom(32), key_id)


class TestHMACKeys:
    """HMAC 키 (vssh 인증) 테스트"""

    def test_generate_hmac_key(self):
        key = KeyManager.generate_hmac_key()
        assert len(key) == 32

    def test_derive_node_key_deterministic(self):
        """같은 마스터 + 노드 → 같은 키"""
        master = KeyManager.generate_hmac_key()

        key1 = KeyManager.derive_node_key(master, "g1")
        key2 = KeyManager.derive_node_key(master, "g1")

        assert key1 == key2

    def test_derive_node_key_different_nodes(self):
        """다른 노드 → 다른 키"""
        master = KeyManager.generate_hmac_key()

        key_g1 = KeyManager.derive_node_key(master, "g1")
        key_g2 = KeyManager.derive_node_key(master, "g2")

        assert key_g1 != key_g2

    def test_derive_node_key_all_nodes(self):
        """실제 클러스터 노드들 — 전부 다른 키"""
        master = KeyManager.generate_hmac_key()
        nodes = ["v1", "v2", "v3", "v4", "g1", "g2", "g3", "g4",
                 "d1", "d2", "s1", "s2", "m1", "n1"]

        keys = [KeyManager.derive_node_key(master, n) for n in nodes]

        # 모두 유니크
        assert len(set(k.hex() for k in keys)) == len(nodes)


class TestMetadata:
    """키 메타데이터 관리 테스트"""

    def test_save_load_metadata(self):
        """메타데이터 저장/로드"""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            meta_path = f.name

        try:
            km = KeyManager(metadata_path=meta_path)
            key = km.generate_master_key()

            key_id, shares = km.split_key(
                key, n=5, k=3,
                key_type="master",
                locations=["맥북", "s1", "s2", "USB", "종이"],
            )

            # 새 인스턴스에서 로드
            km2 = KeyManager(metadata_path=meta_path)
            info = km2.get_key_info(key_id)

            assert info is not None
            assert info.key_type == "master"
            assert info.shamir_n == 5
            assert info.shamir_k == 3
            assert "맥북" in info.locations
        finally:
            os.remove(meta_path)

    def test_list_keys(self):
        """키 목록"""
        km = KeyManager()

        key1 = km.generate_master_key()
        key2 = km.generate_vault_key()

        km.split_key(key1, 5, 3, "master")
        km.split_key(key2, 3, 2, "vault")

        keys = km.list_keys()
        assert len(keys) == 2

    def test_update_locations(self):
        """위치 업데이트"""
        km = KeyManager()
        key = km.generate_master_key()

        key_id, _ = km.split_key(key, 3, 2, "test")

        km.update_locations(key_id, ["서울 금고", "<location> NAS", "USB"])
        info = km.get_key_info(key_id)

        assert "서울 금고" in info.locations


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
