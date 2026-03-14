"""
SecureVault Key Manager
Shamir's Secret Sharing + 키 생성/관리

마스터 키 → 5조각 (3조각이면 복구)
Vault 키  → 3조각 (2조각이면 복구)

키 조각의 물리적 위치는 사람이 결정. 자동 분배 없음.
"""

import os
import json
import hmac
import hashlib
import secrets
from dataclasses import dataclass
from typing import List, Tuple, Optional
from datetime import datetime, timezone

from engine import KEY_SIZE


# ─── Shamir's Secret Sharing (GF(256)) ──────────────────────

class ShamirSecret:
    """GF(2^8) 위의 Shamir's Secret Sharing

    외부 라이브러리 없이 구현 — 의존성 최소화.
    GF(256) 연산으로 바이트 단위 분할/복구.
    """

    # GF(2^8): 다항식 0x11D (x^8+x^4+x^3+x^2+1), 생성자 2
    # 0x11D에서 2가 primitive root (order 255) — Shamir SSS 표준
    # 주의: 0x11B(AES)에서는 2의 order가 51이라 사용 불가
    _EXP = [0] * 512
    _LOG = [0] * 256
    _initialized = False

    @classmethod
    def _init_tables(cls):
        """GF(2^8) 로그/지수 테이블 초기화"""
        if cls._initialized:
            return
        x = 1
        for i in range(255):
            cls._EXP[i] = x
            cls._LOG[x] = i
            x = x << 1
            if x >= 256:
                x ^= 0x11D  # x^8+x^4+x^3+x^2+1 (2가 primitive root)
        for i in range(255, 512):
            cls._EXP[i] = cls._EXP[i - 255]
        cls._initialized = True

    @classmethod
    def _gf_mul(cls, a: int, b: int) -> int:
        """GF(2^8) 곱셈"""
        if a == 0 or b == 0:
            return 0
        cls._init_tables()
        return cls._EXP[cls._LOG[a] + cls._LOG[b]]

    @classmethod
    def _gf_inv(cls, a: int) -> int:
        """GF(2^8) 역원"""
        if a == 0:
            raise ZeroDivisionError("GF(256)에서 0의 역원은 없음")
        cls._init_tables()
        return cls._EXP[255 - cls._LOG[a]]

    @classmethod
    def _eval_poly(cls, coeffs: List[int], x: int) -> int:
        """다항식 평가 (GF(256))"""
        result = 0
        for coeff in reversed(coeffs):
            result = cls._gf_mul(result, x) ^ coeff
        return result

    @classmethod
    def split(cls, secret: bytes, n: int, k: int) -> List[Tuple[int, bytes]]:
        """시크릿을 n개 조각으로 분할 (k개면 복구 가능)

        Args:
            secret: 분할할 시크릿 (바이트)
            n: 총 조각 수 (2 ≤ n ≤ 255)
            k: 복구 임계값 (2 ≤ k ≤ n)

        Returns:
            [(x, share_bytes), ...] — x는 1~n
        """
        cls._init_tables()

        if not (2 <= k <= n <= 255):
            raise ValueError(f"잘못된 파라미터: n={n}, k={k} (2 ≤ k ≤ n ≤ 255)")

        shares = [(i, bytearray()) for i in range(1, n + 1)]

        for byte in secret:
            # k-1개의 랜덤 계수 + 시크릿 바이트가 상수항
            coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
            for idx, (x, share_buf) in enumerate(shares):
                share_buf.append(cls._eval_poly(coeffs, x))

        return [(x, bytes(buf)) for x, buf in shares]

    @classmethod
    def recover(cls, shares: List[Tuple[int, bytes]]) -> bytes:
        """조각들로부터 시크릿 복구 (라그랑주 보간)

        Args:
            shares: [(x, share_bytes), ...] — 최소 k개

        Returns:
            복구된 시크릿
        """
        cls._init_tables()

        if len(shares) < 2:
            raise ValueError("최소 2개 조각 필요")

        # 모든 조각의 길이가 같은지 확인
        length = len(shares[0][1])
        if not all(len(s[1]) == length for _, s in enumerate(shares)):
            raise ValueError("조각 길이 불일치")

        result = bytearray(length)

        for byte_idx in range(length):
            # 라그랑주 보간으로 f(0) 복구
            value = 0
            for i, (xi, si) in enumerate(shares):
                yi = si[byte_idx]
                # 라그랑주 기저 다항식 계산
                basis = 1
                for j, (xj, _) in enumerate(shares):
                    if i != j:
                        # basis *= xj / (xj ^ xi)  in GF(256)
                        basis = cls._gf_mul(basis, cls._gf_mul(xj, cls._gf_inv(xj ^ xi)))
                value ^= cls._gf_mul(yi, basis)
            result[byte_idx] = value

        return bytes(result)


# ─── Key Manager ─────────────────────────────────────────────

@dataclass
class KeyInfo:
    """키 메타데이터"""
    key_id: str
    key_type: str       # "master", "vault", "session", "node"
    created_at: str
    shamir_n: int = 0   # 분할 수
    shamir_k: int = 0   # 임계값
    locations: list = None  # 조각 저장 위치 (사람이 기록)

    def __post_init__(self):
        if self.locations is None:
            self.locations = []


class KeyManager:
    """SecureVault 키 관리자

    원칙:
    - 키 조각의 물리적 위치는 사람이 결정
    - 자동 키 분배 없음
    - 키 메타데이터만 관리 (실제 키/조각은 저장하지 않음)
    """

    def __init__(self, metadata_path: Optional[str] = None):
        self.metadata_path = metadata_path
        self._keys: dict[str, KeyInfo] = {}
        if metadata_path and os.path.exists(metadata_path):
            self._load_metadata()

    # ─── 키 생성 ─────────────────────────────────────────────

    def generate_master_key(self) -> bytes:
        """마스터 키 생성 (32 bytes = AES-256)"""
        return os.urandom(KEY_SIZE)

    def generate_vault_key(self) -> bytes:
        """Vault 키 생성"""
        return os.urandom(KEY_SIZE)

    def generate_session_key(self) -> bytes:
        """세션 키 생성 (메모리 only, 디스크 저장 안 함)"""
        return os.urandom(KEY_SIZE)

    # ─── Shamir 분할/복구 ────────────────────────────────────

    def split_key(
        self,
        key: bytes,
        n: int,
        k: int,
        key_type: str = "master",
        locations: Optional[List[str]] = None,
    ) -> Tuple[str, List[Tuple[int, bytes]]]:
        """키를 Shamir 조각으로 분할

        Args:
            key: 분할할 키
            n: 총 조각 수
            k: 복구 임계값
            key_type: 키 유형
            locations: 조각 저장 위치 목록 (사람이 지정)

        Returns:
            (key_id, [(share_idx, share_bytes), ...])
        """
        shares = ShamirSecret.split(key, n, k)

        # 키 ID 생성 (키 해시 기반, 키 자체는 저장 안 함)
        key_id = hashlib.sha256(key).hexdigest()[:16]

        info = KeyInfo(
            key_id=key_id,
            key_type=key_type,
            created_at=datetime.now(timezone.utc).isoformat(),
            shamir_n=n,
            shamir_k=k,
            locations=locations or [f"조각{i+1}: (위치 미지정)" for i in range(n)],
        )
        self._keys[key_id] = info
        self._save_metadata()

        return key_id, shares

    def recover_key(self, shares: List[Tuple[int, bytes]]) -> bytes:
        """Shamir 조각들로 키 복구"""
        return ShamirSecret.recover(shares)

    # ─── HMAC 키 (vssh 인증용) ───────────────────────────────

    @staticmethod
    def generate_hmac_key() -> bytes:
        """vssh HMAC 인증 키 생성 (32 bytes)"""
        return os.urandom(32)

    @staticmethod
    def derive_node_key(master_hmac: bytes, node_id: str) -> bytes:
        """마스터 HMAC에서 노드별 키 파생

        100+ 노드에서 노드별 키 사용 시:
        node_key = HMAC-SHA256(master_hmac, node_id)
        """
        return hmac.new(
            master_hmac,
            node_id.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    # ─── 키 검증 ─────────────────────────────────────────────

    @staticmethod
    def verify_key(key: bytes, expected_id: str) -> bool:
        """키가 예상 ID와 일치하는지 검증"""
        actual_id = hashlib.sha256(key).hexdigest()[:16]
        return hmac.compare_digest(actual_id, expected_id)

    # ─── 메타데이터 관리 ─────────────────────────────────────

    def _save_metadata(self):
        if not self.metadata_path:
            return
        data = {}
        for key_id, info in self._keys.items():
            data[key_id] = {
                "key_id": info.key_id,
                "key_type": info.key_type,
                "created_at": info.created_at,
                "shamir_n": info.shamir_n,
                "shamir_k": info.shamir_k,
                "locations": info.locations,
            }
        os.makedirs(os.path.dirname(self.metadata_path), exist_ok=True)
        with open(self.metadata_path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_metadata(self):
        try:
            with open(self.metadata_path) as f:
                content = f.read().strip()
                if not content:
                    return  # 빈 파일 — 무시
                data = json.loads(content)
            for key_id, info_dict in data.items():
                self._keys[key_id] = KeyInfo(**info_dict)
        except (json.JSONDecodeError, KeyError):
            pass  # 손상된 파일 — 빈 상태로 시작

    def list_keys(self) -> List[KeyInfo]:
        """등록된 키 목록"""
        return list(self._keys.values())

    def get_key_info(self, key_id: str) -> Optional[KeyInfo]:
        """키 메타데이터 조회"""
        return self._keys.get(key_id)

    def update_locations(self, key_id: str, locations: List[str]):
        """키 조각 위치 업데이트 (사람이 수동으로)"""
        if key_id not in self._keys:
            raise KeyError(f"키 ID를 찾을 수 없음: {key_id}")
        self._keys[key_id].locations = locations
        self._save_metadata()
