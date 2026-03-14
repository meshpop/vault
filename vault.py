"""
SecureVault — 분산 패스워드 관리자 (제품 핵심)

패스워드/시크릿 CRUD + Shamir share 자동 분산/회수.
모든 데이터는 AES-256-GCM + Argon2id로 암호화.
마스터 키는 Shamir's Secret Sharing으로 N개 노드에 분산.

원칙:
- 룰 기반만. AI가 보안 결정 안 함
- 패스워드 위치는 사람이 정함
- vssh 전송, transport-agnostic
"""

import os
import json
import time
import hashlib
import base64
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timezone

from engine import VaultEngine, EncryptedBlob
from keymanager import ShamirSecret, KeyManager


# ─── 데이터 모델 ──────────────────────────────────────────

@dataclass
class SecretEntry:
    """개별 시크릿 엔트리"""
    name: str                   # 식별자 (예: "db_master", "api_key")
    value: str                  # 실제 비밀값
    category: str = "default"   # 분류 (password, api_key, token, cert, etc.)
    tags: list = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    created_by: str = "human"   # 항상 human. AI가 비밀을 만들지 않음
    note: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


@dataclass
class ShareMap:
    """Shamir share 위치 맵"""
    share_index: int
    node: str
    remote_path: str
    stored_at: str = ""
    verified: bool = False
    hash: str = ""  # share 해시 (내용은 저장 안 함)


@dataclass
class VaultMeta:
    """Vault 메타데이터 — 암호화되지 않는 부분"""
    vault_id: str
    version: int = 2
    shamir_n: int = 5
    shamir_k: int = 3
    share_map: list = field(default_factory=list)  # List[ShareMap as dict]
    created_at: str = ""
    last_modified: str = ""
    entry_count: int = 0
    backup_targets: list = field(default_factory=lambda: ["s1", "s2"])


# ─── Vault 코어 ──────────────────────────────────────────

class SecureVaultManager:
    """분산 패스워드 관리자

    사용 흐름:
    1. init() — vault 초기화, 마스터 키 생성
    2. add(name, value) — 시크릿 추가
    3. get(name) — 시크릿 조회
    4. distribute() — Shamir share를 노드에 분산
    5. collect() — 노드에서 share 회수 → 마스터 키 복원
    6. lock() — 메모리에서 키 제거
    7. unlock(password) — 패스워드로 잠금 해제

    마스터 키는 두 가지 방법으로 보호:
    a) 패스워드 기반: AES-256-GCM + Argon2id
    b) Shamir 분산: N개 노드에 share 저장, K개만 있으면 복원
    """

    def __init__(self, vault_dir: str, transport=None):
        """
        Args:
            vault_dir: vault 데이터 디렉토리
            transport: VsshTransport 인스턴스 (None이면 로컬 전용)
        """
        self.vault_dir = vault_dir
        self.transport = transport
        self.engine = VaultEngine()
        self.shamir = ShamirSecret()

        # 파일 경로
        self._meta_path = os.path.join(vault_dir, "vault.meta.json")
        self._data_path = os.path.join(vault_dir, "vault.data")  # 암호화된 시크릿
        self._key_enc_path = os.path.join(vault_dir, "vault.key.enc")  # 패스워드 암호화 마스터키

        # 상태
        self._master_key: Optional[bytes] = None  # 잠금 해제 시에만 존재
        self._secrets: Dict[str, SecretEntry] = {}  # 잠금 해제 시에만 존재
        self._meta: Optional[VaultMeta] = None
        self._audit_log: list = []

        # 메타 로드
        if os.path.exists(self._meta_path):
            self._load_meta()

    # ─── 초기화 ────────────────────────────────────────────

    def init(self, password: str, shamir_n: int = 5, shamir_k: int = 3) -> dict:
        """새 vault 초기화

        Args:
            password: 마스터 패스워드 (Argon2id로 키 유도)
            shamir_n: 총 share 수
            shamir_k: 복원 임계값

        Returns:
            {"vault_id": ..., "master_key_hash": ..., "shares": [...]}
        """
        os.makedirs(self.vault_dir, exist_ok=True)

        if os.path.exists(self._meta_path):
            raise FileExistsError(f"Vault already exists: {self.vault_dir}")

        # 1. 마스터 키 생성
        self._master_key = os.urandom(32)
        key_hash = hashlib.sha256(self._master_key).hexdigest()[:16]

        # 2. 패스워드로 마스터 키 암호화 저장
        blob = self.engine.encrypt(self._master_key, password, context="master-key")
        with open(self._key_enc_path, "wb") as f:
            f.write(blob.to_bytes())

        # 3. Shamir 분할
        shares = self.shamir.split(self._master_key, n=shamir_n, k=shamir_k)

        # 4. 빈 시크릿 저장
        self._secrets = {}
        self._save_data()

        # 5. 메타 생성
        vault_id = hashlib.sha256(
            self._master_key + str(time.time()).encode()
        ).hexdigest()[:12]

        self._meta = VaultMeta(
            vault_id=vault_id,
            shamir_n=shamir_n,
            shamir_k=shamir_k,
            created_at=datetime.now(timezone.utc).isoformat(),
            last_modified=datetime.now(timezone.utc).isoformat(),
        )
        self._save_meta()

        self._audit("init", f"vault created: {vault_id}")

        return {
            "vault_id": vault_id,
            "master_key_hash": key_hash,
            "shares": shares,  # [(index, bytes), ...]
            "shamir": f"{shamir_k}-of-{shamir_n}",
        }

    # ─── 잠금/해제 ─────────────────────────────────────────

    def unlock(self, password: str) -> bool:
        """패스워드로 vault 잠금 해제"""
        if not os.path.exists(self._key_enc_path):
            raise FileNotFoundError("Vault not initialized")

        with open(self._key_enc_path, "rb") as f:
            blob = EncryptedBlob.from_bytes(f.read())

        try:
            self._master_key = self.engine.decrypt(blob, password)
            self._load_data()
            self._audit("unlock", "password")
            return True
        except Exception:
            self._master_key = None
            self._secrets = {}
            return False

    def unlock_shamir(self, shares: List[Tuple[int, bytes]]) -> bool:
        """Shamir share로 vault 잠금 해제 (패스워드 없이)"""
        try:
            self._master_key = self.shamir.recover(shares)
            self._load_data()
            # 마스터 키 검증 — 데이터 복호화 성공 여부로
            self._audit("unlock", f"shamir ({len(shares)} shares)")
            return True
        except Exception:
            self._master_key = None
            self._secrets = {}
            return False

    def lock(self):
        """vault 잠금 — 메모리에서 키/시크릿 제거"""
        self._master_key = None
        self._secrets = {}
        self._audit("lock", "memory cleared")

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    # ─── CRUD ──────────────────────────────────────────────

    def add(self, name: str, value: str, category: str = "default",
            tags: list = None, note: str = "") -> SecretEntry:
        """시크릿 추가"""
        self._require_unlocked()

        if name in self._secrets:
            raise KeyError(f"Secret already exists: {name}. Use update() instead.")

        entry = SecretEntry(
            name=name,
            value=value,
            category=category,
            tags=tags or [],
            note=note,
        )
        self._secrets[name] = entry
        self._save_data()
        self._update_meta()
        self._audit("add", name)
        return entry

    def get(self, name: str) -> Optional[SecretEntry]:
        """시크릿 조회"""
        self._require_unlocked()
        entry = self._secrets.get(name)
        if entry:
            self._audit("read", name)
        return entry

    def update(self, name: str, value: str = None, category: str = None,
               tags: list = None, note: str = None) -> SecretEntry:
        """시크릿 수정"""
        self._require_unlocked()

        if name not in self._secrets:
            raise KeyError(f"Secret not found: {name}")

        entry = self._secrets[name]
        if value is not None:
            entry.value = value
        if category is not None:
            entry.category = category
        if tags is not None:
            entry.tags = tags
        if note is not None:
            entry.note = note
        entry.updated_at = datetime.now(timezone.utc).isoformat()

        self._save_data()
        self._update_meta()
        self._audit("update", name)
        return entry

    def delete(self, name: str) -> bool:
        """시크릿 삭제"""
        self._require_unlocked()

        if name not in self._secrets:
            return False

        del self._secrets[name]
        self._save_data()
        self._update_meta()
        self._audit("delete", name)
        return True

    def list_secrets(self, category: str = None) -> List[dict]:
        """시크릿 목록 (값 제외)"""
        self._require_unlocked()
        result = []
        for name, entry in self._secrets.items():
            if category and entry.category != category:
                continue
            result.append({
                "name": entry.name,
                "category": entry.category,
                "tags": entry.tags,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
                "note": entry.note,
            })
        self._audit("list", f"category={category}" if category else "all")
        return result

    def search(self, query: str) -> List[dict]:
        """이름/태그/노트로 검색 (값 제외)"""
        self._require_unlocked()
        query_lower = query.lower()
        result = []
        for name, entry in self._secrets.items():
            if (query_lower in name.lower() or
                query_lower in entry.note.lower() or
                any(query_lower in t.lower() for t in entry.tags)):
                result.append({
                    "name": entry.name,
                    "category": entry.category,
                    "tags": entry.tags,
                })
        self._audit("search", query)
        return result

    # ─── Shamir 분산/회수 ──────────────────────────────────

    def distribute(self, nodes: List[str], remote_dir: str = "/opt/sv-vault/shares") -> dict:
        """Shamir share를 노드에 분산 저장

        Args:
            nodes: 대상 노드 목록 (len >= shamir_n)
            remote_dir: 원격 저장 디렉토리

        Returns:
            {"distributed": [...], "failed": [...]}
        """
        self._require_unlocked()

        if not self.transport:
            raise RuntimeError("Transport not configured. Cannot distribute.")

        if not self._meta:
            raise RuntimeError("Vault not initialized")

        n = self._meta.shamir_n
        k = self._meta.shamir_k

        if len(nodes) < n:
            raise ValueError(f"Need at least {n} nodes, got {len(nodes)}")

        # 1. Shamir 분할
        shares = self.shamir.split(self._master_key, n=n, k=k)

        # 2. 각 노드에 전송
        distributed = []
        failed = []
        share_map = []

        for i, (idx, share_bytes) in enumerate(shares):
            node = nodes[i]
            remote_path = f"{remote_dir}/share_{self._meta.vault_id}_{idx}.bin"

            # 임시 파일로 저장 후 전송
            tmp_path = os.path.join(self.vault_dir, f".tmp_share_{idx}.bin")
            try:
                with open(tmp_path, "wb") as f:
                    f.write(share_bytes)

                # vssh atomic put
                success = self.transport.atomic_put(
                    tmp_path, node, remote_path, timeout=30
                )

                share_hash = hashlib.sha256(share_bytes).hexdigest()[:16]

                if success:
                    distributed.append({"node": node, "index": idx})
                    share_map.append(asdict(ShareMap(
                        share_index=idx,
                        node=node,
                        remote_path=remote_path,
                        stored_at=datetime.now(timezone.utc).isoformat(),
                        verified=True,
                        hash=share_hash,
                    )))
                else:
                    failed.append({"node": node, "index": idx, "error": "upload failed"})
                    share_map.append(asdict(ShareMap(
                        share_index=idx,
                        node=node,
                        remote_path=remote_path,
                        verified=False,
                        hash=share_hash,
                    )))
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        # 3. share 맵 저장
        self._meta.share_map = share_map
        self._save_meta()

        self._audit("distribute", f"{len(distributed)}/{n} shares to {[s['node'] for s in distributed]}")

        return {
            "distributed": distributed,
            "failed": failed,
            "shamir": f"{k}-of-{n}",
            "vault_id": self._meta.vault_id,
        }

    def collect(self, nodes: List[str] = None, count: int = None) -> List[Tuple[int, bytes]]:
        """노드에서 Shamir share 회수

        Args:
            nodes: 회수 대상 노드 (None이면 share_map에서 자동)
            count: 회수할 share 수 (None이면 k개)

        Returns:
            [(index, share_bytes), ...] — Shamir 복원용
        """
        if not self.transport:
            raise RuntimeError("Transport not configured")

        if not self._meta or not self._meta.share_map:
            raise RuntimeError("No share map. Run distribute() first.")

        k = self._meta.shamir_k
        target_count = count or k

        # share_map에서 타겟 선정
        targets = []
        for sm_dict in self._meta.share_map:
            sm = ShareMap(**sm_dict) if isinstance(sm_dict, dict) else sm_dict
            if nodes and sm.node not in nodes:
                continue
            if sm.verified:
                targets.append(sm)
            if len(targets) >= target_count:
                break

        if len(targets) < k:
            raise RuntimeError(
                f"Not enough reachable shares. Need {k}, found {len(targets)}"
            )

        # 회수
        collected = []
        for sm in targets:
            local_path = os.path.join(self.vault_dir, f".tmp_recv_{sm.share_index}.bin")
            try:
                success = self.transport.get(
                    sm.node, sm.remote_path, local_path, timeout=30
                )
                if success and os.path.exists(local_path):
                    with open(local_path, "rb") as f:
                        share_bytes = f.read()

                    # 해시 검증
                    received_hash = hashlib.sha256(share_bytes).hexdigest()[:16]
                    if sm.hash and received_hash != sm.hash:
                        self._audit("collect_fail", f"hash mismatch on {sm.node}")
                        continue

                    collected.append((sm.share_index, share_bytes))
                    self._audit("collect", f"share[{sm.share_index}] from {sm.node}")
            finally:
                if os.path.exists(local_path):
                    os.remove(local_path)

        return collected

    def redistribute(self, dead_nodes: List[str], new_nodes: List[str]) -> dict:
        """장애 노드의 share를 새 노드에 재분배

        마스터 키가 필요 (unlock 상태).
        기존 share 전부 폐기하고 새로 분할.

        Args:
            dead_nodes: 장애 노드
            new_nodes: 전체 새 노드 목록 (len >= shamir_n)
        """
        self._require_unlocked()

        self._audit("redistribute", f"dead={dead_nodes}, new_targets={new_nodes}")

        # 새로 분산 — 키가 이미 있으니까 distribute() 호출
        return self.distribute(new_nodes)

    def rekey(self, new_password: str) -> dict:
        """마스터 키 교체 (re-key)

        기존 시크릿은 보존. 마스터 키만 새로 생성.
        - 새 패스워드로 마스터 키 암호화
        - 데이터 재암호화
        - 새 Shamir share 생성 (기존 share 무효화)

        Returns:
            {"new_key_hash": ..., "shares": [...]}
        """
        self._require_unlocked()

        # 1. 새 마스터 키
        new_key = os.urandom(32)

        # 2. 새 패스워드로 마스터 키 암호화
        blob = self.engine.encrypt(new_key, new_password, context="master-key")
        with open(self._key_enc_path, "wb") as f:
            f.write(blob.to_bytes())

        # 3. 새 키로 데이터 재암호화
        self._master_key = new_key
        self._save_data()

        # 4. 새 Shamir share
        n = self._meta.shamir_n
        k = self._meta.shamir_k
        shares = self.shamir.split(new_key, n=n, k=k)

        # 5. share 맵 무효화
        self._meta.share_map = []
        self._update_meta()

        self._audit("rekey", f"master key rotated, old shares invalidated")

        return {
            "new_key_hash": hashlib.sha256(new_key).hexdigest()[:16],
            "shares": shares,
            "shamir": f"{k}-of-{n}",
            "warning": "기존 share 무효화됨. distribute() 필요.",
        }

    # ─── 상태/정보 ─────────────────────────────────────────

    def status(self) -> dict:
        """vault 상태"""
        meta = self._meta
        if not meta:
            return {"initialized": False}

        return {
            "initialized": True,
            "vault_id": meta.vault_id,
            "version": meta.version,
            "unlocked": self.is_unlocked,
            "entry_count": meta.entry_count,
            "shamir": f"{meta.shamir_k}-of-{meta.shamir_n}",
            "share_nodes": [
                sm["node"] if isinstance(sm, dict) else sm.node
                for sm in meta.share_map
            ],
            "backup_targets": meta.backup_targets,
            "created_at": meta.created_at,
            "last_modified": meta.last_modified,
        }

    def export_encrypted(self, password: str) -> bytes:
        """전체 vault를 패스워드 암호화 내보내기 (이관/백업용)"""
        self._require_unlocked()

        payload = json.dumps({
            name: asdict(entry) for name, entry in self._secrets.items()
        }, ensure_ascii=False).encode()

        blob = self.engine.encrypt(payload, password, context="vault-export")
        self._audit("export", f"{len(self._secrets)} entries")
        return blob.to_bytes()

    def import_encrypted(self, data: bytes, password: str, merge: bool = False) -> int:
        """암호화된 vault 가져오기"""
        self._require_unlocked()

        blob = EncryptedBlob.from_bytes(data)
        decrypted = self.engine.decrypt(blob, password)
        entries = json.loads(decrypted)

        count = 0
        for name, entry_dict in entries.items():
            if not merge and name in self._secrets:
                continue
            self._secrets[name] = SecretEntry(**entry_dict)
            count += 1

        self._save_data()
        self._update_meta()
        self._audit("import", f"{count} entries (merge={merge})")
        return count

    # ─── 내부 ──────────────────────────────────────────────

    def _require_unlocked(self):
        if not self.is_unlocked:
            raise PermissionError("Vault is locked. Call unlock() or unlock_shamir() first.")

    def _save_data(self):
        """시크릿을 마스터 키로 암호화 저장"""
        payload = json.dumps({
            name: asdict(entry) for name, entry in self._secrets.items()
        }, ensure_ascii=False).encode()

        blob = self.engine.encrypt_with_key(payload, self._master_key)
        with open(self._data_path, "wb") as f:
            f.write(blob.to_bytes())

    def _load_data(self):
        """암호화된 시크릿 로드"""
        if not os.path.exists(self._data_path):
            self._secrets = {}
            return

        with open(self._data_path, "rb") as f:
            blob = EncryptedBlob.from_bytes(f.read())

        decrypted = self.engine.decrypt_with_key(blob, self._master_key)
        entries = json.loads(decrypted)
        self._secrets = {
            name: SecretEntry(**entry_dict)
            for name, entry_dict in entries.items()
        }

    def _save_meta(self):
        with open(self._meta_path, "w") as f:
            json.dump(asdict(self._meta), f, indent=2, ensure_ascii=False)

    def _load_meta(self):
        with open(self._meta_path) as f:
            data = json.load(f)
        self._meta = VaultMeta(**data)

    def _update_meta(self):
        if self._meta:
            self._meta.entry_count = len(self._secrets)
            self._meta.last_modified = datetime.now(timezone.utc).isoformat()
            self._save_meta()

    def _audit(self, action: str, detail: str = ""):
        """감사 이벤트 기록"""
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
            "vault_id": self._meta.vault_id if self._meta else "none",
        }
        self._audit_log.append(event)

        # append-only JSONL 파일
        audit_path = os.path.join(self.vault_dir, "audit.jsonl")
        try:
            with open(audit_path, "a") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass  # 감사 로그 실패가 vault 동작을 막으면 안 됨

    def get_audit_log(self, last_n: int = 50) -> list:
        """감사 로그 조회"""
        audit_path = os.path.join(self.vault_dir, "audit.jsonl")
        if not os.path.exists(audit_path):
            return []

        lines = []
        with open(audit_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        return lines[-last_n:]
