"""
SecureVault — Distributed password manager (product core)

Password/secret CRUD + Shamir share distribution/collection.
All data encrypted with AES-256-GCM + Argon2id.
Master key distributed across N nodes via Shamir's Secret Sharing.

Principles:
- Rule-based only. AI does not make security decisions.
- Password locations are decided by humans.
- vssh transport, transport-agnostic.
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


# ─── Data models ──────────────────────────────────────────

@dataclass
class SecretEntry:
    """Individual secret entry"""
    name: str                   # identifier (e.g. "db_master", "api_key")
    value: str                  # actual secret value
    category: str = "default"   # category (password, api_key, token, cert, etc.)
    tags: list = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    created_by: str = "human"   # always human. AI does not create secrets
    note: str = ""

    def __post_init__(self):
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


@dataclass
class ShareMap:
    """Shamir share location map"""
    share_index: int
    node: str
    remote_path: str
    stored_at: str = ""
    verified: bool = False
    hash: str = ""  # share hash (content not stored)


@dataclass
class VaultMeta:
    """Vault metadata — unencrypted portion"""
    vault_id: str
    version: int = 2
    shamir_n: int = 5
    shamir_k: int = 3
    share_map: list = field(default_factory=list)  # List[ShareMap as dict]
    created_at: str = ""
    last_modified: str = ""
    entry_count: int = 0
    backup_targets: list = field(default_factory=lambda: ["s1", "s2"])


# ─── Vault core ──────────────────────────────────────────

class SecureVaultManager:
    """Distributed password manager

    Usage flow:
    1. init() — initialize vault, generate master key
    2. add(name, value) — add secret
    3. get(name) — retrieve secret
    4. distribute() — distribute Shamir shares to nodes
    5. collect() — collect shares from nodes → recover master key
    6. lock() — remove key from memory
    7. unlock(password) — unlock with password

    Master key is protected in two ways:
    a) Password-based: AES-256-GCM + Argon2id
    b) Shamir distributed: shares stored on N nodes, K shares needed to recover
    """

    def __init__(self, vault_dir: str, transport=None):
        """
        Args:
            vault_dir: vault data directory
            transport: VsshTransport instance (None = local only)
        """
        self.vault_dir = vault_dir
        self.transport = transport
        self.engine = VaultEngine()
        self.shamir = ShamirSecret()

        # file paths
        self._meta_path = os.path.join(vault_dir, "vault.meta.json")
        self._data_path = os.path.join(vault_dir, "vault.data")  # encrypted secrets
        self._key_enc_path = os.path.join(vault_dir, "vault.key.enc")  # password-encrypted master key

        # state
        self._master_key: Optional[bytes] = None  # exists only when unlocked
        self._secrets: Dict[str, SecretEntry] = {}  # exists only when unlocked
        self._meta: Optional[VaultMeta] = None
        self._audit_log: list = []

        # load meta
        if os.path.exists(self._meta_path):
            self._load_meta()

    # ─── Initialization ────────────────────────────────────────────

    def init(self, password: str, shamir_n: int = 5, shamir_k: int = 3) -> dict:
        """Initialize new vault

        Args:
            password: master password (key derived via Argon2id)
            shamir_n: total share count
            shamir_k: recovery threshold

        Returns:
            {"vault_id": ..., "master_key_hash": ..., "shares": [...]}
        """
        os.makedirs(self.vault_dir, exist_ok=True)

        if os.path.exists(self._meta_path):
            raise FileExistsError(f"Vault already exists: {self.vault_dir}")

        # 1. generate master key
        self._master_key = os.urandom(32)
        key_hash = hashlib.sha256(self._master_key).hexdigest()[:16]

        # 2. encrypt and save master key with password
        blob = self.engine.encrypt(self._master_key, password, context="master-key")
        with open(self._key_enc_path, "wb") as f:
            f.write(blob.to_bytes())

        # 3. Shamir split
        shares = self.shamir.split(self._master_key, n=shamir_n, k=shamir_k)

        # 4. save empty secrets
        self._secrets = {}
        self._save_data()

        # 5. generate meta
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

    # ─── Lock/unlock ─────────────────────────────────────────

    def unlock(self, password: str) -> bool:
        """Unlock vault with password"""
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
        """Unlock vault with Shamir shares (without password)"""
        try:
            self._master_key = self.shamir.recover(shares)
            self._load_data()
            # validate master key — by success of data decryption
            self._audit("unlock", f"shamir ({len(shares)} shares)")
            return True
        except Exception:
            self._master_key = None
            self._secrets = {}
            return False

    def lock(self):
        """Lock vault — remove key/secrets from memory"""
        self._master_key = None
        self._secrets = {}
        self._audit("lock", "memory cleared")

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    # ─── CRUD ──────────────────────────────────────────────

    def add(self, name: str, value: str, category: str = "default",
            tags: list = None, note: str = "") -> SecretEntry:
        """Add secret"""
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
        """Get secret"""
        self._require_unlocked()
        entry = self._secrets.get(name)
        if entry:
            self._audit("read", name)
        return entry

    def update(self, name: str, value: str = None, category: str = None,
               tags: list = None, note: str = None) -> SecretEntry:
        """Update secret"""
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
        """Delete secret"""
        self._require_unlocked()

        if name not in self._secrets:
            return False

        del self._secrets[name]
        self._save_data()
        self._update_meta()
        self._audit("delete", name)
        return True

    def list_secrets(self, category: str = None) -> List[dict]:
        """List secrets (values excluded)"""
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
        """Search by name/tag/note (values excluded)"""
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

    # ─── Shamir distribute/collect ──────────────────────────────────

    def distribute(self, nodes: List[str], remote_dir: str = "/opt/sv-vault/shares") -> dict:
        """Distribute Shamir shares to nodes

        Args:
            nodes: target node list (len >= shamir_n)
            remote_dir: remote storage directory

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

        # 1. Shamir split
        shares = self.shamir.split(self._master_key, n=n, k=k)

        # 2. send to each node
        distributed = []
        failed = []
        share_map = []

        for i, (idx, share_bytes) in enumerate(shares):
            node = nodes[i]
            remote_path = f"{remote_dir}/share_{self._meta.vault_id}_{idx}.bin"

            # save to temp file then transfer
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

        # 3. save share map
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
        """Collect Shamir shares from nodes

        Args:
            nodes: collection target nodes (None = auto from share_map)
            count: number of shares to collect (None = k)

        Returns:
            [(index, share_bytes), ...] — for Shamir recovery
        """
        if not self.transport:
            raise RuntimeError("Transport not configured")

        if not self._meta or not self._meta.share_map:
            raise RuntimeError("No share map. Run distribute() first.")

        k = self._meta.shamir_k
        target_count = count or k

        # select targets from share_map
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

        # collect
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

                    # verify hash
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
        """Redistribute shares from dead nodes to new nodes

        Requires master key (must be unlocked).
        Discards all existing shares and re-splits.

        Args:
            dead_nodes: failed nodes
            new_nodes: complete new node list (len >= shamir_n)
        """
        self._require_unlocked()

        self._audit("redistribute", f"dead={dead_nodes}, new_targets={new_nodes}")

        # re-distribute — key is already present, just call distribute()
        return self.distribute(new_nodes)

    def rekey(self, new_password: str) -> dict:
        """Replace master key (re-key)

        Existing secrets are preserved. Only master key is regenerated.
        - Encrypt master key with new password
        - Re-encrypt data
        - Generate new Shamir shares (existing shares invalidated)

        Returns:
            {"new_key_hash": ..., "shares": [...]}
        """
        self._require_unlocked()

        # 1. new master key
        new_key = os.urandom(32)

        # 2. encrypt master key with new password
        blob = self.engine.encrypt(new_key, new_password, context="master-key")
        with open(self._key_enc_path, "wb") as f:
            f.write(blob.to_bytes())

        # 3. re-encrypt data with new key
        self._master_key = new_key
        self._save_data()

        # 4. new Shamir shares
        n = self._meta.shamir_n
        k = self._meta.shamir_k
        shares = self.shamir.split(new_key, n=n, k=k)

        # 5. invalidate share map
        self._meta.share_map = []
        self._update_meta()

        self._audit("rekey", f"master key rotated, old shares invalidated")

        return {
            "new_key_hash": hashlib.sha256(new_key).hexdigest()[:16],
            "shares": shares,
            "shamir": f"{k}-of-{n}",
            "warning": "Existing shares invalidated. Run distribute().",
        }

    # ─── Status/info ─────────────────────────────────────────

    def status(self) -> dict:
        """Vault status"""
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
        """Export entire vault encrypted with password (for migration/backup)"""
        self._require_unlocked()

        payload = json.dumps({
            name: asdict(entry) for name, entry in self._secrets.items()
        }, ensure_ascii=False).encode()

        blob = self.engine.encrypt(payload, password, context="vault-export")
        self._audit("export", f"{len(self._secrets)} entries")
        return blob.to_bytes()

    def import_encrypted(self, data: bytes, password: str, merge: bool = False) -> int:
        """Import encrypted vault"""
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

    # ─── Internal ──────────────────────────────────────────────

    def _require_unlocked(self):
        if not self.is_unlocked:
            raise PermissionError("Vault is locked. Call unlock() or unlock_shamir() first.")

    def _save_data(self):
        """Encrypt and save secrets with master key"""
        payload = json.dumps({
            name: asdict(entry) for name, entry in self._secrets.items()
        }, ensure_ascii=False).encode()

        blob = self.engine.encrypt_with_key(payload, self._master_key)
        with open(self._data_path, "wb") as f:
            f.write(blob.to_bytes())

    def _load_data(self):
        """Load encrypted secrets"""
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
        """Record audit event"""
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
            "vault_id": self._meta.vault_id if self._meta else "none",
        }
        self._audit_log.append(event)

        # append-only JSONL file
        audit_path = os.path.join(self.vault_dir, "audit.jsonl")
        try:
            with open(audit_path, "a") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass  # audit log failure must not block vault operation

    def get_audit_log(self, last_n: int = 50) -> list:
        """Retrieve audit log"""
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
