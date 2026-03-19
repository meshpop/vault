"""
SecureVault Backup Module (sv-backup)

secrets.enc → Vault double-encrypt → vssh atomic upload → fixed targets (s1, s2)
No AI judgment. Score-independent. Backup only to targets specified by humans in config file.
"""

import os
import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, asdict

from engine import VaultEngine, EncryptedBlob
from transport import VsshTransport
from config import ConfigManager


@dataclass
class BackupRecord:
    """Backup record"""
    timestamp: str
    source_file: str
    source_hash: str
    vault_file: str
    vault_hash: str
    targets: list
    results: dict        # {node: success}
    duration_sec: float
    verified: bool = False


class SecureBackup:
    """SecureVault backup manager

    Principles:
    - Backup targets fixed by humans in vault.yml (default: s1, s2)
    - No AI score-based auto-selection
    - Double encryption: secrets.enc → AES-256-GCM + Argon2id → .vault
    - Transfer: vssh atomic upload (tmp → rename)
    - Verification: MD5/SHA256 check
    """

    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        engine: Optional[VaultEngine] = None,
        transport: Optional[VsshTransport] = None,
    ):
        self.config = config or ConfigManager()
        self.engine = engine or VaultEngine(
            argon2_time_cost=self.config.config.encryption.argon2_time_cost,
            argon2_memory_cost=self.config.config.encryption.argon2_memory_cost,
            argon2_parallelism=self.config.config.encryption.argon2_parallelism,
        )
        self.transport = transport  # None = local test mode

        self.audit_log_path = os.path.join(self.config.config_dir, "backup_audit.log")

    # ─── Backup ────────────────────────────────────────────────

    def backup(
        self,
        source_file: str,
        password: str | bytes,
        targets: Optional[list] = None,
    ) -> BackupRecord:
        """Main backup flow

        1. Read source file + hash
        2. AES-256-GCM + Argon2id double-encrypt
        3. Create .vault file
        4. vssh atomic upload to each target
        5. Verify
        6. Write audit log

        Args:
            source_file: file to back up (e.g. secrets.enc)
            password: encryption password
            targets: backup targets (None = load from config)

        Returns:
            BackupRecord
        """
        start_time = time.time()
        targets = targets or self.config.get_backup_targets()

        # 1. read source file
        if not os.path.isfile(source_file):
            raise FileNotFoundError(f"Source file not found: {source_file}")

        with open(source_file, "rb") as f:
            source_data = f.read()

        source_hash = hashlib.sha256(source_data).hexdigest()

        # 2. double-encrypt
        blob = self.engine.encrypt(
            data=source_data,
            password=password,
            context=f"backup:{source_hash[:16]}",  # include original hash in context
        )

        # 3. save .vault file
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        vault_filename = f"secrets_{ts}.vault"
        vault_path = os.path.join(self.config.backup_dir, vault_filename)

        os.makedirs(self.config.backup_dir, exist_ok=True)
        vault_bytes = blob.to_bytes()
        with open(vault_path, "wb") as f:
            f.write(vault_bytes)

        vault_hash = hashlib.sha256(vault_bytes).hexdigest()

        # 4. upload to each target
        results = {}
        if self.transport:
            remote_dir = self.config.config.backup.remote_dir
            for target in targets:
                remote_path = f"{remote_dir}/{vault_filename}"
                # create directory
                self.transport.exec(target, f"mkdir -p {remote_dir}", timeout=10)
                # atomic upload
                success = self.transport.atomic_put(
                    vault_path, target, remote_path,
                    timeout=self.config.config.transport.upload_timeout,
                )
                results[target] = success

                # update latest symlink
                if success:
                    latest_path = f"{remote_dir}/secrets_latest.vault"
                    self.transport.exec(
                        target,
                        f"ln -sf {remote_path} {latest_path}",
                        timeout=5,
                    )
        else:
            # local test mode
            for target in targets:
                local_target = os.path.join(self.config.backup_dir, f"test_{target}")
                os.makedirs(local_target, exist_ok=True)
                target_path = os.path.join(local_target, vault_filename)
                with open(target_path, "wb") as f:
                    f.write(vault_bytes)
                results[target] = True

        duration = time.time() - start_time

        # 5. record
        record = BackupRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_file=os.path.basename(source_file),
            source_hash=source_hash[:16],
            vault_file=vault_filename,
            vault_hash=vault_hash[:16],
            targets=targets,
            results=results,
            duration_sec=round(duration, 2),
        )

        self._write_audit(record)

        # 6. clean up old backups
        self._cleanup_old_backups()

        return record

    # ─── Restore ────────────────────────────────────────────────

    def restore(
        self,
        vault_file: str,
        password: str | bytes,
        output_path: str,
        source_hash: Optional[str] = None,
    ) -> bool:
        """Restore from backup

        Args:
            vault_file: .vault file path
            password: decryption password
            output_path: path to save restored file
            source_hash: original hash (for verification, omit to try without AAD)

        Returns:
            success bool
        """
        with open(vault_file, "rb") as f:
            blob = EncryptedBlob.from_bytes(f.read())

        try:
            plaintext = self.engine.decrypt(blob, password)
        except Exception as e:
            # AAD mismatch or wrong password
            raise ValueError(f"Decryption failed: {e}")

        # back up existing file before restore
        if os.path.exists(output_path):
            backup_path = f"{output_path}.pre_restore.{int(time.time())}"
            os.rename(output_path, backup_path)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        return True

    # ─── Remote restore ───────────────────────────────────────────

    def restore_from_remote(
        self,
        node: str,
        password: str | bytes,
        output_path: str,
        vault_filename: Optional[str] = None,
    ) -> bool:
        """Download backup from remote node and restore

        Args:
            node: source node (e.g. "s1")
            password: decryption password
            output_path: restored file path
            vault_filename: specific backup filename (omit for latest)
        """
        if not self.transport:
            raise RuntimeError("transport not configured")

        remote_dir = self.config.config.backup.remote_dir
        if vault_filename:
            remote_path = f"{remote_dir}/{vault_filename}"
        else:
            remote_path = f"{remote_dir}/secrets_latest.vault"

        # download
        local_tmp = os.path.join(self.config.backup_dir, ".tmp_restore.vault")
        if not self.transport.get(node, remote_path, local_tmp, timeout=120):
            raise RuntimeError(f"Download from {node} failed: {remote_path}")

        try:
            return self.restore(local_tmp, password, output_path)
        finally:
            if os.path.exists(local_tmp):
                os.remove(local_tmp)

    # ─── Verify ────────────────────────────────────────────────

    def verify(self, password: str | bytes) -> dict:
        """Verify integrity of all backups

        Downloads and attempts to decrypt the latest backup on each target.
        """
        results = {}
        targets = self.config.get_backup_targets()

        for target in targets:
            try:
                if self.transport:
                    remote_path = f"{self.config.config.backup.remote_dir}/secrets_latest.vault"
                    local_tmp = os.path.join(
                        self.config.backup_dir, f".verify_{target}.vault"
                    )

                    if not self.transport.get(target, remote_path, local_tmp, timeout=60):
                        results[target] = {"ok": False, "error": "download failed"}
                        continue

                    with open(local_tmp, "rb") as f:
                        blob = EncryptedBlob.from_bytes(f.read())

                    # attempt decryption (without AAD — for verification)
                    self.engine.decrypt(blob, password)
                    results[target] = {
                        "ok": True,
                        "context": blob.context,
                        "created_at": blob.created_at,
                    }

                    os.remove(local_tmp)
                else:
                    # local test mode
                    local_target = os.path.join(
                        self.config.backup_dir, f"test_{target}"
                    )
                    vault_files = sorted(
                        [f for f in os.listdir(local_target) if f.endswith(".vault")],
                        reverse=True,
                    )
                    if not vault_files:
                        results[target] = {"ok": False, "error": "no backup found"}
                        continue

                    vault_path = os.path.join(local_target, vault_files[0])
                    with open(vault_path, "rb") as f:
                        blob = EncryptedBlob.from_bytes(f.read())

                    self.engine.decrypt(blob, password)
                    results[target] = {
                        "ok": True,
                        "file": vault_files[0],
                        "context": blob.context,
                        "created_at": blob.created_at,
                    }

            except Exception as e:
                results[target] = {"ok": False, "error": str(e)}

        return results

    # ─── Status ────────────────────────────────────────────────

    def status(self) -> dict:
        """Backup status summary"""
        targets = self.config.get_backup_targets()

        # local backup file list
        local_vaults = []
        if os.path.isdir(self.config.backup_dir):
            local_vaults = sorted(
                [f for f in os.listdir(self.config.backup_dir) if f.endswith(".vault")],
                reverse=True,
            )

        # last audit log entry
        last_backup = None
        if os.path.isfile(self.audit_log_path):
            with open(self.audit_log_path) as f:
                lines = f.readlines()
                if lines:
                    try:
                        last_backup = json.loads(lines[-1])
                    except json.JSONDecodeError:
                        pass

        return {
            "targets": targets,
            "local_vault_count": len(local_vaults),
            "latest_local": local_vaults[0] if local_vaults else None,
            "last_backup": last_backup,
            "config_dir": self.config.config_dir,
        }

    # ─── Internal ────────────────────────────────────────────────

    def _write_audit(self, record: BackupRecord):
        """Append to audit log (append-only)"""
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        with open(self.audit_log_path, "a") as f:
            f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

    def _cleanup_old_backups(self):
        """Clean up old local backups"""
        max_keep = self.config.config.backup.max_versions
        if not os.path.isdir(self.config.backup_dir):
            return

        vaults = sorted(
            [
                f for f in os.listdir(self.config.backup_dir)
                if f.endswith(".vault") and not f.startswith(".")
            ],
            reverse=True,
        )

        for old_vault in vaults[max_keep:]:
            os.remove(os.path.join(self.config.backup_dir, old_vault))
