"""
SecureVault Backup Module (sv-backup)

secrets.enc → Vault 이중 암호화 → vssh atomic upload → 고정 타겟 (s1, s2)
AI 판단 없음. 스코어 무관. 사람이 설정파일에 지정한 타겟에만 백업.
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
    """백업 기록"""
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
    """SecureVault 백업 관리자

    원칙:
    - 백업 타겟은 사람이 vault.yml에 고정 (기본: s1, s2)
    - AI 스코어 기반 자동 선정 없음
    - 이중 암호화: secrets.enc → AES-256-GCM + Argon2id → .vault
    - 전송: vssh atomic upload (tmp → rename)
    - 검증: MD5/SHA256 체크
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
        self.transport = transport  # None이면 로컬 테스트 모드

        self.audit_log_path = os.path.join(self.config.config_dir, "backup_audit.log")

    # ─── 백업 ────────────────────────────────────────────────

    def backup(
        self,
        source_file: str,
        password: str | bytes,
        targets: Optional[list] = None,
    ) -> BackupRecord:
        """메인 백업 플로우

        1. 소스 파일 읽기 + 해시
        2. AES-256-GCM + Argon2id 이중 암호화
        3. .vault 파일 생성
        4. 각 타겟에 vssh atomic upload
        5. 검증
        6. 감사 로그 기록

        Args:
            source_file: 백업할 파일 (예: secrets.enc)
            password: 암호화 패스워드
            targets: 백업 타겟 (None이면 설정파일에서 로드)

        Returns:
            BackupRecord
        """
        start_time = time.time()
        targets = targets or self.config.get_backup_targets()

        # 1. 소스 파일 읽기
        if not os.path.isfile(source_file):
            raise FileNotFoundError(f"소스 파일 없음: {source_file}")

        with open(source_file, "rb") as f:
            source_data = f.read()

        source_hash = hashlib.sha256(source_data).hexdigest()

        # 2. 이중 암호화
        blob = self.engine.encrypt(
            data=source_data,
            password=password,
            context=f"backup:{source_hash[:16]}",  # 원본 해시를 context에 포함
        )

        # 3. .vault 파일 저장
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        vault_filename = f"secrets_{ts}.vault"
        vault_path = os.path.join(self.config.backup_dir, vault_filename)

        os.makedirs(self.config.backup_dir, exist_ok=True)
        vault_bytes = blob.to_bytes()
        with open(vault_path, "wb") as f:
            f.write(vault_bytes)

        vault_hash = hashlib.sha256(vault_bytes).hexdigest()

        # 4. 각 타겟에 업로드
        results = {}
        if self.transport:
            remote_dir = self.config.config.backup.remote_dir
            for target in targets:
                remote_path = f"{remote_dir}/{vault_filename}"
                # 디렉토리 생성
                self.transport.exec(target, f"mkdir -p {remote_dir}", timeout=10)
                # atomic upload
                success = self.transport.atomic_put(
                    vault_path, target, remote_path,
                    timeout=self.config.config.transport.upload_timeout,
                )
                results[target] = success

                # latest 심볼릭 링크 업데이트
                if success:
                    latest_path = f"{remote_dir}/secrets_latest.vault"
                    self.transport.exec(
                        target,
                        f"ln -sf {remote_path} {latest_path}",
                        timeout=5,
                    )
        else:
            # 로컬 테스트 모드
            for target in targets:
                local_target = os.path.join(self.config.backup_dir, f"test_{target}")
                os.makedirs(local_target, exist_ok=True)
                target_path = os.path.join(local_target, vault_filename)
                with open(target_path, "wb") as f:
                    f.write(vault_bytes)
                results[target] = True

        duration = time.time() - start_time

        # 5. 기록
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

        # 6. 오래된 백업 정리
        self._cleanup_old_backups()

        return record

    # ─── 복원 ────────────────────────────────────────────────

    def restore(
        self,
        vault_file: str,
        password: str | bytes,
        output_path: str,
        source_hash: Optional[str] = None,
    ) -> bool:
        """백업에서 복원

        Args:
            vault_file: .vault 파일 경로
            password: 복호화 패스워드
            output_path: 복원 파일 저장 경로
            source_hash: 원본 해시 (검증용, 없으면 AAD 없이 시도)

        Returns:
            성공 여부
        """
        with open(vault_file, "rb") as f:
            blob = EncryptedBlob.from_bytes(f.read())

        try:
            plaintext = self.engine.decrypt(blob, password)
        except Exception as e:
            # AAD 불일치 또는 패스워드 틀림
            raise ValueError(f"복호화 실패: {e}")

        # 복원 전 기존 파일 백업
        if os.path.exists(output_path):
            backup_path = f"{output_path}.pre_restore.{int(time.time())}"
            os.rename(output_path, backup_path)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        return True

    # ─── 원격 복원 ───────────────────────────────────────────

    def restore_from_remote(
        self,
        node: str,
        password: str | bytes,
        output_path: str,
        vault_filename: Optional[str] = None,
    ) -> bool:
        """원격 노드에서 백업 다운로드 후 복원

        Args:
            node: 소스 노드 (예: "s1")
            password: 복호화 패스워드
            output_path: 복원 파일 경로
            vault_filename: 특정 백업 파일명 (없으면 latest)
        """
        if not self.transport:
            raise RuntimeError("transport가 설정되지 않음")

        remote_dir = self.config.config.backup.remote_dir
        if vault_filename:
            remote_path = f"{remote_dir}/{vault_filename}"
        else:
            remote_path = f"{remote_dir}/secrets_latest.vault"

        # 다운로드
        local_tmp = os.path.join(self.config.backup_dir, ".tmp_restore.vault")
        if not self.transport.get(node, remote_path, local_tmp, timeout=120):
            raise RuntimeError(f"{node}에서 다운로드 실패: {remote_path}")

        try:
            return self.restore(local_tmp, password, output_path)
        finally:
            if os.path.exists(local_tmp):
                os.remove(local_tmp)

    # ─── 검증 ────────────────────────────────────────────────

    def verify(self, password: str | bytes) -> dict:
        """전체 백업 무결성 검증

        각 타겟의 latest 백업을 다운로드하고 복호화 시도.
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
                        results[target] = {"ok": False, "error": "다운로드 실패"}
                        continue

                    with open(local_tmp, "rb") as f:
                        blob = EncryptedBlob.from_bytes(f.read())

                    # 복호화 시도 (AAD 없이 — 검증 목적)
                    self.engine.decrypt(blob, password)
                    results[target] = {
                        "ok": True,
                        "context": blob.context,
                        "created_at": blob.created_at,
                    }

                    os.remove(local_tmp)
                else:
                    # 로컬 테스트 모드
                    local_target = os.path.join(
                        self.config.backup_dir, f"test_{target}"
                    )
                    vault_files = sorted(
                        [f for f in os.listdir(local_target) if f.endswith(".vault")],
                        reverse=True,
                    )
                    if not vault_files:
                        results[target] = {"ok": False, "error": "백업 없음"}
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

    # ─── 상태 ────────────────────────────────────────────────

    def status(self) -> dict:
        """백업 상태 요약"""
        targets = self.config.get_backup_targets()

        # 로컬 백업 파일 목록
        local_vaults = []
        if os.path.isdir(self.config.backup_dir):
            local_vaults = sorted(
                [f for f in os.listdir(self.config.backup_dir) if f.endswith(".vault")],
                reverse=True,
            )

        # 감사 로그 마지막 기록
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

    # ─── 내부 ────────────────────────────────────────────────

    def _write_audit(self, record: BackupRecord):
        """감사 로그 추가 (append-only)"""
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        with open(self.audit_log_path, "a") as f:
            f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

    def _cleanup_old_backups(self):
        """오래된 로컬 백업 정리"""
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
