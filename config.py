"""
SecureVault Configuration Manager

YAML 기반 설정 관리.
모든 보안 결정은 사람이 설정파일에 지정 — 자동 변경 없음.
"""

import os
import yaml
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


# ─── 기본 경로 ───────────────────────────────────────────────

DEFAULT_CONFIG_DIR = os.path.expanduser("~/.sv-vault")
DEFAULT_CONFIG_FILE = "vault.yml"
DEFAULT_METADATA_FILE = "keys.json"
DEFAULT_VAULT_DIR = "vaults"
DEFAULT_BACKUP_DIR = "backups"


@dataclass
class BackupConfig:
    """백업 설정 — 사람이 지정"""
    targets: list = field(default_factory=lambda: ["s1", "s2"])
    remote_dir: str = "~/backup/v1/sv-vault"
    schedule: str = "0 3 * * *"  # 매일 03:00
    verify_schedule: str = "30 3 * * 0"  # 매주 일요일 03:30
    max_versions: int = 30
    atomic_upload: bool = True


@dataclass
class EncryptionConfig:
    """암호화 설정"""
    cipher: str = "AES-256-GCM"
    kdf: str = "Argon2id"
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536  # 64 MB
    argon2_parallelism: int = 4
    # 구식 방식 명시적 비활성화
    deprecated_warning: str = "CBC/PBKDF2 사용하지 않음"


@dataclass
class ShamirConfig:
    """Shamir Secret Sharing 설정 — 사람이 지정"""
    master_key_shares: int = 5   # 마스터 키 분할 수
    master_key_threshold: int = 3  # 복구 임계값
    vault_key_shares: int = 3
    vault_key_threshold: int = 2
    # 조각 위치는 사람이 직접 입력
    master_locations: list = field(default_factory=lambda: [
        "맥북 Secure Enclave",
        "s1 NAS 암호화 영역",
        "s2 NAS 암호화 영역",
        "오프라인 USB (금고)",
        "종이 출력 (금고)",
    ])
    vault_locations: list = field(default_factory=lambda: [
        "맥북 Keychain",
        "s1 NAS",
        "s2 NAS",
    ])


@dataclass
class MonitorConfig:
    """모니터링 설정 (sv-monitor) — 관찰만, 결정 안 함"""
    enabled: bool = True
    healthcheck_interval: int = 300  # 5분
    alert_channels: list = field(default_factory=lambda: ["telegram"])
    log_retention_days: int = 90
    # AI는 리포트만
    ai_role: str = "monitor_only"
    ai_decision_authority: bool = False  # 절대 True로 바꾸지 말 것


@dataclass
class TransportConfig:
    """전송 설정"""
    protocol: str = "vssh"
    vssh_binary: str = "/usr/local/bin/vssh"
    default_timeout: int = 30
    upload_timeout: int = 120
    # SSH fallback 없음
    ssh_fallback: bool = False
    # transport-agnostic
    network_dependency: str = "none"  # Wire/Tailscale/LAN 무관


@dataclass
class VaultConfig:
    """SecureVault 전체 설정"""
    version: str = "2.0"
    name: str = "SecureVault"

    # 핵심 원칙 (변경 불가)
    principles: dict = field(default_factory=lambda: {
        "rule_based_only": True,
        "human_decides": True,
        "ai_monitors_only": True,
        "no_ssh_fallback": True,
        "transport_agnostic": True,
    })

    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    shamir: ShamirConfig = field(default_factory=ShamirConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    transport: TransportConfig = field(default_factory=TransportConfig)

    # 설정 파일 경로
    config_dir: str = DEFAULT_CONFIG_DIR
    config_file: str = DEFAULT_CONFIG_FILE


class ConfigManager:
    """설정 파일 관리자"""

    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = config_dir or DEFAULT_CONFIG_DIR
        self.config_path = os.path.join(self.config_dir, DEFAULT_CONFIG_FILE)
        self.config: VaultConfig = VaultConfig(config_dir=self.config_dir)

    def init(self) -> str:
        """초기 설정 생성

        Returns:
            생성된 설정 파일 경로
        """
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(os.path.join(self.config_dir, DEFAULT_VAULT_DIR), exist_ok=True)
        os.makedirs(os.path.join(self.config_dir, DEFAULT_BACKUP_DIR), exist_ok=True)

        if not os.path.exists(self.config_path):
            self.save()

        return self.config_path

    def load(self) -> VaultConfig:
        """설정 파일 로드"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(
                f"설정 파일 없음: {self.config_path}\n"
                "먼저 'sv init' 실행하세요."
            )

        with open(self.config_path) as f:
            data = yaml.safe_load(f)

        if data:
            self._apply_dict(data)

        # 원칙 검증
        self._validate_principles()

        return self.config

    def save(self):
        """설정 파일 저장"""
        data = self._to_dict()

        with open(self.config_path, "w") as f:
            yaml.dump(
                data,
                f,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
            )

    def _to_dict(self) -> dict:
        """설정을 딕셔너리로 변환"""
        return {
            "version": self.config.version,
            "name": self.config.name,
            "principles": self.config.principles,
            "encryption": asdict(self.config.encryption),
            "shamir": asdict(self.config.shamir),
            "backup": asdict(self.config.backup),
            "monitor": asdict(self.config.monitor),
            "transport": asdict(self.config.transport),
        }

    def _apply_dict(self, data: dict):
        """딕셔너리에서 설정 적용"""
        if "encryption" in data:
            self.config.encryption = EncryptionConfig(**data["encryption"])
        if "shamir" in data:
            self.config.shamir = ShamirConfig(**data["shamir"])
        if "backup" in data:
            self.config.backup = BackupConfig(**data["backup"])
        if "monitor" in data:
            self.config.monitor = MonitorConfig(**data["monitor"])
        if "transport" in data:
            self.config.transport = TransportConfig(**data["transport"])

    def _validate_principles(self):
        """핵심 원칙 위반 검사"""
        p = self.config.principles

        violations = []

        if not p.get("rule_based_only", True):
            violations.append("rule_based_only가 False — 룰기반만 허용")

        if not p.get("human_decides", True):
            violations.append("human_decides가 False — 사람이 결정해야 함")

        if p.get("ai_monitors_only") is False:
            violations.append("ai_monitors_only가 False — AI는 모니터링만")

        if p.get("no_ssh_fallback") is False:
            violations.append("no_ssh_fallback가 False — SSH fallback 허용 안 됨")

        if self.config.transport.ssh_fallback:
            violations.append("transport.ssh_fallback이 True — SSH fallback 허용 안 됨")

        if self.config.monitor.ai_decision_authority:
            violations.append("monitor.ai_decision_authority가 True — AI에게 결정권 없음")

        if violations:
            raise ValueError(
                "⚠️ SecureVault 원칙 위반!\n" +
                "\n".join(f"  - {v}" for v in violations) +
                "\n\n설정 파일을 수정하세요: " + self.config_path
            )

    # ─── 편의 메서드 ─────────────────────────────────────────

    @property
    def vault_dir(self) -> str:
        return os.path.join(self.config_dir, DEFAULT_VAULT_DIR)

    @property
    def backup_dir(self) -> str:
        return os.path.join(self.config_dir, DEFAULT_BACKUP_DIR)

    @property
    def metadata_path(self) -> str:
        return os.path.join(self.config_dir, DEFAULT_METADATA_FILE)

    def get_backup_targets(self) -> list:
        """백업 타겟 목록 (사람이 설정파일에 지정한 것)"""
        return self.config.backup.targets

    def show(self) -> str:
        """현재 설정 요약"""
        c = self.config
        lines = [
            f"SecureVault v{c.version}",
            f"",
            f"암호화: {c.encryption.cipher} + {c.encryption.kdf}",
            f"  Argon2: time={c.encryption.argon2_time_cost}, "
            f"mem={c.encryption.argon2_memory_cost // 1024}MB, "
            f"parallel={c.encryption.argon2_parallelism}",
            f"",
            f"Shamir (마스터): {c.shamir.master_key_threshold}-of-{c.shamir.master_key_shares}",
            f"  위치: {', '.join(c.shamir.master_locations)}",
            f"Shamir (볼트): {c.shamir.vault_key_threshold}-of-{c.shamir.vault_key_shares}",
            f"  위치: {', '.join(c.shamir.vault_locations)}",
            f"",
            f"백업 타겟: {', '.join(c.backup.targets)} (사람이 지정)",
            f"  원격 경로: {c.backup.remote_dir}",
            f"  스케줄: {c.backup.schedule}",
            f"",
            f"전송: {c.transport.protocol} (transport-agnostic)",
            f"  SSH fallback: {'❌ 없음' if not c.transport.ssh_fallback else '⚠️ 활성화됨'}",
            f"",
            f"모니터링: {'✅ 활성' if c.monitor.enabled else '❌ 비활성'}",
            f"  AI 역할: {c.monitor.ai_role}",
            f"  AI 결정권: {'⚠️ 있음' if c.monitor.ai_decision_authority else '❌ 없음 (정상)'}",
        ]
        return "\n".join(lines)
