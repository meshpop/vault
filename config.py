"""
SecureVault Configuration Manager

YAML-based configuration management.
All security decisions are set by humans in config file — no automatic changes.
"""

import os
import yaml
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path


# ─── Default paths ───────────────────────────────────────────────

DEFAULT_CONFIG_DIR = os.path.expanduser("~/.sv-vault")
DEFAULT_CONFIG_FILE = "vault.yml"
DEFAULT_METADATA_FILE = "keys.json"
DEFAULT_VAULT_DIR = "vaults"
DEFAULT_BACKUP_DIR = "backups"


@dataclass
class BackupConfig:
    """Backup config — set by humans"""
    targets: list = field(default_factory=lambda: ["s1", "s2"])
    remote_dir: str = "~/backup/v1/sv-vault"
    schedule: str = "0 3 * * *"  # daily 03:00
    verify_schedule: str = "30 3 * * 0"  # weekly Sunday 03:30
    max_versions: int = 30
    atomic_upload: bool = True


@dataclass
class EncryptionConfig:
    """Encryption config"""
    cipher: str = "AES-256-GCM"
    kdf: str = "Argon2id"
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536  # 64 MB
    argon2_parallelism: int = 4
    # explicitly disable legacy methods
    deprecated_warning: str = "CBC/PBKDF2 not used"


@dataclass
class ShamirConfig:
    """Shamir Secret Sharing config — set by humans"""
    master_key_shares: int = 5   # master key split count
    master_key_threshold: int = 3  # recovery threshold
    vault_key_shares: int = 3
    vault_key_threshold: int = 2
    # shard locations are entered manually by humans
    master_locations: list = field(default_factory=lambda: [
        "MacBook Secure Enclave",
        "s1 NAS encrypted partition",
        "s2 NAS encrypted partition",
        "Offline USB (safe)",
        "Paper printout (safe)",
    ])
    vault_locations: list = field(default_factory=lambda: [
        "MacBook Keychain",
        "s1 NAS",
        "s2 NAS",
    ])


@dataclass
class MonitorConfig:
    """Monitoring config (sv-monitor) — observe only, no decisions"""
    enabled: bool = True
    healthcheck_interval: int = 300  # 5 minutes
    alert_channels: list = field(default_factory=lambda: ["telegram"])
    log_retention_days: int = 90
    # AI reports only
    ai_role: str = "monitor_only"
    ai_decision_authority: bool = False  # never set to True


@dataclass
class TransportConfig:
    """Transport config"""
    protocol: str = "vssh"
    vssh_binary: str = "/usr/local/bin/vssh"
    default_timeout: int = 30
    upload_timeout: int = 120
    # no SSH fallback
    ssh_fallback: bool = False
    # transport-agnostic
    network_dependency: str = "none"  # Wire/Tailscale/LAN agnostic


@dataclass
class VaultConfig:
    """SecureVault global config"""
    version: str = "2.0"
    name: str = "SecureVault"

    # core principles (immutable)
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

    # config file path
    config_dir: str = DEFAULT_CONFIG_DIR
    config_file: str = DEFAULT_CONFIG_FILE


class ConfigManager:
    """Config file manager"""

    def __init__(self, config_dir: Optional[str] = None):
        self.config_dir = config_dir or DEFAULT_CONFIG_DIR
        self.config_path = os.path.join(self.config_dir, DEFAULT_CONFIG_FILE)
        self.config: VaultConfig = VaultConfig(config_dir=self.config_dir)

    def init(self) -> str:
        """Create initial config

        Returns:
            path to generated config file
        """
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(os.path.join(self.config_dir, DEFAULT_VAULT_DIR), exist_ok=True)
        os.makedirs(os.path.join(self.config_dir, DEFAULT_BACKUP_DIR), exist_ok=True)

        if not os.path.exists(self.config_path):
            self.save()

        return self.config_path

    def load(self) -> VaultConfig:
        """Load config file"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(
                f"Config file not found: {self.config_path}\n"
                "Run 'sv init' first."
            )

        with open(self.config_path) as f:
            data = yaml.safe_load(f)

        if data:
            self._apply_dict(data)

        # validate principles
        self._validate_principles()

        return self.config

    def save(self):
        """Save config file"""
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
        """Convert config to dictionary"""
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
        """Apply config from dictionary"""
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
        """Check for core principle violations"""
        p = self.config.principles

        violations = []

        if not p.get("rule_based_only", True):
            violations.append("rule_based_only is False — rule-based only allowed")

        if not p.get("human_decides", True):
            violations.append("human_decides is False — humans must decide")

        if p.get("ai_monitors_only") is False:
            violations.append("ai_monitors_only is False — AI monitors only")

        if p.get("no_ssh_fallback") is False:
            violations.append("no_ssh_fallback is False — SSH fallback not allowed")

        if self.config.transport.ssh_fallback:
            violations.append("transport.ssh_fallback is True — SSH fallback not allowed")

        if self.config.monitor.ai_decision_authority:
            violations.append("monitor.ai_decision_authority is True — AI has no decision authority")

        if violations:
            raise ValueError(
                "\u26a0\ufe0f SecureVault principle violation!\n" +
                "\n".join(f"  - {v}" for v in violations) +
                "\n\nFix your config file: " + self.config_path
            )

    # ─── Convenience methods ─────────────────────────────────────────

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
        """Backup target list (as specified by humans in config file)"""
        return self.config.backup.targets

    def show(self) -> str:
        """Current config summary"""
        c = self.config
        lines = [
            f"SecureVault v{c.version}",
            f"",
            f"Encryption: {c.encryption.cipher} + {c.encryption.kdf}",
            f"  Argon2: time={c.encryption.argon2_time_cost}, "
            f"mem={c.encryption.argon2_memory_cost // 1024}MB, "
            f"parallel={c.encryption.argon2_parallelism}",
            f"",
            f"Shamir (master): {c.shamir.master_key_threshold}-of-{c.shamir.master_key_shares}",
            f"  locations: {', '.join(c.shamir.master_locations)}",
            f"Shamir (vault): {c.shamir.vault_key_threshold}-of-{c.shamir.vault_key_shares}",
            f"  locations: {', '.join(c.shamir.vault_locations)}",
            f"",
            f"Backup targets: {', '.join(c.backup.targets)} (human-defined)",
            f"  remote path: {c.backup.remote_dir}",
            f"  schedule: {c.backup.schedule}",
            f"",
            f"Transport: {c.transport.protocol} (transport-agnostic)",
            f"  SSH fallback: {'disabled' if not c.transport.ssh_fallback else 'ENABLED (warning)'}",
            f"",
            f"Monitoring: {'enabled' if c.monitor.enabled else 'disabled'}",
            f"  AI role: {c.monitor.ai_role}",
            f"  AI authority: {'ENABLED (warning)' if c.monitor.ai_decision_authority else 'none (normal)'}",
        ]
        return "\n".join(lines)
