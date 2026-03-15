# sv-vault (SecureVault)

Distributed secret management with AES-256-GCM encryption, Argon2id key derivation, and Shamir's Secret Sharing.

## Quick Start

```bash
pip install sv-vault
```

This installs the `sv` CLI.

## CLI Usage

```bash
# Initialize a new vault
sv init

# Unlock vault (enters interactive mode)
sv unlock

# Secret management
sv add myservice/api_key              # Add a secret (prompts for value)
sv get myservice/api_key              # Retrieve a secret
sv list                               # List all secrets
sv search "api"                       # Search secrets
sv update myservice/api_key           # Update existing secret
sv delete myservice/api_key           # Delete a secret

# Shamir's Secret Sharing (distributed backup)
sv distribute --shares 5 --threshold 3   # Split master key into 5 shares (need 3 to recover)
sv recover                               # Recover from shares

# Sync across servers (via vssh transport)
sv sync                                  # Sync vault to registered peers
sv backup                                # Create encrypted backup

# Rotate master key
sv rotate

# Lock vault
sv lock
```

## Security Architecture

```
┌─────────────────────────────────────┐
│          Master Password            │
│              │                      │
│      ┌───────▼────────┐            │
│      │   Argon2id      │            │
│      │   Key Derivation│            │
│      └───────┬────────┘            │
│              │                      │
│      ┌───────▼────────┐            │
│      │  AES-256-GCM   │            │
│      │  Encryption     │            │
│      └───────┬────────┘            │
│              │                      │
│      ┌───────▼────────┐            │
│      │  Encrypted      │            │
│      │  Vault File     │            │
│      └─────────────────┘            │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  Shamir's Secret Sharing     │  │
│  │  Split key → N shares        │  │
│  │  Recover with K of N shares  │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: Argon2id (memory-hard, side-channel resistant)
- **Distributed Backup**: Shamir's Secret Sharing — split master key across trusted parties
- **Transport**: vssh-based peer sync (no plaintext over network)
- **Rule Engine**: Access policies, auto-rotation, audit logging

## Python API

```python
from engine import VaultEngine
from config import VaultConfig

config = VaultConfig.load()
vault = VaultEngine(config)
vault.unlock("master-password")

# CRUD
vault.add("service/key", "secret-value")
value = vault.get("service/key")
vault.list_secrets()
```

## Integration with mpop

sv-vault integrates with mpop's secret management:

```bash
mpop secret list                    # Uses vault backend
mpop secret get github_pat          # Retrieve via vault
```

## Requirements

- Python 3.9+
- cryptography >= 41.0
- argon2-cffi >= 23.1
- pyyaml >= 6.0

## License

MIT — [MeshPOP](https://github.com/meshpop)
