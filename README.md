# Vault

**Encrypted secret management with Shamir Secret Sharing and zero-knowledge architecture.**

Part of [MeshPOP](https://mpop.dev) — Layer 5 (Secrets)

- AES-256 encryption with PBKDF2 key derivation
- Shamir Secret Sharing for distributed key management
- 11 MCP tools for AI agent secret operations

## Install

```bash
pip install sv-vault
```

## Usage

```bash
# List stored secrets
vault list

# Get a secret
vault get api_key

# Add a new secret
vault add db_password "s3cure_v4lue"

# Audit access log
vault audit
```

## MCP Setup

```json
{
  "mcpServers": {
    "vault": { "command": "vault-mcp" }
  }
}
```

Gives AI agents: `vault_status`, `vault_list`, `vault_get`, `vault_add`, `vault_update`, `vault_delete`, `vault_search`, `vault_audit`, `vault_info`, `vault_encrypt_file`, `vault_decrypt_file`

## Links

- Main project: [github.com/meshpop/mpop](https://github.com/meshpop/mpop)
- Website: [mpop.dev](https://mpop.dev)
- PyPI: [pypi.org/project/sv-vault](https://pypi.org/project/sv-vault/)

## License

Apache-2.0

