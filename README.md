# SecureVault

Distributed secret management with Shamir's Secret Sharing.

AES-256-GCM + Argon2id encryption, secrets split across N nodes via vssh transport.

## Status

Work in progress. Core vault.py (667 lines) with CRUD + Shamir share distribution.

## Architecture

- `vault.py` — Core secret CRUD + share distribution
- `engine.py` — AES-256-GCM encryption engine
- `keymanager.py` — Shamir's Secret Sharing key management
- `transport.py` — vssh-based share transport
- `backup.py` — Encrypted backup/restore
- `cli.py` — CLI interface

## TODO

- [ ] Complete engine.py + keymanager.py implementation
- [ ] Migrate mpop secret → vault backend
- [ ] AI whitelist config (currently hardcoded in MCP server)
- [ ] Vault MCP server
