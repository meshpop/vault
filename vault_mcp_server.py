#!/usr/bin/env python3
"""
SecureVault MCP Server - vault-mcp

MCP server for sv-vault. Exposes vault operations as JSON-RPC tools for AI agents.

Usage:
    vault-mcp                      # Start MCP server (stdio)

MCP config (Claude Code):
    {"mcpServers": {"vault": {"command": "vault-mcp", "args": []}}}
"""

import sys, os, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SERVER_NAME = "vault-mcp"
SERVER_VERSION = "2.1.0"
PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {"name": "vault_status", "description": "Check vault status - initialized, locked/unlocked, secret count, Shamir config", "inputSchema": {"type": "object", "properties": {"vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}}}},
    {"name": "vault_list", "description": "List all secrets (names, categories, tags - no values). Requires password.", "inputSchema": {"type": "object", "properties": {"password": {"type": "string", "description": "Vault master password"}, "category": {"type": "string", "description": "Filter by category"}, "vault_dir": {"type": "string"}}, "required": ["password"]}},
    {"name": "vault_get", "description": "Retrieve a secret value by name. Requires password.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string", "description": "Secret name"}, "password": {"type": "string", "description": "Vault master password"}, "vault_dir": {"type": "string"}}, "required": ["name", "password"]}},
    {"name": "vault_add", "description": "Add a new secret. Requires password.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "value": {"type": "string"}, "password": {"type": "string"}, "category": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "note": {"type": "string"}, "vault_dir": {"type": "string"}}, "required": ["name", "value", "password"]}},
    {"name": "vault_update", "description": "Update an existing secret. Requires password.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "password": {"type": "string"}, "value": {"type": "string"}, "category": {"type": "string"}, "tags": {"type": "array", "items": {"type": "string"}}, "note": {"type": "string"}, "vault_dir": {"type": "string"}}, "required": ["name", "password"]}},
    {"name": "vault_delete", "description": "Delete a secret. Requires password.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "password": {"type": "string"}, "vault_dir": {"type": "string"}}, "required": ["name", "password"]}},
    {"name": "vault_search", "description": "Search secrets by name or tag. Requires password.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "password": {"type": "string"}, "vault_dir": {"type": "string"}}, "required": ["query", "password"]}},
    {"name": "vault_audit", "description": "View vault audit log - recent operations with timestamps", "inputSchema": {"type": "object", "properties": {"last": {"type": "integer", "description": "Number of recent events (default: 20)"}, "vault_dir": {"type": "string"}}}},
    {"name": "vault_info", "description": "Show vault engine info - cipher, KDF, version", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "vault_encrypt_file", "description": "Encrypt a file with AES-256-GCM + Argon2id", "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}, "password": {"type": "string"}, "output": {"type": "string"}}, "required": ["file_path", "password"]}},
    {"name": "vault_decrypt_file", "description": "Decrypt a .vault file", "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}, "password": {"type": "string"}, "output": {"type": "string"}}, "required": ["file_path", "password"]}},
]

def _get_vault(vault_dir=None):
    try:
        from vault import SecureVaultManager
    except ImportError:
        return None, "sv-vault not installed. Run: pip install sv-vault"
    vdir = vault_dir or os.path.expanduser("~/.sv-vault")
    transport = None
    try:
        from transport import VsshTransport
        transport = VsshTransport()
    except (ImportError, FileNotFoundError):
        pass
    return SecureVaultManager(vdir, transport=transport), None

def _get_engine():
    try:
        from engine import VaultEngine
        return VaultEngine(), None
    except ImportError:
        return None, "sv-vault not installed"

def handle_vault_status(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    return json.dumps(vm.status(), indent=2, default=str)

def handle_vault_list(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    if not vm.unlock(p.get("password", "")): return "Error: wrong password"
    secrets = vm.list_secrets(category=p.get("category"))
    vm.lock()
    if not secrets: return "Vault is empty"
    lines = []
    for s in secrets:
        tags = ", ".join(s.get("tags", []))
        lines.append(f"  {s['name']:<30} {s.get('category',''):<15} {tags}")
    return f"Secrets ({len(secrets)}):\n" + "\n".join(lines)

def handle_vault_get(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    if not vm.unlock(p.get("password", "")): return "Error: wrong password"
    entry = vm.get(p.get("name", ""))
    vm.lock()
    if not entry: return f"Error: secret '{p.get('name')}' not found"
    return json.dumps({"name": entry.name, "value": entry.value, "category": entry.category, "tags": getattr(entry, 'tags', []), "note": getattr(entry, 'note', "")}, indent=2, default=str)

def handle_vault_add(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    if not vm.unlock(p.get("password", "")): return "Error: wrong password"
    try:
        entry = vm.add(p["name"], p["value"], category=p.get("category", "default"), tags=p.get("tags", []), note=p.get("note", ""))
        vm.lock()
        return f"Added: {entry.name} (category: {entry.category})"
    except KeyError as e:
        vm.lock()
        return f"Error: {e}"

def handle_vault_update(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    if not vm.unlock(p.get("password", "")): return "Error: wrong password"
    kwargs = {k: p[k] for k in ("value", "category", "tags", "note") if k in p}
    if not kwargs: vm.lock(); return "Error: nothing to update"
    try:
        entry = vm.update(p["name"], **kwargs)
        vm.lock()
        return f"Updated: {entry.name}"
    except KeyError as e:
        vm.lock()
        return f"Error: {e}"

def handle_vault_delete(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    if not vm.unlock(p.get("password", "")): return "Error: wrong password"
    ok = vm.delete(p.get("name", ""))
    vm.lock()
    return f"Deleted: {p['name']}" if ok else f"Error: not found"

def handle_vault_search(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    if not vm.unlock(p.get("password", "")): return "Error: wrong password"
    results = vm.search(p.get("query", ""))
    vm.lock()
    if not results: return f"No secrets matching '{p.get('query')}'"
    lines = [f"  {r['name']} ({r.get('category','')})" for r in results]
    return f"{len(results)} found:\n" + "\n".join(lines)

def handle_vault_audit(p):
    vm, err = _get_vault(p.get("vault_dir"))
    if err: return err
    log = vm.get_audit_log(last_n=p.get("last", 20))
    if not log: return "No audit events"
    lines = [f"[{e.get('ts','?')[:19]}] {e.get('action','?'):12s} {e.get('detail','')}" for e in log]
    return "\n".join(lines)

def handle_vault_info(p):
    engine, err = _get_engine()
    if err: return err
    info = engine.info()
    return "SecureVault Engine v2.1\n" + "\n".join(f"  {k}: {v}" for k, v in info.items())

def handle_vault_encrypt_file(p):
    engine, err = _get_engine()
    if err: return err
    src = p.get("file_path", "")
    if not os.path.isfile(src): return f"Error: file not found: {src}"
    dst = p.get("output") or f"{src}.vault"
    try:
        engine.encrypt_file(src, dst, p.get("password", ""), context="file")
        return f"Encrypted: {dst} ({os.path.getsize(dst)} bytes)"
    except Exception as e:
        return f"Error: {e}"

def handle_vault_decrypt_file(p):
    engine, err = _get_engine()
    if err: return err
    src = p.get("file_path", "")
    if not os.path.isfile(src): return f"Error: file not found: {src}"
    dst = p.get("output") or (src[:-6] if src.endswith(".vault") else f"{src}.dec")
    try:
        engine.decrypt_file(src, dst, p.get("password", ""))
        return f"Decrypted: {dst}"
    except Exception as e:
        return f"Error: {e}"

HANDLERS = {t["name"]: globals()[f"handle_{t['name']}"] for t in TOOLS}

def handle_request(req):
    method, rid, params = req.get("method",""), req.get("id"), req.get("params",{})
    if method == "initialize":
        return {"jsonrpc":"2.0","id":rid,"result":{"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":SERVER_NAME,"version":SERVER_VERSION}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc":"2.0","id":rid,"result":{"tools":TOOLS}}
    if method == "tools/call":
        name = params.get("name","")
        handler = HANDLERS.get(name)
        if not handler:
            return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":f"Unknown tool: {name}"}],"isError":True}}
        try:
            result = handler(params.get("arguments",{}))
            return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":str(result)}],"isError":False}}
        except Exception as e:
            return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":f"Error: {e}"}],"isError":True}}
    return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"Unknown method: {method}"}}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try: req = json.loads(line)
        except json.JSONDecodeError: continue
        resp = handle_request(req)
        if resp:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
