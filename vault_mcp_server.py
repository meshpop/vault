#!/usr/bin/env python3
"""
SecureVault MCP Server — vault secret management

Tools:
- vault_status       : query vault status (locked state, secret count, etc.)
- vault_init         : initialize vault (first time only)
- vault_unlock       : unlock with password (session persists)
- vault_lock         : lock (clear memory)
- vault_add          : add secret
- vault_get          : get secret value
- vault_update       : update secret
- vault_delete       : delete secret
- vault_list         : list secrets (values excluded)
- vault_search       : search by name/tag
- vault_encrypt_file : encrypt file
- vault_decrypt_file : decrypt file
- vault_distribute   : distribute Shamir shares to nodes
- vault_collect      : collect shares from nodes → unlock
- vault_audit        : query audit log

Session: after vault_unlock, remains unlocked within the same process.
      get/list/add etc. available without password.

Run: python3 -m vault.vault_mcp_server
  or python3 vault_mcp_server.py
"""

import json
import sys
import os

# add path since vault package is in the same directory as this file
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── Session management ────────────────────────────────────────────

DEFAULT_VAULT_DIR = os.path.expanduser("~/.sv-vault")
_vault_managers: dict = {}  # vault_dir -> SecureVaultManager


def _get_vm(vault_dir: str = ""):
    """Return SecureVaultManager instance, creating it if needed."""
    d = vault_dir or DEFAULT_VAULT_DIR
    if d not in _vault_managers:
        from vault import SecureVaultManager
        transport = None
        try:
            from transport import VsshTransport
            transport = VsshTransport()
        except (FileNotFoundError, ImportError):
            pass
        _vault_managers[d] = SecureVaultManager(d, transport=transport)
    return _vault_managers[d]


def _unlock_or_fail(vm, password: str = "") -> dict | None:
    """Return None if already unlocked, otherwise try to unlock with password.
    Return error dict on failure."""
    if vm.is_unlocked:
        return None
    if not password:
        return {"error": "Vault is locked. Provide password parameter or call vault_unlock first."}
    if not vm.unlock(password):
        return {"error": "Wrong password."}
    return None


# ─── Tool implementations ────────────────────────────────────────────

def tool_vault_status(params: dict) -> dict:
    """Query vault status."""
    vault_dir = params.get("vault_dir", "")
    try:
        vm = _get_vm(vault_dir)
        s = vm.status()
        return {
            "vault_dir": vm.vault_dir,
            "initialized": s.get("initialized", False),
            "locked": not s.get("unlocked", False),
            "entry_count": s.get("entry_count", 0),
            "vault_id": s.get("vault_id", ""),
            "shamir": s.get("shamir", ""),
            "share_nodes": s.get("share_nodes", []),
            "backup_targets": s.get("backup_targets", []),
            "created_at": s.get("created_at", ""),
            "last_modified": s.get("last_modified", ""),
        }
    except Exception as e:
        return {"initialized": False, "error": str(e)}


def tool_vault_init(params: dict) -> dict:
    """Initialize vault (first time only). Specify password, shamir_n, shamir_k."""
    import base64
    vault_dir = params.get("vault_dir", "")
    password = params.get("password", "")
    n = int(params.get("shamir_n", 5))
    k = int(params.get("shamir_k", 3))

    if not password:
        return {"error": "password parameter is required."}

    try:
        vm = _get_vm(vault_dir)
        result = vm.init(password, shamir_n=n, shamir_k=k)
        shares_b64 = [
            {"index": idx, "share": base64.b64encode(share_bytes).decode()}
            for idx, share_bytes in result["shares"]
        ]
        return {
            "ok": True,
            "vault_id": result["vault_id"],
            "shamir": result["shamir"],
            "master_key_hash": result["master_key_hash"],
            "shares": shares_b64,
            "note": f"Store each share in a separate safe location. Only {k} shares needed to recover.",
        }
    except FileExistsError:
        return {"error": "Vault is already initialized. Delete the vault directory to reinitialize."}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_unlock(params: dict) -> dict:
    """Unlock vault with password. Remains unlocked within this process."""
    vault_dir = params.get("vault_dir", "")
    password = params.get("password", "")
    if not password:
        return {"error": "password parameter is required."}
    try:
        vm = _get_vm(vault_dir)
        if vm.is_unlocked:
            s = vm.status()
            return {"ok": True, "already_unlocked": True, "entry_count": s.get("entry_count", 0)}
        if vm.unlock(password):
            s = vm.status()
            return {"ok": True, "entry_count": s.get("entry_count", 0)}
        return {"error": "Wrong password."}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_lock(params: dict) -> dict:
    """Lock vault (remove master key from memory)."""
    vault_dir = params.get("vault_dir", "")
    try:
        vm = _get_vm(vault_dir)
        vm.lock()
        return {"ok": True, "message": "Vault locked — memory cleared"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_add(params: dict) -> dict:
    """Add secret. name, value, password (optional), etc."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    value = params.get("value", "")
    if not name:
        return {"error": "name parameter is required."}
    if not value:
        return {"error": "value parameter is required."}

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        entry = vm.add(
            name, value,
            category=params.get("category", "default"),
            tags=[t.strip() for t in params.get("tags", "").split(",") if t.strip()],
            note=params.get("note", ""),
        )
        return {"ok": True, "name": entry.name, "category": entry.category, "created_at": entry.created_at}
    except KeyError as e:
        return {"error": f"Name already exists: {e}"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_get(params: dict) -> dict:
    """Get secret value. Use with caution."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    if not name:
        return {"error": "name parameter is required."}

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        entry = vm.get(name)
        if not entry:
            return {"error": f"Secret not found: {name}"}
        return {
            "name": entry.name,
            "value": entry.value,
            "category": entry.category,
            "tags": entry.tags,
            "note": entry.note,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        }
    except Exception as e:
        return {"error": str(e)}


def tool_vault_update(params: dict) -> dict:
    """Update secret. Specify one or more of value, category, tags, note."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    if not name:
        return {"error": "name parameter is required."}

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err

        kwargs: dict = {}
        if "value" in params and params["value"]:
            kwargs["value"] = params["value"]
        if "category" in params and params["category"]:
            kwargs["category"] = params["category"]
        if "tags" in params and params["tags"]:
            kwargs["tags"] = [t.strip() for t in params["tags"].split(",") if t.strip()]
        if "note" in params and params["note"] is not None:
            kwargs["note"] = params["note"]

        if not kwargs:
            return {"error": "Nothing to update. Specify one of: value, category, tags, note."}

        entry = vm.update(name, **kwargs)
        return {"ok": True, "name": entry.name, "updated_at": entry.updated_at}
    except KeyError as e:
        return {"error": f"Secret not found: {e}"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_delete(params: dict) -> dict:
    """Delete secret."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    if not name:
        return {"error": "name parameter is required."}

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        if vm.delete(name):
            return {"ok": True, "deleted": name}
        return {"error": f"Secret not found: {name}"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_list(params: dict) -> dict:
    """List secrets (values excluded)."""
    vault_dir = params.get("vault_dir", "")
    category = params.get("category", "")

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        secrets = vm.list_secrets(category=category or None)
        return {"count": len(secrets), "secrets": secrets}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_search(params: dict) -> dict:
    """Search secrets by name/tag."""
    vault_dir = params.get("vault_dir", "")
    query = params.get("query", "")
    if not query:
        return {"error": "query parameter is required."}

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        results = vm.search(query)
        return {"query": query, "count": len(results), "results": results}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_encrypt_file(params: dict) -> dict:
    """Encrypt file with AES-256-GCM."""
    src = params.get("file", "")
    dst = params.get("output", "") or f"{src}.vault"
    password = params.get("password", "")

    if not src:
        return {"error": "file parameter is required."}
    if not os.path.isfile(src):
        return {"error": f"File not found: {src}"}
    if not password:
        return {"error": "password parameter is required."}

    try:
        from engine import VaultEngine
        engine = VaultEngine()
        engine.encrypt_file(src, dst, password, context="file")
        size = os.path.getsize(dst)
        return {"ok": True, "output": dst, "size_bytes": size}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_decrypt_file(params: dict) -> dict:
    """Decrypt encrypted file (.vault)."""
    src = params.get("file", "")
    dst = params.get("output", "") or (src[:-6] if src.endswith(".vault") else f"{src}.decrypted")
    password = params.get("password", "")

    if not src:
        return {"error": "file parameter is required."}
    if not os.path.isfile(src):
        return {"error": f"File not found: {src}"}
    if not password:
        return {"error": "password parameter is required."}

    try:
        from engine import VaultEngine
        engine = VaultEngine()
        engine.decrypt_file(src, dst, password)
        size = os.path.getsize(dst)
        return {"ok": True, "output": dst, "size_bytes": size}
    except Exception as e:
        msg = str(e).strip()
        if not msg or type(e).__name__ == "InvalidTag":
            msg = "Wrong password or corrupted file (AES-GCM auth failed)"
        return {"error": msg}


def tool_vault_distribute(params: dict) -> dict:
    """Auto-distribute Shamir shares to specified nodes."""
    vault_dir = params.get("vault_dir", "")
    nodes_str = params.get("nodes", "")
    if not nodes_str:
        return {"error": "nodes parameter required. Example: 'd2,g1,g2,v1,v2'"}

    nodes = [n.strip() for n in nodes_str.split(",") if n.strip()]
    remote_dir = params.get("remote_dir", "/opt/sv-vault/shares")

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        result = vm.distribute(nodes, remote_dir=remote_dir)
        return {
            "ok": True,
            "vault_id": result["vault_id"],
            "shamir": result["shamir"],
            "distributed": result["distributed"],
            "failed": result["failed"],
        }
    except Exception as e:
        return {"error": str(e)}


def tool_vault_collect(params: dict) -> dict:
    """Collect Shamir shares from nodes → recover master key → unlock."""
    vault_dir = params.get("vault_dir", "")
    nodes_str = params.get("nodes", "")
    nodes = [n.strip() for n in nodes_str.split(",") if n.strip()] if nodes_str else None

    try:
        vm = _get_vm(vault_dir)
        shares = vm.collect(nodes=nodes)
        if vm.unlock_shamir(shares):
            s = vm.status()
            return {
                "ok": True,
                "shares_collected": len(shares),
                "entry_count": s.get("entry_count", 0),
            }
        return {"error": "Shamir recovery failed — shares corrupted or insufficient."}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_audit(params: dict) -> dict:
    """Query audit log."""
    vault_dir = params.get("vault_dir", "")
    last_n = int(params.get("last", 20))

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        log = vm.get_audit_log(last_n=last_n)
        return {"count": len(log), "events": log}
    except Exception as e:
        return {"error": str(e)}


# ─── MCP server ──────────────────────────────────────────────

TOOLS = [
    {
        "name": "vault_status",
        "description": "Query SecureVault status: initialization, locked state, secret count, Shamir config, backup targets, etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_init",
        "description": "Initialize SecureVault (first time only). Generates master key + Shamir split. Outputs Shamir shares — store them safely.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "Master password (use a strong one)"},
                "shamir_n": {"type": "integer", "description": "Total Shamir share count (default: 5)", "default": 5},
                "shamir_k": {"type": "integer", "description": "Shares required for recovery (default: 3)", "default": 3},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["password"]
        }
    },
    {
        "name": "vault_unlock",
        "description": "Unlock vault with password. Subsequent secret access in the same session requires no password.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "Master password"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["password"]
        }
    },
    {
        "name": "vault_lock",
        "description": "Lock vault. Removes master key from memory for security.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_add",
        "description": "Add secret. name and value required. category, tags, note optional.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Secret name (e.g. db_password, github_token)"},
                "value": {"type": "string", "description": "Secret value"},
                "category": {"type": "string", "description": "Category (password/api_key/token/cert/default)", "default": "default"},
                "tags": {"type": "string", "description": "Tags (comma-separated, e.g. prod,db)"},
                "note": {"type": "string", "description": "Note"},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["name", "value"]
        }
    },
    {
        "name": "vault_get",
        "description": "Get secret value. Sensitive info — call only when needed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Secret name"},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "vault_update",
        "description": "Update secret. Specify only the fields you want to change: value, category, tags, note.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Secret name"},
                "value": {"type": "string", "description": "New value"},
                "category": {"type": "string", "description": "New category"},
                "tags": {"type": "string", "description": "New tags (comma-separated)"},
                "note": {"type": "string", "description": "New note"},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "vault_delete",
        "description": "Delete secret. Irreversible — use with caution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name of secret to delete"},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "vault_list",
        "description": "List secrets (values excluded). Filterable by category.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Category filter (optional)"},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_search",
        "description": "Search secrets by name/tag.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "vault_encrypt_file",
        "description": "Encrypt file with AES-256-GCM. Output filename is <original>.vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "Path to file to encrypt"},
                "output": {"type": "string", "description": "Output file path (default: <file>.vault)"},
                "password": {"type": "string", "description": "Encryption password"}
            },
            "required": ["file", "password"]
        }
    },
    {
        "name": "vault_decrypt_file",
        "description": "Decrypt a vault-encrypted file. Clear error message on wrong password.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "Path to file to decrypt (.vault)"},
                "output": {"type": "string", "description": "Output file path (default: strip .vault extension)"},
                "password": {"type": "string", "description": "Decryption password"}
            },
            "required": ["file", "password"]
        }
    },
    {
        "name": "vault_distribute",
        "description": "Auto-distribute Shamir shares to specified nodes. After distribution, recovery possible with K nodes without password.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "nodes": {"type": "string", "description": "Target nodes (comma-separated, e.g. 'd2,g1,g2,v1,v2')"},
                "remote_dir": {"type": "string", "description": "Remote storage path (default: /opt/sv-vault/shares)", "default": "/opt/sv-vault/shares"},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": ["nodes"]
        }
    },
    {
        "name": "vault_collect",
        "description": "Collect Shamir shares from nodes → recover master key → unlock vault. K or more shares allows passwordless recovery.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "nodes": {"type": "string", "description": "Nodes to collect from (comma-separated, empty = auto-detect)"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_audit",
        "description": "Query audit log. Check secret access/modification history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "last": {"type": "integer", "description": "Last N events (default: 20)", "default": 20},
                "password": {"type": "string", "description": "Master password if vault is locked"},
                "vault_dir": {"type": "string", "description": "Vault directory (default: ~/.sv-vault)"}
            },
            "required": []
        }
    },
]

TOOL_HANDLERS = {
    "vault_status": tool_vault_status,
    "vault_init": tool_vault_init,
    "vault_unlock": tool_vault_unlock,
    "vault_lock": tool_vault_lock,
    "vault_add": tool_vault_add,
    "vault_get": tool_vault_get,
    "vault_update": tool_vault_update,
    "vault_delete": tool_vault_delete,
    "vault_list": tool_vault_list,
    "vault_search": tool_vault_search,
    "vault_encrypt_file": tool_vault_encrypt_file,
    "vault_decrypt_file": tool_vault_decrypt_file,
    "vault_distribute": tool_vault_distribute,
    "vault_collect": tool_vault_collect,
    "vault_audit": tool_vault_audit,
}


# ─── JSON-RPC / MCP protocol ──────────────────────────────

def send_response(response: dict) -> None:
    line = json.dumps(response) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()


def read_request() -> dict | None:
    try:
        line = sys.stdin.readline()
        if not line:
            return None
        return json.loads(line.strip())
    except (json.JSONDecodeError, EOFError):
        return None


def handle_request(request: dict) -> dict | None:
    method = request.get("method", "")
    params = request.get("params", {})
    req_id = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vault-mcp", "version": "1.0.0"},
            }
        }

    elif method == "notifications/initialized":
        return None

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS}
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}
            }
        try:
            result = handler(tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": str(e)}, ensure_ascii=False)}]
                }
            }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    return None


def main():
    while True:
        try:
            request = read_request()
            if request is None:
                break
            response = handle_request(request)
            if response:
                send_response(response)
        except Exception as e:
            sys.stderr.write(f"vault_mcp_server error: {e}\n")
            break


if __name__ == "__main__":
    main()
