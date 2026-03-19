#!/usr/bin/env python3
"""
SecureVault CLI — sv command

Password/secret management:
    sv init                          # initialize vault (master key + Shamir split)
    sv unlock                        # unlock with password
    sv lock                          # lock (clear memory)
    sv add <name> [--cat TYPE]       # add secret
    sv get <name>                    # get secret
    sv update <name>                 # update secret
    sv delete <name>                 # delete secret
    sv list [--cat TYPE]             # list (values excluded)
    sv search <query>                # search by name/tag

Shamir distribution:
    sv distribute <node1,node2,...>   # distribute shares to nodes
    sv collect [node1,node2,...]      # collect shares from nodes → unlock
    sv rekey                          # replace master key + redistribute

File encrypt/decrypt:
    sv encrypt <file> [-o output]     # encrypt file
    sv decrypt <file> [-o output]     # decrypt file

Backup/restore:
    sv backup <file>                  # encrypted backup → fixed targets
    sv restore [-n node]              # restore
    sv verify                         # verify backup integrity

Misc:
    sv status                         # vault status
    sv audit [--last N]               # audit log
    sv export [-o file]               # encrypted export
    sv import <file>                  # import
    sv info                           # engine info
    sv key generate                   # generate random key
    sv key split [-n 5] [-k 3]       # Shamir split
    sv key recover                    # Shamir recover (interactive)
"""

import os
import sys
import json
import getpass
import base64
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import VaultEngine, EncryptedBlob
from keymanager import KeyManager, ShamirSecret
from config import ConfigManager
from backup import SecureBackup
from vault import SecureVaultManager


# ─── Common utils ────────────────────────────────────────────

DEFAULT_VAULT_DIR = os.path.expanduser("~/.sv-vault")


def get_password(prompt: str = "Password: ", confirm: bool = False) -> str:
    password = getpass.getpass(prompt)
    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            print("\u274c Passwords do not match.")
            sys.exit(1)
    return password


def get_vault(args) -> SecureVaultManager:
    vault_dir = args.get("--vault-dir") or DEFAULT_VAULT_DIR
    transport = None
    try:
        from transport import VsshTransport
        transport = VsshTransport()
    except (FileNotFoundError, ImportError):
        pass  # no vssh — local only
    return SecureVaultManager(vault_dir, transport=transport)


def require_unlocked(vm: SecureVaultManager):
    if not vm.is_unlocked:
        print("\U0001f512 Vault is locked. Run unlock first.")
        sys.exit(1)


# ─── Vault management ────────────────────────────────────────────

def cmd_init(args):
    """sv init"""
    vm = get_vault(args)
    password = get_password("Set master password: ", confirm=True)

    n = int(args.get("-n", "5"))
    k = int(args.get("-k", "3"))

    try:
        result = vm.init(password, shamir_n=n, shamir_k=k)
    except FileExistsError:
        print("\u274c Vault already exists.")
        sys.exit(1)

    print(f"\u2705 SecureVault initialized")
    print(f"   Vault ID: {result['vault_id']}")
    print(f"   Shamir: {result['shamir']}")
    print(f"   Master key hash: {result['master_key_hash']}")
    print()

    # print shares
    print(f"\U0001f511 Shamir shares {n} total ({k} needed to recover):")
    for idx, share_bytes in result["shares"]:
        b64 = base64.b64encode(share_bytes).decode()
        print(f"   share {idx}: {b64}")
    print()
    print("\u26a0\ufe0f  Store each share in a separate safe location!")
    print("   Use 'sv distribute' to distribute to nodes automatically.")


def cmd_unlock(args):
    """sv unlock"""
    vm = get_vault(args)
    if vm.is_unlocked:
        print("\U0001f513 Already unlocked")
        return

    password = get_password("Password: ")
    if vm.unlock(password):
        print("\U0001f513 Vault unlocked")
        s = vm.status()
        print(f"   Secrets: {s['entry_count']}")
    else:
        print("\u274c Wrong password")
        sys.exit(1)


def cmd_lock(args):
    """sv lock"""
    vm = get_vault(args)
    vm.lock()
    print("\U0001f512 Vault locked — memory cleared")


# ─── CRUD ──────────────────────────────────────────────────

def cmd_add(args):
    """sv add <name>"""
    vm = get_vault(args)
    password = get_password("Password: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("Usage: sv add <name> [--cat TYPE] [--tags t1,t2] [--note TEXT]")
        sys.exit(1)

    value = get_password("Secret value: ", confirm=True)

    category = args.get("--cat", "default")
    tags = args.get("--tags", "").split(",") if args.get("--tags") else []
    note = args.get("--note", "")

    try:
        entry = vm.add(name, value, category=category, tags=tags, note=note)
        print(f"\u2705 Added: {entry.name} (category: {entry.category})")
    except KeyError as e:
        print(f"❌ {e}")
        sys.exit(1)


def cmd_get(args):
    """sv get <name>"""
    vm = get_vault(args)
    password = get_password("Password: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("Usage: sv get <name>")
        sys.exit(1)

    entry = vm.get(name)
    if entry:
        print(f"Name: {entry.name}")
        print(f"Value: {entry.value}")
        print(f"Category: {entry.category}")
        if entry.tags:
            print(f"Tags: {', '.join(entry.tags)}")
        if entry.note:
            print(f"Note: {entry.note}")
        print(f"Created: {entry.created_at}")
        print(f"Updated: {entry.updated_at}")
    else:
        print(f"\u274c Not found: {name}")
        sys.exit(1)


def cmd_update(args):
    """sv update <name>"""
    vm = get_vault(args)
    password = get_password("Password: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("Usage: sv update <name> [--value] [--cat TYPE] [--note TEXT]")
        sys.exit(1)

    kwargs = {}
    if args.get("--value") or args.get("-v"):
        kwargs["value"] = get_password("New secret value: ", confirm=True)
    if args.get("--cat"):
        kwargs["category"] = args["--cat"]
    if args.get("--tags"):
        kwargs["tags"] = args["--tags"].split(",")
    if args.get("--note"):
        kwargs["note"] = args["--note"]

    if not kwargs:
        # default to value change
        kwargs["value"] = get_password("New secret value: ", confirm=True)

    try:
        entry = vm.update(name, **kwargs)
        print(f"\u2705 Updated: {entry.name}")
    except KeyError as e:
        print(f"❌ {e}")
        sys.exit(1)


def cmd_delete(args):
    """sv delete <name>"""
    vm = get_vault(args)
    password = get_password("Password: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("Usage: sv delete <name>")
        sys.exit(1)

    confirm = input(f"Delete '{name}'? (y/N): ").strip().lower()
    if confirm != "y":
        print("Cancelled")
        return

    if vm.delete(name):
        print(f"\u2705 Deleted: {name}")
    else:
        print(f"\u274c Not found: {name}")


def cmd_list(args):
    """sv list"""
    vm = get_vault(args)
    password = get_password("Password: ")
    vm.unlock(password)

    category = args.get("--cat")
    secrets = vm.list_secrets(category=category)

    if not secrets:
        print("(empty)")
        return

    # print table
    max_name = max(len(s["name"]) for s in secrets)
    max_cat = max(len(s["category"]) for s in secrets)

    print(f"{'Name':<{max_name+2}} {'Category':<{max_cat+2}} Tags")
    print("─" * (max_name + max_cat + 30))
    for s in secrets:
        tags = ", ".join(s["tags"]) if s["tags"] else ""
        print(f"{s['name']:<{max_name+2}} {s['category']:<{max_cat+2}} {tags}")

    print(f"\nTotal: {len(secrets)}")


def cmd_search(args):
    """sv search <query>"""
    vm = get_vault(args)
    password = get_password("Password: ")
    vm.unlock(password)

    query = args.get("<name>") or args.get("<query>")
    if not query:
        print("Usage: sv search <query>")
        sys.exit(1)

    results = vm.search(query)
    if not results:
        print(f"No secrets matching '{query}'")
        return

    for r in results:
        tags = f" [{', '.join(r['tags'])}]" if r["tags"] else ""
        print(f"  {r['name']} ({r['category']}){tags}")
    print(f"\n{len(results)} found")


# ─── Shamir distribute/collect ──────────────────────────────────────

def cmd_distribute(args):
    """sv distribute <node1,node2,...>"""
    vm = get_vault(args)
    password = get_password("Password: ")
    vm.unlock(password)

    nodes_str = args.get("<name>") or args.get("<nodes>")
    if not nodes_str:
        print("Usage: sv distribute <node1,node2,...>")
        print("Example: sv distribute d2,g1,g2,v1,v2")
        sys.exit(1)

    nodes = [n.strip() for n in nodes_str.split(",")]
    remote_dir = args.get("--remote-dir", "/opt/sv-vault/shares")

    try:
        result = vm.distribute(nodes, remote_dir=remote_dir)
        print(f"✅ Share distribution complete ({result['shamir']})")
        print(f"   Vault ID: {result['vault_id']}")
        for d in result["distributed"]:
            print(f"   ✅ {d['node']} → share[{d['index']}]")
        for f in result["failed"]:
            print(f"   ❌ {f['node']} → share[{f['index']}]: {f.get('error')}")
    except Exception as e:
        print(f"\u274c Distribution failed: {e}")
        sys.exit(1)


def cmd_collect(args):
    """sv collect [node1,node2,...]"""
    vm = get_vault(args)

    nodes_str = args.get("<name>") or args.get("<nodes>")
    nodes = [n.strip() for n in nodes_str.split(",")] if nodes_str else None

    try:
        shares = vm.collect(nodes=nodes)
        print(f"\U0001f4e6 {len(shares)} shares collected")

        if vm.unlock_shamir(shares):
            print("\U0001f513 Shamir recovery unlock successful!")
            s = vm.status()
            print(f"   Secrets: {s['entry_count']}")
        else:
            print("\u274c Shamir recovery failed — shares may be corrupted")
            sys.exit(1)
    except Exception as e:
        print(f"\u274c Collection failed: {e}")
        sys.exit(1)


def cmd_rekey(args):
    """sv rekey — replace master key"""
    vm = get_vault(args)
    old_password = get_password("Current password: ")
    if not vm.unlock(old_password):
        print("\u274c Wrong password")
        sys.exit(1)

    new_password = get_password("New password: ", confirm=True)

    # 1. preserve existing secrets
    secrets_backup = {}
    for s in vm.list_secrets():
        entry = vm.get(s["name"])
        secrets_backup[s["name"]] = entry

    # 2. generate new master key
    new_master = os.urandom(32)

    # 3. encrypt master key with new password
    engine = VaultEngine()
    blob = engine.encrypt(new_master, new_password, context="master-key")
    with open(vm._key_enc_path, "wb") as f:
        f.write(blob.to_bytes())

    # 4. re-encrypt data with new master key
    vm._master_key = new_master
    vm._save_data()

    # 5. generate new Shamir shares
    n = vm._meta.shamir_n
    k = vm._meta.shamir_k
    shamir = ShamirSecret()
    shares = shamir.split(new_master, n=n, k=k)

    vm._meta.last_modified = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).isoformat()
    vm._save_meta()
    vm._audit("rekey", f"master key rotated, new {k}-of-{n} shares")

    print(f"\u2705 Master key replaced")
    print(f"   New key hash: {__import__('hashlib').sha256(new_master).hexdigest()[:16]}")
    print(f"   Shamir: {k}-of-{n}")
    print()

    for idx, share_bytes in shares:
        b64 = base64.b64encode(share_bytes).decode()
        print(f"   share {idx}: {b64}")

    print()
    print("\u26a0\ufe0f  Existing shares invalidated! Must run 'sv distribute' to redistribute.")


# ─── File encrypt/decrypt ──────────────────────────────────────────

def cmd_encrypt(args):
    """sv encrypt <file>"""
    src = args.get("<name>") or args.get("<file>")
    dst = args.get("-o") or f"{src}.vault"

    if not src or not os.path.isfile(src):
        print(f"\u274c File not found: {src}")
        sys.exit(1)

    password = get_password("Encryption password: ", confirm=True)
    engine = VaultEngine()
    blob = engine.encrypt_file(src, dst, password, context="file")

    print(f"\u2705 Encrypted: {dst}")
    print(f"   {engine.info()['cipher']} + {engine.info()['kdf']}")


def cmd_decrypt(args):
    """sv decrypt <file>"""
    src = args.get("<name>") or args.get("<file>")
    if not src:
        print("Usage: sv decrypt <file.vault> [-o output]")
        sys.exit(1)

    dst = args.get("-o")
    if not dst:
        dst = src[:-6] if src.endswith(".vault") else f"{src}.decrypted"

    password = get_password("Decryption password: ")
    engine = VaultEngine()
    try:
        engine.decrypt_file(src, dst, password, original_filename=args.get("--original-name"))
        print(f"\u2705 Decrypted: {dst}")
    except Exception as e:
        # cryptography.exceptions.InvalidTag has no message — give a clear hint
        msg = str(e).strip()
        if not msg or type(e).__name__ == "InvalidTag":
            msg = "Wrong password or corrupted file (AES-GCM auth failed)"
        print(f"\u274c Decryption failed: {msg}")
        sys.exit(1)


# ─── Backup/restore ──────────────────────────────────────────────

def cmd_backup(args):
    """sv backup <file>"""
    src = args.get("<name>") or args.get("<file>")
    config_dir = args.get("--config-dir")

    if not src or not os.path.isfile(src):
        print(f"\u274c File not found: {src}")
        sys.exit(1)

    password = get_password("Backup encryption password: ", confirm=True)

    cm = ConfigManager(config_dir=config_dir)
    try:
        cm.load()
    except FileNotFoundError:
        cm.init()

    transport = None
    try:
        from transport import VsshTransport
        transport = VsshTransport()
    except (FileNotFoundError, ImportError):
        print("\u26a0\ufe0f  vssh not found — local mode")

    sb = SecureBackup(config=cm, transport=transport)
    record = sb.backup(src, password)

    print(f"\u2705 Backup complete")
    print(f"   Targets: {', '.join(record.targets)}")
    for node, ok in record.results.items():
        print(f"   {'✅' if ok else '❌'} {node}")


def cmd_restore(args):
    """sv restore"""
    node = args.get("-n")
    output = args.get("-o") or "restored_secrets"
    config_dir = args.get("--config-dir")
    password = get_password("Decryption password: ")

    cm = ConfigManager(config_dir=config_dir)
    cm.load()

    transport = None
    if node:
        from transport import VsshTransport
        transport = VsshTransport()

    sb = SecureBackup(config=cm, transport=transport)
    if node:
        sb.restore_from_remote(node, password, output)
    else:
        status = sb.status()
        if not status["latest_local"]:
            print("\u274c No local backup found")
            sys.exit(1)
        sb.restore(os.path.join(cm.backup_dir, status["latest_local"]), password, output)

    print(f"\u2705 Restore complete \u2192 {output}")


def cmd_verify(args):
    """sv verify"""
    config_dir = args.get("--config-dir")
    password = get_password("Verification password: ")

    cm = ConfigManager(config_dir=config_dir)
    cm.load()

    transport = None
    try:
        from transport import VsshTransport
        transport = VsshTransport()
    except (FileNotFoundError, ImportError):
        print("\u26a0\ufe0f  vssh not found — local mode")

    sb = SecureBackup(config=cm, transport=transport)
    results = sb.verify(password)

    for node, r in results.items():
        print(f"  {'✅' if r['ok'] else '❌'} {node}: {'OK' if r['ok'] else r.get('error', '?')}")


# ─── Misc ──────────────────────────────────────────────────

def cmd_status(args):
    """sv status"""
    vm = get_vault(args)
    s = vm.status()

    if not s["initialized"]:
        print("\u274c Not initialized. Run 'sv init'.")
        return

    print(f"SecureVault [{s['vault_id']}]")
    print(f"  Status: {'unlocked' if s['unlocked'] else 'locked'}")
    print(f"  Secrets: {s['entry_count']}")
    print(f"  Shamir: {s['shamir']}")
    if s["share_nodes"]:
        print(f"  Share nodes: {', '.join(s['share_nodes'])}")
    print(f"  Backup targets: {', '.join(s['backup_targets'])}")
    print(f"  Created: {s['created_at']}")
    print(f"  Modified: {s['last_modified']}")


def cmd_audit(args):
    """sv audit"""
    vm = get_vault(args)
    last_n = int(args.get("--last", "20"))
    log = vm.get_audit_log(last_n=last_n)

    if not log:
        print("No audit log")
        return

    for event in log:
        ts = event.get("ts", "?")[:19]
        action = event.get("action", "?")
        detail = event.get("detail", "")
        print(f"  [{ts}] {action:12s} {detail}")

    print(f"\nLast {len(log)} events")


def cmd_export(args):
    """sv export"""
    vm = get_vault(args)
    password = get_password("Vault password: ")
    vm.unlock(password)

    export_password = get_password("Export password: ", confirm=True)
    output = args.get("-o", "vault_export.vault")

    data = vm.export_encrypted(export_password)
    with open(output, "wb") as f:
        f.write(data)
    print(f"\u2705 Export complete: {output} ({len(data)} bytes)")


def cmd_import(args):
    """sv import <file>"""
    vm = get_vault(args)
    password = get_password("Vault password: ")
    vm.unlock(password)

    src = args.get("<name>") or args.get("<file>")
    if not src or not os.path.isfile(src):
        print(f"\u274c File not found: {src}")
        sys.exit(1)

    import_password = get_password("Import password: ")
    merge = args.get("--merge", False)

    with open(src, "rb") as f:
        data = f.read()

    count = vm.import_encrypted(data, import_password, merge=bool(merge))
    print(f"\u2705 {count} secrets imported")


def cmd_info(args):
    """sv info"""
    engine = VaultEngine()
    info = engine.info()
    print("SecureVault Engine v2.0")
    for k, v in info.items():
        print(f"  {k}: {v}")


def cmd_key_generate(args):
    """sv key generate"""
    key = os.urandom(32)
    print(f"\U0001f511 AES-256 key:")
    print(f"   hex: {key.hex()}")
    print(f"   b64: {base64.b64encode(key).decode()}")


def cmd_key_split(args):
    """sv key split"""
    n = int(args.get("-n", "5"))
    k = int(args.get("-k", "3"))

    key_hex = args.get("--key")
    if key_hex:
        key = bytes.fromhex(key_hex)
    else:
        key_input = input("Key (hex, Enter=new key): ").strip()
        key = bytes.fromhex(key_input) if key_input else os.urandom(32)

    shamir = ShamirSecret()
    shares = shamir.split(key, n=n, k=k)
    print(f"Shamir {k}-of-{n}:")
    for idx, share_bytes in shares:
        print(f"  share {idx}: {base64.b64encode(share_bytes).decode()}")


def cmd_key_recover(args):
    """sv key recover (interactive)"""
    print("Enter shares (format: index:base64, blank line = done)")
    shares = []
    while True:
        line = input(f"share {len(shares)+1}> ").strip()
        if not line:
            break
        if ":" not in line:
            print("  Format: index:base64")
            continue
        idx_str, b64 = line.split(":", 1)
        try:
            shares.append((int(idx_str), base64.b64decode(b64)))
            print(f"  \u2705 share {idx_str} added")
        except Exception as e:
            print(f"  ❌ {e}")

    if len(shares) < 2:
        print("Need at least 2 shares")
        sys.exit(1)

    shamir = ShamirSecret()
    key = shamir.recover(shares)
    print(f"\U0001f511 Recovered: {key.hex()}")


def cmd_help(_args=None):
    print(__doc__)


# ─── Main ───────────────────────────────────────────────────

COMMANDS = {
    "init": cmd_init,
    "unlock": cmd_unlock,
    "lock": cmd_lock,
    "add": cmd_add,
    "get": cmd_get,
    "update": cmd_update,
    "delete": cmd_delete,
    "list": cmd_list,
    "search": cmd_search,
    "distribute": cmd_distribute,
    "collect": cmd_collect,
    "rekey": cmd_rekey,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "backup": cmd_backup,
    "restore": cmd_restore,
    "verify": cmd_verify,
    "status": cmd_status,
    "audit": cmd_audit,
    "export": cmd_export,
    "import": cmd_import,
    "info": cmd_info,
    "help": cmd_help,
}

KEY_COMMANDS = {
    "generate": cmd_key_generate,
    "split": cmd_key_split,
    "recover": cmd_key_recover,
}


def parse_args(argv: list) -> dict:
    args = {}
    positional = []
    i = 0
    while i < len(argv):
        if argv[i].startswith("-"):
            key = argv[i]
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                args[key] = argv[i + 1]
                i += 2
            else:
                args[key] = True
                i += 1
        else:
            positional.append(argv[i])
            i += 1

    if positional:
        args["<name>"] = positional[0]
        args["<file>"] = positional[0]
        if len(positional) > 1:
            args["<query>"] = positional[1]
            args["<nodes>"] = positional[1]

    return args


def main():
    argv = sys.argv[1:]

    if not argv:
        cmd_help()
        sys.exit(0)

    cmd_name = argv[0]

    if cmd_name == "key" and len(argv) > 1:
        sub = argv[1]
        if sub in KEY_COMMANDS:
            KEY_COMMANDS[sub](parse_args(argv[2:]))
            return
        print(f"\u274c key subcommand: generate, split, recover")
        sys.exit(1)

    if cmd_name in COMMANDS:
        COMMANDS[cmd_name](parse_args(argv[1:]))
    else:
        print(f"\u274c Unknown command: {cmd_name}")
        cmd_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
