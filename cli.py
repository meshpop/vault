#!/usr/bin/env python3
"""
SecureVault CLI — sv 명령어

패스워드/시크릿 관리:
    sv init                          # vault 초기화 (마스터 키 + Shamir 분할)
    sv unlock                        # 패스워드로 잠금 해제
    sv lock                          # 잠금 (메모리 클리어)
    sv add <name> [--cat TYPE]       # 시크릿 추가
    sv get <name>                    # 시크릿 조회
    sv update <name>                 # 시크릿 수정
    sv delete <name>                 # 시크릿 삭제
    sv list [--cat TYPE]             # 목록 (값 제외)
    sv search <query>                # 이름/태그 검색

Shamir 분산:
    sv distribute <node1,node2,...>   # share를 노드에 자동 분산
    sv collect [node1,node2,...]      # 노드에서 share 회수 → 잠금 해제
    sv rekey                          # 마스터 키 교체 + 재분산

파일 암복호화:
    sv encrypt <file> [-o output]     # 파일 암호화
    sv decrypt <file> [-o output]     # 파일 복호화

백업/복원:
    sv backup <file>                  # 암호화 백업 → 고정 타겟
    sv restore [-n node]              # 복원
    sv verify                         # 백업 무결성 검증

기타:
    sv status                         # vault 상태
    sv audit [--last N]               # 감사 로그
    sv export [-o file]               # 암호화 내보내기
    sv import <file>                  # 가져오기
    sv info                           # 엔진 정보
    sv key generate                   # 랜덤 키 생성
    sv key split [-n 5] [-k 3]       # Shamir 분할
    sv key recover                    # Shamir 복원 (인터랙티브)
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


# ─── 공통 유틸 ────────────────────────────────────────────

DEFAULT_VAULT_DIR = os.path.expanduser("~/.sv-vault")


def get_password(prompt: str = "패스워드: ", confirm: bool = False) -> str:
    password = getpass.getpass(prompt)
    if confirm:
        password2 = getpass.getpass("패스워드 확인: ")
        if password != password2:
            print("❌ 패스워드가 일치하지 않습니다.")
            sys.exit(1)
    return password


def get_vault(args) -> SecureVaultManager:
    vault_dir = args.get("--vault-dir") or DEFAULT_VAULT_DIR
    transport = None
    try:
        from transport import VsshTransport
        transport = VsshTransport()
    except (FileNotFoundError, ImportError):
        pass  # vssh 없으면 로컬 전용
    return SecureVaultManager(vault_dir, transport=transport)


def require_unlocked(vm: SecureVaultManager):
    if not vm.is_unlocked:
        print("🔒 Vault 잠겨있음. 먼저 unlock 하세요.")
        sys.exit(1)


# ─── Vault 관리 ────────────────────────────────────────────

def cmd_init(args):
    """sv init"""
    vm = get_vault(args)
    password = get_password("마스터 패스워드 설정: ", confirm=True)

    n = int(args.get("-n", "5"))
    k = int(args.get("-k", "3"))

    try:
        result = vm.init(password, shamir_n=n, shamir_k=k)
    except FileExistsError:
        print("❌ Vault이 이미 존재합니다.")
        sys.exit(1)

    print(f"✅ SecureVault 초기화 완료")
    print(f"   Vault ID: {result['vault_id']}")
    print(f"   Shamir: {result['shamir']}")
    print(f"   마스터 키 해시: {result['master_key_hash']}")
    print()

    # share 출력
    print(f"🔑 Shamir 조각 {n}개 ({k}개로 복구 가능):")
    for idx, share_bytes in result["shares"]:
        b64 = base64.b64encode(share_bytes).decode()
        print(f"   조각 {idx}: {b64}")
    print()
    print("⚠️  각 조각을 별도의 안전한 위치에 보관하세요!")
    print("   'sv distribute' 로 노드에 자동 분산할 수 있습니다.")


def cmd_unlock(args):
    """sv unlock"""
    vm = get_vault(args)
    if vm.is_unlocked:
        print("🔓 이미 잠금 해제됨")
        return

    password = get_password("패스워드: ")
    if vm.unlock(password):
        print("🔓 Vault 잠금 해제됨")
        s = vm.status()
        print(f"   시크릿: {s['entry_count']}개")
    else:
        print("❌ 패스워드 틀림")
        sys.exit(1)


def cmd_lock(args):
    """sv lock"""
    vm = get_vault(args)
    vm.lock()
    print("🔒 Vault 잠금 완료 — 메모리 클리어됨")


# ─── CRUD ──────────────────────────────────────────────────

def cmd_add(args):
    """sv add <name>"""
    vm = get_vault(args)
    password = get_password("패스워드: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("사용법: sv add <name> [--cat TYPE] [--tags t1,t2] [--note TEXT]")
        sys.exit(1)

    value = get_password("시크릿 값: ", confirm=True)

    category = args.get("--cat", "default")
    tags = args.get("--tags", "").split(",") if args.get("--tags") else []
    note = args.get("--note", "")

    try:
        entry = vm.add(name, value, category=category, tags=tags, note=note)
        print(f"✅ 추가됨: {entry.name} (카테고리: {entry.category})")
    except KeyError as e:
        print(f"❌ {e}")
        sys.exit(1)


def cmd_get(args):
    """sv get <name>"""
    vm = get_vault(args)
    password = get_password("패스워드: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("사용법: sv get <name>")
        sys.exit(1)

    entry = vm.get(name)
    if entry:
        print(f"이름: {entry.name}")
        print(f"값: {entry.value}")
        print(f"카테고리: {entry.category}")
        if entry.tags:
            print(f"태그: {', '.join(entry.tags)}")
        if entry.note:
            print(f"노트: {entry.note}")
        print(f"생성: {entry.created_at}")
        print(f"수정: {entry.updated_at}")
    else:
        print(f"❌ 없음: {name}")
        sys.exit(1)


def cmd_update(args):
    """sv update <name>"""
    vm = get_vault(args)
    password = get_password("패스워드: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("사용법: sv update <name> [--value] [--cat TYPE] [--note TEXT]")
        sys.exit(1)

    kwargs = {}
    if args.get("--value") or args.get("-v"):
        kwargs["value"] = get_password("새 시크릿 값: ", confirm=True)
    if args.get("--cat"):
        kwargs["category"] = args["--cat"]
    if args.get("--tags"):
        kwargs["tags"] = args["--tags"].split(",")
    if args.get("--note"):
        kwargs["note"] = args["--note"]

    if not kwargs:
        # 값 변경 기본
        kwargs["value"] = get_password("새 시크릿 값: ", confirm=True)

    try:
        entry = vm.update(name, **kwargs)
        print(f"✅ 수정됨: {entry.name}")
    except KeyError as e:
        print(f"❌ {e}")
        sys.exit(1)


def cmd_delete(args):
    """sv delete <name>"""
    vm = get_vault(args)
    password = get_password("패스워드: ")
    vm.unlock(password)

    name = args.get("<name>")
    if not name:
        print("사용법: sv delete <name>")
        sys.exit(1)

    confirm = input(f"'{name}' 삭제할까요? (y/N): ").strip().lower()
    if confirm != "y":
        print("취소")
        return

    if vm.delete(name):
        print(f"✅ 삭제됨: {name}")
    else:
        print(f"❌ 없음: {name}")


def cmd_list(args):
    """sv list"""
    vm = get_vault(args)
    password = get_password("패스워드: ")
    vm.unlock(password)

    category = args.get("--cat")
    secrets = vm.list_secrets(category=category)

    if not secrets:
        print("(비어있음)")
        return

    # 테이블 출력
    max_name = max(len(s["name"]) for s in secrets)
    max_cat = max(len(s["category"]) for s in secrets)

    print(f"{'이름':<{max_name+2}} {'카테고리':<{max_cat+2}} 태그")
    print("─" * (max_name + max_cat + 30))
    for s in secrets:
        tags = ", ".join(s["tags"]) if s["tags"] else ""
        print(f"{s['name']:<{max_name+2}} {s['category']:<{max_cat+2}} {tags}")

    print(f"\n총 {len(secrets)}개")


def cmd_search(args):
    """sv search <query>"""
    vm = get_vault(args)
    password = get_password("패스워드: ")
    vm.unlock(password)

    query = args.get("<name>") or args.get("<query>")
    if not query:
        print("사용법: sv search <query>")
        sys.exit(1)

    results = vm.search(query)
    if not results:
        print(f"'{query}'에 해당하는 시크릿 없음")
        return

    for r in results:
        tags = f" [{', '.join(r['tags'])}]" if r["tags"] else ""
        print(f"  {r['name']} ({r['category']}){tags}")
    print(f"\n{len(results)}개 찾음")


# ─── Shamir 분산/회수 ──────────────────────────────────────

def cmd_distribute(args):
    """sv distribute <node1,node2,...>"""
    vm = get_vault(args)
    password = get_password("패스워드: ")
    vm.unlock(password)

    nodes_str = args.get("<name>") or args.get("<nodes>")
    if not nodes_str:
        print("사용법: sv distribute <node1,node2,...>")
        print("예: sv distribute d2,g1,g2,v1,v2")
        sys.exit(1)

    nodes = [n.strip() for n in nodes_str.split(",")]
    remote_dir = args.get("--remote-dir", "/opt/sv-vault/shares")

    try:
        result = vm.distribute(nodes, remote_dir=remote_dir)
        print(f"✅ Share 분산 완료 ({result['shamir']})")
        print(f"   Vault ID: {result['vault_id']}")
        for d in result["distributed"]:
            print(f"   ✅ {d['node']} → share[{d['index']}]")
        for f in result["failed"]:
            print(f"   ❌ {f['node']} → share[{f['index']}]: {f.get('error')}")
    except Exception as e:
        print(f"❌ 분산 실패: {e}")
        sys.exit(1)


def cmd_collect(args):
    """sv collect [node1,node2,...]"""
    vm = get_vault(args)

    nodes_str = args.get("<name>") or args.get("<nodes>")
    nodes = [n.strip() for n in nodes_str.split(",")] if nodes_str else None

    try:
        shares = vm.collect(nodes=nodes)
        print(f"📦 {len(shares)}개 share 회수 완료")

        if vm.unlock_shamir(shares):
            print("🔓 Shamir 복원으로 잠금 해제 성공!")
            s = vm.status()
            print(f"   시크릿: {s['entry_count']}개")
        else:
            print("❌ Shamir 복원 실패 — share가 손상되었을 수 있음")
            sys.exit(1)
    except Exception as e:
        print(f"❌ 회수 실패: {e}")
        sys.exit(1)


def cmd_rekey(args):
    """sv rekey — 마스터 키 교체"""
    vm = get_vault(args)
    old_password = get_password("현재 패스워드: ")
    if not vm.unlock(old_password):
        print("❌ 패스워드 틀림")
        sys.exit(1)

    new_password = get_password("새 패스워드: ", confirm=True)

    # 1. 기존 시크릿 보존
    secrets_backup = {}
    for s in vm.list_secrets():
        entry = vm.get(s["name"])
        secrets_backup[s["name"]] = entry

    # 2. 새 마스터 키 생성
    new_master = os.urandom(32)

    # 3. 새 패스워드로 마스터 키 암호화
    engine = VaultEngine()
    blob = engine.encrypt(new_master, new_password, context="master-key")
    with open(vm._key_enc_path, "wb") as f:
        f.write(blob.to_bytes())

    # 4. 새 마스터 키로 데이터 재암호화
    vm._master_key = new_master
    vm._save_data()

    # 5. 새 Shamir share 생성
    n = vm._meta.shamir_n
    k = vm._meta.shamir_k
    shamir = ShamirSecret()
    shares = shamir.split(new_master, n=n, k=k)

    vm._meta.last_modified = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).isoformat()
    vm._save_meta()
    vm._audit("rekey", f"master key rotated, new {k}-of-{n} shares")

    print(f"✅ 마스터 키 교체 완료")
    print(f"   새 키 해시: {__import__('hashlib').sha256(new_master).hexdigest()[:16]}")
    print(f"   Shamir: {k}-of-{n}")
    print()

    for idx, share_bytes in shares:
        b64 = base64.b64encode(share_bytes).decode()
        print(f"   조각 {idx}: {b64}")

    print()
    print("⚠️  기존 share는 무효화됨! 반드시 'sv distribute'로 재분산하세요.")


# ─── 파일 암복호화 ──────────────────────────────────────────

def cmd_encrypt(args):
    """sv encrypt <file>"""
    src = args.get("<name>") or args.get("<file>")
    dst = args.get("-o") or f"{src}.vault"

    if not src or not os.path.isfile(src):
        print(f"❌ 파일 없음: {src}")
        sys.exit(1)

    password = get_password("암호화 패스워드: ", confirm=True)
    engine = VaultEngine()
    blob = engine.encrypt_file(src, dst, password, context="file")

    print(f"✅ 암호화 완료: {dst}")
    print(f"   {engine.info()['cipher']} + {engine.info()['kdf']}")


def cmd_decrypt(args):
    """sv decrypt <file>"""
    src = args.get("<name>") or args.get("<file>")
    if not src:
        print("사용법: sv decrypt <file.vault> [-o output]")
        sys.exit(1)

    dst = args.get("-o")
    if not dst:
        dst = src[:-6] if src.endswith(".vault") else f"{src}.decrypted"

    password = get_password("복호화 패스워드: ")
    engine = VaultEngine()
    try:
        engine.decrypt_file(src, dst, password, original_filename=args.get("--original-name"))
        print(f"✅ 복호화 완료: {dst}")
    except Exception as e:
        print(f"❌ 복호화 실패: {e}")
        sys.exit(1)


# ─── 백업/복원 ──────────────────────────────────────────────

def cmd_backup(args):
    """sv backup <file>"""
    src = args.get("<name>") or args.get("<file>")
    config_dir = args.get("--config-dir")

    if not src or not os.path.isfile(src):
        print(f"❌ 파일 없음: {src}")
        sys.exit(1)

    password = get_password("백업 암호화 패스워드: ", confirm=True)

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
        print("⚠️  vssh 없음 — 로컬 모드")

    sb = SecureBackup(config=cm, transport=transport)
    record = sb.backup(src, password)

    print(f"✅ 백업 완료")
    print(f"   타겟: {', '.join(record.targets)}")
    for node, ok in record.results.items():
        print(f"   {'✅' if ok else '❌'} {node}")


def cmd_restore(args):
    """sv restore"""
    node = args.get("-n")
    output = args.get("-o") or "restored_secrets"
    config_dir = args.get("--config-dir")
    password = get_password("복호화 패스워드: ")

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
            print("❌ 로컬 백업 없음")
            sys.exit(1)
        sb.restore(os.path.join(cm.backup_dir, status["latest_local"]), password, output)

    print(f"✅ 복원 완료 → {output}")


def cmd_verify(args):
    """sv verify"""
    config_dir = args.get("--config-dir")
    password = get_password("검증용 패스워드: ")

    cm = ConfigManager(config_dir=config_dir)
    cm.load()

    transport = None
    try:
        from transport import VsshTransport
        transport = VsshTransport()
    except (FileNotFoundError, ImportError):
        print("⚠️  vssh 없음 — 로컬 모드")

    sb = SecureBackup(config=cm, transport=transport)
    results = sb.verify(password)

    for node, r in results.items():
        print(f"  {'✅' if r['ok'] else '❌'} {node}: {'OK' if r['ok'] else r.get('error', '?')}")


# ─── 기타 ──────────────────────────────────────────────────

def cmd_status(args):
    """sv status"""
    vm = get_vault(args)
    s = vm.status()

    if not s["initialized"]:
        print("❌ 초기화 안 됨. 'sv init' 실행하세요.")
        return

    print(f"SecureVault [{s['vault_id']}]")
    print(f"  상태: {'🔓 잠금 해제' if s['unlocked'] else '🔒 잠금'}")
    print(f"  시크릿: {s['entry_count']}개")
    print(f"  Shamir: {s['shamir']}")
    if s["share_nodes"]:
        print(f"  Share 노드: {', '.join(s['share_nodes'])}")
    print(f"  백업 타겟: {', '.join(s['backup_targets'])}")
    print(f"  생성: {s['created_at']}")
    print(f"  수정: {s['last_modified']}")


def cmd_audit(args):
    """sv audit"""
    vm = get_vault(args)
    last_n = int(args.get("--last", "20"))
    log = vm.get_audit_log(last_n=last_n)

    if not log:
        print("감사 로그 없음")
        return

    for event in log:
        ts = event.get("ts", "?")[:19]
        action = event.get("action", "?")
        detail = event.get("detail", "")
        print(f"  [{ts}] {action:12s} {detail}")

    print(f"\n최근 {len(log)}개 이벤트")


def cmd_export(args):
    """sv export"""
    vm = get_vault(args)
    password = get_password("Vault 패스워드: ")
    vm.unlock(password)

    export_password = get_password("내보내기 암호: ", confirm=True)
    output = args.get("-o", "vault_export.vault")

    data = vm.export_encrypted(export_password)
    with open(output, "wb") as f:
        f.write(data)
    print(f"✅ 내보내기 완료: {output} ({len(data)} bytes)")


def cmd_import(args):
    """sv import <file>"""
    vm = get_vault(args)
    password = get_password("Vault 패스워드: ")
    vm.unlock(password)

    src = args.get("<name>") or args.get("<file>")
    if not src or not os.path.isfile(src):
        print(f"❌ 파일 없음: {src}")
        sys.exit(1)

    import_password = get_password("가져오기 암호: ")
    merge = args.get("--merge", False)

    with open(src, "rb") as f:
        data = f.read()

    count = vm.import_encrypted(data, import_password, merge=bool(merge))
    print(f"✅ {count}개 시크릿 가져옴")


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
    print(f"🔑 AES-256 키:")
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
        key_input = input("키 (hex, Enter=새 키): ").strip()
        key = bytes.fromhex(key_input) if key_input else os.urandom(32)

    shamir = ShamirSecret()
    shares = shamir.split(key, n=n, k=k)
    print(f"Shamir {k}-of-{n}:")
    for idx, share_bytes in shares:
        print(f"  조각 {idx}: {base64.b64encode(share_bytes).decode()}")


def cmd_key_recover(args):
    """sv key recover (인터랙티브)"""
    print("조각 입력 (형식: 번호:base64, 빈 줄=완료)")
    shares = []
    while True:
        line = input(f"조각 {len(shares)+1}> ").strip()
        if not line:
            break
        if ":" not in line:
            print("  형식: 번호:base64")
            continue
        idx_str, b64 = line.split(":", 1)
        try:
            shares.append((int(idx_str), base64.b64decode(b64)))
            print(f"  ✅ 조각 {idx_str} 추가")
        except Exception as e:
            print(f"  ❌ {e}")

    if len(shares) < 2:
        print("최소 2개 필요")
        sys.exit(1)

    shamir = ShamirSecret()
    key = shamir.recover(shares)
    print(f"🔑 복원: {key.hex()}")


def cmd_help(_args=None):
    print(__doc__)


# ─── 메인 ───────────────────────────────────────────────────

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
        print(f"❌ key 하위 명령: generate, split, recover")
        sys.exit(1)

    if cmd_name in COMMANDS:
        COMMANDS[cmd_name](parse_args(argv[1:]))
    else:
        print(f"❌ 알 수 없는 명령: {cmd_name}")
        cmd_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
