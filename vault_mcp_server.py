#!/usr/bin/env python3
"""
SecureVault MCP Server — vault 시크릿 관리

Tools:
- vault_status       : vault 상태 조회 (잠금 여부, 시크릿 수 등)
- vault_init         : vault 초기화 (최초 1회)
- vault_unlock       : 패스워드로 잠금 해제 (세션 유지)
- vault_lock         : 잠금 (메모리 클리어)
- vault_add          : 시크릿 추가
- vault_get          : 시크릿 값 조회
- vault_update       : 시크릿 수정
- vault_delete       : 시크릿 삭제
- vault_list         : 시크릿 목록 (값 제외)
- vault_search       : 이름/태그로 검색
- vault_encrypt_file : 파일 암호화
- vault_decrypt_file : 파일 복호화
- vault_distribute   : Shamir share를 노드에 분산
- vault_collect      : 노드에서 share 회수 → 잠금 해제
- vault_audit        : 감사 로그 조회

세션: vault_unlock 후 동일 프로세스 내에서 계속 잠금 해제 상태 유지.
      패스워드 없이도 get/list/add 등 가능.

Run: python3 -m vault.vault_mcp_server
  or python3 vault_mcp_server.py
"""

import json
import sys
import os

# vault 패키지가 현재 파일과 같은 디렉토리에 있으므로 경로 추가
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── 세션 관리 ────────────────────────────────────────────

DEFAULT_VAULT_DIR = os.path.expanduser("~/.sv-vault")
_vault_managers: dict = {}  # vault_dir -> SecureVaultManager


def _get_vm(vault_dir: str = ""):
    """SecureVaultManager 인스턴스를 반환 (없으면 생성)."""
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
    """이미 잠금 해제 상태면 None 반환, 아니면 password로 해제 시도.
    실패 시 에러 dict 반환."""
    if vm.is_unlocked:
        return None
    if not password:
        return {"error": "Vault이 잠겨있습니다. password 파라미터를 제공하거나 먼저 vault_unlock을 호출하세요."}
    if not vm.unlock(password):
        return {"error": "패스워드가 틀렸습니다."}
    return None


# ─── Tool 구현 ────────────────────────────────────────────

def tool_vault_status(params: dict) -> dict:
    """vault 상태 조회."""
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
    """vault 초기화 (최초 1회). password, shamir_n, shamir_k 지정."""
    import base64
    vault_dir = params.get("vault_dir", "")
    password = params.get("password", "")
    n = int(params.get("shamir_n", 5))
    k = int(params.get("shamir_k", 3))

    if not password:
        return {"error": "password 파라미터가 필요합니다."}

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
            "note": f"각 share를 별도 안전한 위치에 보관하세요. {k}개만 있어도 복구 가능.",
        }
    except FileExistsError:
        return {"error": "Vault이 이미 초기화되어 있습니다. 재초기화하려면 vault 디렉토리를 삭제하세요."}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_unlock(params: dict) -> dict:
    """패스워드로 vault 잠금 해제. 이후 이 프로세스 내에서 계속 해제 상태."""
    vault_dir = params.get("vault_dir", "")
    password = params.get("password", "")
    if not password:
        return {"error": "password 파라미터가 필요합니다."}
    try:
        vm = _get_vm(vault_dir)
        if vm.is_unlocked:
            s = vm.status()
            return {"ok": True, "already_unlocked": True, "entry_count": s.get("entry_count", 0)}
        if vm.unlock(password):
            s = vm.status()
            return {"ok": True, "entry_count": s.get("entry_count", 0)}
        return {"error": "패스워드가 틀렸습니다."}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_lock(params: dict) -> dict:
    """vault 잠금 (메모리에서 마스터 키 제거)."""
    vault_dir = params.get("vault_dir", "")
    try:
        vm = _get_vm(vault_dir)
        vm.lock()
        return {"ok": True, "message": "Vault 잠금 완료 — 메모리 클리어됨"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_add(params: dict) -> dict:
    """시크릿 추가. name, value, password(옵션) 등."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    value = params.get("value", "")
    if not name:
        return {"error": "name 파라미터가 필요합니다."}
    if not value:
        return {"error": "value 파라미터가 필요합니다."}

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
        return {"error": f"이미 존재하는 이름: {e}"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_get(params: dict) -> dict:
    """시크릿 값 조회. 보안상 주의."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    if not name:
        return {"error": "name 파라미터가 필요합니다."}

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        entry = vm.get(name)
        if not entry:
            return {"error": f"시크릿 없음: {name}"}
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
    """시크릿 수정. value, category, tags, note 중 하나 이상 지정."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    if not name:
        return {"error": "name 파라미터가 필요합니다."}

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
            return {"error": "수정할 항목이 없습니다. value, category, tags, note 중 하나를 지정하세요."}

        entry = vm.update(name, **kwargs)
        return {"ok": True, "name": entry.name, "updated_at": entry.updated_at}
    except KeyError as e:
        return {"error": f"시크릿 없음: {e}"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_delete(params: dict) -> dict:
    """시크릿 삭제."""
    vault_dir = params.get("vault_dir", "")
    name = params.get("name", "")
    if not name:
        return {"error": "name 파라미터가 필요합니다."}

    try:
        vm = _get_vm(vault_dir)
        err = _unlock_or_fail(vm, params.get("password", ""))
        if err:
            return err
        if vm.delete(name):
            return {"ok": True, "deleted": name}
        return {"error": f"시크릿 없음: {name}"}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_list(params: dict) -> dict:
    """시크릿 목록 조회 (값 제외)."""
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
    """시크릿 이름/태그 검색."""
    vault_dir = params.get("vault_dir", "")
    query = params.get("query", "")
    if not query:
        return {"error": "query 파라미터가 필요합니다."}

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
    """파일을 AES-256-GCM으로 암호화."""
    src = params.get("file", "")
    dst = params.get("output", "") or f"{src}.vault"
    password = params.get("password", "")

    if not src:
        return {"error": "file 파라미터가 필요합니다."}
    if not os.path.isfile(src):
        return {"error": f"파일 없음: {src}"}
    if not password:
        return {"error": "password 파라미터가 필요합니다."}

    try:
        from engine import VaultEngine
        engine = VaultEngine()
        engine.encrypt_file(src, dst, password, context="file")
        size = os.path.getsize(dst)
        return {"ok": True, "output": dst, "size_bytes": size}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_decrypt_file(params: dict) -> dict:
    """암호화된 파일(.vault)을 복호화."""
    src = params.get("file", "")
    dst = params.get("output", "") or (src[:-6] if src.endswith(".vault") else f"{src}.decrypted")
    password = params.get("password", "")

    if not src:
        return {"error": "file 파라미터가 필요합니다."}
    if not os.path.isfile(src):
        return {"error": f"파일 없음: {src}"}
    if not password:
        return {"error": "password 파라미터가 필요합니다."}

    try:
        from engine import VaultEngine
        engine = VaultEngine()
        engine.decrypt_file(src, dst, password)
        size = os.path.getsize(dst)
        return {"ok": True, "output": dst, "size_bytes": size}
    except Exception as e:
        msg = str(e).strip()
        if not msg or type(e).__name__ == "InvalidTag":
            msg = "패스워드가 틀리거나 파일이 손상됨 (AES-GCM 인증 실패)"
        return {"error": msg}


def tool_vault_distribute(params: dict) -> dict:
    """Shamir share를 지정된 노드에 자동 분산."""
    vault_dir = params.get("vault_dir", "")
    nodes_str = params.get("nodes", "")
    if not nodes_str:
        return {"error": "nodes 파라미터가 필요합니다. 예: 'd2,g1,g2,v1,v2'"}

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
    """노드에서 Shamir share 회수 → 마스터 키 복원 → 잠금 해제."""
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
        return {"error": "Shamir 복원 실패 — share가 손상되었거나 부족합니다."}
    except Exception as e:
        return {"error": str(e)}


def tool_vault_audit(params: dict) -> dict:
    """감사 로그 조회."""
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


# ─── MCP 서버 ──────────────────────────────────────────────

TOOLS = [
    {
        "name": "vault_status",
        "description": "SecureVault 상태 조회. 초기화 여부, 잠금 상태, 시크릿 수, Shamir 설정, 백업 타겟 등.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_init",
        "description": "SecureVault 초기화 (최초 1회). 마스터 키 생성 + Shamir 분할. Shamir share를 출력하니 안전한 곳에 보관.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "마스터 패스워드 (강력한 것 사용 권장)"},
                "shamir_n": {"type": "integer", "description": "Shamir 총 조각 수 (기본: 5)", "default": 5},
                "shamir_k": {"type": "integer", "description": "복구에 필요한 조각 수 (기본: 3)", "default": 3},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["password"]
        }
    },
    {
        "name": "vault_unlock",
        "description": "패스워드로 vault 잠금 해제. 이후 동일 세션에서 password 없이 시크릿 접근 가능.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "password": {"type": "string", "description": "마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["password"]
        }
    },
    {
        "name": "vault_lock",
        "description": "vault 잠금. 메모리에서 마스터 키를 제거하여 보안 강화.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_add",
        "description": "시크릿 추가. name과 value 필수. category, tags, note 선택.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "시크릿 이름 (예: db_password, github_token)"},
                "value": {"type": "string", "description": "시크릿 값"},
                "category": {"type": "string", "description": "분류 (password/api_key/token/cert/default)", "default": "default"},
                "tags": {"type": "string", "description": "태그 (쉼표 구분, 예: prod,db)"},
                "note": {"type": "string", "description": "메모"},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["name", "value"]
        }
    },
    {
        "name": "vault_get",
        "description": "시크릿 값 조회. 민감 정보이므로 필요할 때만 호출.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "시크릿 이름"},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "vault_update",
        "description": "시크릿 수정. value, category, tags, note 중 원하는 항목만 지정.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "시크릿 이름"},
                "value": {"type": "string", "description": "새 값"},
                "category": {"type": "string", "description": "새 분류"},
                "tags": {"type": "string", "description": "새 태그 (쉼표 구분)"},
                "note": {"type": "string", "description": "새 메모"},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "vault_delete",
        "description": "시크릿 삭제. 복구 불가 — 신중하게 사용.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "삭제할 시크릿 이름"},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "vault_list",
        "description": "시크릿 목록 조회 (값 제외). category로 필터링 가능.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "카테고리 필터 (선택)"},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_search",
        "description": "시크릿 이름/태그로 검색.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "검색어"},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "vault_encrypt_file",
        "description": "파일을 AES-256-GCM으로 암호화. 출력 파일명은 <원본>.vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "암호화할 파일 경로"},
                "output": {"type": "string", "description": "출력 파일 경로 (기본: <file>.vault)"},
                "password": {"type": "string", "description": "암호화 패스워드"}
            },
            "required": ["file", "password"]
        }
    },
    {
        "name": "vault_decrypt_file",
        "description": "vault 암호화 파일을 복호화. 잘못된 패스워드 시 명확한 오류 메시지.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "description": "복호화할 파일 경로 (.vault)"},
                "output": {"type": "string", "description": "출력 파일 경로 (기본: .vault 확장자 제거)"},
                "password": {"type": "string", "description": "복호화 패스워드"}
            },
            "required": ["file", "password"]
        }
    },
    {
        "name": "vault_distribute",
        "description": "Shamir share를 지정 노드에 자동 분산. 분산 후 단일 패스워드 없이도 K개 노드로 복구 가능.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "nodes": {"type": "string", "description": "분산 대상 노드 (쉼표 구분, 예: 'd2,g1,g2,v1,v2')"},
                "remote_dir": {"type": "string", "description": "원격 저장 경로 (기본: /opt/sv-vault/shares)", "default": "/opt/sv-vault/shares"},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": ["nodes"]
        }
    },
    {
        "name": "vault_collect",
        "description": "노드에서 Shamir share 회수 → 마스터 키 복원 → vault 잠금 해제. K개 이상이면 패스워드 없이 복원.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "nodes": {"type": "string", "description": "회수할 노드 (쉼표 구분, 비어있으면 자동 탐색)"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
            },
            "required": []
        }
    },
    {
        "name": "vault_audit",
        "description": "감사 로그 조회. 시크릿 접근/수정 이력 확인.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "last": {"type": "integer", "description": "최근 N개 이벤트 (기본: 20)", "default": 20},
                "password": {"type": "string", "description": "Vault이 잠겨있을 경우 마스터 패스워드"},
                "vault_dir": {"type": "string", "description": "Vault 디렉토리 (기본: ~/.sv-vault)"}
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


# ─── JSON-RPC / MCP 프로토콜 ──────────────────────────────

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
