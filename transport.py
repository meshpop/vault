"""
SecureVault Transport Layer — VsshTransport

vssh 바이너리를 감싸는 래퍼. SecureVault의 모든 원격 작업은 이 인터페이스를 통함.
SSH/SCP/paramiko 완전 제거. Transport fallback 없음.
vssh가 안 되면 안 되는 것.

transport-agnostic: 하부가 Wire든 Tailscale이든 LAN이든
vssh는 IP만 닿으면 동작.
"""

import subprocess
import shutil
import hashlib
import os
from typing import Optional
from dataclasses import dataclass


@dataclass
class ExecResult:
    """원격 명령 실행 결과"""
    node: str
    stdout: str
    stderr: str
    returncode: int
    success: bool


class VsshTransport:
    """SecureVault 전용 vssh 래퍼

    모든 원격 작업 (exec, put, get, broadcast)은 이 클래스를 통해서만 수행.
    SSH fallback 없음. vssh binary가 없으면 초기화 시 에러.
    """

    def __init__(self, vssh_path: Optional[str] = None, timeout: int = 30):
        """
        Args:
            vssh_path: vssh 바이너리 경로 (None이면 자동 탐색)
            timeout: 기본 타임아웃 (초)
        """
        self.vssh = vssh_path or shutil.which("vssh") or "/usr/local/bin/vssh"
        self.timeout = timeout

        if not os.path.isfile(self.vssh):
            raise FileNotFoundError(
                f"vssh 바이너리를 찾을 수 없음: {self.vssh}\n"
                "SecureVault는 vssh 없이 동작하지 않습니다."
            )

    def _run(self, args: list, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        """vssh 프로세스 실행"""
        cmd = [self.vssh] + args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout or self.timeout,
            env={
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "NO_COLOR": "1",
                "TERM": "dumb",
            },
        )

    # ─── exec ────────────────────────────────────────────────

    def exec(self, node: str, cmd: str, timeout: Optional[int] = None) -> ExecResult:
        """원격 명령 실행

        Args:
            node: 노드 이름 (예: "node1", "node2", "node3")
            cmd: 실행할 명령
            timeout: 타임아웃 (초)

        Returns:
            ExecResult
        """
        try:
            r = self._run(["exec", node, cmd], timeout=timeout)
            return ExecResult(
                node=node,
                stdout=r.stdout.strip(),
                stderr=r.stderr.strip(),
                returncode=r.returncode,
                success=r.returncode == 0,
            )
        except subprocess.TimeoutExpired:
            return ExecResult(
                node=node,
                stdout="",
                stderr=f"timeout ({timeout or self.timeout}s)",
                returncode=-1,
                success=False,
            )
        except Exception as e:
            return ExecResult(
                node=node,
                stdout="",
                stderr=str(e),
                returncode=-1,
                success=False,
            )

    # ─── put (파일 업로드) ───────────────────────────────────

    def put(
        self,
        local_path: str,
        node: str,
        remote_path: str,
        timeout: Optional[int] = None,
        verify: bool = True,
    ) -> bool:
        """파일을 원격 노드에 업로드

        Args:
            local_path: 로컬 파일 경로
            node: 대상 노드
            remote_path: 원격 저장 경로
            timeout: 타임아웃 (초)
            verify: 업로드 후 MD5 검증

        Returns:
            성공 여부
        """
        if not os.path.isfile(local_path):
            raise FileNotFoundError(f"로컬 파일 없음: {local_path}")

        try:
            r = self._run(
                ["put", local_path, f"{node}:{remote_path}"],
                timeout=timeout or 120,
            )

            if r.returncode != 0:
                return False

            if verify:
                local_md5 = self._file_md5(local_path)
                result = self.exec(node, f"md5sum {remote_path} | cut -d' ' -f1", timeout=30)
                if result.success and result.stdout.strip() == local_md5:
                    return True
                # md5sum 없으면 (Synology 등) sha256 시도
                result = self.exec(node, f"sha256sum {remote_path} | cut -d' ' -f1", timeout=30)
                local_sha = self._file_sha256(local_path)
                return result.success and result.stdout.strip() == local_sha

            return True

        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False

    # ─── get (파일 다운로드) ──────────────────────────────────

    def get(
        self,
        node: str,
        remote_path: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> bool:
        """원격 노드에서 파일 다운로드

        Args:
            node: 소스 노드
            remote_path: 원격 파일 경로
            local_path: 로컬 저장 경로
            timeout: 타임아웃 (초)

        Returns:
            성공 여부
        """
        try:
            r = self._run(
                ["get", f"{node}:{remote_path}", local_path],
                timeout=timeout or 120,
            )
            return r.returncode == 0 and os.path.isfile(local_path)
        except (subprocess.TimeoutExpired, Exception):
            return False

    # ─── broadcast ───────────────────────────────────────────

    def broadcast(
        self,
        cmd: str,
        nodes: Optional[list] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, ExecResult]:
        """전 노드(또는 지정 노드)에 명령 브로드캐스트

        킬스위치, 긴급 잠금 등에 사용.

        Args:
            cmd: 실행할 명령
            nodes: 대상 노드 목록 (None이면 전체)
            timeout: 노드당 타임아웃

        Returns:
            {node_name: ExecResult}
        """
        if nodes is None:
            # vssh status에서 노드 목록 가져오기
            r = self._run(["status"], timeout=10)
            if r.returncode == 0:
                nodes = self._parse_status_nodes(r.stdout)
            else:
                return {}

        results = {}
        for node in nodes:
            results[node] = self.exec(node, cmd, timeout=timeout)

        return results

    # ─── health ──────────────────────────────────────────────

    def health_ping(self, node: str, timeout: int = 5) -> bool:
        """노드 헬스 체크 (빠른 핑)"""
        result = self.exec(node, "echo OK", timeout=timeout)
        return result.success and "OK" in result.stdout

    def health_check(self, node: str, timeout: int = 10) -> dict:
        """노드 상세 헬스 체크"""
        cmd = " && ".join([
            "echo HOSTNAME=$(hostname)",
            "echo UPTIME=$(uptime -s 2>/dev/null || uptime)",
            "echo DISK=$(df / --output=pcent 2>/dev/null | tail -1 | tr -d ' %' || df -h / | tail -1 | awk '{print $5}' | tr -d '%')",
            "echo LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1}' || sysctl -n vm.loadavg 2>/dev/null | awk '{print $2}')",
            "echo MEM=$(free 2>/dev/null | awk '/Mem:/{printf \"%.0f\", $3/$2*100}' || echo 'N/A')",
        ])
        result = self.exec(node, cmd, timeout=timeout)
        if not result.success:
            return {"node": node, "online": False, "error": result.stderr}

        info = {"node": node, "online": True}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, _, val = line.partition("=")
                info[key.strip().lower()] = val.strip()
        return info

    # ─── atomic upload (백업용) ───────────────────────────────

    def atomic_put(
        self,
        local_path: str,
        node: str,
        remote_path: str,
        timeout: Optional[int] = None,
    ) -> bool:
        """원자적 파일 업로드 (tmp → rename)

        백업 파일 업로드 시 사용. 중간에 실패해도 기존 파일 안 깨짐.
        """
        remote_dir = os.path.dirname(remote_path)
        remote_name = os.path.basename(remote_path)
        tmp_path = f"{remote_dir}/.tmp_{remote_name}_{os.getpid()}"

        # 1. tmp에 업로드
        if not self.put(local_path, node, tmp_path, timeout=timeout, verify=True):
            # 실패 시 tmp 정리
            self.exec(node, f"rm -f {tmp_path}", timeout=5)
            return False

        # 2. 디렉토리 확인 및 rename
        result = self.exec(
            node,
            f"mkdir -p {remote_dir} && mv {tmp_path} {remote_path}",
            timeout=10,
        )

        if not result.success:
            self.exec(node, f"rm -f {tmp_path}", timeout=5)
            return False

        return True

    # ─── 유틸리티 ────────────────────────────────────────────

    @staticmethod
    def _file_md5(path: str) -> str:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _parse_status_nodes(status_output: str) -> list:
        """vssh status 출력에서 노드 이름 추출"""
        nodes = []
        for line in status_output.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-", "=", "Node")):
                parts = line.split()
                if parts:
                    nodes.append(parts[0])
        return nodes

    def info(self) -> dict:
        """트랜스포트 정보"""
        return {
            "protocol": "vssh",
            "binary": self.vssh,
            "default_timeout": self.timeout,
            "transport_agnostic": True,
            "supported_networks": ["Wire", "Tailscale", "LAN", "Direct IP"],
            "ssh_fallback": False,
            "note": "SSH/SCP/paramiko 완전 제거. vssh가 안 되면 안 되는 것.",
        }
