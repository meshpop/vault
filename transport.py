"""
SecureVault Transport Layer — VsshTransport

Wrapper around the vssh binary. All SecureVault remote operations go through this interface.
SSH/SCP/paramiko completely removed. No transport fallback.
If vssh doesn't work, nothing works.

transport-agnostic: underlying network may be Wire, Tailscale, or LAN —
vssh works as long as IP is reachable.
"""

import subprocess
import shutil
import hashlib
import os
from typing import Optional
from dataclasses import dataclass


@dataclass
class ExecResult:
    """Remote command execution result"""
    node: str
    stdout: str
    stderr: str
    returncode: int
    success: bool


class VsshTransport:
    """SecureVault-specific vssh wrapper

    All remote operations (exec, put, get, broadcast) go through this class only.
    No SSH fallback. Raises error on init if vssh binary is missing.
    """

    def __init__(self, vssh_path: Optional[str] = None, timeout: int = 30):
        """
        Args:
            vssh_path: vssh binary path (None = auto-detect)
            timeout: default timeout (seconds)
        """
        self.vssh = vssh_path or shutil.which("vssh") or "/usr/local/bin/vssh"
        self.timeout = timeout

        if not os.path.isfile(self.vssh):
            raise FileNotFoundError(
                f"vssh binary not found: {self.vssh}\n"
                "SecureVault cannot operate without vssh."
            )

    def _run(self, args: list, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        """Run vssh process"""
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
        """Execute remote command

        Args:
            node: node name (e.g. "node1", "node2", "node3")
            cmd: command to run
            timeout: timeout (seconds)

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

    # ─── put (file upload) ───────────────────────────────────

    def put(
        self,
        local_path: str,
        node: str,
        remote_path: str,
        timeout: Optional[int] = None,
        verify: bool = True,
    ) -> bool:
        """Upload file to remote node

        Args:
            local_path: local file path
            node: target node
            remote_path: remote storage path
            timeout: timeout (seconds)
            verify: MD5 verify after upload

        Returns:
            success bool
        """
        if not os.path.isfile(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")

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
                # fallback to sha256 if md5sum not available (e.g. Synology)
                result = self.exec(node, f"sha256sum {remote_path} | cut -d' ' -f1", timeout=30)
                local_sha = self._file_sha256(local_path)
                return result.success and result.stdout.strip() == local_sha

            return True

        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False

    # ─── get (file download) ──────────────────────────────────

    def get(
        self,
        node: str,
        remote_path: str,
        local_path: str,
        timeout: Optional[int] = None,
    ) -> bool:
        """Download file from remote node

        Args:
            node: source node
            remote_path: remote file path
            local_path: local storage path
            timeout: timeout (seconds)

        Returns:
            success bool
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
        """Broadcast command to all (or specified) nodes

        Used for kill-switch, emergency lock, etc.

        Args:
            cmd: command to run
            nodes: target node list (None = all)
            timeout: per-node timeout

        Returns:
            {node_name: ExecResult}
        """
        if nodes is None:
            # get node list from vssh status
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
        """Node health check (fast ping)"""
        result = self.exec(node, "echo OK", timeout=timeout)
        return result.success and "OK" in result.stdout

    def health_check(self, node: str, timeout: int = 10) -> dict:
        """Detailed node health check"""
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

    # ─── atomic upload (for backup) ───────────────────────────────

    def atomic_put(
        self,
        local_path: str,
        node: str,
        remote_path: str,
        timeout: Optional[int] = None,
    ) -> bool:
        """Atomic file upload (tmp → rename)

        Used for backup uploads. Existing file not corrupted on partial failure.
        """
        remote_dir = os.path.dirname(remote_path)
        remote_name = os.path.basename(remote_path)
        tmp_path = f"{remote_dir}/.tmp_{remote_name}_{os.getpid()}"

        # 1. upload to tmp
        if not self.put(local_path, node, tmp_path, timeout=timeout, verify=True):
            # clean up tmp on failure
            self.exec(node, f"rm -f {tmp_path}", timeout=5)
            return False

        # 2. verify directory and rename
        result = self.exec(
            node,
            f"mkdir -p {remote_dir} && mv {tmp_path} {remote_path}",
            timeout=10,
        )

        if not result.success:
            self.exec(node, f"rm -f {tmp_path}", timeout=5)
            return False

        return True

    # ─── Utilities ────────────────────────────────────────────

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
        """Extract node names from vssh status output"""
        nodes = []
        for line in status_output.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "-", "=", "Node")):
                parts = line.split()
                if parts:
                    nodes.append(parts[0])
        return nodes

    def info(self) -> dict:
        """Transport info"""
        return {
            "protocol": "vssh",
            "binary": self.vssh,
            "default_timeout": self.timeout,
            "transport_agnostic": True,
            "supported_networks": ["Wire", "Tailscale", "LAN", "Direct IP"],
            "ssh_fallback": False,
            "note": "SSH/SCP/paramiko completely removed. vssh only.",
        }
