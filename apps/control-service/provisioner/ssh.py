"""SSH session protocol and Paramiko-backed client."""

from __future__ import annotations

import posixpath
import shlex
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@runtime_checkable
class SSHSession(Protocol):
    """Minimal remote ops used by the provisioner (mockable in tests)."""

    def run(self, command: str, *, timeout: float = 120.0) -> CommandResult: ...

    def upload_file(
        self, local_path: Path, remote_path: str, *, mode: int = 0o644
    ) -> None: ...

    def upload_tree(self, local_dir: Path, remote_dir: str) -> None: ...

    def close(self) -> None: ...


class SSHError(RuntimeError):
    """Transport or remote command failure."""


class ParamikoSSHSession:
    """Paramiko implementation. Connect timeout 15s; retries transport errors twice."""

    def __init__(
        self,
        host: str,
        username: str,
        *,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: int = 22,
        connect_timeout: float = 15.0,
    ) -> None:
        try:
            import paramiko
        except ImportError as e:  # pragma: no cover - exercised when dep missing
            raise SSHError(
                "paramiko is required for live SSH; pip install -r "
                "apps/control-service/requirements.txt"
            ) from e

        self.host = host
        self.username = username
        self.port = port
        self._client = paramiko.SSHClient()
        # Host-key pin lands in Setup Wizard (PR8); AutoAdd for CLI dogfood only.
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                connect_kwargs: dict = {
                    "hostname": host,
                    "port": port,
                    "username": username,
                    "timeout": connect_timeout,
                    "allow_agent": key_filename is None and password is None,
                    "look_for_keys": key_filename is None and password is None,
                }
                if password is not None:
                    connect_kwargs["password"] = password
                if key_filename is not None:
                    connect_kwargs["key_filename"] = key_filename
                self._client.connect(**connect_kwargs)
                break
            except Exception as e:  # noqa: BLE001 — retry transport only
                last_err = e
                if _is_auth_error(e):
                    raise SSHError(f"SSH auth failed for {username}@{host}: {e}") from e
                if attempt == 2:
                    raise SSHError(f"SSH connect failed for {host}: {e}") from e
                time.sleep(0.5 * (attempt + 1))
        else:  # pragma: no cover
            raise SSHError(f"SSH connect failed for {host}: {last_err}")

    def run(self, command: str, *, timeout: float = 120.0) -> CommandResult:
        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        try:
            stdin.close()
        except Exception:  # noqa: BLE001
            pass
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        return CommandResult(exit_code=code, stdout=out, stderr=err)

    def upload_file(
        self, local_path: Path, remote_path: str, *, mode: int = 0o644
    ) -> None:
        local_path = Path(local_path)
        if not local_path.is_file():
            raise SSHError(f"local file not found: {local_path}")
        sftp = self._client.open_sftp()
        try:
            parent = posixpath.dirname(remote_path)
            if parent and parent != "/":
                _sftp_makedirs(sftp, parent)
            sftp.put(str(local_path), remote_path)
            sftp.chmod(remote_path, mode)
        finally:
            sftp.close()

    def upload_tree(self, local_dir: Path, remote_dir: str) -> None:
        """Tar local_dir to a temp file, SFTP put, extract on remote."""
        local_dir = Path(local_dir)
        if not local_dir.is_dir():
            raise SSHError(f"local tree not found: {local_dir}")
        remote_tar = f"/tmp/iotgw-bundle-{int(time.time())}.tar.gz"
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            with tarfile.open(tmp_path, mode="w:gz") as tar:
                tar.add(str(local_dir), arcname=".")
            self.upload_file(tmp_path, remote_tar, mode=0o600)
        finally:
            tmp_path.unlink(missing_ok=True)
        quoted_root = shlex.quote(remote_dir)
        quoted_tar = shlex.quote(remote_tar)
        result = self.run(
            f"mkdir -p {quoted_root} && tar xzf {quoted_tar} -C {quoted_root} "
            f"&& rm -f {quoted_tar}",
            timeout=300.0,
        )
        if not result.ok:
            raise SSHError(
                f"remote extract failed ({result.exit_code}): {result.stderr or result.stdout}"
            )

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> "ParamikoSSHSession":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _is_auth_error(exc: BaseException) -> bool:
    name = type(exc).__name__
    msg = str(exc).lower()
    if "AuthenticationException" in name or "PasswordRequiredException" in name:
        return True
    return "authentication" in msg or "auth failed" in msg


def _sftp_makedirs(sftp: object, path: str) -> None:
    """mkdir -p over SFTP."""
    parts = []
    cur = path
    while cur and cur != "/":
        parts.append(cur)
        cur = posixpath.dirname(cur)
    for p in reversed(parts):
        try:
            sftp.stat(p)  # type: ignore[attr-defined]
        except OSError:
            try:
                sftp.mkdir(p)  # type: ignore[attr-defined]
            except OSError:
                pass


# Re-export for callers that still import shell_quote from this module.
shell_quote = shlex.quote
