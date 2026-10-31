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

    def run(
        self,
        command: str,
        *,
        timeout: float = 120.0,
        stdin: Optional[str] = None,
    ) -> CommandResult: ...

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

    def run(
        self,
        command: str,
        *,
        timeout: float = 120.0,
        stdin: Optional[str] = None,
    ) -> CommandResult:
        """Run ``command`` and return stdout/stderr/exit.

        Uses a **wall-clock** deadline. Paramiko's per-read channel timeout would
        abort silent long jobs (e.g. ``curl -fsSL`` Kafka tarball) even while
        the remote process is healthy.
        """
        import socket

        # Secrets (e.g. sudo password) must go on stdin — never on remote argv.
        chan_in, stdout, stderr = self._client.exec_command(command, timeout=None)
        channel = stdout.channel
        try:
            if stdin is not None:
                chan_in.write(stdin if stdin.endswith("\n") else stdin + "\n")
                chan_in.flush()
            chan_in.channel.shutdown_write()
        except Exception:  # noqa: BLE001
            try:
                chan_in.close()
            except Exception:  # noqa: BLE001
                pass

        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        deadline = time.time() + max(1.0, float(timeout))
        channel.settimeout(1.0)
        while True:
            if channel.exit_status_ready():
                # Drain remaining buffered output after exit.
                while channel.recv_ready():
                    chunk = channel.recv(65536)
                    if not chunk:
                        break
                    out_chunks.append(chunk)
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    if not chunk:
                        break
                    err_chunks.append(chunk)
                break
            if time.time() > deadline:
                try:
                    channel.close()
                except Exception:  # noqa: BLE001
                    pass
                raise TimeoutError(
                    f"remote command exceeded {timeout:.0f}s wall clock"
                )
            try:
                if channel.recv_ready():
                    chunk = channel.recv(65536)
                    if chunk:
                        out_chunks.append(chunk)
                if channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    if chunk:
                        err_chunks.append(chunk)
            except socket.timeout:
                pass
            time.sleep(0.05)

        code = channel.recv_exit_status()
        out = b"".join(out_chunks).decode("utf-8", errors="replace")
        err = b"".join(err_chunks).decode("utf-8", errors="replace")
        # Also pull anything left on the file wrappers (Paramiko buffers).
        try:
            extra_out = stdout.read()
            if extra_out:
                out += (
                    extra_out.decode("utf-8", errors="replace")
                    if isinstance(extra_out, bytes)
                    else str(extra_out)
                )
        except Exception:  # noqa: BLE001
            pass
        try:
            extra_err = stderr.read()
            if extra_err:
                err += (
                    extra_err.decode("utf-8", errors="replace")
                    if isinstance(extra_err, bytes)
                    else str(extra_err)
                )
        except Exception:  # noqa: BLE001
            pass
        return CommandResult(exit_code=code, stdout=out, stderr=err)

    def read_text(self, path: str) -> str:
        """Read a remote UTF-8 text file via SFTP (playbook / fake teardown API)."""
        sftp = self._client.open_sftp()
        try:
            with sftp.open(path, "r") as fh:
                data = fh.read()
        except FileNotFoundError:
            raise
        except OSError as exc:
            # Paramiko raises IOError subclasses; normalize missing files.
            if getattr(exc, "errno", None) in (2, None) and "No such file" in str(exc):
                raise FileNotFoundError(path) from exc
            raise
        finally:
            sftp.close()
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)

    def write_text(self, path: str, content: str, *, mode: int = 0o644) -> None:
        """Write a remote UTF-8 text file via SFTP (tmp + rename)."""
        data = content.encode("utf-8")
        sftp = self._client.open_sftp()
        try:
            parent = posixpath.dirname(path)
            if parent and parent != "/":
                _sftp_makedirs(sftp, parent)
            tmp = f"{path}.tmp.{int(time.time())}"
            with sftp.open(tmp, "w") as fh:
                fh.write(data)
            try:
                sftp.chmod(tmp, mode)
            except OSError:
                pass
            try:
                sftp.remove(path)
            except OSError:
                pass
            sftp.rename(tmp, path)
            try:
                sftp.chmod(path, mode)
            except OSError:
                pass
        finally:
            sftp.close()

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
