"""Paramiko SSH/SFTP session for gateway mutations."""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from typing import Optional

import paramiko

from .shellutil import shell_quote

_DEFAULT_BACKUP_KEEP = 5


@dataclass
class SSHTarget:
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    key_filename: Optional[str] = None
    pkey: Optional[paramiko.PKey] = None
    # When set, refuse connect if remote key base64 does not match.
    # Handshake uses WarningPolicy so Paramiko does not Reject before verify.
    host_key_base64: Optional[str] = None
    # Extra OpenSSH known_hosts files (e.g. app data pin store).
    known_hosts_paths: Optional[list[str]] = None
    # First-connect / lab only — playbooks should pass a pin instead.
    allow_unknown_host: bool = False


@dataclass
class CommandResult:
    argv: str
    exit_code: int
    stdout: str
    stderr: str

    def check(self) -> CommandResult:
        if self.exit_code != 0:
            raise RuntimeError(
                f"remote command failed ({self.exit_code}): {self.argv}\n"
                f"stdout: {self.stdout}\nstderr: {self.stderr}"
            )
        return self


class SSHClient:
    """Thin Paramiko wrapper with backup/read/write helpers."""

    def __init__(
        self,
        target: SSHTarget,
        *,
        connect_timeout: float = 15.0,
        command_timeout: float = 120.0,
        transport_retries: int = 2,
        backup_keep: int = _DEFAULT_BACKUP_KEEP,
    ) -> None:
        self.target = target
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.transport_retries = transport_retries
        self.backup_keep = max(1, backup_keep)
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    def connect(self) -> SSHClient:
        last_err: Exception | None = None
        attempts = 1 + max(0, self.transport_retries)
        for attempt in range(attempts):
            try:
                client = paramiko.SSHClient()
                client.load_system_host_keys()
                known = os.path.expanduser("~/.ssh/known_hosts")
                if os.path.isfile(known):
                    try:
                        client.load_host_keys(known)
                    except OSError:
                        pass
                for extra in self.target.known_hosts_paths or []:
                    if extra and os.path.isfile(extra):
                        try:
                            client.load_host_keys(extra)
                        except OSError:
                            pass
                if self.target.host_key_base64:
                    # Allow handshake; pin enforced via post-connect base64 check.
                    # RejectPolicy would fail before that check on fresh machines.
                    client.set_missing_host_key_policy(paramiko.WarningPolicy())
                elif self.target.allow_unknown_host:
                    client.set_missing_host_key_policy(paramiko.WarningPolicy())
                else:
                    # K7: pin or known_hosts required for secret-bearing mutations.
                    client.set_missing_host_key_policy(paramiko.RejectPolicy())
                connect_kwargs: dict = {
                    "hostname": self.target.host,
                    "port": self.target.port,
                    "username": self.target.username,
                    "timeout": self.connect_timeout,
                    "allow_agent": True,
                    "look_for_keys": self.target.key_filename is None
                    and self.target.pkey is None,
                }
                if self.target.password is not None:
                    connect_kwargs["password"] = self.target.password
                if self.target.key_filename:
                    connect_kwargs["key_filename"] = self.target.key_filename
                if self.target.pkey is not None:
                    connect_kwargs["pkey"] = self.target.pkey
                client.connect(**connect_kwargs)
                transport = client.get_transport()
                if transport is None:
                    raise RuntimeError("SSH transport missing after connect")
                remote_key = transport.get_remote_server_key()
                if (
                    self.target.host_key_base64
                    and remote_key.get_base64() != self.target.host_key_base64
                ):
                    client.close()
                    raise RuntimeError(
                        f"SSH host key mismatch for {self.target.host}: "
                        f"got {remote_key.get_base64()}"
                    )
                self._client = client
                self._sftp = client.open_sftp()
                return self
            except paramiko.AuthenticationException:
                raise
            except RuntimeError:
                raise
            except Exception as exc:
                last_err = exc
                if attempt + 1 >= attempts:
                    break
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError(f"SSH connect failed: {last_err}") from last_err

    def close(self) -> None:
        if self._sftp is not None:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __enter__(self) -> SSHClient:
        return self.connect()

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def sftp(self) -> paramiko.SFTPClient:
        if self._sftp is None:
            raise RuntimeError("SSH client not connected")
        return self._sftp

    @property
    def client(self) -> paramiko.SSHClient:
        if self._client is None:
            raise RuntimeError("SSH client not connected")
        return self._client

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        to = self.command_timeout if timeout is None else timeout
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=to)
        exit_code = stdout.channel.recv_exit_status()
        return CommandResult(
            argv=command,
            exit_code=exit_code,
            stdout=stdout.read().decode("utf-8", errors="replace"),
            stderr=stderr.read().decode("utf-8", errors="replace"),
        )

    def read_text(self, path: str) -> str:
        with self.sftp.open(path, "r") as fh:
            data = fh.read()
        if isinstance(data, bytes):
            return data.decode("utf-8")
        return str(data)

    def write_text(self, path: str, content: str, *, mode: int = 0o644) -> None:
        self.write_bytes(path, content.encode("utf-8"), mode=mode)

    def write_bytes(self, path: str, data: bytes, *, mode: int = 0o600) -> None:
        tmp = f"{path}.tmp.{int(time.time())}"
        with self.sftp.open(tmp, "w") as fh:
            fh.write(data)
        try:
            self.sftp.chmod(tmp, mode)
        except OSError:
            pass
        try:
            self.sftp.remove(path)
        except OSError:
            pass
        self.sftp.rename(tmp, path)
        try:
            self.sftp.chmod(path, mode)
        except OSError:
            pass

    def read_bytes(self, path: str) -> bytes:
        with self.sftp.open(path, "r") as fh:
            data = fh.read()
        return data if isinstance(data, bytes) else str(data).encode("utf-8")

    def exists(self, path: str) -> bool:
        try:
            self.sftp.stat(path)
            return True
        except OSError:
            return False

    def listdir(self, path: str) -> list[str]:
        return self.sftp.listdir(path)

    def backup(self, path: str) -> str:
        """Copy ``path`` to ``path.bak.<epoch>``; keep last ``backup_keep`` copies."""
        bak = f"{path}.bak.{int(time.time())}"
        data = self.read_bytes(path)
        mode = 0o644
        try:
            mode = stat.S_IMODE(self.sftp.stat(path).st_mode)
        except OSError:
            pass
        self.write_bytes(bak, data, mode=mode)
        self._prune_backups(path)
        return bak

    def _prune_backups(self, path: str) -> None:
        directory, name = path.rsplit("/", 1) if "/" in path else (".", path)
        try:
            entries = self.listdir(directory)
        except OSError:
            return
        prefix = f"{name}.bak."
        found: list[tuple[int, str]] = []
        for entry in entries:
            if not entry.startswith(prefix):
                continue
            suffix = entry[len(prefix) :]
            if not suffix.isdigit():
                continue
            full = f"{directory}/{entry}" if directory != "." else entry
            found.append((int(suffix), full))
        found.sort(key=lambda t: t[0], reverse=True)
        for _epoch, old in found[self.backup_keep :]:
            try:
                self.unlink(old)
            except Exception:
                pass

    def restore_backup(self, path: str, bak_path: str) -> None:
        data = self.read_bytes(bak_path)
        mode = 0o644
        try:
            mode = stat.S_IMODE(self.sftp.stat(bak_path).st_mode)
        except OSError:
            pass
        self.write_bytes(path, data, mode=mode)

    def unlink(self, path: str) -> None:
        try:
            self.sftp.remove(path)
        except OSError:
            self.run(f"rm -f -- {shell_quote(path)}").check()
