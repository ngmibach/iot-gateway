"""In-memory fake SSHClient for playbook unit tests."""

from __future__ import annotations

import time
from typing import Callable

from actions.ssh import CommandResult


class FakeSSH:
    def __init__(
        self,
        files: dict[str, str] | None = None,
        *,
        run_handler: Callable[[str], CommandResult] | None = None,
    ) -> None:
        self.files: dict[str, bytes] = {
            k: v.encode("utf-8") for k, v in (files or {}).items()
        }
        self.commands: list[str] = []
        self._run_handler = run_handler
        self.unlinked: list[str] = []

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.commands.append(command)
        if self._run_handler is not None:
            return self._run_handler(command)
        # Default: succeed; for openssl sign, plant a cert at -out path.
        if "openssl x509 -req" in command:
            out_path = None
            parts = command.split()
            for i, p in enumerate(parts):
                if p == "-out" and i + 1 < len(parts):
                    out_path = parts[i + 1].strip("'")
            if out_path:
                self.files[out_path] = (
                    b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
                )
        return CommandResult(argv=command, exit_code=0, stdout="", stderr="")

    def read_text(self, path: str) -> str:
        return self.read_bytes(path).decode("utf-8")

    def read_bytes(self, path: str) -> bytes:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write_text(self, path: str, content: str, *, mode: int = 0o644) -> None:
        self.write_bytes(path, content.encode("utf-8"), mode=mode)

    def write_bytes(self, path: str, data: bytes, *, mode: int = 0o600) -> None:
        self.files[path] = data

    def exists(self, path: str) -> bool:
        return path in self.files

    def backup(self, path: str) -> str:
        bak = f"{path}.bak.{int(time.time())}"
        self.files[bak] = self.read_bytes(path)
        return bak

    def restore_backup(self, path: str, bak_path: str) -> None:
        self.files[path] = self.read_bytes(bak_path)

    def unlink(self, path: str) -> None:
        self.unlinked.append(path)
        self.files.pop(path, None)
