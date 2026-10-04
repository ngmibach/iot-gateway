"""In-memory fake SSHClient for playbook unit tests."""

from __future__ import annotations

import re
import time
from typing import Callable

from actions.ssh import CommandResult

_TRUNCATE_RE = re.compile(
    r"(?::\s*>\s*'([^']+)'|truncate\s+-s\s+0\s+'([^']+)')"
)


class FakeSSH:
    def __init__(
        self,
        files: dict[str, str] | None = None,
        *,
        run_handler: Callable[[str], CommandResult] | None = None,
        backup_keep: int = 5,
    ) -> None:
        self.files: dict[str, bytes] = {
            k: v.encode("utf-8") for k, v in (files or {}).items()
        }
        self.commands: list[str] = []
        self._run_handler = run_handler
        self.unlinked: list[str] = []
        self.backup_keep = backup_keep

    def run(self, command: str, *, timeout: float | None = None) -> CommandResult:
        self.commands.append(command)
        if self._run_handler is not None:
            return self._run_handler(command)
        for m in _TRUNCATE_RE.finditer(command):
            path = m.group(1) or m.group(2)
            if path and path in self.files:
                self.files[path] = b""
        if "openssl x509 -req" in command:
            parts = command.split()
            out_path = None
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

    def listdir(self, path: str) -> list[str]:
        prefix = path.rstrip("/") + "/"
        names: set[str] = set()
        for full in self.files:
            if full.startswith(prefix):
                rest = full[len(prefix) :]
                names.add(rest.split("/", 1)[0])
        return sorted(names)

    def backup(self, path: str) -> str:
        bak = f"{path}.bak.{int(time.time())}"
        # Unique-ish if called thrice in same second
        while bak in self.files:
            bak = f"{path}.bak.{int(time.time())}.{len(self.files)}"
        self.files[bak] = self.read_bytes(path)
        self._prune_backups(path)
        return bak

    def _prune_backups(self, path: str) -> None:
        directory, name = path.rsplit("/", 1)
        prefix = f"{name}.bak."
        found: list[tuple[str, str]] = []
        for full in list(self.files):
            if not full.startswith(directory + "/"):
                continue
            entry = full[len(directory) + 1 :]
            if entry.startswith(prefix):
                found.append((entry[len(prefix) :], full))
        # Sort by suffix string; numeric epochs sort ok for zero-padded-ish ints
        found.sort(key=lambda t: t[0], reverse=True)
        for _suf, old in found[self.backup_keep :]:
            self.unlink(old)

    def restore_backup(self, path: str, bak_path: str) -> None:
        self.files[path] = self.read_bytes(bak_path)

    def unlink(self, path: str) -> None:
        self.unlinked.append(path)
        self.files.pop(path, None)
