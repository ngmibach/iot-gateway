"""In-memory fake SSHClient for playbook unit tests."""

from __future__ import annotations

import re
import time
from typing import Callable

from actions.ssh import CommandResult

_TRUNCATE_RE = re.compile(
    r"(?::\s*>\s*'([^']+)'|truncate\s+-s\s+0\s+'([^']+)')"
)

# 100 GiB filesystem (1K-blocks) so Kafka capacity tests have headroom by default.
_FAKE_DF_LINE = "/dev/root 104857600 1024000 103833600 1% /\n"


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
        self.stdins: list[str | None] = []
        self._run_handler = run_handler
        self.unlinked: list[str] = []
        self.backup_keep = backup_keep

    def run(
        self,
        command: str,
        *,
        timeout: float | None = None,
        stdin: str | None = None,
    ) -> CommandResult:
        self.commands.append(command)
        self.stdins.append(stdin)
        if self._run_handler is not None:
            handled = self._run_handler(command)
            # Still apply filesystem side effects on success so sudo mv/rm work.
            if handled.exit_code == 0:
                self._apply_fs_side_effects(command)
            # Handlers often return empty stdout; synthesize df so capacity probes work.
            if "df -Pk" in command and not (handled.stdout or "").strip():
                return CommandResult(
                    argv=command,
                    exit_code=handled.exit_code,
                    stdout=_FAKE_DF_LINE,
                    stderr=handled.stderr,
                )
            # Prefer real file content for sudo cat when handler left stdout empty.
            cat_out = self._cat_stdout(command)
            if cat_out is not None and not (handled.stdout or "").strip():
                return CommandResult(
                    argv=command,
                    exit_code=handled.exit_code,
                    stdout=cat_out,
                    stderr=handled.stderr,
                )
            return handled
        if "df -Pk" in command:
            return CommandResult(
                argv=command, exit_code=0, stdout=_FAKE_DF_LINE, stderr=""
            )
        self._apply_fs_side_effects(command)
        cat_out = self._cat_stdout(command)
        if cat_out is not None:
            return CommandResult(
                argv=command, exit_code=0, stdout=cat_out, stderr=""
            )
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

    def _cat_stdout(self, command: str) -> str | None:
        normalized = command.replace("'\"'\"'", "'")
        cat_m = re.search(r"\bcat\s+'([^']+)'", normalized)
        if not cat_m:
            return None
        path = cat_m.group(1)
        if path not in self.files:
            return None
        data = self.files[path]
        return data.decode("utf-8") if isinstance(data, bytes) else str(data)

    def _apply_fs_side_effects(self, command: str) -> None:
        self._apply_rm(command)
        self._apply_mv(command)
        for m in _TRUNCATE_RE.finditer(command):
            path = m.group(1) or m.group(2)
            if path and path in self.files:
                self.files[path] = b""

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

    def _apply_rm(self, command: str) -> None:
        """Best-effort simulate ``rm -rf`` / ``rm -f`` for playbook tests."""
        normalized = command.replace("'\"'\"'", "'")
        # Match rm -rf 'path' or rm -f 'path' (possibly several paths).
        for m in re.finditer(
            r"\brm\s+(-[a-zA-Z]+\s+)*'([^']+)'",
            normalized,
        ):
            flags = m.group(1) or ""
            path = m.group(2)
            recursive = "r" in flags
            if recursive:
                prefix = path.rstrip("/") + "/"
                for full in list(self.files):
                    if full == path or full.startswith(prefix):
                        self.unlink(full)
            else:
                if path in self.files:
                    self.unlink(path)

    def _apply_mv(self, command: str) -> None:
        """Best-effort simulate ``mv 'src' 'dst'`` (incl. inside sudo sh -c).

        ``shell_quote`` embeds paths as ``'"'"'path'"'"'``; normalize those to
        plain single quotes before matching.
        """
        normalized = command.replace("'\"'\"'", "'")
        for m in re.finditer(r"\bmv\s+'([^']+)'\s+'([^']+)'", normalized):
            src, dst = m.group(1), m.group(2)
            if src in self.files:
                self.files[dst] = self.files.pop(src)
