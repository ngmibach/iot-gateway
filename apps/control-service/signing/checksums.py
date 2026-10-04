"""SHA256SUMS export helper (GNU coreutils compatible format)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable


def sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def write_sha256sums(
    files: Iterable[Path],
    dest: Path,
    *,
    relative_to: Path | None = None,
) -> Path:
    """Write ``SHA256SUMS`` with ``<hash>  <name>`` lines (two spaces)."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    base = Path(relative_to) if relative_to else dest.parent
    lines: list[str] = []
    for path in files:
        path = Path(path)
        if not path.is_file():
            continue
        digest = sha256_file(path)
        try:
            name = str(path.resolve().relative_to(base.resolve()))
        except ValueError:
            name = path.name
        lines.append(f"{digest}  {name}")
    dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return dest
