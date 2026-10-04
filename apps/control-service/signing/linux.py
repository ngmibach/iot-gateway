"""GPG detach-sign for AppImage / .deb (Ubuntu ship artifacts)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, Optional

from .tools import SigningToolMissing, SigningTools, detect_signing_tools

RunFn = Callable[..., subprocess.CompletedProcess]


def sig_output_path(src: Path) -> Path:
    """``foo.AppImage`` → ``foo.AppImage.sig``."""
    return Path(str(src) + ".sig")


def sign_gpg_detach(
    artifact: Path,
    *,
    key_id: str,
    passphrase: str,
    output: Optional[Path] = None,
    tools: Optional[SigningTools] = None,
    run: Optional[RunFn] = None,
) -> Path:
    """Create a detached GPG signature beside the artifact.

    Passphrase is fed on stdin (``--passphrase-fd 0``) so it is not on argv.
    """
    artifact = Path(artifact)
    if not artifact.is_file():
        raise FileNotFoundError(f"artifact not found: {artifact}")
    key_id = (key_id or "").strip()
    if not key_id:
        raise ValueError("gpg key_id required")

    out = Path(output) if output else sig_output_path(artifact)
    out.parent.mkdir(parents=True, exist_ok=True)
    tools = tools or detect_signing_tools()
    if not tools.gpg:
        raise SigningToolMissing(
            "gpg/gpg2 not found on PATH. Install gnupg to sign AppImage/.deb."
        )
    run_fn: RunFn = run or subprocess.run

    cmd = [
        tools.gpg,
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase-fd",
        "0",
        "--local-user",
        key_id,
        "--detach-sign",
        "--output",
        str(out),
        str(artifact),
    ]
    proc = run_fn(
        cmd,
        input=passphrase + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        if passphrase:
            err = err.replace(passphrase, "***")
        raise RuntimeError(f"gpg detach-sign failed: {err}")
    return out
