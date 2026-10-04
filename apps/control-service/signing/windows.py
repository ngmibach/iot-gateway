"""Authenticode signing for .msi / .exe / NSIS via osslsigncode or signtool."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Callable, Optional

from .tools import SigningToolMissing, SigningTools, detect_signing_tools

RunFn = Callable[..., subprocess.CompletedProcess]


def _scrub(err: str, passphrase: str) -> str:
    return err.replace(passphrase, "***") if passphrase else err


def signed_output_path(src: Path) -> Path:
    """``foo.exe`` → ``foo-signed.exe`` (beside the unsigned input)."""
    return src.with_name(f"{src.stem}-signed{src.suffix}")


def sign_authenticode(
    artifact: Path,
    *,
    pfx_path: Path,
    passphrase: str,
    output: Optional[Path] = None,
    tools: Optional[SigningTools] = None,
    run: Optional[RunFn] = None,
    description: str = "IoT Gateway Monitor",
) -> Path:
    """Sign a Windows PE/MSI artifact. Passphrase is never written to argv logs."""
    artifact = Path(artifact)
    pfx_path = Path(pfx_path)
    if not artifact.is_file():
        raise FileNotFoundError(f"artifact not found: {artifact}")
    if not pfx_path.is_file():
        raise FileNotFoundError(f"PFX not found: {pfx_path}")

    out = Path(output) if output else signed_output_path(artifact)
    out.parent.mkdir(parents=True, exist_ok=True)
    tools = tools or detect_signing_tools()
    run_fn: RunFn = run or subprocess.run

    if tools.osslsigncode:
        return _sign_osslsigncode(
            tools.osslsigncode,
            artifact,
            out,
            pfx_path,
            passphrase,
            description=description,
            run=run_fn,
        )
    if tools.signtool:
        return _sign_signtool(
            tools.signtool,
            artifact,
            out,
            pfx_path,
            passphrase,
            description=description,
            run=run_fn,
        )
    raise SigningToolMissing(
        "Neither osslsigncode nor signtool found on PATH. "
        "Install osslsigncode (Linux/macOS/cross) or the Windows SDK signtool."
    )


def _sign_osslsigncode(
    binary: str,
    artifact: Path,
    out: Path,
    pfx_path: Path,
    passphrase: str,
    *,
    description: str,
    run: RunFn,
) -> Path:
    # Passphrase via argv is unavoidable for osslsigncode; callers must not log cmd.
    cmd = [
        binary,
        "sign",
        "-pkcs12",
        str(pfx_path),
        "-pass",
        passphrase,
        "-n",
        description,
        "-in",
        str(artifact),
        "-out",
        str(out),
    ]
    proc = run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"osslsigncode failed: {_scrub(err, passphrase)}")
    return out


def _sign_signtool(
    binary: str,
    artifact: Path,
    out: Path,
    pfx_path: Path,
    passphrase: str,
    *,
    description: str,
    run: RunFn,
) -> Path:
    # signtool signs in place — copy first so unsigned input is preserved.
    if out.resolve() != artifact.resolve():
        shutil.copy2(artifact, out)
    cmd = [
        binary,
        "sign",
        "/fd",
        "SHA256",
        "/f",
        str(pfx_path),
        "/p",
        passphrase,
        "/d",
        description,
        str(out),
    ]
    proc = run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise RuntimeError(f"signtool failed: {_scrub(err, passphrase)}")
    return out
