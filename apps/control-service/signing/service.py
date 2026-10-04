"""Orchestrate artifact signing + export folder + audit-safe metadata."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Optional

from .linux import sign_gpg_detach
from .tools import SigningTools, detect_signing_tools
from .windows import sign_authenticode

WINDOWS_SUFFIXES = {".msi", ".exe"}
LINUX_SUFFIXES = {".appimage", ".deb"}
SIGNABLE_SUFFIXES = WINDOWS_SUFFIXES | LINUX_SUFFIXES

Platform = Literal["windows", "linux", "auto"]


def _sha256_file(path: Path, *, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def write_sha256sums(
    files: list[Path],
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
        digest = _sha256_file(path)
        try:
            name = str(path.resolve().relative_to(base.resolve()))
        except ValueError:
            name = path.name
        lines.append(f"{digest}  {name}")
    dest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return dest


def _scrub_error(msg: str, identity: "SigningIdentity") -> str:
    """Strip known passphrases from exception text before audit/UI return."""
    out = msg
    for secret in (identity.pfx_passphrase, identity.gpg_passphrase):
        if secret:
            out = out.replace(secret, "***")
    return out


@dataclass
class SigningIdentity:
    """Signing material refs — passphrases are never serialized to audit_log."""

    platform: Platform = "auto"
    pfx_path: Optional[str] = None
    pfx_passphrase: Optional[str] = None
    thumbprint: Optional[str] = None
    gpg_key_id: Optional[str] = None
    gpg_passphrase: Optional[str] = None

    def public_fingerprint(self) -> str:
        """Safe identity label for audit (thumbprint or GPG key id)."""
        if self.thumbprint:
            return f"thumbprint:{self.thumbprint}"
        if self.gpg_key_id:
            return f"gpg:{self.gpg_key_id}"
        if self.pfx_path:
            return f"pfx:{Path(self.pfx_path).name}"
        return "unknown"

    def audit_dict(self) -> dict[str, Any]:
        """Fields safe to persist — no passphrases / key bytes."""
        out: dict[str, Any] = {
            "platform": self.platform,
            "identity": self.public_fingerprint(),
        }
        if self.pfx_path:
            out["pfx_name"] = Path(self.pfx_path).name
        if self.thumbprint:
            out["thumbprint"] = self.thumbprint
        if self.gpg_key_id:
            out["gpg_key_id"] = self.gpg_key_id
        return out


@dataclass
class SignRequest:
    artifacts: list[str]
    identity: SigningIdentity
    export_dir: Optional[str] = None


@dataclass
class SignResult:
    ok: bool
    signed_paths: list[str] = field(default_factory=list)
    source_paths: list[str] = field(default_factory=list)
    checksums_path: Optional[str] = None
    export_dir: Optional[str] = None
    tool_used: Optional[str] = None
    identity_fingerprint: Optional[str] = None
    error: Optional[str] = None
    audit_detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "signed_paths": self.signed_paths,
            "source_paths": self.source_paths,
            "checksums_path": self.checksums_path,
            "export_dir": self.export_dir,
            "tool_used": self.tool_used,
            "identity_fingerprint": self.identity_fingerprint,
            "error": self.error,
        }


def list_signable_artifacts(folder: Path) -> list[dict[str, str]]:
    """Scan a build/export folder for signable artifacts."""
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"folder not found: {folder}")
    found: list[dict[str, str]] = []
    for path in sorted(folder.iterdir()):
        if not path.is_file():
            continue
        suf = path.suffix.lower()
        name_lower = path.name.lower()
        platform = ""
        if suf in WINDOWS_SUFFIXES:
            platform = "windows"
        elif suf in LINUX_SUFFIXES or name_lower.endswith(".appimage"):
            platform = "linux"
        else:
            continue
        found.append(
            {
                "path": str(path.resolve()),
                "name": path.name,
                "platform": platform,
            }
        )
    return found


def _infer_platform(path: Path, identity: SigningIdentity) -> str:
    if identity.platform and identity.platform != "auto":
        return identity.platform
    suf = path.suffix.lower()
    name = path.name.lower()
    if suf in WINDOWS_SUFFIXES:
        return "windows"
    if suf in LINUX_SUFFIXES or name.endswith(".appimage"):
        return "linux"
    raise ValueError(f"cannot infer platform for {path.name}")


def sign_artifacts(
    request: SignRequest,
    *,
    tools: Optional[SigningTools] = None,
    windows_signer: Optional[Callable[..., Path]] = None,
    linux_signer: Optional[Callable[..., Path]] = None,
) -> SignResult:
    """Sign one or more artifacts and write an export folder + SHA256SUMS.

    ``windows_signer`` / ``linux_signer`` injectables support unit tests.
    """
    tools = tools or detect_signing_tools()
    win_fn = windows_signer or sign_authenticode
    lin_fn = linux_signer or sign_gpg_detach
    identity = request.identity

    if not request.artifacts:
        return SignResult(ok=False, error="no artifacts provided")

    paths = [Path(p) for p in request.artifacts]
    for p in paths:
        if not p.is_file():
            return SignResult(ok=False, error=f"artifact not found: {p}")

    # Resolve export dir: explicit, else beside first artifact under signed-export/
    if request.export_dir:
        export_dir = Path(request.export_dir)
    else:
        export_dir = paths[0].resolve().parent / "signed-export"
    export_dir.mkdir(parents=True, exist_ok=True)

    signed: list[Path] = []
    tools_used: set[str] = set()
    try:
        for src in paths:
            platform = _infer_platform(src, identity)
            missing = tools.missing_for(platform)
            if missing and windows_signer is None and linux_signer is None:
                raise RuntimeError("; ".join(missing))

            if platform == "windows":
                if not identity.pfx_path:
                    raise ValueError("pfx_path required for Windows signing")
                if identity.pfx_passphrase is None:
                    raise ValueError("pfx_passphrase required for Windows signing")
                out = win_fn(
                    src,
                    pfx_path=Path(identity.pfx_path),
                    passphrase=identity.pfx_passphrase,
                    tools=tools,
                )
                if tools.osslsigncode:
                    tools_used.add("osslsigncode")
                elif tools.signtool:
                    tools_used.add("signtool")
                else:
                    tools_used.add("windows-signer")
            else:
                if not identity.gpg_key_id:
                    raise ValueError("gpg_key_id required for Linux signing")
                if identity.gpg_passphrase is None:
                    raise ValueError("gpg_passphrase required for Linux signing")
                out = lin_fn(
                    src,
                    key_id=identity.gpg_key_id,
                    passphrase=identity.gpg_passphrase,
                    tools=tools,
                )
                tools_used.add("gpg")
                # Ship payload must appear in export/SHA256SUMS (sig alone is not enough).
                dest_src = export_dir / src.name
                if dest_src.resolve() != src.resolve():
                    shutil.copy2(src, dest_src)
                if dest_src not in signed:
                    signed.append(dest_src)

            dest = export_dir / out.name
            if dest.resolve() != Path(out).resolve():
                shutil.copy2(out, dest)
            else:
                dest = Path(out)
            signed.append(dest)

        sums = write_sha256sums(signed, export_dir / "SHA256SUMS", relative_to=export_dir)
        tool_label = "+".join(sorted(tools_used)) or None
        identity_fp = identity.public_fingerprint()
        detail = {
            "artifacts": [str(p) for p in paths],
            "signed": [str(p) for p in signed],
            "tool": tool_label,
            "export_dir": str(export_dir),
            "checksums": str(sums),
            **identity.audit_dict(),
        }
        return SignResult(
            ok=True,
            signed_paths=[str(p) for p in signed],
            source_paths=[str(p) for p in paths],
            checksums_path=str(sums),
            export_dir=str(export_dir),
            tool_used=tool_label,
            identity_fingerprint=identity_fp,
            audit_detail=detail,
        )
    except Exception as e:  # noqa: BLE001 — surface to API/UI
        err = _scrub_error(str(e), identity)
        return SignResult(
            ok=False,
            source_paths=[str(p) for p in paths],
            export_dir=str(export_dir),
            identity_fingerprint=identity.public_fingerprint(),
            error=err,
            audit_detail={
                "artifacts": [str(p) for p in paths],
                "error": err,
                **identity.audit_dict(),
            },
        )
