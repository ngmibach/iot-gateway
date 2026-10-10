"""Download and verify pinned Loki/Prometheus binaries into app data.

The desktop app performs the download — the user never opens a browser for it.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

ProgressCb = Callable[[str, float], None]  # (message, fraction 0..1)

_VERSIONS_PATH = Path(__file__).resolve().parent / "native_versions.json"


class BinaryFetchError(RuntimeError):
    """Checksum, download, or extract failure."""


def platform_key() -> str:
    """Return ``linux-amd64`` / ``windows-amd64`` (v1 supported targets)."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    else:
        raise BinaryFetchError(
            f"unsupported CPU architecture for native telemetry: {machine} "
            "(need amd64/x86_64 in this build)"
        )
    if system == "windows" or os.name == "nt":
        return f"windows-{arch}"
    if system == "linux":
        return f"linux-{arch}"
    raise BinaryFetchError(f"unsupported OS for native telemetry: {system}")


def load_versions(path: Path | None = None) -> dict[str, Any]:
    p = path or _VERSIONS_PATH
    return json.loads(p.read_text(encoding="utf-8"))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, *, progress: ProgressCb | None = None) -> None:
    req = Request(url, headers={"User-Agent": "iot-gateway-monitor/0.1"})
    try:
        with urlopen(req, timeout=120) as resp:  # noqa: S310 — pinned HTTPS release URLs
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("wb") as out:
                while True:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    if progress and total:
                        progress(f"Downloading {dest.name}", min(0.95, done / total))
    except URLError as e:
        raise BinaryFetchError(f"download failed: {url}: {e}") from e


def _extract_binary(
    archive: Path,
    *,
    kind: str,
    binary_name: str,
    dest_bin: Path,
) -> None:
    dest_bin.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="iotgw-bin-") as tmp:
        tmp_path = Path(tmp)
        if kind == "tar.gz":
            with tarfile.open(archive, "r:gz") as tf:
                tf.extractall(tmp_path)  # noqa: S202 — trusted pinned release
        elif kind == "zip":
            with zipfile.ZipFile(archive, "r") as zf:
                zf.extractall(tmp_path)
        else:
            raise BinaryFetchError(f"unknown archive type: {kind}")

        matches = [p for p in tmp_path.rglob(binary_name) if p.is_file()]
        if not matches:
            # Loki zip sometimes is a single file named exactly binary_name at root.
            raise BinaryFetchError(
                f"binary {binary_name!r} not found inside {archive.name}"
            )
        src = matches[0]
        if dest_bin.exists():
            dest_bin.unlink()
        shutil.copy2(src, dest_bin)
        try:
            dest_bin.chmod(dest_bin.stat().st_mode | 0o111)
        except OSError:
            pass


def ensure_component(
    name: str,
    bin_dir: Path,
    *,
    versions: dict[str, Any] | None = None,
    platform: str | None = None,
    progress: ProgressCb | None = None,
    force: bool = False,
) -> Path:
    """Ensure ``name`` (``prometheus``|``loki``) binary exists under ``bin_dir``."""
    versions = versions or load_versions()
    plat = platform or platform_key()
    if plat not in versions[name]["assets"]:
        raise BinaryFetchError(f"no {name} asset for platform {plat}")
    meta = versions[name]
    asset = meta["assets"][plat]
    if name == "loki":
        out_name = "loki.exe" if plat.startswith("windows") else "loki"
    else:
        out_name = "prometheus.exe" if plat.startswith("windows") else "prometheus"

    dest = bin_dir / out_name
    marker = bin_dir / f".{name}-{meta['version']}-{plat}.ok"
    if dest.is_file() and marker.is_file() and not force:
        if progress:
            progress(f"{name} already present", 1.0)
        return dest

    with tempfile.TemporaryDirectory(prefix="iotgw-dl-") as tmp:
        tmp_path = Path(tmp)
        archive_name = asset["url"].rsplit("/", 1)[-1]
        archive_path = tmp_path / archive_name
        if progress:
            progress(f"Fetching {name} {meta['version']}", 0.05)
        _download(asset["url"], archive_path, progress=progress)
        digest = _sha256_file(archive_path)
        if digest.lower() != str(asset["sha256"]).lower():
            raise BinaryFetchError(
                f"SHA256 mismatch for {name}: got {digest}, expected {asset['sha256']}"
            )
        if progress:
            progress(f"Extracting {name}", 0.97)
        _extract_binary(
            archive_path,
            kind=asset["archive"],
            binary_name=asset["binary"],
            dest_bin=dest,
        )
        # Normalize loki binary name on Linux (archive member is loki-linux-amd64).
        if name == "loki" and not plat.startswith("windows") and dest.name != "loki":
            final = bin_dir / "loki"
            if dest != final:
                if final.exists():
                    final.unlink()
                dest.rename(final)
                dest = final
        marker.write_text(f"{meta['version']}\n{digest}\n", encoding="utf-8")
    if progress:
        progress(f"{name} ready", 1.0)
    return dest


def ensure_telemetry_binaries(
    bin_dir: Path,
    *,
    progress: ProgressCb | None = None,
    force: bool = False,
) -> dict[str, Path]:
    """Download both Prometheus and Loki into ``bin_dir``."""
    bin_dir = Path(bin_dir)
    bin_dir.mkdir(parents=True, exist_ok=True)
    out: dict[str, Path] = {}

    def _wrap(label: str, base: float, span: float) -> ProgressCb:
        def cb(msg: str, frac: float) -> None:
            if progress:
                progress(f"{label}: {msg}", base + span * frac)

        return cb

    out["prometheus"] = ensure_component(
        "prometheus", bin_dir, progress=_wrap("Prometheus", 0.0, 0.5), force=force
    )
    out["loki"] = ensure_component(
        "loki", bin_dir, progress=_wrap("Loki", 0.5, 0.5), force=force
    )
    return out
