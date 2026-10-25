"""Download and verify pinned Loki/Prometheus binaries and Grafana OSS trees.

The desktop app performs the download — the user never opens a browser for it.
"""

from __future__ import annotations

import fnmatch
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

_GRAFANA_SERVER_NAMES = (
    "grafana.exe",
    "grafana-server.exe",
    "grafana",
    "grafana-server",
)


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


def _extract_archive(archive: Path, dest_dir: Path, *, kind: str) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if kind == "tar.gz":
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest_dir)  # noqa: S202 — trusted pinned release
    elif kind == "zip":
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(dest_dir)
    else:
        raise BinaryFetchError(f"unknown archive type: {kind}")


def _rmtree_if_exists(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def _ensure_free_space(probe: Path, min_free_bytes: int) -> None:
    """Best-effort volume free-space check; raise if usable and below threshold."""
    try:
        usage = shutil.disk_usage(probe)
    except OSError:
        return
    if usage.free < min_free_bytes:
        need_gib = min_free_bytes / (1024**3)
        have_gib = usage.free / (1024**3)
        raise BinaryFetchError(
            f"insufficient disk space for Grafana tree at {probe}: "
            f"{have_gib:.2f} GiB free, need at least {need_gib:.2f} GiB"
        )


def _find_tree_root(extract_dir: Path, root_dir_glob: str | None) -> Path:
    if root_dir_glob:
        matches = sorted(
            p
            for p in extract_dir.iterdir()
            if p.is_dir() and fnmatch.fnmatch(p.name, root_dir_glob)
        )
        if matches:
            return matches[0]
    top_dirs = [p for p in extract_dir.iterdir() if p.is_dir()]
    if len(top_dirs) == 1:
        return top_dirs[0]
    return extract_dir


def _grafana_layout_ok(tree: Path) -> bool:
    if not (tree / "public").is_dir():
        return False
    if not (tree / "conf").is_dir():
        return False
    bin_dir = tree / "bin"
    if not bin_dir.is_dir():
        return False
    return any((bin_dir / name).is_file() for name in _GRAFANA_SERVER_NAMES)


def _atomic_replace_dir(staging: Path, dest: Path, old: Path) -> None:
    """Replace ``dest`` with ``staging``; roll back on rename failure."""
    _rmtree_if_exists(old)
    if dest.exists():
        dest.rename(old)
        try:
            staging.rename(dest)
        except OSError:
            if old.exists() and not dest.exists():
                try:
                    old.rename(dest)
                except OSError:
                    pass
            _rmtree_if_exists(staging)
            raise
        shutil.rmtree(old, ignore_errors=True)
    else:
        try:
            staging.rename(dest)
        except OSError:
            _rmtree_if_exists(staging)
            raise


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


def ensure_grafana_tree(
    dest_dir: Path,
    *,
    versions: dict[str, Any] | None = None,
    platform: str | None = None,
    progress: ProgressCb | None = None,
    force: bool = False,
    min_free_bytes: int | None = 2_500_000_000,  # 2.5 GiB; None skips check
) -> Path:
    """Ensure a Grafana OSS directory tree is present under ``dest_dir``.

    Caller must ensure no process holds files under ``dest_dir`` when
    ``force=True`` or when the version marker mismatches (manager
    stop-before-replace is PR 3).
    """
    dest_dir = Path(dest_dir)
    versions = versions or load_versions()
    plat = platform or platform_key()
    if "grafana" not in versions:
        raise BinaryFetchError("versions pin missing grafana section")
    meta = versions["grafana"]
    if plat not in meta["assets"]:
        raise BinaryFetchError(f"no grafana asset for platform {plat}")
    asset = meta["assets"][plat]
    version = str(meta["version"])
    marker = dest_dir / f".grafana-{version}-{plat}.ok"

    if dest_dir.is_dir() and marker.is_file() and not force:
        if _grafana_layout_ok(dest_dir):
            if progress:
                progress("grafana already present", 1.0)
            return dest_dir

    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    if min_free_bytes is not None:
        probe = dest_dir if dest_dir.exists() else dest_dir.parent
        _ensure_free_space(probe, min_free_bytes)

    staging = dest_dir.with_name(dest_dir.name + ".new")
    old = dest_dir.with_name(dest_dir.name + ".old")
    _rmtree_if_exists(staging)
    _rmtree_if_exists(old)

    digest = ""
    try:
        with tempfile.TemporaryDirectory(prefix="iotgw-grafana-") as tmp:
            tmp_path = Path(tmp)
            archive_name = asset["url"].rsplit("/", 1)[-1]
            archive_path = tmp_path / archive_name
            if progress:
                progress(f"Fetching grafana {version}", 0.05)
            _download(asset["url"], archive_path, progress=progress)
            digest = _sha256_file(archive_path)
            if digest.lower() != str(asset["sha256"]).lower():
                raise BinaryFetchError(
                    f"SHA256 mismatch for grafana: got {digest}, "
                    f"expected {asset['sha256']}"
                )
            if progress:
                progress("Extracting grafana", 0.9)
            extract_dir = tmp_path / "extract"
            _extract_archive(archive_path, extract_dir, kind=asset["archive"])
            root = _find_tree_root(extract_dir, asset.get("root_dir_glob"))
            if not _grafana_layout_ok(root):
                raise BinaryFetchError(
                    "grafana archive layout invalid: need public/, conf/, and "
                    "bin/grafana[-server][.exe]"
                )
            shutil.copytree(root, staging)
        _atomic_replace_dir(staging, dest_dir, old)
        marker.write_text(f"{version}\n{digest}\n", encoding="utf-8")
    except Exception:
        _rmtree_if_exists(staging)
        # Drop a marker only after a successful replace; never leave marker on failure.
        if marker.is_file() and not _grafana_layout_ok(dest_dir):
            try:
                marker.unlink()
            except OSError:
                pass
        raise

    if progress:
        progress("grafana ready", 1.0)
    return dest_dir


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
