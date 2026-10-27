"""Download and verify pinned Loki/Prometheus binaries, Grafana OSS trees, and plugins.

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


def _assert_member_within(dest_dir: Path, member_name: str) -> None:
    """Reject absolute paths and ``..`` traversal in archive members."""
    name = member_name.replace("\\", "/")
    if (
        not name
        or name.startswith("/")
        or name.startswith("//")
        or ".." in Path(name).parts
        or (len(name) >= 2 and name[1] == ":")
    ):
        raise BinaryFetchError(f"unsafe archive member path: {member_name!r}")
    dest_root = dest_dir.resolve()
    target = (dest_dir / name).resolve()
    if target != dest_root and dest_root not in target.parents:
        raise BinaryFetchError(f"archive member escapes destination: {member_name!r}")


def _extract_archive(archive: Path, dest_dir: Path, *, kind: str) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if kind == "tar.gz":
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                _assert_member_within(dest_dir, member.name)
            # filter="data" blocks links / absolute paths on Python 3.12+.
            if hasattr(tarfile, "data_filter"):
                tf.extractall(dest_dir, filter="data")  # noqa: S202 — pinned + filtered
            else:
                tf.extractall(dest_dir)  # noqa: S202 — members pre-checked above
    elif kind == "zip":
        with zipfile.ZipFile(archive, "r") as zf:
            for info in zf.infolist():
                _assert_member_within(dest_dir, info.filename)
            zf.extractall(dest_dir)
    else:
        raise BinaryFetchError(f"unknown archive type: {kind}")


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
        _extract_archive(archive, tmp_path, kind=kind)

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


def _find_tree_root(extract_dir: Path, root_dir_glob: str) -> Path:
    matches = sorted(
        p
        for p in extract_dir.iterdir()
        if p.is_dir() and fnmatch.fnmatch(p.name, root_dir_glob)
    )
    if len(matches) != 1:
        raise BinaryFetchError(
            f"expected exactly one directory matching {root_dir_glob!r} "
            f"in archive, found {len(matches)}"
        )
    return matches[0]


def grafana_tree_layout_ok(tree: Path) -> bool:
    """True when ``tree`` has public/, conf/, and a grafana[-server][.exe] binary."""
    tree = Path(tree)
    if not (tree / "public").is_dir():
        return False
    if not (tree / "conf").is_dir():
        return False
    bin_dir = tree / "bin"
    if not bin_dir.is_dir():
        return False
    return any((bin_dir / name).is_file() for name in _GRAFANA_SERVER_NAMES)


def _grafana_layout_ok(tree: Path) -> bool:
    return grafana_tree_layout_ok(tree)


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
    min_free_bytes: int | None = int(2.5 * 1024**3),  # 2.5 GiB; None skips check
) -> Path:
    """Ensure a Grafana OSS directory tree is present under ``dest_dir``.

    Caller must ensure no process holds files under ``dest_dir`` when
    ``force=True`` or when the version marker mismatches.
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
    root_dir_glob = asset.get("root_dir_glob")
    if not root_dir_glob:
        raise BinaryFetchError("grafana asset missing root_dir_glob")
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
            root = _find_tree_root(extract_dir, root_dir_glob)
            if not _grafana_layout_ok(root):
                raise BinaryFetchError(
                    "grafana archive layout invalid: need public/, conf/, and "
                    "bin/grafana[-server][.exe]"
                )
            shutil.move(str(root), staging)
        _atomic_replace_dir(staging, dest_dir, old)
        marker.write_text(f"{version}\n{digest}\n", encoding="utf-8")
    except Exception:
        _rmtree_if_exists(staging)
        # Never leave a version marker on a tree that fails layout checks.
        if marker.is_file() and not _grafana_layout_ok(dest_dir):
            try:
                marker.unlink()
            except OSError:
                pass
        raise

    if progress:
        progress("grafana ready", 1.0)
    return dest_dir


def _find_plugin_root(extract_dir: Path, plugin_id: str) -> Path:
    """Pinned catalog zips extract as ``<plugin_id>/plugin.json`` at archive root."""
    direct = extract_dir / plugin_id
    if (direct / "plugin.json").is_file():
        return direct
    raise BinaryFetchError(
        f"expected {plugin_id}/plugin.json at archive root"
    )


def _plugin_json_id(plugin_dir: Path) -> str:
    raw = (plugin_dir / "plugin.json").read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BinaryFetchError("plugin.json is not valid JSON") from exc
    if not isinstance(data, dict):
        raise BinaryFetchError("plugin.json root must be an object")
    return str(data.get("id") or "").strip()


def _clear_stale_plugin_markers(plugins_dir: Path, plugin_id: str, keep: Path) -> None:
    for path in plugins_dir.glob(f".{plugin_id}-*.ok"):
        if path == keep:
            continue
        try:
            path.unlink()
        except OSError:
            pass


def ensure_grafana_kafka_plugin(
    plugins_dir: Path,
    *,
    versions: dict[str, Any] | None = None,
    progress: ProgressCb | None = None,
    force: bool = False,
) -> Path:
    """Download and install the pinned Grafana Kafka datasource plugin.

    Extracts into ``plugins_dir / <plugin_id>/``. Writes a version marker only
    after a successful replace.
    """
    plugins_dir = Path(plugins_dir)
    versions = versions or load_versions()
    if "grafana_kafka_plugin" not in versions:
        raise BinaryFetchError("versions pin missing grafana_kafka_plugin section")
    meta = versions["grafana_kafka_plugin"]
    plugin_id = str(meta.get("plugin_id") or "").strip()
    if not plugin_id:
        raise BinaryFetchError("grafana_kafka_plugin missing plugin_id")
    assets = meta.get("assets") or {}
    asset = assets.get("any")
    if not isinstance(asset, dict):
        raise BinaryFetchError("grafana_kafka_plugin missing assets.any")
    version = str(meta["version"])
    dest = plugins_dir / plugin_id
    marker = plugins_dir / f".{plugin_id}-{version}.ok"

    if dest.is_dir() and marker.is_file() and not force:
        if (dest / "plugin.json").is_file():
            if progress:
                progress("grafana kafka plugin already present", 1.0)
            return dest

    plugins_dir.mkdir(parents=True, exist_ok=True)
    staging = plugins_dir / f"{plugin_id}.new"
    old = plugins_dir / f"{plugin_id}.old"
    _rmtree_if_exists(staging)
    _rmtree_if_exists(old)

    digest = ""
    try:
        with tempfile.TemporaryDirectory(prefix="iotgw-gf-kafka-") as tmp:
            tmp_path = Path(tmp)
            archive_name = str(asset["url"]).rsplit("/", 1)[-1]
            archive_path = tmp_path / archive_name
            if progress:
                progress(f"Fetching grafana kafka plugin {version}", 0.05)
            _download(str(asset["url"]), archive_path, progress=progress)
            digest = _sha256_file(archive_path)
            if digest.lower() != str(asset["sha256"]).lower():
                raise BinaryFetchError(
                    f"SHA256 mismatch for grafana_kafka_plugin: got {digest}, "
                    f"expected {asset['sha256']}"
                )
            if progress:
                progress("Extracting grafana kafka plugin", 0.9)
            extract_dir = tmp_path / "extract"
            _extract_archive(archive_path, extract_dir, kind=str(asset["archive"]))
            root = _find_plugin_root(extract_dir, plugin_id)
            found_id = _plugin_json_id(root)
            if found_id != plugin_id:
                raise BinaryFetchError(
                    f"plugin.json id {found_id!r} does not match pin {plugin_id!r}"
                )
            shutil.move(str(root), staging)
        _atomic_replace_dir(staging, dest, old)
        marker.write_text(f"{version}\n{digest}\n", encoding="utf-8")
        _clear_stale_plugin_markers(plugins_dir, plugin_id, marker)
    except Exception:
        _rmtree_if_exists(staging)
        if marker.is_file() and not (dest / "plugin.json").is_file():
            try:
                marker.unlink()
            except OSError:
                pass
        raise

    if progress:
        progress("grafana kafka plugin ready", 1.0)
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
