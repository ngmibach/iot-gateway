"""Tests for pinned binary fetch (no network)."""

from __future__ import annotations

import hashlib
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from telemetry import binary_fetch as bf

_KAFKA_PLUGIN_ID = "hamedkarbasi93-kafka-datasource"


def _grafana_versions(digest: str, plat: str = "linux-amd64") -> dict:
    return {
        "grafana": {
            "version": "13.2.4",
            "assets": {
                plat: {
                    "url": "https://example.test/grafana.tar.gz",
                    "sha256": digest,
                    "archive": "tar.gz",
                    "root_dir_glob": "grafana-*",
                }
            },
        }
    }


def _kafka_plugin_versions(digest: str) -> dict:
    return {
        "grafana_kafka_plugin": {
            "version": "1.9.1",
            "plugin_id": _KAFKA_PLUGIN_ID,
            "assets": {
                "any": {
                    "url": "https://example.test/kafka-plugin.zip",
                    "sha256": digest,
                    "archive": "zip",
                }
            },
        }
    }


def _make_kafka_plugin_zip(root: Path) -> tuple[Path, str]:
    plugin = root / "pkg" / _KAFKA_PLUGIN_ID
    plugin.mkdir(parents=True)
    (plugin / "plugin.json").write_text(
        '{"id":"%s","type":"datasource"}' % _KAFKA_PLUGIN_ID,
        encoding="utf-8",
    )
    (plugin / "module.js").write_text("// stub\n", encoding="utf-8")
    archive = root / "kafka-plugin.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for path in plugin.rglob("*"):
            if path.is_file():
                zf.write(path, arcname=str(path.relative_to(root / "pkg")))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, digest


def _make_grafana_archive(
    root: Path,
    *,
    with_public: bool = True,
    with_conf: bool = True,
    with_bin: bool = True,
    bin_name: str = "grafana-server",
    arcname: str = "grafana-v13.2.4",
) -> tuple[Path, str]:
    tree = root / "tree" / arcname
    if with_public:
        (tree / "public").mkdir(parents=True)
        (tree / "public" / "index.html").write_text("ok", encoding="utf-8")
    if with_conf:
        (tree / "conf").mkdir(parents=True)
        (tree / "conf" / "defaults.ini").write_text("x", encoding="utf-8")
    if with_bin:
        (tree / "bin").mkdir(parents=True)
        (tree / "bin" / bin_name).write_bytes(b"#!/bin/sh\necho ok\n")
    # Ensure parents exist even when some layout pieces are omitted.
    tree.mkdir(parents=True, exist_ok=True)
    archive = root / "grafana.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(tree, arcname=arcname)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, digest


class BinaryFetchTests(unittest.TestCase):
    def test_sha_mismatch_raises(self) -> None:
        versions = {
            "prometheus": {
                "version": "0.0.1",
                "assets": {
                    "linux-amd64": {
                        "url": "https://example.test/prom.tar.gz",
                        "sha256": "0" * 64,
                        "archive": "tar.gz",
                        "binary": "prometheus",
                    }
                },
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download") as dl:

                    def _write(url, dest, progress=None):
                        dest.write_bytes(b"not-real")

                    dl.side_effect = _write
                    with self.assertRaises(bf.BinaryFetchError) as ctx:
                        bf.ensure_component(
                            "prometheus", Path(tmp), versions=versions
                        )
                    self.assertIn("SHA256", str(ctx.exception))

    def test_extract_and_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Build a tiny tar.gz containing prometheus
            payload = root / "payload"
            payload.mkdir()
            (payload / "prometheus").write_bytes(b"#!/bin/sh\necho ok\n")
            archive = root / "prom.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                tf.add(payload / "prometheus", arcname="prometheus-x/prometheus")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            versions = {
                "prometheus": {
                    "version": "9.9.9",
                    "assets": {
                        "linux-amd64": {
                            "url": "https://example.test/prom.tar.gz",
                            "sha256": digest,
                            "archive": "tar.gz",
                            "binary": "prometheus",
                        }
                    },
                }
            }

            def _dl(url, dest, progress=None):
                dest.write_bytes(archive.read_bytes())
                if progress:
                    progress("x", 1.0)

            bin_dir = root / "bin"
            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download", side_effect=_dl):
                    path = bf.ensure_component(
                        "prometheus", bin_dir, versions=versions
                    )
            self.assertTrue(path.is_file())
            self.assertEqual(path.name, "prometheus")
            # Second call should no-op (marker present)
            with mock.patch.object(bf, "_download") as dl:
                with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                    path2 = bf.ensure_component(
                        "prometheus", bin_dir, versions=versions
                    )
                dl.assert_not_called()
            self.assertEqual(path2, path)

    def test_load_versions_file(self) -> None:
        data = bf.load_versions()
        self.assertIn("prometheus", data)
        self.assertIn("loki", data)
        self.assertIn("linux-amd64", data["prometheus"]["assets"])
        self.assertIn("grafana", data)
        self.assertEqual(data["grafana"]["version"], "13.2.4")
        self.assertNotIn("extract", data["grafana"])
        assets = data["grafana"]["assets"]
        self.assertIn("linux-amd64", assets)
        self.assertIn("windows-amd64", assets)
        for plat in ("linux-amd64", "windows-amd64"):
            self.assertEqual(assets[plat]["archive"], "tar.gz")
            self.assertEqual(assets[plat]["root_dir_glob"], "grafana-*")
            self.assertTrue(assets[plat]["url"].startswith("https://dl.grafana.com/"))
            self.assertEqual(len(assets[plat]["sha256"]), 64)
        plugin = data["grafana_kafka_plugin"]
        self.assertEqual(plugin["version"], "1.9.1")
        self.assertEqual(plugin["plugin_id"], _KAFKA_PLUGIN_ID)
        any_asset = plugin["assets"]["any"]
        self.assertEqual(any_asset["archive"], "zip")
        self.assertEqual(len(any_asset["sha256"]), 64)
        self.assertTrue(any_asset["url"].startswith("https://storage.googleapis.com/"))

    def test_grafana_layout_ok_permission_error_is_false(self) -> None:
        tree = Path("/tmp/iotgw-grafana-missing-acl")
        with mock.patch.object(Path, "is_dir", side_effect=PermissionError(5, "denied")):
            self.assertFalse(bf.grafana_tree_layout_ok(tree))

    def test_ensure_grafana_tree_repairs_windows_acl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_grafana_archive(root)
            versions = _grafana_versions(digest)
            dest = root / "grafana"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())
                if progress:
                    progress("x", 1.0)

            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download", side_effect=_dl):
                    with mock.patch.object(
                        bf, "ensure_windows_tree_access"
                    ) as acl:
                        bf.ensure_grafana_tree(
                            dest, versions=versions, min_free_bytes=None
                        )
                        acl.assert_called_once_with(dest)

    def test_ensure_grafana_tree_extract_and_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_grafana_archive(root)
            versions = _grafana_versions(digest)
            dest = root / "grafana"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())
                if progress:
                    progress("x", 1.0)

            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download", side_effect=_dl) as dl:
                    path = bf.ensure_grafana_tree(
                        dest, versions=versions, min_free_bytes=None
                    )
                    self.assertEqual(dl.call_count, 1)

            self.assertEqual(path, dest)
            self.assertTrue((dest / "public").is_dir())
            self.assertTrue((dest / "conf").is_dir())
            self.assertTrue((dest / "bin" / "grafana-server").is_file())
            marker = dest / ".grafana-13.2.4-linux-amd64.ok"
            self.assertTrue(marker.is_file())
            self.assertIn("13.2.4", marker.read_text(encoding="utf-8"))

            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download") as dl2:
                    path2 = bf.ensure_grafana_tree(
                        dest, versions=versions, min_free_bytes=None
                    )
                    dl2.assert_not_called()
            self.assertEqual(path2, dest)

    def test_ensure_grafana_tree_sha_mismatch_cleans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, _digest = _make_grafana_archive(root)
            versions = _grafana_versions("0" * 64)
            dest = root / "grafana"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())

            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download", side_effect=_dl):
                    with self.assertRaises(bf.BinaryFetchError) as ctx:
                        bf.ensure_grafana_tree(
                            dest, versions=versions, min_free_bytes=None
                        )
            self.assertIn("SHA256", str(ctx.exception))
            self.assertFalse(dest.exists())
            self.assertFalse((root / "grafana.new").exists())
            self.assertFalse((dest / ".grafana-13.2.4-linux-amd64.ok").exists())

    def test_ensure_grafana_tree_missing_public_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_grafana_archive(root, with_public=False)
            versions = _grafana_versions(digest)
            dest = root / "grafana"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())

            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download", side_effect=_dl):
                    with self.assertRaises(bf.BinaryFetchError) as ctx:
                        bf.ensure_grafana_tree(
                            dest, versions=versions, min_free_bytes=None
                        )
            self.assertIn("layout invalid", str(ctx.exception))
            self.assertFalse(dest.exists())
            self.assertFalse((root / "grafana.new").exists())

    def test_ensure_grafana_tree_missing_server_binary_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_grafana_archive(root, with_bin=False)
            versions = _grafana_versions(digest)
            dest = root / "grafana"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())

            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download", side_effect=_dl):
                    with self.assertRaises(bf.BinaryFetchError) as ctx:
                        bf.ensure_grafana_tree(
                            dest, versions=versions, min_free_bytes=None
                        )
            self.assertIn("layout invalid", str(ctx.exception))
            self.assertFalse(dest.exists())

    def test_ensure_grafana_tree_force_redownloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_grafana_archive(root)
            versions = _grafana_versions(digest)
            dest = root / "grafana"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())

            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf, "_download", side_effect=_dl):
                    bf.ensure_grafana_tree(
                        dest, versions=versions, min_free_bytes=None
                    )
                with mock.patch.object(bf, "_download", side_effect=_dl) as dl:
                    bf.ensure_grafana_tree(
                        dest, versions=versions, force=True, min_free_bytes=None
                    )
                    self.assertEqual(dl.call_count, 1)
            self.assertTrue((dest / "public").is_dir())
            self.assertTrue((dest / ".grafana-13.2.4-linux-amd64.ok").is_file())

    def test_ensure_grafana_tree_insufficient_free_space(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_grafana_archive(root)
            versions = _grafana_versions(digest)
            dest = root / "grafana"

            fake_usage = mock.Mock(free=1000, total=10_000, used=9000)
            with mock.patch.object(bf, "platform_key", return_value="linux-amd64"):
                with mock.patch.object(bf.shutil, "disk_usage", return_value=fake_usage):
                    with mock.patch.object(bf, "_download") as dl:
                        with self.assertRaises(bf.BinaryFetchError) as ctx:
                            bf.ensure_grafana_tree(
                                dest,
                                versions=versions,
                                min_free_bytes=2_500_000_000,
                            )
                        dl.assert_not_called()
            self.assertIn("insufficient disk", str(ctx.exception).lower())
            self.assertFalse(dest.exists())

    def test_ensure_grafana_kafka_plugin_extract_and_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_kafka_plugin_zip(root)
            versions = _kafka_plugin_versions(digest)
            plugins = root / "plugins"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())
                if progress:
                    progress("x", 1.0)

            with mock.patch.object(bf, "_download", side_effect=_dl) as dl:
                path = bf.ensure_grafana_kafka_plugin(plugins, versions=versions)
                self.assertEqual(dl.call_count, 1)

            dest = plugins / _KAFKA_PLUGIN_ID
            self.assertEqual(path, dest)
            self.assertTrue((dest / "plugin.json").is_file())
            marker = plugins / f".{_KAFKA_PLUGIN_ID}-1.9.1.ok"
            self.assertTrue(marker.is_file())
            self.assertIn("1.9.1", marker.read_text(encoding="utf-8"))

            with mock.patch.object(bf, "_download") as dl2:
                path2 = bf.ensure_grafana_kafka_plugin(plugins, versions=versions)
                dl2.assert_not_called()
            self.assertEqual(path2, dest)

    def test_ensure_grafana_kafka_plugin_sha_mismatch_cleans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, _digest = _make_kafka_plugin_zip(root)
            versions = _kafka_plugin_versions("0" * 64)
            plugins = root / "plugins"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())

            with mock.patch.object(bf, "_download", side_effect=_dl):
                with self.assertRaises(bf.BinaryFetchError) as ctx:
                    bf.ensure_grafana_kafka_plugin(plugins, versions=versions)
            self.assertIn("SHA256", str(ctx.exception))
            self.assertFalse((plugins / _KAFKA_PLUGIN_ID).exists())
            self.assertFalse((plugins / f"{_KAFKA_PLUGIN_ID}.new").exists())
            self.assertFalse(
                (plugins / f".{_KAFKA_PLUGIN_ID}-1.9.1.ok").exists()
            )

    def test_ensure_grafana_kafka_plugin_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin = root / "pkg" / _KAFKA_PLUGIN_ID
            plugin.mkdir(parents=True)
            (plugin / "plugin.json").write_text(
                '{"id":"other-plugin","type":"datasource"}',
                encoding="utf-8",
            )
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.write(
                    plugin / "plugin.json",
                    arcname=f"{_KAFKA_PLUGIN_ID}/plugin.json",
                )
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            versions = _kafka_plugin_versions(digest)
            plugins = root / "plugins"

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())

            with mock.patch.object(bf, "_download", side_effect=_dl):
                with self.assertRaises(bf.BinaryFetchError) as ctx:
                    bf.ensure_grafana_kafka_plugin(plugins, versions=versions)
            self.assertIn("does not match pin", str(ctx.exception))

    def test_ensure_grafana_kafka_plugin_clears_stale_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, digest = _make_kafka_plugin_zip(root)
            versions = _kafka_plugin_versions(digest)
            plugins = root / "plugins"
            plugins.mkdir()
            stale = plugins / f".{_KAFKA_PLUGIN_ID}-0.0.1.ok"
            stale.write_text("old\n", encoding="utf-8")

            def _dl(url, dest_path, progress=None):
                dest_path.write_bytes(archive.read_bytes())

            with mock.patch.object(bf, "_download", side_effect=_dl):
                bf.ensure_grafana_kafka_plugin(plugins, versions=versions)
            self.assertFalse(stale.exists())
            self.assertTrue(
                (plugins / f".{_KAFKA_PLUGIN_ID}-1.9.1.ok").is_file()
            )

    def test_extract_archive_rejects_zip_slip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "slip.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../evil.txt", "nope")
            dest = root / "out"
            with self.assertRaises(bf.BinaryFetchError) as ctx:
                bf._extract_archive(archive, dest, kind="zip")
            self.assertIn("unsafe archive member", str(ctx.exception))
            self.assertFalse((root / "evil.txt").exists())


if __name__ == "__main__":
    unittest.main()
