"""Tests for pinned binary fetch (no network)."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from telemetry import binary_fetch as bf


class BinaryFetchTests(unittest.TestCase):
    def test_sha_mismatch_raises(self) -> None:
        import tempfile

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
        import tempfile

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


if __name__ == "__main__":
    unittest.main()
