"""wipe_app_data best-effort cleanup under IOTGW_DATA_DIR."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from shell import paths


class WipeAppDataTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_wipe_removes_contents_and_recreates_dir(self) -> None:
        root = Path(self._td.name)
        (root / "telemetry").mkdir()
        (root / "telemetry" / "bin").mkdir()
        (root / "settings.json").write_text("{}", encoding="utf-8")
        (root / "ui-state.json").write_text('{"simulate":{}}', encoding="utf-8")
        (root / "chromium-profile").mkdir()
        (root / "chromium-profile" / "SingletonLock").write_text("x", encoding="utf-8")
        out = paths.wipe_app_data()
        self.assertTrue(out["ok"])
        self.assertIn("telemetry", out["removed"])
        self.assertIn("settings.json", out["removed"])
        self.assertIn("ui-state.json", out["removed"])
        self.assertTrue(root.is_dir())
        self.assertFalse((root / "settings.json").exists())
        self.assertFalse((root / "ui-state.json").exists())
        self.assertFalse((root / "telemetry").exists())

    def test_ui_state_roundtrip(self) -> None:
        paths.save_ui_state(
            {
                "selected_gateway_id": "gw1",
                "simulate": {"gw1:fake1": {"send_interval_ms": 1500}},
            }
        )
        data = paths.load_ui_state()
        self.assertEqual(data["selected_gateway_id"], "gw1")
        self.assertEqual(data["simulate"]["gw1:fake1"]["send_interval_ms"], 1500)
        self.assertTrue(paths.ui_state_path().is_file())

    def test_wipe_preserves_named_entries(self) -> None:
        root = Path(self._td.name)
        (root / "keep-me").write_text("1", encoding="utf-8")
        (root / "gone").write_text("2", encoding="utf-8")
        out = paths.wipe_app_data(preserve_names=frozenset({"keep-me"}))
        self.assertIn("keep-me", out["skipped"])
        self.assertTrue((root / "keep-me").is_file())
        self.assertFalse((root / "gone").exists())


if __name__ == "__main__":
    unittest.main()
