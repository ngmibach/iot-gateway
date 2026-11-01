"""Unit tests for AutoPrevent sliding-window quarantine."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from iot_gateway_agent.auto_prevent import AutoPrevent
from iot_gateway_agent.deny_log import DenyLog


class AutoPreventTests(unittest.TestCase):
    def _policy(self, root: Path, *, limit: int = 3, window_s: int = 60) -> None:
        body = {
            "devices": {
                "fake1": {
                    "enabled": True,
                    "limit": limit,
                    "window_s": window_s,
                }
            }
        }
        (root / "auto_prevent.json").write_text(
            json.dumps(body), encoding="utf-8"
        )

    def test_trips_after_limit_and_calls_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root, limit=3, window_s=300)
            helper = root / "iotgw-auto-prevent"
            helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            helper.chmod(0o755)
            ap = AutoPrevent(data_dir=root, helper_path=helper)
            with mock.patch.object(
                ap, "_run_helper", return_value=(True, "dropped")
            ) as run:
                self.assertIsNone(
                    ap.note_deny(
                        device_id="fake1",
                        source_ip="10.255.0.5",
                        reason="bad_client_cert",
                        arrival_ms=1_000,
                    )
                )
                self.assertIsNone(
                    ap.note_deny(
                        device_id="fake1",
                        source_ip="10.255.0.5",
                        reason="bad_client_cert",
                        arrival_ms=2_000,
                    )
                )
                trip = ap.note_deny(
                    device_id="fake1",
                    source_ip="10.255.0.5",
                    reason="bad_client_cert",
                    arrival_ms=3_000,
                )
                self.assertIsNotNone(trip)
                assert trip is not None
                self.assertEqual(trip["ip"], "10.255.0.5")
                run.assert_called_with(["drop", "10.255.0.5", "fake1"])
                self.assertTrue(ap.is_quarantined("fake1"))
                # Further denies while quarantined do not re-trip.
                self.assertIsNone(
                    ap.note_deny(
                        device_id="fake1",
                        source_ip="10.255.0.5",
                        reason="acl_deny",
                        arrival_ms=4_000,
                    )
                )
                self.assertEqual(run.call_count, 1)

    def test_skips_without_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root, limit=1)
            ap = AutoPrevent(data_dir=root, helper_path=root / "missing")
            with mock.patch.object(ap, "_run_helper") as run:
                self.assertIsNone(
                    ap.note_deny(
                        device_id="fake1",
                        source_ip="",
                        reason="schema",
                        arrival_ms=1_000,
                    )
                )
                run.assert_not_called()

    def test_disabled_policy_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "auto_prevent.json").write_text(
                json.dumps(
                    {
                        "devices": {
                            "fake1": {
                                "enabled": False,
                                "limit": 1,
                                "window_s": 60,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            ap = AutoPrevent(data_dir=root)
            with mock.patch.object(ap, "_run_helper") as run:
                self.assertIsNone(
                    ap.note_deny(
                        device_id="fake1",
                        source_ip="10.255.0.5",
                        reason="schema",
                        arrival_ms=1_000,
                    )
                )
                run.assert_not_called()

    def test_deny_log_hook_triggers_auto_prevent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._policy(root, limit=1)
            deny = DenyLog(path=root / "denied.jsonl")
            ap = AutoPrevent(data_dir=root, deny_log=deny)
            deny.on_record = lambda ev: ap.note_deny(
                device_id=ev.device_id,
                source_ip=ev.source_ip,
                reason=ev.reason,
                arrival_ms=ev.arrival_ms,
            )
            with mock.patch.object(
                ap, "_run_helper", return_value=(True, "ok")
            ):
                deny.record(
                    reason="bad_client_cert",
                    device_id="fake1",
                    source_ip="10.255.0.9",
                )
                self.assertTrue(ap.is_quarantined("fake1"))
                # auto_prevent reason must not recurse.
                before = len(deny.recent(limit=50))
                deny.record(
                    reason="auto_prevent",
                    device_id="fake1",
                    source_ip="10.255.0.9",
                )
                self.assertGreaterEqual(len(deny.recent(limit=50)), before)


if __name__ == "__main__":
    unittest.main()
