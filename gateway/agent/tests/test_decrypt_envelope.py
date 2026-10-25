"""Decrypt worker envelope pairing tests."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from iot_gateway_agent.device_crypto import save_device_secrets, save_schema
from iot_gateway_agent.decrypt_worker import DecryptWorker
from iot_gateway_agent.envelope_v1 import (
    generate_device_secrets,
    key_topic,
    data_topic,
    seal,
    today_day_id,
)


class DecryptEnvelopeTests(unittest.TestCase):
    def test_pair_and_accept(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secrets = generate_device_secrets("dev1", profile="v1-psk", schema_id="default")
            save_device_secrets(root, secrets)
            save_schema(
                root,
                "default",
                {
                    "schema_id": "default",
                    "type": "object",
                    "additionalProperties": True,
                },
            )
            log_path = root / "logs" / "sensor_data.log"
            worker = DecryptWorker(
                log_path=log_path,
                data_dir=root,
                envelope_enabled=True,
                envelope_require=False,
                pair_timeout_s=2.0,
                replay_cache_size=64,
            )
            payload = {"device_id": "dev1", "hello": 1}
            sealed = seal(payload, secrets, day_id=today_day_id())
            worker._handle_message(
                key_topic("dev1"),
                json.dumps(sealed.key_part).encode(),
            )
            worker._handle_message(
                data_topic("dev1"),
                json.dumps(sealed.data_part).encode(),
            )
            self.assertEqual(worker.messages_ok, 1)
            self.assertEqual(worker.envelope_ok, 1)
            text = log_path.read_text(encoding="utf-8")
            self.assertIn('"hello":1', text.replace(" ", ""))

    def test_key_only_times_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secrets = generate_device_secrets("dev2", profile="v1-psk")
            save_device_secrets(root, secrets)
            worker = DecryptWorker(
                log_path=root / "logs" / "s.log",
                data_dir=root,
                envelope_enabled=True,
                pair_timeout_s=0.2,
            )
            sealed = seal({"hello": 1}, secrets, day_id=today_day_id())
            worker._handle_message(
                key_topic("dev2"),
                json.dumps(sealed.key_part).encode(),
            )
            # Manually run one janitor pass after timeout.
            time.sleep(0.35)
            now_ms = int(time.time() * 1000)
            timeout_ms = int(worker.pair_timeout_s * 1000)
            expired = []
            with worker._lock:
                for key, half in list(worker._pending.items()):
                    if now_ms - half.received_ms >= timeout_ms:
                        expired.append((key, half.kind))
                        worker._pending.pop(key, None)
            for key, kind in expired:
                device_id = key.split(":", 1)[0]
                reason = "key_only" if kind == "key" else "data_only"
                worker._fail(device_id, reason)
            self.assertEqual(worker.messages_fail, 1)
            snap = worker.device_snapshot()["dev2"]
            self.assertGreaterEqual(snap.deny_reasons.get("key_only", 0), 1)

    def test_require_rejects_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worker = DecryptWorker(
                log_path=root / "logs" / "s.log",
                data_dir=root,
                envelope_require=True,
            )
            worker._handle_message(
                "sensors/dev3/process",
                json.dumps({"hello": 1}).encode(),
            )
            self.assertEqual(worker.messages_fail, 1)


if __name__ == "__main__":
    unittest.main()
