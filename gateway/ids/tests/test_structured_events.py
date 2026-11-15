from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ids_gateway.structured_events import StructuredEventCapture


def _event(*, device_id: str = "sensor1") -> dict:
    return {
        "event_type": "sensor_data",
        "device_id": device_id,
        "topic": f"sensors/{device_id}/process",
        "payload": {"temperature": 21.5},
        "gateway_received_at": "2026-11-03T10:00:00+00:00",
        "device_reported_at": "2026-11-03T09:59:59+00:00",
        "payload_size_bytes": 23,
        "broker_port": 8883,
        "delay": 1.0,
    }


class StructuredEventCaptureTests(unittest.TestCase):
    def test_buffers_partial_lines_and_does_not_invent_source_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ids_events.jsonl"
            capture = StructuredEventCapture(path, start_at_end=False)
            encoded = json.dumps(_event()).encode("utf-8")
            path.write_bytes(encoded[:40])
            self.assertEqual(capture.poll_once(), {})

            with path.open("ab") as handle:
                handle.write(encoded[40:] + b"\n")
            records = capture.poll_once()["sensor1"]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].mqtt_device_id, "sensor1")
            self.assertEqual(records[0].src_ip, "")
            self.assertEqual(records[0].mqtt_delay, 1.0)
            self.assertEqual(records[0].pkt_len, 23)

    def test_handles_truncation_and_rotation_without_replaying_old_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ids_events.jsonl"
            capture = StructuredEventCapture(path, start_at_end=False)
            first = (json.dumps(_event(device_id="sensor1")) + "\n").encode()
            path.write_bytes(first)
            self.assertEqual(len(capture.poll_once()["sensor1"]), 1)
            self.assertEqual(capture.poll_once(), {})

            second = (json.dumps(_event(device_id="s2")) + "\n").encode()
            path.write_bytes(second)
            self.assertEqual(len(capture.poll_once()["s2"]), 1)
            self.assertEqual(capture.poll_once(), {})

    def test_starts_at_end_to_avoid_reprocessing_existing_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ids_events.jsonl"
            path.write_text(json.dumps(_event()) + "\n", encoding="utf-8")
            capture = StructuredEventCapture(path)
            self.assertEqual(capture.poll_once(), {})
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(_event(device_id="sensor2")) + "\n")
            self.assertEqual(len(capture.poll_once()["sensor2"]), 1)


if __name__ == "__main__":
    unittest.main()
