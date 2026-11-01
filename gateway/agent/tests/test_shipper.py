from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from iot_gateway_agent.shipper import LokiShipper


class LokiShipperTailTests(unittest.TestCase):
    def test_partial_writes_rotation_and_truncation_are_sent_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ids_alerts.log"
            path.touch()
            sent: list[str] = []
            shipper = LokiShipper(
                path,
                loki_url="http://127.0.0.1:3100",
                interval_s=0.01,
            )
            shipper._push = lambda lines: sent.extend(lines)  # type: ignore[method-assign]

            def wait_for_count(count: int) -> None:
                deadline = time.monotonic() + 1.0
                while len(sent) < count and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(len(sent), count)

            shipper.start()
            self.addCleanup(shipper.stop)
            first = b'{"event_type":"ids_alert","device_id":"sensor1"}\n'
            with path.open("ab") as fh:
                fh.write(first[:19])
            time.sleep(0.05)
            self.assertEqual(sent, [])
            with path.open("ab") as fh:
                fh.write(first[19:])
            wait_for_count(1)

            second = b'{"event_type":"ids_alert","device_id":"sensor2"}\n'
            path.write_bytes(second)
            wait_for_count(2)

            rotated = path.with_suffix(".log.1")
            os.replace(path, rotated)
            third = b'{"event_type":"ids_alert","device_id":"sensor3"}\n'
            path.write_bytes(third)
            wait_for_count(3)

            path.write_bytes(b"")
            time.sleep(0.05)
            fourth = b'{"event_type":"ids_alert","device_id":"sensor4"}\n'
            with path.open("ab") as fh:
                fh.write(fourth)
            wait_for_count(4)
            self.assertEqual(
                sent,
                [
                    first.decode().strip(),
                    second.decode().strip(),
                    third.decode().strip(),
                    fourth.decode().strip(),
                ],
            )


if __name__ == "__main__":
    unittest.main()
