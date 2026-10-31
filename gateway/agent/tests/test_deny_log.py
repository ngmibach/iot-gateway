"""DenyLog ring buffer and IP map lookup."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from iot_gateway_agent.deny_log import DenyLog


class DenyLogTests(unittest.TestCase):
    def test_recent_newest_first_and_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "denied.jsonl"
            log = DenyLog(path=path, gateway_id="gw1", max_events=10)
            log.record(reason="fernet", device_id="fake2", source_ip="10.255.0.3")
            log.record(reason="acl_deny", device_id="fake1")
            events = log.recent(limit=10)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["reason"], "acl_deny")
            self.assertEqual(events[0]["gateway_id"], "gw1")
            self.assertEqual(events[1]["device_id"], "fake2")
            lines = path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 2)

    def test_ip_map_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ip_map = root / "ip-map.json"
            ip_map.write_text(
                json.dumps(
                    {
                        "devices": {
                            "fake2": {"ip": "10.255.0.3"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            log = DenyLog(gateway_id="gateway")
            log.set_ip_map_path(ip_map)
            self.assertEqual(log.lookup_device("10.255.0.3"), "fake2")
            ev = log.record(reason="missing_client_cert", device_id="unknown", source_ip="10.255.0.3")
            self.assertEqual(ev.device_id, "fake2")
            ev2 = log.record(reason="schema", device_id="fake2")
            self.assertEqual(ev2.source_ip, "10.255.0.3")

    def test_filter_by_device(self) -> None:
        log = DenyLog(max_events=20)
        log.record(reason="a", device_id="fake1")
        log.record(reason="b", device_id="fake2")
        log.record(reason="c", device_id="fake2")
        only = log.recent(device_id="fake2")
        self.assertEqual(len(only), 2)
        self.assertTrue(all(e["device_id"] == "fake2" for e in only))


if __name__ == "__main__":
    unittest.main()
