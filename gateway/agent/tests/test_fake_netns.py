"""Unit tests for fake_netns ensure (reboot-safe /run/netns recreate)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Allow ``python -m`` style imports when running from repo root.
_AGENT_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENT_ROOT))

from iot_gateway_agent import fake_netns  # noqa: E402


class TestFakeNetns(unittest.TestCase):
    def test_ensure_recreates_when_netns_missing(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "fake"
            fake.mkdir()
            (fake / "ip-map.json").write_text(
                json.dumps(
                    {
                        "bridge": "iotgw-fake",
                        "gateway_ip": "10.255.0.1",
                        "devices": {
                            "fake1": {
                                "ip": "10.255.0.2",
                                "host_num": 2,
                                "host_if": "vf2",
                                "ns_if": "vn2",
                                "netns": "iotgw-fake-fake1",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            calls: list[list[str]] = []

            def fake_run(argv, check=True, text=True, capture_output=True):  # noqa: ARG001
                calls.append(list(argv))
                # First link show → missing bridge; later commands succeed.
                from subprocess import CompletedProcess

                if argv[1:3] == ["link", "show"] and argv[-1] == "iotgw-fake":
                    return CompletedProcess(argv, 1, "", "not found")
                if argv[1:3] == ["-br", "addr"] or (
                    len(argv) > 3 and argv[1] == "-n" and "addr" in argv
                ):
                    return CompletedProcess(argv, 1, "", "")
                return CompletedProcess(argv, 0, "", "")

            with patch.object(fake_netns, "_run", side_effect=fake_run):
                with patch.object(fake_netns, "_ip_bin", return_value="/sbin/ip"):
                    with patch.object(fake_netns, "_netns_ready", return_value=False):
                        alloc = fake_netns.ensure_netns("fake1", data_dir=root)

            self.assertEqual(alloc["ip"], "10.255.0.2")
            joined = " ".join(" ".join(c) for c in calls)
            self.assertIn("netns add", joined)
            self.assertIn("type veth", joined)
            self.assertIn("iotgw-fake-fake1", joined)


if __name__ == "__main__":
    unittest.main()
