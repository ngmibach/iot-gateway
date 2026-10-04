"""Unit tests for NIC candidate filtering."""

from __future__ import annotations

import unittest

from telemetry.nic import (
    NicCandidate,
    filter_nic_candidates,
    name_excluded,
    pick_default_monitoring_ip,
)


def _c(name: str, ip: str, prefix: int | None = 24) -> NicCandidate:
    return NicCandidate(name=name, ip=ip, prefix=prefix)


class NicFilterTests(unittest.TestCase):
    def test_excludes_docker0_and_bridge(self) -> None:
        raw = [
            _c("eth0", "192.168.1.10"),
            _c("docker0", "172.17.0.1"),
            _c("br-abcd1234", "172.18.0.1"),
            _c("veth0abc", "169.254.1.1"),
            _c("lo", "127.0.0.1", 8),
        ]
        got = filter_nic_candidates(raw)
        self.assertEqual([c.name for c in got], ["eth0"])
        self.assertEqual(got[0].ip, "192.168.1.10")

    def test_excludes_wsl_vethernet_by_name(self) -> None:
        raw = [
            _c("Ethernet", "192.168.40.20"),
            _c("vEthernet (WSL)", "172.28.0.1"),
            _c("vEthernet (WSL (Hyper-V firewall))", "172.29.0.1"),
            _c("vEthernet (Default Switch)", "172.27.0.1"),
            _c("Wi-Fi", "10.0.0.5"),
        ]
        got = filter_nic_candidates(raw)
        names = [c.name for c in got]
        self.assertEqual(names, ["Ethernet", "Wi-Fi"])

    def test_excludes_loopback_and_link_local_ips(self) -> None:
        raw = [
            _c("eth0", "127.0.0.2"),
            _c("eth0", "169.254.10.10"),
            _c("eth0", "192.168.1.50"),
        ]
        got = filter_nic_candidates(raw)
        self.assertEqual([c.ip for c in got], ["192.168.1.50"])

    def test_can_keep_docker_when_flag_false(self) -> None:
        raw = [_c("docker0", "172.17.0.1"), _c("eth0", "192.168.1.10")]
        got = filter_nic_candidates(raw, exclude_docker_wsl=False, exclude_link_local=False)
        # docker0 still excluded? No — exclude_docker_wsl=False keeps it;
        # loopback filter does not apply to 172.17.
        self.assertEqual([c.name for c in got], ["docker0", "eth0"])

    def test_name_excluded_helpers(self) -> None:
        self.assertTrue(name_excluded("docker0"))
        self.assertTrue(name_excluded("br-deadbeef"))
        self.assertTrue(name_excluded("vEthernet (WSL)"))
        self.assertFalse(name_excluded("enp0s3"))
        self.assertFalse(name_excluded("Ethernet 2"))

    def test_pick_default_prefers_gateway_subnet(self) -> None:
        cands = [
            _c("wlan0", "10.0.0.5", 24),
            _c("eth0", "192.168.40.20", 24),
        ]
        pick = pick_default_monitoring_ip(cands, gateway_ip="192.168.40.177")
        assert pick is not None
        self.assertEqual(pick.name, "eth0")

    def test_pick_default_falls_back_to_first(self) -> None:
        cands = [_c("wlan0", "10.0.0.5", 24)]
        pick = pick_default_monitoring_ip(cands, gateway_ip="192.168.1.1")
        assert pick is not None
        self.assertEqual(pick.ip, "10.0.0.5")

    def test_pick_default_empty(self) -> None:
        self.assertIsNone(pick_default_monitoring_ip([]))


if __name__ == "__main__":
    unittest.main()
