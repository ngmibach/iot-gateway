"""Unit tests for gateway neighbor parsing (sensor discover)."""

from __future__ import annotations

import unittest

from actions.discover_sensors import (
    merge_hosts,
    parse_gateway_ips,
    parse_ip_neigh,
    parse_proc_arp,
)


class DiscoverSensorsParseTests(unittest.TestCase):
    def test_parse_gateway_ips(self) -> None:
        addr = (
            "2: eth0    inet 172.20.10.2/28 brd 172.20.10.15 scope global eth0\n"
            "3: lo      inet 127.0.0.1/8 scope host lo\n"
        )
        ips = parse_gateway_ips(addr, "172.20.10.2 172.20.10.2")
        self.assertEqual(ips, ["172.20.10.2"])

    def test_parse_ip_neigh_filters_self_and_incomplete(self) -> None:
        text = """
172.20.10.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
172.20.10.2 dev eth0 lladdr 88:a2:9e:72:0a:dc STALE
172.20.10.5 dev eth0 INCOMPLETE
172.20.10.8 dev eth0 lladdr 11:22:33:44:55:66 STALE
127.0.0.1 dev lo FAILED
"""
        hosts = parse_ip_neigh(text, gateway_ips=["172.20.10.2"])
        ips = [h["ip"] for h in hosts]
        self.assertEqual(ips, ["172.20.10.1", "172.20.10.8"])
        self.assertEqual(hosts[0]["mac"], "aa:bb:cc:dd:ee:01")

    def test_parse_proc_arp(self) -> None:
        text = """IP address       HW type     Flags       HW address            Mask     Device
172.20.10.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
172.20.10.2      0x1         0x2         88:a2:9e:72:0a:dc     *        eth0
172.20.10.9      0x1         0x0         00:00:00:00:00:00     *        eth0
"""
        hosts = parse_proc_arp(text, gateway_ips=["172.20.10.2"])
        self.assertEqual([h["ip"] for h in hosts], ["172.20.10.1"])

    def test_merge_hosts(self) -> None:
        a = [{"ip": "10.0.0.2", "state": "STALE"}]
        b = [{"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff", "state": "ARP"}]
        c = [{"ip": "10.0.0.1", "mac": "11:22:33:44:55:66", "state": "REACHABLE"}]
        merged = merge_hosts(a, b, c)
        self.assertEqual([h["ip"] for h in merged], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(merged[1]["mac"], "aa:bb:cc:dd:ee:ff")


if __name__ == "__main__":
    unittest.main()
