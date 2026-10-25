"""Unit tests for Windows native firewall checklist generation (K18)."""

from __future__ import annotations

import unittest

from telemetry.checklist import (
    FIREWALL_RULE_NAME,
    format_checklist_for_display,
    generate_windows_native_checklist,
)
from telemetry.readiness import gateway_loki_ready_curl


class NativeWindowsChecklistTests(unittest.TestCase):
    def test_native_firewall_only_no_portproxy(self) -> None:
        items = generate_windows_native_checklist(monitoring_ip="192.168.1.10")
        by_id = {i.id: i for i in items}
        self.assertIn("firewall_allow", by_id)
        self.assertIn("firewall_show", by_id)
        self.assertIn("user_confirm", by_id)
        self.assertNotIn("portproxy_add", by_id)
        cmds = "\n".join(i.command for i in items if i.command)
        self.assertNotIn("portproxy", cmds.lower())
        self.assertIn("advfirewall", by_id["firewall_allow"].command)
        self.assertIn(FIREWALL_RULE_NAME, by_id["firewall_allow"].command)
        self.assertIn("192.168.1.10:3100/ready", by_id["user_confirm"].notes)
        text = format_checklist_for_display(items)
        self.assertIn("firewall checklist", text.lower())
        self.assertNotIn("wsl2 nat", text.lower())

    def test_include_firewall_delete(self) -> None:
        items = generate_windows_native_checklist(include_firewall_delete=True)
        by_id = {i.id: i for i in items}
        self.assertIn("firewall_delete", by_id)
        self.assertIn("delete rule", by_id["firewall_delete"].command)
        self.assertIn(FIREWALL_RULE_NAME, by_id["firewall_delete"].command)

    def test_gateway_loki_ready_curl_helper(self) -> None:
        cmd = gateway_loki_ready_curl("192.168.1.10")
        self.assertEqual(
            cmd,
            "curl -fsS --max-time 5 http://192.168.1.10:3100/ready",
        )


if __name__ == "__main__":
    unittest.main()
