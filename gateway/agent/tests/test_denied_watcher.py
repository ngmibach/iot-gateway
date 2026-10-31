"""Mosquitto TLS / ACL line parsing for DeniedWatcher."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from iot_gateway_agent.denied_watcher import DeniedWatcher, _classify_tls_detail
from iot_gateway_agent.deny_log import DenyLog


class ClassifyTlsTests(unittest.TestCase):
    def test_missing_cert(self) -> None:
        self.assertEqual(
            _classify_tls_detail("SSL routines::peer did not return a certificate"),
            "missing_client_cert",
        )

    def test_bad_cert(self) -> None:
        self.assertEqual(
            _classify_tls_detail("certificate verify failed"),
            "bad_client_cert",
        )


class DeniedWatcherParseTests(unittest.TestCase):
    def test_openssl_maps_ip_to_device_and_bumps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ip_map = root / "ip-map.json"
            ip_map.write_text(
                json.dumps({"devices": {"fake2": {"ip": "10.255.0.3"}}}),
                encoding="utf-8",
            )
            deny_log = DenyLog(gateway_id="gateway")
            deny_log.set_ip_map_path(ip_map)
            worker = mock.Mock()
            watcher = DeniedWatcher(worker=worker, deny_log=deny_log)
            watcher._on_mosquitto_line(
                "New connection from 10.255.0.3:33393 on port 8883.\n"
            )
            watcher._on_mosquitto_line(
                "OpenSSL Error[0]: error:0A0000C7:SSL routines::peer did not return a certificate\n"
            )
            self.assertEqual(watcher.denied_total, 1)
            worker.bump_denied.assert_called_once()
            kwargs = worker.bump_denied.call_args
            self.assertEqual(kwargs[0][0], "fake2")
            self.assertEqual(kwargs[1]["reason"], "missing_client_cert")
            self.assertEqual(kwargs[1]["source_ip"], "10.255.0.3")
            self.assertTrue(kwargs[1]["count_as_message"])

    def test_acl_deny(self) -> None:
        worker = mock.Mock()
        watcher = DeniedWatcher(worker=worker)
        watcher._on_mosquitto_line(
            "Denied PUBLISH from fake1 (ACL deny) on topic sensors/x\n"
        )
        self.assertEqual(watcher.denied_total, 1)
        worker.bump_denied.assert_called_once()
        self.assertEqual(worker.bump_denied.call_args[0][0], "fake1")
        self.assertEqual(worker.bump_denied.call_args[1]["reason"], "acl_deny")

    def test_skips_localhost_conn_failed(self) -> None:
        worker = mock.Mock()
        watcher = DeniedWatcher(worker=worker)
        watcher._on_mosquitto_line(
            "Client connection from 127.0.0.1 failed: error:0A000126:SSL routines::unexpected eof while reading.\n"
        )
        self.assertEqual(watcher.denied_total, 0)
        worker.bump_denied.assert_not_called()


if __name__ == "__main__":
    unittest.main()
