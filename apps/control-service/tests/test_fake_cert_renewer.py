"""Unit tests for fake-sensor cert renew window + FakeCertRenewer."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import patch

from actions.fake_sensors import FakePlaybookResult
from actions.playbooks import RegisterResult
from api.fake_cert_renewer import (
    FakeCertRenewer,
    attack_pauses_auto_renew,
    default_renew_window_s,
    evaluate_renew,
    resolve_ca_passphrase,
)
from registry.registry import Registry


class RenewWindowTests(unittest.TestCase):
    def test_default_window_min_30d_or_10_percent(self) -> None:
        # 730d → 10% = 73d → capped at 30d
        self.assertEqual(default_renew_window_s(730), 30 * 86400)
        # 100d → 10% = 10d
        self.assertEqual(default_renew_window_s(100), 10 * 86400)
        # tiny lifetime still at least 60s
        self.assertGreaterEqual(default_renew_window_s(1), 60)

    def test_evaluate_near_expiry(self) -> None:
        now = 1_700_000_000
        row = {
            "id": "fake1",
            "monitor_enabled": 1,
            "cert_expires_at": now + 100,
            "cert_fingerprint": "aa",
            "meta_json": {
                "is_fake": True,
                "fake": {"cert_feed_fingerprint": "aa", "behaviors": {}},
            },
        }
        d = evaluate_renew(row, now=now, renew_window_s=1000)
        self.assertTrue(d.needed)
        self.assertEqual(d.reason, "near_expiry")

        d2 = evaluate_renew(row, now=now, renew_window_s=10)
        self.assertFalse(d2.needed)
        self.assertEqual(d2.reason, "ok")

    def test_evaluate_feed_lag(self) -> None:
        row = {
            "id": "fake1",
            "monitor_enabled": 1,
            "cert_expires_at": int(time.time()) + 10_000_000,
            "cert_fingerprint": "newfp",
            "meta_json": {
                "is_fake": True,
                "fake": {"cert_feed_fingerprint": "oldfp", "behaviors": {}},
            },
        }
        d = evaluate_renew(row, now=int(time.time()), renew_window_s=86400)
        self.assertTrue(d.needed)
        self.assertEqual(d.reason, "feed_lag")

    def test_evaluate_skips_attack_and_real(self) -> None:
        meta_attack = {
            "is_fake": True,
            "fake": {
                "behaviors": {"omit_client_cert": True},
                "cert_feed_fingerprint": "x",
            },
        }
        self.assertTrue(attack_pauses_auto_renew(meta_attack))
        row = {
            "id": "fake1",
            "monitor_enabled": 1,
            "cert_expires_at": int(time.time()) + 1,
            "cert_fingerprint": "aa",
            "meta_json": meta_attack,
        }
        d = evaluate_renew(row, now=int(time.time()), renew_window_s=10_000)
        self.assertFalse(d.needed)
        self.assertEqual(d.reason, "skip_attack")

        real = {
            "id": "s1",
            "monitor_enabled": 1,
            "cert_expires_at": int(time.time()) + 1,
            "cert_fingerprint": "aa",
            "meta_json": {},
        }
        self.assertEqual(
            evaluate_renew(real, now=int(time.time()), renew_window_s=10_000).reason,
            "ok",
        )


class ResolveCaTests(unittest.TestCase):
    def test_settings_wins(self) -> None:
        self.assertEqual(
            resolve_ca_passphrase(
                gateway_id="gw1", settings_ca="from-settings", data_dir=None
            ),
            "from-settings",
        )

    def test_fallback_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keyring-fallback.json"
            path.write_text(json.dumps({"ca:gw1": "file-secret"}), encoding="utf-8")
            self.assertEqual(
                resolve_ca_passphrase(
                    gateway_id="gw1", settings_ca=None, data_dir=tmp
                ),
                "file-secret",
            )


class FakeCertRenewerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        db = Path(self._tmp.name) / "registry.sqlite"
        self.registry = Registry(str(db))
        self.registry.upsert_gateway(
            id="gw1",
            host="192.168.1.50",
            ssh_user="pi",
            install_root="/opt/iot-gateway-agent",
            fingerprint="fp",
        )
        self.now = 1_700_000_000

        @contextmanager
        def open_ssh(_gw: dict[str, Any]) -> Iterator[Any]:
            yield object()

        self.open_ssh = open_ssh

    def _seed_fake(
        self,
        *,
        expires_at: int,
        fingerprint: str = "oldfp",
        fed_fp: str = "oldfp",
        behaviors: dict[str, bool] | None = None,
    ) -> None:
        self.registry.upsert_device(
            "gw1",
            "fake1",
            ip="10.255.0.2",
            monitor_enabled=1,
            cert_expires_at=expires_at,
            cert_fingerprint=fingerprint,
            meta_json={
                "is_fake": True,
                "fake": {
                    "ip": "10.255.0.2",
                    "status": "running",
                    "cert_feed_fingerprint": fed_fp,
                    "behaviors": behaviors
                    or {
                        "omit_client_cert": False,
                        "wrong_client_cert": False,
                    },
                },
            },
        )

    def test_run_once_renews_near_expiry(self) -> None:
        self._seed_fake(expires_at=self.now + 60)
        renewer = FakeCertRenewer(
            registry=self.registry,
            open_ssh=self.open_ssh,
            settings_ca="secret-ca",
            client_cert_days=730,
            renew_window_s=1000,
            enabled=True,
            clock=lambda: float(self.now),
        )

        def _reissue(_ssh: Any = None, **kwargs: Any) -> RegisterResult:
            return RegisterResult(
                ok=True,
                status="ok",
                message="reissued",
                cert_fingerprint="newfp",
                cert_expires_at="2035-01-01T00:00:00+00:00",
                ca_crt_pem=b"CA",
                client_crt_pem=b"CRT",
                client_key_pem=b"KEY",
            )

        with (
            patch(
                "api.fake_cert_renewer.reissue_device_cert", side_effect=_reissue
            ) as reiss,
            patch(
                "api.fake_cert_renewer.feed_fake_certs",
                return_value=FakePlaybookResult(ok=True, message="fed"),
            ) as fed,
        ):
            results = renewer.run_once()

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)
        self.assertEqual(results[0].reason, "near_expiry")
        self.assertEqual(results[0].new_fingerprint, "newfp")
        reiss.assert_called_once()
        fed.assert_called_once()
        row = self.registry.get_device("gw1", "fake1")
        assert row is not None
        self.assertEqual(row["cert_fingerprint"], "newfp")
        meta = json.loads(row["meta_json"])
        self.assertEqual(meta["fake"]["cert_feed_fingerprint"], "newfp")
        audits = [
            a
            for a in self.registry.list_audit(gateway_id="gw1")
            if a["action"] == "fake_cert_auto_renew"
        ]
        self.assertTrue(audits)

    def test_run_once_skips_attack_mode(self) -> None:
        self._seed_fake(
            expires_at=self.now + 60,
            behaviors={"omit_client_cert": True, "wrong_client_cert": False},
        )
        renewer = FakeCertRenewer(
            registry=self.registry,
            open_ssh=self.open_ssh,
            settings_ca="secret-ca",
            renew_window_s=1000,
            clock=lambda: float(self.now),
        )
        with patch("api.fake_cert_renewer.reissue_device_cert") as reiss:
            results = renewer.run_once()
        self.assertEqual(results, [])
        reiss.assert_not_called()

    def test_run_once_skips_real_devices(self) -> None:
        self.registry.upsert_device(
            "gw1",
            "sensor1",
            ip="10.0.0.2",
            cert_expires_at=self.now + 60,
            cert_fingerprint="aa",
        )
        renewer = FakeCertRenewer(
            registry=self.registry,
            open_ssh=self.open_ssh,
            settings_ca="secret-ca",
            renew_window_s=1000,
            clock=lambda: float(self.now),
        )
        with patch("api.fake_cert_renewer.reissue_device_cert") as reiss:
            self.assertEqual(renewer.run_once(), [])
        reiss.assert_not_called()

    def test_missing_ca_audits_with_backoff(self) -> None:
        self._seed_fake(expires_at=self.now + 60)
        renewer = FakeCertRenewer(
            registry=self.registry,
            open_ssh=self.open_ssh,
            settings_ca=None,
            renew_window_s=1000,
            clock=lambda: float(self.now),
        )
        with patch("api.fake_cert_renewer.reissue_device_cert") as reiss:
            self.assertEqual(renewer.run_once(), [])
            self.assertEqual(renewer.run_once(), [])
        reiss.assert_not_called()
        skips = [
            a
            for a in self.registry.list_audit(gateway_id="gw1")
            if a["action"] == "fake_cert_auto_renew_skip"
        ]
        self.assertEqual(len(skips), 1)


if __name__ == "__main__":
    unittest.main()
