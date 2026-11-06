"""Decrypt worker device_id / delay helpers and Kafka handoff."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from iot_gateway_agent.decrypt_worker import (
    DecryptWorker,
    _delay_ms_from_payload,
    _ids_event_times,
    device_id_from_mqtt_topic,
)


class DeviceIdTests(unittest.TestCase):
    def test_sensors_prefix(self) -> None:
        self.assertEqual(device_id_from_mqtt_topic("sensors/sensor1/data"), "sensor1")

    def test_empty(self) -> None:
        self.assertEqual(device_id_from_mqtt_topic(""), "unknown")


class DelayTests(unittest.TestCase):
    def test_explicit_delay(self) -> None:
        self.assertEqual(
            _delay_ms_from_payload(json.dumps({"delay": 12.5}), received_ms=1000),
            12.5,
        )

    def test_ts_ms(self) -> None:
        self.assertEqual(
            _delay_ms_from_payload(json.dumps({"ts_ms": 900}), received_ms=1000),
            100.0,
        )

    def test_ts_ms_zero_ignored(self) -> None:
        # ts_ms=0 yields epoch-sized "delay" (~1.7e12); must not be reported.
        self.assertIsNone(
            _delay_ms_from_payload(json.dumps({"ts_ms": 0}), received_ms=1_793_198_925_490)
        )

    def test_absurd_explicit_delay_ignored(self) -> None:
        self.assertIsNone(
            _delay_ms_from_payload(
                json.dumps({"delay": 1_793_198_925_490}), received_ms=1_793_198_925_490
            )
        )

    def test_ids_delay_requires_a_valid_device_timestamp(self) -> None:
        received_ms = 1_793_198_925_490
        timestamp, delay = _ids_event_times(
            json.dumps({"ts_ms": received_ms - 1500}),
            received_ms=received_ms,
        )
        self.assertIsNotNone(timestamp)
        self.assertEqual(delay, 1.5)
        self.assertEqual(
            _ids_event_times(
                json.dumps({"delay": 12.5}),
                received_ms=received_ms,
            ),
            (None, None),
        )


class DecryptWorkerKafkaTests(unittest.TestCase):
    def test_produce_after_plain_payload(self) -> None:
        kafka = mock.Mock()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "sensor_data.log"
            worker = DecryptWorker(log_path=log_path, kafka=kafka, data_dir=Path(tmp))
            received_ms = int(time.time() * 1000)
            clear = json.dumps({"temp": 1, "ts_ms": received_ms - 1000})
            payload = clear.encode("utf-8")
            with mock.patch(
                "iot_gateway_agent.decrypt_worker.decrypt_wrapper_payload",
                return_value=clear,
            ):
                worker._handle_message("sensors/sensor9/x", payload)
            kafka.produce.assert_called_once()
            args = kafka.produce.call_args[0]
            self.assertEqual(args[0], "sensor.sensor9")
            snap = worker.device_snapshot()
            self.assertEqual(snap["sensor9"].messages_ok, 1)
            # Processing delay is measured on the gateway (receive → Kafka),
            # not from payload delay/ts_ms fields (may be 0.0 in the same ms).
            self.assertIsNotNone(snap["sensor9"].last_delay_ms)
            self.assertGreaterEqual(float(snap["sensor9"].last_delay_ms), 0.0)
            self.assertEqual(snap["sensor9"].delay_ms_count, 1)
            self.assertGreaterEqual(snap["sensor9"].delay_ms_sum, 0.0)
            events = (Path(tmp) / "logs" / "ids_events.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertEqual(len(events), 1)
            event = json.loads(events[0])
            self.assertEqual(event["device_id"], "sensor9")
            self.assertEqual(event["topic"], "sensors/sensor9/x")
            self.assertNotIn("source_ip", event)
            self.assertAlmostEqual(event["delay"], 1.0, delta=0.01)


class DecryptWorkerTlsTests(unittest.TestCase):
    def test_tls_set_called_when_paths_provided(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca = root / "ca.crt"
            cert = root / "decrypt.crt"
            key = root / "decrypt.key"
            for p in (ca, cert, key):
                p.write_text("x", encoding="utf-8")
            worker = DecryptWorker(
                log_path=root / "sensor_data.log",
                port=8883,
                tls_ca=ca,
                tls_cert=cert,
                tls_key=key,
            )
            self.assertTrue(worker.tls_enabled)

            fake_client = mock.MagicMock()
            fake_mqtt = mock.MagicMock()
            fake_mqtt.CallbackAPIVersion.VERSION2 = 2
            fake_mqtt.Client.return_value = fake_client

            def _connect(*_a, **_k):
                worker._stop.set()
                raise OSError("stop")

            fake_client.connect.side_effect = _connect

            # _run does `import paho.mqtt.client as mqtt` — seed sys.modules.
            import ssl
            import sys
            import types

            fake_ctx = mock.MagicMock()
            paho_mod = types.ModuleType("paho")
            mqtt_pkg = types.ModuleType("paho.mqtt")
            with mock.patch.dict(
                sys.modules,
                {
                    "paho": paho_mod,
                    "paho.mqtt": mqtt_pkg,
                    "paho.mqtt.client": fake_mqtt,
                },
            ), mock.patch("ssl.SSLContext", return_value=fake_ctx):
                worker._run()

            fake_client.tls_set_context.assert_called_once_with(fake_ctx)
            self.assertFalse(fake_ctx.check_hostname)
            self.assertEqual(fake_ctx.verify_mode, ssl.CERT_REQUIRED)
            fake_ctx.load_verify_locations.assert_called_once_with(cafile=str(ca))
            fake_ctx.load_cert_chain.assert_called_once_with(
                certfile=str(cert), keyfile=str(key)
            )
            fake_client.username_pw_set.assert_called_once()

    def test_tls_disabled_without_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worker = DecryptWorker(log_path=Path(tmp) / "log")
            self.assertFalse(worker.tls_enabled)


class MosquittoConfTlsTests(unittest.TestCase):
    def test_write_plain_without_tls(self) -> None:
        from iot_gateway_agent.broker import write_mosquitto_conf

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf = write_mosquitto_conf(
                root / "mosquitto.conf",
                data_dir=root / "data",
                log_dir=root / "log",
                passwords=root / "passwords",
                acl=root / "acl",
                listen_port=1883,
            )
            text = conf.read_text(encoding="utf-8")
            self.assertIn("listener 1883", text)
            self.assertNotIn("require_certificate", text)
            self.assertNotIn("cafile", text)

    def test_write_tls_listener(self) -> None:
        from iot_gateway_agent.broker import write_mosquitto_conf

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca = root / "ca.crt"
            cert = root / "server.crt"
            key = root / "server.key"
            conf = write_mosquitto_conf(
                root / "mosquitto.conf",
                data_dir=root / "data",
                log_dir=root / "log",
                passwords=root / "passwords",
                acl=root / "acl",
                listen_port=8883,
                cafile=ca,
                certfile=cert,
                keyfile=key,
            )
            text = conf.read_text(encoding="utf-8")
            self.assertIn("listener 8883", text)
            self.assertIn(f"cafile {ca.as_posix()}", text)
            self.assertIn(f"certfile {cert.as_posix()}", text)
            self.assertIn(f"keyfile {key.as_posix()}", text)
            self.assertIn("require_certificate true", text)


if __name__ == "__main__":
    unittest.main()
