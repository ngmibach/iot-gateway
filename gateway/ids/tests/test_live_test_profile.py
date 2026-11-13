from __future__ import annotations

import json
import tempfile
import time
import unittest
from collections import defaultdict, deque
from pathlib import Path

from ids_gateway.detector import Detector
from ids_gateway.features import FEATURE_NAMES
from ids_gateway.main import AlertWriter, _process_window
from ids_gateway.model import IDSModel
from ids_gateway.rules import RuleEngine
from ids_gateway.structured_events import StructuredEventCapture
from iot_gateway_agent.decrypt_worker import DecryptWorker
from iot_gateway_agent.device_crypto import save_device_secrets
from iot_gateway_agent.envelope_v1 import DeviceSecrets
from iot_gateway_agent.fake_sensor.simulator import _build_envelope_pubs


class LiveTestProfileTests(unittest.TestCase):
    def test_encrypted_test_messages_reach_real_model_and_produce_ml_alert(self) -> None:
        ids_root = Path(__file__).resolve().parents[1]
        model = IDSModel(
            str(ids_root / "models" / "ids_model.joblib"),
            str(ids_root / "models" / "feature_scaler.joblib"),
            FEATURE_NAMES,
        )
        detector = Detector(
            model, threshold=0.05, rule_engine=RuleEngine({"enabled": False}),
            min_packets_per_window=1,
        )
        secrets = DeviceSecrets(
            device_id="ids-test",
            profile="v1-psk",
            mac_key=b"a" * 32,
            wrap_secret=b"b" * 32,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            save_device_secrets(root, secrets)
            worker = DecryptWorker(log_path=root / "sensor_data.log", data_dir=root)
            capture = StructuredEventCapture(root / "logs" / "ids_events.jsonl", start_at_end=False)
            writer = AlertWriter(root / "ids_alerts.log")
            history = defaultdict(lambda: deque(maxlen=6))
            last_alert = {}
            start_ms = int(time.time() * 1000)
            for window in range(4):
                for index in range(30):
                    pubs = _build_envelope_pubs(
                        {"device_id": "ids-test", "hello": 1}, {},
                        secrets=secrets, data_dir=tmp, reverse_order=index % 2 == 1,
                    )
                    received_ms = start_ms + window * 3000 + index * 100
                    for topic, body in pubs:
                        worker._handle_envelope_half(
                            "ids-test", topic.rsplit("/", 1)[-1],
                            body.encode(), topic=topic, received_ms=received_ms,
                        )
                records = capture.poll_once()["ids-test"]
                self.assertEqual(len(records), 30)
                self.assertEqual(len({record.mqtt_topic for record in records}), 2)
                _process_window(
                    device_id="ids-test", records=records, detector=detector,
                    alert_writer=writer, history=history, last_ml_alert=last_alert,
                    threshold=0.05, aggregation_size=6, min_windows=4,
                    min_attack_windows=3, vote_threshold=0.6,
                    average_threshold=0.68, cooldown_seconds=60,
                )
            alert = json.loads(writer.path.read_text(encoding="utf-8").strip())
            self.assertEqual(alert["device_id"], "ids-test")
            self.assertEqual(alert["alert_type"], "ml_anomaly")
            self.assertEqual(alert["score_type"], "ml_probability")


if __name__ == "__main__":
    unittest.main()
