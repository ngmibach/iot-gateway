from __future__ import annotations

import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ids_gateway.detector import Detector
from ids_gateway.features import FEATURE_NAMES
from ids_gateway.log_capture import SensorLogCapture
from ids_gateway.model import IDSModel
from ids_gateway.rules import RuleEngine


IDS_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = IDS_ROOT / "models"
BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _event(
    *,
    device_id: str,
    topic: str,
    payload: dict,
    seconds_after_start: float,
) -> dict:
    received_at = BASE_TIME + timedelta(seconds=seconds_after_start)
    return {
        "event_type": "sensor_data",
        "deviceId": device_id,
        "topic": topic,
        "payload": payload,
        "gateway_received_at": received_at.isoformat(),
        "payload_size_bytes": len(json.dumps(payload, separators=(",", ":"))),
        "broker_port": 8883,
    }


class IDSModelPipelineE2ETests(unittest.TestCase):
    def test_training_metadata_matches_runtime_and_uses_disjoint_session_splits(self) -> None:
        metadata = json.loads(
            (MODEL_DIR / "model_metadata.json").read_text(encoding="utf-8")
        )

        self.assertEqual(metadata["model_type"], "lightgbm")
        self.assertEqual(metadata["target_column"], "label")
        self.assertEqual(metadata["split_strategy"], "group")
        self.assertEqual(metadata["group_column"], "session_id")
        self.assertEqual(metadata["feature_columns"], FEATURE_NAMES)
        self.assertEqual(metadata["selected_threshold"], 0.05)

        split_stats = metadata["split_stats"]
        train = set(split_stats["train_sessions"])
        validation = set(split_stats["val_sessions"])
        test = set(split_stats["test_sessions"])
        self.assertTrue(train)
        self.assertTrue(validation)
        self.assertTrue(test)
        self.assertFalse(train & validation)
        self.assertFalse(train & test)
        self.assertFalse(validation & test)

        self.assertEqual(split_stats["train_rows"], 834)
        self.assertEqual(split_stats["val_rows"], 1227)
        self.assertEqual(split_stats["test_rows"], 516)
        self.assertTrue(metadata["sample_weight_stats"]["enabled"])
        self.assertFalse(metadata["scaler_enabled"])

    def test_bundled_model_evaluates_on_held_out_training_sessions(self) -> None:
        metadata = json.loads(
            (MODEL_DIR / "model_metadata.json").read_text(encoding="utf-8")
        )
        fixture_path = IDS_ROOT / "tests" / "fixtures" / "model_heldout_test.csv"
        with fixture_path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))

        split_stats = metadata["split_stats"]
        expected_sessions = set(split_stats["test_sessions"])
        self.assertEqual(len(rows), split_stats["test_rows"])
        self.assertEqual({row["session_id"] for row in rows}, expected_sessions)
        self.assertEqual(
            set(rows[0]),
            {"session_id", *metadata["feature_columns"], "label"},
        )
        labels = [int(row["label"]) for row in rows]
        self.assertIn(0, labels)
        self.assertIn(1, labels)
        self.assertEqual(sum(labels), round(split_stats["test_attack_ratio"] * len(rows)))

        model = IDSModel(
            str(MODEL_DIR / "ids_model.joblib"),
            str(MODEL_DIR / "feature_scaler.joblib"),
            FEATURE_NAMES,
        )
        features = [
            {name: float(row[name]) for name in FEATURE_NAMES}
            for row in rows
        ]
        scores = model.predict_batch(features)
        threshold = model.get_default_threshold()
        self.assertIsNotNone(threshold)
        predictions = [int(score >= threshold) for score in scores]

        true_positive = sum(y == 1 and pred == 1 for y, pred in zip(labels, predictions))
        true_negative = sum(y == 0 and pred == 0 for y, pred in zip(labels, predictions))
        false_positive = sum(y == 0 and pred == 1 for y, pred in zip(labels, predictions))
        false_negative = sum(y == 1 and pred == 0 for y, pred in zip(labels, predictions))
        metrics = metadata["test_metrics_at_selected_threshold"]

        self.assertEqual(
            [[true_negative, false_positive], [false_negative, true_positive]],
            metadata["confusion_matrix_test"],
        )
        self.assertEqual(
            (true_positive, true_negative, false_positive, false_negative),
            (metrics["tp"], metrics["tn"], metrics["fp"], metrics["fn"]),
        )
        self.assertAlmostEqual(
            true_positive / (true_positive + false_positive),
            metrics["precision_attack"],
        )
        self.assertAlmostEqual(
            true_positive / (true_positive + false_negative),
            metrics["recall_attack"],
        )
        self.assertAlmostEqual(
            false_positive / (false_positive + true_negative),
            metrics["fpr"],
        )
        self.assertAlmostEqual(
            false_negative / (false_negative + true_positive),
            metrics["fnr"],
        )

    def test_structured_sensor_events_reach_bundled_model_inference(self) -> None:
        model = IDSModel(
            str(MODEL_DIR / "ids_model.joblib"),
            str(MODEL_DIR / "feature_scaler.joblib"),
            FEATURE_NAMES,
        )
        self.assertEqual(model.features, FEATURE_NAMES)
        threshold = model.get_default_threshold()
        self.assertEqual(threshold, 0.05)

        with tempfile.TemporaryDirectory() as tmp:
            event_log = Path(tmp) / "ids_events.jsonl"
            event_log.touch()
            capture = SensorLogCapture(str(event_log))
            regular_events = [
                _event(
                    device_id="sensor_regular",
                    topic="sensors/sensor_regular/telemetry",
                    payload={"temperature_c": 21.0 + index / 10},
                    seconds_after_start=index * 0.6,
                )
                for index in range(5)
            ]
            attack_like_events = [
                _event(
                    device_id="sensor_burst",
                    topic=f"sensors/sensor_burst/flood/{index}",
                    payload={"debug": {"attack_blob": "X" * (512 + index)}},
                    seconds_after_start=3 + index * 0.05,
                )
                for index in range(8)
            ]
            with event_log.open("a", encoding="utf-8") as fh:
                for event in regular_events + attack_like_events:
                    fh.write(json.dumps(event, separators=(",", ":")) + "\n")

            batches = capture.poll_once()

        self.assertEqual(set(batches), {"sensor_regular", "sensor_burst"})
        self.assertEqual(len(batches["sensor_regular"]), len(regular_events))
        self.assertEqual(len(batches["sensor_burst"]), len(attack_like_events))
        self.assertTrue(
            all(
                not record.src_ip
                for records in batches.values()
                for record in records
            )
        )

        detector = Detector(
            model=model,
            threshold=threshold,
            rule_engine=RuleEngine({"enabled": False}),
            min_packets_per_window=1,
        )
        regular = detector.evaluate_device(
            "sensor_regular", "", batches["sensor_regular"]
        )
        attack_like = detector.evaluate_device(
            "sensor_burst", "", batches["sensor_burst"]
        )

        self.assertEqual(regular.features["msg_count"], 5.0)
        self.assertEqual(attack_like.features["msg_count"], 8.0)
        self.assertEqual(attack_like.features["topic_flood_ratio"], 1.0)
        self.assertEqual(attack_like.features["attack_blob_ratio"], 1.0)
        for result in (regular, attack_like):
            self.assertGreaterEqual(result.attack_probability, 0.0)
            self.assertLessEqual(result.attack_probability, 1.0)
            self.assertEqual(result.is_attack, result.attack_probability >= threshold)


if __name__ == "__main__":
    unittest.main()
