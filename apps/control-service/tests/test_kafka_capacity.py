"""Unit tests for Kafka storage-capped sensor capacity."""

from __future__ import annotations

import json
import unittest

from actions.csr import generate_client_key_and_csr
from actions.kafka_capacity import (
    DEFAULT_TOPIC_RETENTION_BYTES,
    kafka_topic_name,
    max_sensor_slots,
    parse_df_total_bytes,
    plan_capacity,
)
from actions.kafka_topics import TopicCatalog
from actions.playbooks import gateway_kafka_capacity, register_device, unregister_device
from tests.cert_helpers import local_self_sign_for_tests
from tests.fake_ssh import FakeSSH
from tests.test_playbooks import ACL, DATA, _base_files, _register_ok_handler


class TestCapacityMath(unittest.TestCase):
    def test_example_ten_disk_one_cap_yields_seven(self) -> None:
        # Abstract units from the architecture: disk=10, topic_cap=1 → 7 sensors.
        self.assertEqual(max_sensor_slots(10, 1, safety_ratio=0.70), 7)

    def test_bytes_example(self) -> None:
        disk = 10 * DEFAULT_TOPIC_RETENTION_BYTES
        self.assertEqual(max_sensor_slots(disk, DEFAULT_TOPIC_RETENTION_BYTES), 7)

    def test_zero_inputs(self) -> None:
        self.assertEqual(max_sensor_slots(0, 1), 0)
        self.assertEqual(max_sensor_slots(10, 0), 0)

    def test_plan_remaining(self) -> None:
        plan = plan_capacity(
            total_storage_bytes=10,
            registered_sensors=5,
            topic_retention_bytes=1,
            safety_ratio=0.7,
        )
        self.assertEqual(plan.max_sensors, 7)
        self.assertEqual(plan.remaining_slots, 2)
        self.assertFalse(plan.at_capacity)

    def test_topic_name(self) -> None:
        self.assertEqual(kafka_topic_name("sensor1"), "sensor.sensor1")

    def test_parse_df_total(self) -> None:
        line = "/dev/root 10485760 1000 10484760 1% /\n"
        self.assertEqual(parse_df_total_bytes(line), 10485760 * 1024)


class TestTopicCatalog(unittest.TestCase):
    def test_round_trip(self) -> None:
        cat = TopicCatalog(retention_bytes_default=100, safety_ratio=0.7)
        cat.upsert_device("s1", retention_bytes=100)
        cat.upsert_device("s2", retention_bytes=100)
        restored = TopicCatalog.from_json(cat.to_json())
        self.assertEqual(restored.count, 2)
        self.assertEqual(restored.get_by_device("s1").topic, "sensor.s1")
        removed = restored.remove_device("s1")
        self.assertIsNotNone(removed)
        self.assertEqual(restored.count, 1)


class TestRegisterKafkaCapacity(unittest.TestCase):
    def test_register_writes_kafka_topic(self) -> None:
        ssh = FakeSSH(_base_files())
        mat = generate_client_key_and_csr("sensor9")
        signed = local_self_sign_for_tests(mat)
        ssh._run_handler = _register_ok_handler(ssh, signed.client_crt_pem)

        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor9",
            password="hunter2xx",
            ip="10.0.0.9",
            topic_rw="sensors/sensor9/#",
            ca_passphrase="correct-horse",
            key_material=mat,
            total_storage_bytes=10 * DEFAULT_TOPIC_RETENTION_BYTES,
            topic_retention_bytes=DEFAULT_TOPIC_RETENTION_BYTES,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.details.get("kafka_topic"), "sensor.sensor9")
        catalog_path = f"{DATA}/kafka/topics.json"
        self.assertTrue(ssh.exists(catalog_path))
        data = json.loads(ssh.read_text(catalog_path))
        self.assertIn("sensor.sensor9", data["topics"])
        self.assertEqual(
            result.details["kafka_capacity"]["max_sensors"],
            7,
        )

    def test_register_rejects_when_full(self) -> None:
        ssh = FakeSSH(_base_files())
        # Pre-fill 7 topics on a 10-unit disk with 1-unit caps.
        cat = TopicCatalog(retention_bytes_default=1, safety_ratio=0.7)
        for i in range(7):
            cat.upsert_device(f"s{i}", retention_bytes=1)
        ssh.write_text(f"{DATA}/kafka/topics.json", cat.to_json())

        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor_new",
            password="hunter2xx",
            ip="10.0.0.99",
            topic_rw="sensors/new/#",
            ca_passphrase="secret",
            total_storage_bytes=10,
            topic_retention_bytes=1,
        )
        self.assertFalse(result.ok)
        self.assertIn("capacity full", result.message)
        self.assertEqual(result.details["kafka_capacity"]["max_sensors"], 7)
        self.assertNotIn("user sensor_new\n", ssh.read_text(ACL))

    def test_reregister_does_not_consume_extra_slot(self) -> None:
        ssh = FakeSSH(_base_files())
        cat = TopicCatalog(retention_bytes_default=1, safety_ratio=0.7)
        for i in range(7):
            cat.upsert_device(f"s{i}", retention_bytes=1)
        # sensor1 already counted in MQTT ACL fixtures; put it in kafka too.
        cat.upsert_device("sensor1", retention_bytes=1)
        # Now at 8 topics but max is 7 — still allow refresh of existing sensor1.
        # Trim to exactly 7 including sensor1.
        cat = TopicCatalog(retention_bytes_default=1, safety_ratio=0.7)
        for i in range(6):
            cat.upsert_device(f"s{i}", retention_bytes=1)
        cat.upsert_device("sensor1", retention_bytes=1)
        ssh.write_text(f"{DATA}/kafka/topics.json", cat.to_json())

        mat = generate_client_key_and_csr("sensor1")
        signed = local_self_sign_for_tests(mat)
        ssh._run_handler = _register_ok_handler(ssh, signed.client_crt_pem)

        result = register_device(
            ssh,  # type: ignore[arg-type]
            user_id="sensor1",
            password="newpass12",
            ip="10.0.0.1",
            topic_rw="sensors/sensor1/#",
            ca_passphrase="secret",
            key_material=mat,
            total_storage_bytes=10,
            topic_retention_bytes=1,
        )
        self.assertTrue(result.ok, result.message)

    def test_unregister_removes_kafka_topic(self) -> None:
        ssh = FakeSSH(_base_files())
        cat = TopicCatalog()
        cat.upsert_device("sensor1")
        ssh.write_text(f"{DATA}/kafka/topics.json", cat.to_json())

        result = unregister_device(ssh, user_id="sensor1")  # type: ignore[arg-type]
        self.assertTrue(result.ok)
        self.assertEqual(result.details.get("kafka_topic_removed"), "sensor.sensor1")
        data = json.loads(ssh.read_text(f"{DATA}/kafka/topics.json"))
        self.assertNotIn("sensor.sensor1", data["topics"])

    def test_gateway_kafka_capacity_probe(self) -> None:
        ssh = FakeSSH(_base_files())
        cat = TopicCatalog(retention_bytes_default=DEFAULT_TOPIC_RETENTION_BYTES)
        cat.upsert_device("a")
        cat.upsert_device("b")
        ssh.write_text(f"{DATA}/kafka/topics.json", cat.to_json())

        plan = gateway_kafka_capacity(
            ssh,  # type: ignore[arg-type]
            total_storage_bytes=10 * DEFAULT_TOPIC_RETENTION_BYTES,
        )
        self.assertEqual(plan.max_sensors, 7)
        self.assertEqual(plan.registered_sensors, 2)
        self.assertEqual(plan.remaining_slots, 5)


if __name__ == "__main__":
    unittest.main()
