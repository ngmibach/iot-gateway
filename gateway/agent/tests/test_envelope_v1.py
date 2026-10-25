"""Unit tests for envelope_v1 seal/open."""

from __future__ import annotations

import json
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from iot_gateway_agent.envelope_v1 import (
    EnvelopeDayError,
    EnvelopeStampError,
    generate_device_secrets,
    open_envelope,
    parse_envelope_topic,
    seal,
    today_day_id,
)


class EnvelopeV1Tests(unittest.TestCase):
    def test_roundtrip_psk(self) -> None:
        secrets = generate_device_secrets("dev-1", profile="v1-psk", schema_id="temp-v1")
        day_id = today_day_id()
        payload = {"device_id": "dev-1", "temp_c": 21.5, "ts_ms": 1}
        result = seal(payload, secrets, day_id=day_id)
        self.assertEqual(result.day_id, day_id)
        self.assertEqual(result.key_part["alg"], "v1-psk")
        self.assertIn("wrap_nonce", result.key_part)
        self.assertEqual(result.key_part["stamp"], result.data_part["stamp"])
        plain = open_envelope(result.key_part, result.data_part, secrets)
        self.assertEqual(json.loads(plain.decode("utf-8")), payload)

    def test_roundtrip_ecdhe(self) -> None:
        secrets = generate_device_secrets(
            "dev-2", profile="v1-ecdhe", schema_id="temp-v1"
        )
        day_private = ec.generate_private_key(ec.SECP256R1())
        day_id = today_day_id()
        payload = {"ok": True}
        result = seal(
            payload,
            secrets,
            day_id=day_id,
            day_public_key=day_private.public_key(),
        )
        self.assertEqual(result.key_part["alg"], "v1-ecdhe")
        self.assertIn("eph_pub", result.key_part)
        plain = open_envelope(
            result.key_part,
            result.data_part,
            secrets,
            day_private_key=day_private,
        )
        self.assertEqual(json.loads(plain.decode("utf-8")), payload)

    def test_stamp_corruption_fails(self) -> None:
        secrets = generate_device_secrets("dev-1", profile="v1-psk")
        day_id = today_day_id()
        result = seal({"n": 1}, secrets, day_id=day_id)
        bad_key = dict(result.key_part)
        stamp = bad_key["stamp"]
        flip = "A" if stamp[0] != "A" else "B"
        bad_key["stamp"] = flip + stamp[1:]
        with self.assertRaises(EnvelopeStampError):
            open_envelope(bad_key, result.data_part, secrets)

        bad_data = dict(result.data_part)
        stamp = bad_data["stamp"]
        flip = "A" if stamp[0] != "A" else "B"
        bad_data["stamp"] = flip + stamp[1:]
        with self.assertRaises(EnvelopeStampError):
            open_envelope(result.key_part, bad_data, secrets)

    def test_wrong_day_fails(self) -> None:
        secrets = generate_device_secrets("dev-1", profile="v1-psk")
        result = seal({"n": 1}, secrets, day_id="19990101")
        with self.assertRaises(EnvelopeDayError):
            open_envelope(
                result.key_part,
                result.data_part,
                secrets,
                allowed_day_ids={today_day_id()},
            )

    def test_msg_id_mismatch_fails(self) -> None:
        secrets = generate_device_secrets("dev-1", profile="v1-psk")
        day_id = today_day_id()
        a = seal({"n": 1}, secrets, day_id=day_id)
        b = seal({"n": 2}, secrets, day_id=day_id)
        with self.assertRaises(EnvelopeStampError):
            open_envelope(a.key_part, b.data_part, secrets)

    def test_topic_helpers(self) -> None:
        from iot_gateway_agent.envelope_v1 import data_topic, key_topic

        self.assertEqual(key_topic("abc"), "sensors/abc/env/key")
        self.assertEqual(data_topic("abc"), "sensors/abc/env/data")
        self.assertEqual(parse_envelope_topic("sensors/abc/env/key"), ("abc", "key"))
        self.assertEqual(parse_envelope_topic("sensors/abc/env/data"), ("abc", "data"))
        self.assertIsNone(parse_envelope_topic("sensors/abc/data"))


if __name__ == "__main__":
    unittest.main()
