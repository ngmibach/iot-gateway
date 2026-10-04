"""Tests for local Mosquitto $7$ hashing."""

from __future__ import annotations

import base64
import hashlib
import unittest

from actions.mosquitto_hash import hash_password_line


class TestMosquittoHash(unittest.TestCase):
    def test_format_and_verify(self) -> None:
        line = hash_password_line("sensor9", "s3cret")
        self.assertTrue(line.startswith("sensor9:$7$1000$"))
        _user, rest = line.split(":", 1)
        parts = rest.split("$")
        # '', '7', '1000', salt, hash
        self.assertEqual(parts[1], "7")
        self.assertEqual(parts[2], "1000")
        salt = base64.b64decode(parts[3])
        expected = base64.b64decode(parts[4])
        self.assertEqual(len(salt), 64)
        self.assertEqual(len(expected), 64)
        dk = hashlib.pbkdf2_hmac("sha512", b"s3cret", salt, 1000, dklen=64)
        self.assertEqual(dk, expected)

    def test_deterministic_with_salt(self) -> None:
        salt = b"\x01" * 64
        a = hash_password_line("u", "p", salt=salt)
        b = hash_password_line("u", "p", salt=salt)
        self.assertEqual(a, b)

    def test_rejects_bad_username(self) -> None:
        with self.assertRaises(ValueError):
            hash_password_line("bad:user", "p")
        with self.assertRaises(ValueError):
            hash_password_line("", "p")

    def test_rejects_empty_password(self) -> None:
        with self.assertRaises(ValueError):
            hash_password_line("u", "")


if __name__ == "__main__":
    unittest.main()
