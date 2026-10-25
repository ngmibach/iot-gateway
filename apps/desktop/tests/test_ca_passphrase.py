"""Unit tests for CA passphrase generate/validate helpers."""

from __future__ import annotations

import unittest

from shell import ca_passphrase


class CaPassphraseTests(unittest.TestCase):
    def test_generate_is_non_empty_and_not_admin(self) -> None:
        token = ca_passphrase.generate_ca_passphrase(
            sudo_password="s3cret-sudo",
            gateway_id="gw1",
            utc_ns=1,
            extra_salt=b"fixed-salt-16b!!",
        )
        self.assertIsInstance(token, str)
        self.assertGreaterEqual(len(token), 24)
        self.assertNotEqual(token, "admin")
        self.assertTrue(token.strip())

    def test_generate_differs_with_salt(self) -> None:
        a = ca_passphrase.generate_ca_passphrase(
            sudo_password="s3cret-sudo",
            gateway_id="gw1",
            utc_ns=1,
            extra_salt=b"aaaaaaaaaaaaaaaa",
        )
        b = ca_passphrase.generate_ca_passphrase(
            sudo_password="s3cret-sudo",
            gateway_id="gw1",
            utc_ns=1,
            extra_salt=b"bbbbbbbbbbbbbbbb",
        )
        self.assertNotEqual(a, b)

    def test_generate_requires_sudo(self) -> None:
        with self.assertRaises(ValueError):
            ca_passphrase.generate_ca_passphrase(sudo_password="", gateway_id="gw1")
        with self.assertRaises(ValueError):
            ca_passphrase.generate_ca_passphrase(sudo_password="   ", gateway_id="gw1")

    def test_validate_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            ca_passphrase.validate_ca_passphrase("")
        with self.assertRaises(ValueError):
            ca_passphrase.validate_ca_passphrase("   ")

    def test_validate_rejects_admin(self) -> None:
        with self.assertRaises(ValueError):
            ca_passphrase.validate_ca_passphrase("admin")

    def test_validate_accepts_normal(self) -> None:
        self.assertEqual(
            ca_passphrase.validate_ca_passphrase("  correct-horse  "),
            "correct-horse",
        )


if __name__ == "__main__":
    unittest.main()
