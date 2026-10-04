"""FastAPI admin signing routes — mocked sign_artifacts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.app import create_app
from api.settings import Settings
from registry.registry import Registry
from signing.service import SignResult


class SigningApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        db = Path(self._tmp.name) / "registry.sqlite"
        self.registry = Registry(str(db))
        self.settings = Settings(
            host="127.0.0.1",
            port=9137,
            data_dir=Path(self._tmp.name),
            registry_path=db,
            api_token=None,
        )
        self.app = create_app(settings=self.settings, registry=self.registry)
        self.client = TestClient(self.app)

    def test_tools_endpoint(self) -> None:
        r = self.client.get("/api/v1/admin/signing/tools")
        self.assertEqual(r.status_code, 200)
        self.assertIn("windows_ready", r.json())

    def test_sign_audits_without_secrets(self) -> None:
        fake = SignResult(
            ok=True,
            signed_paths=["/tmp/a-signed.exe"],
            source_paths=["/tmp/a.exe"],
            checksums_path="/tmp/SHA256SUMS",
            export_dir="/tmp",
            tool_used="osslsigncode",
            identity_fingerprint="thumbprint:ABCD",
            audit_detail={
                "artifacts": ["/tmp/a.exe"],
                "identity": "thumbprint:ABCD",
                "thumbprint": "ABCD",
            },
        )
        with patch("api.signing_routes.sign_artifacts", return_value=fake):
            r = self.client.post(
                "/api/v1/admin/signing/sign",
                json={
                    "artifacts": ["/tmp/a.exe"],
                    "platform": "windows",
                    "pfx_path": "/tmp/c.pfx",
                    "pfx_passphrase": "should-not-be-audited",
                    "thumbprint": "ABCD",
                },
            )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["ok"])
        self.assertIsNotNone(body["audit_id"])
        rows = self.registry.list_audit(limit=1)
        self.assertEqual(rows[0]["action"], "code_sign")
        self.assertNotIn("should-not-be-audited", rows[0]["detail_json"] or "")
