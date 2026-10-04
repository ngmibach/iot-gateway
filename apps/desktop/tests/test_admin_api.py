"""Admin unlock + Code Signing HTTP API (mocked signers)."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from shell import keyring_store
from shell.wizard_server import STATE, serve


class AdminApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.env = mock.patch.dict(os.environ, {"IOTGW_DATA_DIR": self._td.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.krring = mock.patch.object(
            keyring_store, "_keyring_usable", return_value=False
        )
        self.krring.start()
        self.addCleanup(self.krring.stop)
        STATE.admin.lock()
        # Reset PIN by clearing fallback file
        from shell import admin_auth

        admin_auth.clear_admin_pin()

        self.server = serve("127.0.0.1", 0, open_browser=False)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)
        self.session = ""

    def _shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _req(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.session:
            headers["X-Admin-Session"] = self.session
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            payload = e.read().decode("utf-8")
            try:
                detail = json.loads(payload)
            except json.JSONDecodeError:
                detail = {"error": payload}
            raise AssertionError(f"{method} {path} -> {e.code}: {detail}") from e

    def test_admin_static_and_gate(self) -> None:
        with urllib.request.urlopen(self.base + "/admin.html", timeout=5) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("Code Signing", html)
        st = self._req("GET", "/api/admin/status")
        self.assertFalse(st["has_pin"])
        self.assertFalse(st["unlocked"])

    def test_unlock_and_sign_mocked(self) -> None:
        out = self._req("POST", "/api/admin/pin/set", {"pin": "4242"})
        self.assertTrue(out["unlocked"])
        self.session = out["session"]

        # Signing without session must 403 — use raw request
        req = urllib.request.Request(
            self.base + "/api/admin/signing/tools",
            headers={"Content-Type": "application/json"},
            method="GET",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 403)

        tools = self._req("GET", "/api/admin/signing/tools")
        self.assertIn("windows_ready", tools)

        root = Path(self._td.name)
        artifact = root / "App.AppImage"
        artifact.write_bytes(b"image")
        export = root / "export"

        def fake_gpg(src, **kwargs):
            sig = Path(str(src) + ".sig")
            sig.write_bytes(b"sig")
            return sig

        with mock.patch(
            "signing.service.sign_gpg_detach", fake_gpg
        ), mock.patch(
            "signing.tools.detect_signing_tools",
            return_value=__import__(
                "signing.tools", fromlist=["SigningTools"]
            ).SigningTools(None, None, "/usr/bin/gpg"),
        ):
            # Save identity then sign via API (uses real sign_artifacts → mocked gpg)
            self._req(
                "POST",
                "/api/admin/signing/identity",
                {
                    "platform": "linux",
                    "gpg_key_id": "0xTEST",
                    "gpg_passphrase": "sekrit",
                },
            )
            with mock.patch(
                "signing.service.sign_artifacts"
            ) as sign_mock:
                from signing.service import SignResult

                sign_mock.return_value = SignResult(
                    ok=True,
                    signed_paths=[str(export / "App.AppImage.sig")],
                    source_paths=[str(artifact)],
                    checksums_path=str(export / "SHA256SUMS"),
                    export_dir=str(export),
                    tool_used="gpg",
                    identity_fingerprint="gpg:0xTEST",
                    audit_detail={
                        "artifacts": [str(artifact)],
                        "identity": "gpg:0xTEST",
                        "gpg_key_id": "0xTEST",
                    },
                )
                result = self._req(
                    "POST",
                    "/api/admin/signing/sign",
                    {
                        "artifacts": [str(artifact)],
                        "platform": "linux",
                        "export_dir": str(export),
                    },
                )
        self.assertTrue(result["ok"])
        self.assertIsNotNone(result.get("audit_id"))
        # Passphrase must not appear in audit
        from registry.registry import Registry

        reg = Registry(str(Path(self._td.name) / "registry.sqlite"))
        rows = reg.list_audit(limit=5)
        reg.close()
        blob = json.dumps(rows)
        self.assertNotIn("sekrit", blob)
        self.assertIn("code_sign", blob)

    def test_list_artifacts(self) -> None:
        out = self._req("POST", "/api/admin/pin/set", {"pin": "5555"})
        self.session = out["session"]
        root = Path(self._td.name) / "bundle"
        root.mkdir()
        (root / "x.msi").write_bytes(b"m")
        (root / "y.deb").write_bytes(b"d")
        data = self._req(
            "POST", "/api/admin/signing/list-artifacts", {"folder": str(root)}
        )
        names = {a["name"] for a in data["artifacts"]}
        self.assertEqual(names, {"x.msi", "y.deb"})
