"""Unit tests for signing helpers — mocked CLI signers (no real osslsigncode/gpg)."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from signing.linux import sign_gpg_detach, sig_output_path
from signing.service import (
    SignRequest,
    SigningIdentity,
    list_signable_artifacts,
    sign_artifacts,
    write_sha256sums,
)
from signing.tools import SigningTools, detect_signing_tools
from signing.windows import sign_authenticode, signed_output_path


class ToolsTests(unittest.TestCase):
    def test_missing_messages(self) -> None:
        empty = SigningTools(None, None, None)
        self.assertFalse(empty.windows_ready)
        self.assertFalse(empty.linux_ready)
        self.assertTrue(any("osslsigncode" in m for m in empty.missing_for("windows")))
        self.assertTrue(any("gpg" in m for m in empty.missing_for("linux")))

    def test_detect_returns_dataclass(self) -> None:
        t = detect_signing_tools()
        self.assertIsInstance(t, SigningTools)
        d = t.as_dict()
        self.assertIn("windows_ready", d)
        self.assertIn("gpg", d)


class ChecksumsTests(unittest.TestCase):
    def test_sha256sums_format(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            a = root / "a.bin"
            a.write_bytes(b"abc")
            out = write_sha256sums([a], root / "SHA256SUMS", relative_to=root)
            text = out.read_text(encoding="utf-8")
            digest = hashlib.sha256(b"abc").hexdigest()
            self.assertEqual(text.strip(), f"{digest}  a.bin")


class WindowsSignerTests(unittest.TestCase):
    def test_signed_output_name(self) -> None:
        self.assertEqual(
            signed_output_path(Path("/tmp/App.msi")).name, "App-signed.msi"
        )

    def test_osslsigncode_invoked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "app.exe"
            artifact.write_bytes(b"MZ-fake")
            pfx = root / "c.pfx"
            pfx.write_bytes(b"pfx")
            run = MagicMock()
            run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            tools = SigningTools(osslsigncode="/bin/osslsigncode", signtool=None, gpg=None)
            out = sign_authenticode(
                artifact,
                pfx_path=pfx,
                passphrase="s3cret",
                tools=tools,
                run=run,
            )
            self.assertTrue(out.name.endswith("-signed.exe"))
            cmd = run.call_args[0][0]
            self.assertEqual(cmd[0], "/bin/osslsigncode")
            self.assertIn("s3cret", cmd)  # tool needs it; must not be audited
            self.assertNotIn("s3cret", str(out))

    def test_empty_passphrase_scrub_does_not_garble(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "app.exe"
            artifact.write_bytes(b"MZ")
            pfx = root / "c.pfx"
            pfx.write_bytes(b"pfx")
            run = MagicMock()
            run.return_value = MagicMock(
                returncode=1, stdout="", stderr="tool failed: bad cert"
            )
            tools = SigningTools(osslsigncode="/bin/osslsigncode", signtool=None, gpg=None)
            with self.assertRaises(RuntimeError) as ctx:
                sign_authenticode(
                    artifact,
                    pfx_path=pfx,
                    passphrase="",
                    tools=tools,
                    run=run,
                )
            self.assertEqual(str(ctx.exception), "osslsigncode failed: tool failed: bad cert")

    def test_missing_tool_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "app.exe"
            artifact.write_bytes(b"x")
            pfx = root / "c.pfx"
            pfx.write_bytes(b"pfx")
            tools = SigningTools(None, None, None)
            with self.assertRaises(Exception) as ctx:
                sign_authenticode(
                    artifact, pfx_path=pfx, passphrase="x", tools=tools, run=MagicMock()
                )
            self.assertIn("osslsigncode", str(ctx.exception).lower())


class LinuxSignerTests(unittest.TestCase):
    def test_gpg_passphrase_on_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "App.AppImage"
            artifact.write_bytes(b"AI")
            run = MagicMock()
            run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            tools = SigningTools(None, None, gpg="/usr/bin/gpg")
            out = sign_gpg_detach(
                artifact,
                key_id="0xABC",
                passphrase="gpg-secret",
                tools=tools,
                run=run,
            )
            self.assertEqual(out, sig_output_path(artifact))
            kwargs = run.call_args.kwargs
            self.assertIn("gpg-secret", kwargs.get("input", ""))
            cmd = run.call_args[0][0]
            self.assertNotIn("gpg-secret", cmd)

    def test_missing_gpg(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            artifact = Path(td) / "a.deb"
            artifact.write_bytes(b"deb")
            with self.assertRaises(Exception) as ctx:
                sign_gpg_detach(
                    artifact,
                    key_id="x",
                    passphrase="p",
                    tools=SigningTools(None, None, None),
                    run=MagicMock(),
                )
            self.assertIn("gpg", str(ctx.exception).lower())


class ServiceTests(unittest.TestCase):
    def test_list_signable(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.msi").write_bytes(b"1")
            (root / "b.AppImage").write_bytes(b"2")
            (root / "readme.txt").write_bytes(b"3")
            items = list_signable_artifacts(root)
            names = {i["name"] for i in items}
            self.assertEqual(names, {"a.msi", "b.AppImage"})

    def test_sign_artifacts_mocked_windows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "Setup.msi"
            artifact.write_bytes(b"msi")
            pfx = root / "c.pfx"
            pfx.write_bytes(b"pfx")
            export = root / "out"

            def fake_win(src, **kwargs):
                out = src.with_name(src.stem + "-signed" + src.suffix)
                out.write_bytes(b"signed")
                return out

            secret = "p4ss-w1n-secret"
            result = sign_artifacts(
                SignRequest(
                    artifacts=[str(artifact)],
                    identity=SigningIdentity(
                        platform="windows",
                        pfx_path=str(pfx),
                        pfx_passphrase=secret,
                        thumbprint="DEADBEEF",
                    ),
                    export_dir=str(export),
                ),
                tools=SigningTools(None, None, None),
                windows_signer=fake_win,
                linux_signer=MagicMock(),
            )
            self.assertTrue(result.ok, result.error)
            self.assertTrue((export / "SHA256SUMS").is_file())
            self.assertIn("DEADBEEF", result.identity_fingerprint or "")
            blob = json.dumps(result.audit_detail)
            self.assertNotIn(secret, blob)
            self.assertIn("thumbprint", blob)

    def test_sign_artifacts_mocked_linux(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "App.AppImage"
            artifact.write_bytes(b"img")
            export = root / "out"

            def fake_gpg(src, **kwargs):
                out = Path(str(src) + ".sig")
                out.write_bytes(b"sig")
                return out

            result = sign_artifacts(
                SignRequest(
                    artifacts=[str(artifact)],
                    identity=SigningIdentity(
                        platform="linux",
                        gpg_key_id="0x1234",
                        gpg_passphrase="gpg-pass",
                    ),
                    export_dir=str(export),
                ),
                tools=SigningTools(None, None, None),
                windows_signer=MagicMock(),
                linux_signer=fake_gpg,
            )
            self.assertTrue(result.ok, result.error)
            names = {Path(p).name for p in result.signed_paths}
            self.assertIn("App.AppImage", names)
            self.assertIn("App.AppImage.sig", names)
            self.assertNotIn("gpg-pass", json.dumps(result.audit_detail))

    def test_linux_export_dir_same_as_artifact_parent(self) -> None:
        """Ship payload must be in signed_paths/SHA256SUMS even when no copy needed."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "App.AppImage"
            artifact.write_bytes(b"img")

            def fake_gpg(src, **kwargs):
                out = Path(str(src) + ".sig")
                out.write_bytes(b"sig")
                return out

            result = sign_artifacts(
                SignRequest(
                    artifacts=[str(artifact)],
                    identity=SigningIdentity(
                        platform="linux",
                        gpg_key_id="0xABCD",
                        gpg_passphrase="sekrit",
                    ),
                    export_dir=str(root),
                ),
                tools=SigningTools(None, None, None),
                windows_signer=MagicMock(),
                linux_signer=fake_gpg,
            )
            self.assertTrue(result.ok, result.error)
            names = {Path(p).name for p in result.signed_paths}
            self.assertEqual(names, {"App.AppImage", "App.AppImage.sig"})
            sums = (root / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("App.AppImage\n", sums + "\n")
            self.assertIn("App.AppImage.sig", sums)

    def test_failure_scrubs_passphrase_from_audit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            artifact = root / "Setup.msi"
            artifact.write_bytes(b"msi")
            pfx = root / "c.pfx"
            pfx.write_bytes(b"pfx")
            secret = "leak-me-passphrase"

            def boom(src, **kwargs):
                raise RuntimeError(f"signer exploded with {secret}")

            result = sign_artifacts(
                SignRequest(
                    artifacts=[str(artifact)],
                    identity=SigningIdentity(
                        platform="windows",
                        pfx_path=str(pfx),
                        pfx_passphrase=secret,
                    ),
                    export_dir=str(root / "out"),
                ),
                tools=SigningTools(None, None, None),
                windows_signer=boom,
                linux_signer=MagicMock(),
            )
            self.assertFalse(result.ok)
            self.assertNotIn(secret, result.error or "")
            self.assertNotIn(secret, json.dumps(result.audit_detail))
            self.assertIn("***", result.error or "")


if __name__ == "__main__":
    unittest.main()
