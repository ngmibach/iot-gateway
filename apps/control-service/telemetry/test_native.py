"""Unit tests for native Loki/Prometheus/Grafana lifecycle helpers."""

from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from telemetry import native as nv
from telemetry.lifecycle import BackendStatus
from telemetry.readiness import ProbeResult


def _ok() -> ProbeResult:
    return ProbeResult(True, "u", "ok")


def _down() -> ProbeResult:
    return ProbeResult(False, "u", "down")


class NativeHelperTests(unittest.TestCase):
    def test_bind_conflict_message(self) -> None:
        msg = nv._bind_conflict_message(
            "level=error msg=\"listen tcp :3100: bind: address already in use\"",
            port=3100,
            name="Loki",
        )
        self.assertIsNotNone(msg)
        self.assertIn("3100", msg or "")
        self.assertIsNone(
            nv._bind_conflict_message("level=info msg=ready", port=3100, name="Loki")
        )

    def test_port_conflict_detail_when_occupied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = nv.NativeTelemetryManager(tmp)
            with mock.patch.object(nv, "_port_open", side_effect=[True, False, False]):
                with mock.patch.object(
                    nv,
                    "check_loki",
                    return_value=ProbeResult(False, "u", "down"),
                ):
                    with mock.patch.object(
                        nv,
                        "check_prometheus",
                        return_value=ProbeResult(True, "u", "ok"),
                    ):
                        with mock.patch.object(
                            nv,
                            "check_grafana",
                            return_value=ProbeResult(True, "u", "ok"),
                        ):
                            detail = mgr._port_conflict_detail()
            self.assertIsNotNone(detail)
            self.assertIn("3100", detail or "")

    def test_port_conflict_detail_mentions_9140(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = nv.NativeTelemetryManager(tmp)
            with mock.patch.object(
                nv, "_port_open", side_effect=[False, False, True]
            ):
                with mock.patch.object(nv, "check_loki", return_value=_ok()):
                    with mock.patch.object(
                        nv, "check_prometheus", return_value=_ok()
                    ):
                        with mock.patch.object(
                            nv, "check_grafana", return_value=_down()
                        ):
                            detail = mgr._port_conflict_detail()
            self.assertIsNotNone(detail)
            self.assertIn("9140", detail or "")
            self.assertIn("Grafana", detail or "")

    def test_start_fails_fast_on_port_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            (root / "bin" / "loki").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "bin" / "prometheus").write_text("#!/bin/sh\n", encoding="utf-8")
            mgr = nv.NativeTelemetryManager(root)
            not_ready = _down()
            with mock.patch.object(
                mgr,
                "_http_ready",
                return_value=(False, not_ready, not_ready, not_ready),
            ):
                with mock.patch.object(
                    mgr,
                    "_port_conflict_detail",
                    return_value="Port 3100 is in use but Loki is not ready.",
                ):
                    st = mgr.start(ensure_bins=False, wait=False)
            self.assertFalse(st.running)
            self.assertIn("3100", st.detail)

    def test_snapshot_does_not_probe_before_binaries_exist(self) -> None:
        """Fresh PC: no Loki/Prometheus/Grafana files, so status must not touch ports."""
        with tempfile.TemporaryDirectory() as tmp:
            mgr = nv.NativeTelemetryManager(tmp)
            with mock.patch.object(mgr, "_http_ready") as probe:
                snap = mgr.snapshot()
            probe.assert_not_called()
            self.assertFalse(snap.ready)
            self.assertFalse(snap.binaries_present)
            self.assertIn("not installed", snap.detail.lower())

    def test_snapshot_skips_grafana_https_when_tree_absent(self) -> None:
        """Loki+Prom bins alone are not enough; no Grafana HTTPS probe."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            (root / "bin" / "loki").write_text("x", encoding="utf-8")
            (root / "bin" / "prometheus").write_text("x", encoding="utf-8")
            mgr = nv.NativeTelemetryManager(root)
            with mock.patch.object(mgr, "_grafana_tree_present", return_value=False):
                with mock.patch.object(nv, "check_grafana") as cg:
                    with mock.patch.object(mgr, "_http_ready") as probe:
                        snap = mgr.snapshot()
            probe.assert_not_called()
            cg.assert_not_called()
            self.assertFalse(snap.binaries_present)
            self.assertFalse(snap.grafana_running)

    def test_http_ready_short_circuits_grafana_probe_when_tree_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = nv.NativeTelemetryManager(tmp)
            with mock.patch.object(mgr, "_grafana_tree_present", return_value=False):
                with mock.patch.object(nv, "check_loki", return_value=_ok()):
                    with mock.patch.object(
                        nv, "check_prometheus", return_value=_ok()
                    ):
                        with mock.patch.object(nv, "check_grafana") as cg:
                            ok, loki, prom, grafana = mgr._http_ready()
            self.assertFalse(ok)
            self.assertTrue(loki.ok)
            self.assertTrue(prom.ok)
            self.assertFalse(grafana.ok)
            self.assertIn("tree missing", grafana.detail)
            cg.assert_not_called()

    def test_start_reuses_already_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = nv.NativeTelemetryManager(tmp)
            ok = _ok()
            with mock.patch.object(
                mgr, "_http_ready", return_value=(True, ok, ok, ok)
            ):
                st = mgr.start(ensure_bins=False, wait=False)
            self.assertTrue(st.running)
            self.assertIn("running", st.detail.lower())
            self.assertIsNotNone(st.grafana)

    def test_start_does_not_early_return_when_grafana_down(self) -> None:
        """Loki+Prom healthy but Grafana missing/failing must still ensure binaries."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mgr = nv.NativeTelemetryManager(root)
            ok, down = _ok(), _down()
            with mock.patch.object(
                mgr, "_http_ready", return_value=(False, ok, ok, down)
            ):
                with mock.patch.object(mgr, "_port_conflict_detail", return_value=None):
                    with mock.patch.object(
                        mgr, "ensure_binaries", return_value={}
                    ) as ensure:
                        with mock.patch.object(mgr, "write_configs"):
                            with mock.patch.object(
                                mgr, "_grafana_tree_present", return_value=False
                            ):
                                with mock.patch.object(
                                    mgr,
                                    "_bin",
                                    side_effect=lambda n: root / "bin" / n,
                                ):
                                    (root / "bin").mkdir(parents=True)
                                    (root / "bin" / "loki").write_text(
                                        "x", encoding="utf-8"
                                    )
                                    (root / "bin" / "prometheus").write_text(
                                        "x", encoding="utf-8"
                                    )
                                    st = mgr.start(ensure_bins=True, wait=False)
            ensure.assert_called_once()
            self.assertFalse(st.running)
            self.assertIn("grafana", st.detail.lower())

    def test_force_ensure_stops_grafana_before_tree_replace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = nv.NativeTelemetryManager(tmp)
            mgr._grafana = mock.Mock()
            mgr._grafana.poll.return_value = None  # still running
            with mock.patch.object(
                mgr, "_grafana_needs_ensure", return_value=True
            ):
                with mock.patch.object(mgr, "_stop_grafana_only") as stop_g:
                    with mock.patch(
                        "telemetry.native.ensure_telemetry_binaries",
                        return_value={"loki": Path("l"), "prometheus": Path("p")},
                    ):
                        with mock.patch(
                            "telemetry.native.ensure_grafana_tree",
                            return_value=Path(tmp) / "grafana",
                        ) as ensure_tree:
                            with mock.patch(
                                "telemetry.native.ensure_grafana_kafka_plugin",
                                return_value=Path(tmp) / "plugins",
                            ):
                                mgr.ensure_binaries(force=True)
            stop_g.assert_called_once()
            ensure_tree.assert_called_once()
            self.assertTrue(ensure_tree.call_args.kwargs.get("force"))

    def test_uninstall_removes_bins_and_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "telemetry"
            mgr = nv.NativeTelemetryManager(root)
            mgr.bin_dir.mkdir(parents=True)
            (mgr.bin_dir / "loki").write_text("x", encoding="utf-8")
            (mgr.bin_dir / "prometheus").write_text("x", encoding="utf-8")
            mgr.loki_data.mkdir(parents=True)
            (mgr.loki_data / "chunk").write_text("d", encoding="utf-8")
            mgr.config_dir.mkdir(parents=True)
            (mgr.config_dir / "loki-config.yaml").write_text("x", encoding="utf-8")
            with mock.patch.object(mgr, "stop") as stop:
                out = mgr.uninstall()
            stop.assert_called_once()
            self.assertTrue(out["ok"])
            self.assertFalse(mgr.bin_dir.exists())
            self.assertFalse(mgr.loki_data.exists())
            self.assertFalse(root.exists())

    def test_uninstall_idempotent_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-telemetry"
            mgr = nv.NativeTelemetryManager(root)
            with mock.patch.object(mgr, "stop"):
                out = mgr.uninstall()
            self.assertTrue(out["ok"])
            self.assertEqual(out["removed"], [])


class PortOpenTests(unittest.TestCase):
    def test_port_open_false_when_free(self) -> None:
        # Bind ephemeral to learn a free port, then close and probe it.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertFalse(nv._port_open("127.0.0.1", port, timeout=0.2))

    def test_port_open_true_when_listening(self) -> None:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            self.assertTrue(nv._port_open("127.0.0.1", port, timeout=0.5))
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
