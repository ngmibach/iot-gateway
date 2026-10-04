"""Unit tests for Lab HOST templating and short-lived fake_sensor lifecycle."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from lab.lifecycle import (
    DEFAULT_DURATION_MINUTES,
    MAX_DURATION_MINUTES,
    STORAGE_OVERFLOW_WARNING,
    LabFakeSensorManager,
    _apply_host_to_script,
    _stage_fake_sensor_tree,
)


def _mini_tree(root: Path) -> Path:
    build = root / "build" / "sensor1"
    build.mkdir(parents=True)
    (build / "test_sensor_data.sh").write_text(
        '#!/bin/bash\nHOST="172.20.10.2"\nPORT="8883"\n',
        encoding="utf-8",
    )
    (root / "build" / "sensor2").mkdir(parents=True)
    (root / "build" / "sensor2" / "test_sensor_data.sh").write_text(
        "#!/bin/bash\nHOST={{GATEWAY_IP}}\n",
        encoding="utf-8",
    )
    (root / "docker-compose.yaml").write_text(
        "services:\n  sensor1:\n    build: {context: build, dockerfile: Dockerfile.sensor1}\n",
        encoding="utf-8",
    )
    return root


class HostTemplateTests(unittest.TestCase):
    def test_apply_host_rewrites_quoted_and_placeholder(self) -> None:
        a = _apply_host_to_script('HOST="172.20.10.2"\n', "10.0.0.5")
        self.assertIn('HOST="10.0.0.5"', a)
        b = _apply_host_to_script("HOST={{GATEWAY_IP}}\n", "192.168.1.9")
        self.assertIn('HOST="192.168.1.9"', b)

    def test_stage_and_template_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            src_script = (src / "build" / "sensor1" / "test_sensor_data.sh").read_text(
                encoding="utf-8"
            )
            dest = Path(tmp) / "dest"
            _stage_fake_sensor_tree(src, dest, gateway_ip="10.1.2.3")
            s1 = (dest / "build" / "sensor1" / "test_sensor_data.sh").read_text(
                encoding="utf-8"
            )
            s2 = (dest / "build" / "sensor2" / "test_sensor_data.sh").read_text(
                encoding="utf-8"
            )
            self.assertIn('HOST="10.1.2.3"', s1)
            self.assertIn('HOST="10.1.2.3"', s2)
            self.assertNotIn("172.20.10.2", s1)
            self.assertNotIn("{{GATEWAY_IP}}", s2)
            # Source tree must remain unchanged.
            self.assertEqual(
                (src / "build" / "sensor1" / "test_sensor_data.sh").read_text(
                    encoding="utf-8"
                ),
                src_script,
            )

    def test_stage_refuses_dest_equal_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            before = (src / "build" / "sensor1" / "test_sensor_data.sh").read_text(
                encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                _stage_fake_sensor_tree(src, src, gateway_ip="10.0.0.1")
            self.assertEqual(
                (src / "build" / "sensor1" / "test_sensor_data.sh").read_text(
                    encoding="utf-8"
                ),
                before,
            )
            self.assertTrue(src.is_dir())


class LifecycleTests(unittest.TestCase):
    def test_start_templates_down_then_up_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            work = Path(tmp) / "work"
            calls: list[list[str]] = []

            def runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
                calls.append(list(cmd))
                out = (
                    "NAME STATUS\nsensor1 Up 2 seconds\n"
                    if "ps" in cmd
                    else "ok\n"
                )
                return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

            mgr = LabFakeSensorManager(work, source_dir=src, runner=runner)
            # Seed a prior compose file so start must down first.
            staged = work / "fake_sensor"
            staged.mkdir(parents=True)
            (staged / "docker-compose.yaml").write_text("services: {}\n", encoding="utf-8")

            st = mgr.start(
                gateway_ip="192.168.10.50",
                duration_minutes=5,
                sensors=["sensor1"],
            )
            self.assertTrue(st.running)
            self.assertEqual(st.gateway_ip, "192.168.10.50")
            self.assertEqual(st.sensors, ["sensor1"])
            self.assertEqual(st.duration_minutes, 5)
            self.assertIn("overflow", st.warning.lower())
            self.assertIn("keep this app", st.warning.lower())
            script = (
                work / "fake_sensor" / "build" / "sensor1" / "test_sensor_data.sh"
            ).read_text(encoding="utf-8")
            self.assertIn('HOST="192.168.10.50"', script)
            # First compose op is down (prior project), then up --build.
            compose_ops = [c for c in calls if "compose" in c]
            self.assertGreaterEqual(len(compose_ops), 2)
            self.assertIn("down", compose_ops[0])
            up = next(c for c in compose_ops if "up" in c)
            self.assertIn("--build", up)
            self.assertIn("sensor1", up)
            mgr._cancel_timer()

    def test_stale_auto_stop_ignored_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            work = Path(tmp) / "work"
            calls: list[list[str]] = []

            def runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
                calls.append(list(cmd))
                out = (
                    "NAME STATUS\nsensor1 Up 2 seconds\n"
                    if "ps" in cmd
                    else "ok\n"
                )
                return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

            mgr = LabFakeSensorManager(work, source_dir=src, runner=runner)
            mgr.start(gateway_ip="10.0.0.1", duration_minutes=5, sensors=["sensor1"])
            old_id = mgr._run_id
            mgr.start(gateway_ip="10.0.0.2", duration_minutes=5, sensors=["sensor1"])
            downs_before = sum(1 for c in calls if "down" in c)
            st = mgr.stop(
                detail="auto-stopped after duration (storage overflow guard)",
                expected_run_id=old_id,
            )
            self.assertIn("stale", st.detail.lower())
            self.assertEqual(mgr._run_id, old_id + 1)
            self.assertEqual(mgr._gateway_ip, "10.0.0.2")
            self.assertIsNotNone(mgr._stops_at)
            self.assertEqual(sum(1 for c in calls if "down" in c), downs_before)
            mgr._cancel_timer()

    def test_stale_stop_blocked_on_lock_cannot_tear_down_new_run(self) -> None:
        """Auto-stop that entered stop() before start() finishes must no-op."""
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            work = Path(tmp) / "work"
            calls: list[list[str]] = []
            entered_stop = threading.Event()
            release_start = threading.Event()

            def runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
                calls.append(list(cmd))
                out = (
                    "NAME STATUS\nsensor1 Up 2 seconds\n"
                    if "ps" in cmd
                    else "ok\n"
                )
                return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

            mgr = LabFakeSensorManager(work, source_dir=src, runner=runner)
            mgr.start(gateway_ip="10.0.0.1", duration_minutes=5, sensors=["sensor1"])
            stale_id = mgr._run_id

            results: list[object] = []

            def stale_stop() -> None:
                # Hold path: wait until start has bumped run_id then call stop.
                release_start.wait(timeout=5)
                results.append(
                    mgr.stop(
                        detail="auto-stopped after duration (storage overflow guard)",
                        expected_run_id=stale_id,
                    )
                )
                entered_stop.set()

            t = threading.Thread(target=stale_stop, daemon=True)
            t.start()
            # New start invalidates stale_id.
            st = mgr.start(
                gateway_ip="10.0.0.9", duration_minutes=5, sensors=["sensor1"]
            )
            release_start.set()
            self.assertTrue(entered_stop.wait(timeout=5))
            t.join(timeout=5)
            self.assertEqual(len(results), 1)
            stale_st = results[0]
            assert isinstance(stale_st, type(st))
            self.assertIn("stale", stale_st.detail.lower())
            self.assertEqual(mgr._gateway_ip, "10.0.0.9")
            self.assertIsNotNone(mgr._stops_at)
            mgr._cancel_timer()

    def test_up_failure_clears_runtime_and_attempts_down(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            work = Path(tmp) / "work"
            calls: list[list[str]] = []

            def runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
                calls.append(list(cmd))
                if "up" in cmd:
                    return subprocess.CompletedProcess(
                        cmd, 1, stdout="", stderr="boom"
                    )
                return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")

            mgr = LabFakeSensorManager(work, source_dir=src, runner=runner)
            with self.assertRaises(RuntimeError):
                mgr.start(
                    gateway_ip="10.0.0.9",
                    duration_minutes=5,
                    sensors=["sensor1"],
                )
            self.assertIsNone(mgr._stops_at)
            self.assertIsNone(mgr._started_at)
            self.assertIsNone(mgr._gateway_ip)
            self.assertIsNone(mgr._timer)
            downs = [c for c in calls if "down" in c]
            self.assertTrue(downs, "expected compose down after failed up")

    def test_rejects_bad_duration_and_cidr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            mgr = LabFakeSensorManager(
                Path(tmp) / "work",
                source_dir=src,
                runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""),
            )
            with self.assertRaises(ValueError):
                mgr.start(gateway_ip="10.0.0.0/24", duration_minutes=5)
            with self.assertRaises(ValueError):
                mgr.start(
                    gateway_ip="10.0.0.1",
                    duration_minutes=MAX_DURATION_MINUTES + 1,
                )

    def test_stop_without_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = LabFakeSensorManager(Path(tmp) / "work", source_dir=Path(tmp))
            st = mgr.stop()
            self.assertFalse(st.running)
            self.assertEqual(st.warning, STORAGE_OVERFLOW_WARNING)

    def test_defaults(self) -> None:
        self.assertEqual(DEFAULT_DURATION_MINUTES, 10)
        self.assertLessEqual(DEFAULT_DURATION_MINUTES, MAX_DURATION_MINUTES)


class ApiLabTests(unittest.TestCase):
    def test_lab_routes(self) -> None:
        import tempfile as tf
        from contextlib import contextmanager
        from pathlib import Path as P
        from typing import Any, Iterator

        from fastapi.testclient import TestClient

        from api.app import create_app
        from api.settings import Settings
        from lab.lifecycle import FakeSensorStatus, LabFakeSensorManager
        from registry.registry import Registry

        with tf.TemporaryDirectory() as tmp:
            db = P(tmp) / "registry.sqlite"
            reg = Registry(str(db))
            settings = Settings(
                host="127.0.0.1",
                port=9137,
                data_dir=P(tmp),
                registry_path=db,
            )
            mgr = MagicMock(spec=LabFakeSensorManager)
            mgr.start.return_value = FakeSensorStatus(
                running=True,
                gateway_ip="10.0.0.8",
                sensors=["sensor1"],
                duration_minutes=10,
                warning=STORAGE_OVERFLOW_WARNING,
                detail="started",
            )
            mgr.stop.return_value = FakeSensorStatus(
                running=False, warning=STORAGE_OVERFLOW_WARNING, detail="stopped"
            )
            mgr.status.return_value = FakeSensorStatus(
                running=False, warning=STORAGE_OVERFLOW_WARNING
            )

            @contextmanager
            def open_ssh(_gw: dict[str, Any]) -> Iterator[Any]:
                yield object()

            app = create_app(
                settings=settings,
                registry=reg,
                open_ssh=open_ssh,
                lab_manager=mgr,
            )
            client = TestClient(app)
            r = client.post(
                "/api/v1/lab/fake-sensors/start",
                json={"gateway_ip": "10.0.0.8", "duration_minutes": 10},
            )
            self.assertEqual(r.status_code, 200, r.text)
            self.assertTrue(r.json()["running"])
            self.assertIn("overflow", r.json()["warning"].lower())
            mgr.start.assert_called_once()
            self.assertNotIn("build", mgr.start.call_args.kwargs)
            r2 = client.get("/api/v1/lab/fake-sensors/status")
            self.assertEqual(r2.status_code, 200)
            r3 = client.post("/api/v1/lab/fake-sensors/stop")
            self.assertEqual(r3.status_code, 200)
            self.assertFalse(r3.json()["running"])


if __name__ == "__main__":
    unittest.main()
