"""Unit tests for Lab HOST templating and short-lived fake_sensor lifecycle."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from lab.host_template import apply_host_to_script, stage_fake_sensor_tree
from lab.lifecycle import (
    DEFAULT_DURATION_MINUTES,
    MAX_DURATION_MINUTES,
    STORAGE_OVERFLOW_WARNING,
    LabFakeSensorManager,
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
        a = apply_host_to_script('HOST="172.20.10.2"\n', "10.0.0.5")
        self.assertIn('HOST="10.0.0.5"', a)
        b = apply_host_to_script("HOST={{GATEWAY_IP}}\n", "192.168.1.9")
        self.assertIn('HOST="192.168.1.9"', b)

    def test_stage_and_template_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            dest = Path(tmp) / "dest"
            stage_fake_sensor_tree(src, dest, gateway_ip="10.1.2.3")
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


class LifecycleTests(unittest.TestCase):
    def test_start_templates_and_compose_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = _mini_tree(Path(tmp) / "src")
            work = Path(tmp) / "work"
            calls: list[list[str]] = []

            def runner(cmd, **kwargs):  # type: ignore[no-untyped-def]
                calls.append(list(cmd))
                out = "NAME STATUS\nsensor1 Up 2 seconds\n" if "ps" in cmd else "started\n"
                return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

            mgr = LabFakeSensorManager(work, source_dir=src, runner=runner)
            st = mgr.start(
                gateway_ip="192.168.10.50",
                duration_minutes=5,
                sensors=["sensor1"],
                build=True,
            )
            self.assertTrue(st.running)
            self.assertEqual(st.gateway_ip, "192.168.10.50")
            self.assertEqual(st.sensors, ["sensor1"])
            self.assertEqual(st.duration_minutes, 5)
            self.assertIn("overflow", st.warning.lower())
            script = (
                work / "fake_sensor" / "build" / "sensor1" / "test_sensor_data.sh"
            ).read_text(encoding="utf-8")
            self.assertIn('HOST="192.168.10.50"', script)
            self.assertTrue(calls)
            self.assertIn("compose", calls[0])
            self.assertIn("up", calls[0])
            self.assertIn("sensor1", calls[0])
            mgr._cancel_timer()

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
            r2 = client.get("/api/v1/lab/fake-sensors/status")
            self.assertEqual(r2.status_code, 200)
            r3 = client.post("/api/v1/lab/fake-sensors/stop")
            self.assertEqual(r3.status_code, 200)
            self.assertFalse(r3.json()["running"])


if __name__ == "__main__":
    unittest.main()
