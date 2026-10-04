"""Short-lived local fake_sensor compose for Lab demos (storage-overflow risk)."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from actions.validate import validate_ip_or_cidr

from .host_template import stage_fake_sensor_tree

_SENSOR_NAME_RE = re.compile(r"^sensor[1-9]$")


def re_sensor_name(name: str) -> bool:
    return bool(_SENSOR_NAME_RE.fullmatch(name.strip()))

PROJECT_NAME = "iotgw-lab-fake-sensor"
DEFAULT_SENSORS = ("sensor1", "sensor2", "sensor3", "sensor4")
DEFAULT_DURATION_MINUTES = 10
MAX_DURATION_MINUTES = 60
STORAGE_OVERFLOW_WARNING = (
    "fake_sensor must run only for a short period — prolonged use can overflow "
    "gateway/monitoring storage (logs, Loki, Mosquitto)."
)


def _repo_fake_sensor_dir() -> Path:
    # apps/control-service/lab/lifecycle.py → repo root
    return Path(__file__).resolve().parents[3] / "fake_sensor"


@dataclass
class FakeSensorStatus:
    running: bool
    gateway_ip: Optional[str] = None
    sensors: list[str] = field(default_factory=list)
    duration_minutes: Optional[int] = None
    started_at: Optional[float] = None
    stops_at: Optional[float] = None
    warning: str = STORAGE_OVERFLOW_WARNING
    compose_ps: str = ""
    staged_root: Optional[str] = None
    detail: str = ""


class LabFakeSensorManager:
    """Stage templated HOST= tree, ``compose up`` selected sensors, auto-stop."""

    def __init__(
        self,
        work_root: Path | str,
        *,
        source_dir: Path | str | None = None,
        project_name: str = PROJECT_NAME,
        docker_bin: str | None = None,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self.work_root = Path(work_root)
        self.source_dir = Path(source_dir) if source_dir else _repo_fake_sensor_dir()
        self.project_name = project_name
        self.docker_bin = docker_bin or shutil.which("docker") or "docker"
        self._runner = runner or subprocess.run
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._gateway_ip: str | None = None
        self._sensors: list[str] = []
        self._duration_minutes: int | None = None
        self._started_at: float | None = None
        self._stops_at: float | None = None
        self._staged: Path | None = None

    @property
    def staged_dir(self) -> Path:
        return self.work_root / "fake_sensor"

    @property
    def compose_file(self) -> Path:
        return self.staged_dir / "docker-compose.yaml"

    def _compose_cmd(self, *args: str) -> list[str]:
        return [
            self.docker_bin,
            "compose",
            "-p",
            self.project_name,
            "-f",
            str(self.compose_file),
            *args,
        ]

    def _run(
        self, *args: str, check: bool = True, timeout: float | None = 600
    ) -> subprocess.CompletedProcess[str]:
        if not self.compose_file.is_file():
            raise FileNotFoundError(
                f"lab compose missing — call start() first: {self.compose_file}"
            )
        proc = self._runner(
            self._compose_cmd(*args),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(self.staged_dir),
        )
        if check and proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(
                f"docker compose {' '.join(args)} failed (exit {proc.returncode}): {err}"
            )
        return proc

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _schedule_stop(self, duration_minutes: int) -> None:
        self._cancel_timer()
        seconds = max(1, int(duration_minutes * 60))

        def _fire() -> None:
            try:
                self.stop(detail="auto-stopped after duration (storage overflow guard)")
            except Exception:  # noqa: BLE001 — timer must not raise into thread
                pass

        self._timer = threading.Timer(seconds, _fire)
        self._timer.daemon = True
        self._timer.start()

    def start(
        self,
        *,
        gateway_ip: str,
        duration_minutes: int = DEFAULT_DURATION_MINUTES,
        sensors: Sequence[str] | None = None,
        build: bool = True,
    ) -> FakeSensorStatus:
        """Template HOST, ``compose up -d`` (optional build), schedule auto-stop."""
        ip = validate_ip_or_cidr(gateway_ip.strip())
        if "/" in ip:
            raise ValueError("gateway_ip must be a single host address, not CIDR")
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"invalid gateway_ip: {gateway_ip!r}") from exc
        if parsed.version != 4:
            raise ValueError("gateway_ip must be IPv4")

        mins = int(duration_minutes)
        if mins < 1 or mins > MAX_DURATION_MINUTES:
            raise ValueError(
                f"duration_minutes must be 1..{MAX_DURATION_MINUTES} (got {mins})"
            )
        selected = list(sensors) if sensors else list(DEFAULT_SENSORS)
        if not selected:
            raise ValueError("sensors list empty")
        for name in selected:
            if not re_sensor_name(name):
                raise ValueError(f"invalid sensor name: {name!r}")

        with self._lock:
            self._cancel_timer()
            staged = stage_fake_sensor_tree(
                self.source_dir, self.staged_dir, gateway_ip=ip
            )
            self._staged = staged
            self._gateway_ip = ip
            self._sensors = selected
            self._duration_minutes = mins
            self._started_at = time.time()
            self._stops_at = self._started_at + mins * 60

            up_args: list[str] = ["up", "-d"]
            if build:
                up_args.append("--build")
            up_args.extend(selected)
            proc = self._run(*up_args)
            self._schedule_stop(mins)
            detail = (proc.stdout or proc.stderr or "").strip()
            return self.status(detail=detail or "started")

    def stop(self, *, detail: str = "stopped") -> FakeSensorStatus:
        with self._lock:
            self._cancel_timer()
            if not self.compose_file.is_file():
                self._clear_runtime()
                return FakeSensorStatus(
                    running=False, warning=STORAGE_OVERFLOW_WARNING, detail="no compose"
                )
            proc = self._run("down", check=False, timeout=180)
            down_detail = (proc.stderr or proc.stdout or "").strip()
            if proc.returncode != 0:
                down_detail = f"compose down exit {proc.returncode}: {down_detail}"
            self._clear_runtime()
            return FakeSensorStatus(
                running=False,
                warning=STORAGE_OVERFLOW_WARNING,
                compose_ps="",
                detail=f"{detail}; {down_detail}".strip("; "),
            )

    def _clear_runtime(self) -> None:
        self._gateway_ip = None
        self._sensors = []
        self._duration_minutes = None
        self._started_at = None
        self._stops_at = None

    def status(self, *, detail: str = "", probe_compose: bool = True) -> FakeSensorStatus:
        ps_out = ""
        running = False
        if probe_compose and self.compose_file.is_file():
            proc = self._run("ps", check=False, timeout=60)
            ps_out = (proc.stdout or "").strip()
            running = proc.returncode == 0 and any(
                tok in ps_out.lower() for tok in ("running", "up ")
            )
        elif self._started_at is not None and self._stops_at is not None:
            running = time.time() < self._stops_at
        return FakeSensorStatus(
            running=running,
            gateway_ip=self._gateway_ip,
            sensors=list(self._sensors),
            duration_minutes=self._duration_minutes,
            started_at=self._started_at,
            stops_at=self._stops_at,
            warning=STORAGE_OVERFLOW_WARNING,
            compose_ps=ps_out,
            staged_root=str(self._staged) if self._staged else None,
            detail=detail,
        )
