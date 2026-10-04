"""Short-lived local fake_sensor compose for Lab demos (storage-overflow risk).

HOST is baked into sensor images at build time, so every start rebuilds
(``compose up --build``). Auto-stop uses an in-process timer — the Lab
wizard/control process must stay running for the overflow guard to fire.
"""

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

PROJECT_NAME = "iotgw-lab-fake-sensor"
DEFAULT_SENSORS = ("sensor1", "sensor2", "sensor3", "sensor4")
DEFAULT_DURATION_MINUTES = 10
MAX_DURATION_MINUTES = 60
STORAGE_OVERFLOW_WARNING = (
    "fake_sensor must run only for a short period — prolonged use can overflow "
    "gateway/monitoring storage (logs, Loki, Mosquitto). Keep this app/wizard "
    "open until auto-stop; exiting cancels the overflow timer while containers "
    "may keep running."
)

_SENSOR_NAME_RE = re.compile(r"^sensor[1-9]$")
_HOST_LINE_RE = re.compile(
    r'^(HOST\s*=\s*)(?:\{\{GATEWAY_IP\}\}|["\']?[^"\'\n]*["\']?)(.*)$',
    re.MULTILINE,
)


def _apply_host_to_script(text: str, gateway_ip: str) -> str:
    """Rewrite HOST= lines to ``HOST="<gateway_ip>"``."""
    ip = gateway_ip.strip()
    if not ip:
        raise ValueError("gateway_ip required")

    def _sub(m: re.Match[str]) -> str:
        return f'{m.group(1)}"{ip}"{m.group(2)}'

    return _HOST_LINE_RE.sub(_sub, text)


def _stage_fake_sensor_tree(
    source: Path | str,
    dest: Path | str,
    *,
    gateway_ip: str,
) -> Path:
    """Copy ``fake_sensor/`` into ``dest`` and template HOST. Never mutates source."""
    source = Path(source).resolve()
    dest = Path(dest).resolve()
    if not source.is_dir():
        raise FileNotFoundError(f"fake_sensor source missing: {source}")
    if dest == source or source in dest.parents or dest in source.parents:
        raise ValueError(
            f"refusing to stage onto overlapping paths: source={source} dest={dest}"
        )
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        source,
        dest,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"),
    )
    for script in dest.rglob("test_sensor_data.sh"):
        original = script.read_text(encoding="utf-8")
        updated = _apply_host_to_script(original, gateway_ip)
        if updated != original:
            script.write_text(updated, encoding="utf-8")
    return dest


def _repo_fake_sensor_dir() -> Path:
    # apps/control-service/lab/lifecycle.py → repo root
    return Path(__file__).resolve().parents[3] / "fake_sensor"


def _parse_gateway_ipv4(gateway_ip: str) -> str:
    raw = gateway_ip.strip()
    try:
        return str(ipaddress.IPv4Address(raw))
    except ValueError as exc:
        raise ValueError(f"invalid gateway_ip (need IPv4 host): {gateway_ip!r}") from exc


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
    """Stage templated HOST= tree, always ``compose up --build``, auto-stop."""

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
        self._lock = threading.RLock()
        self._timer: threading.Timer | None = None
        # Bumped at each start(); stale auto-stop callbacks no-op when mismatched.
        self._run_id: int = 0
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

    def _schedule_stop(self, duration_minutes: int, run_id: int) -> None:
        self._cancel_timer()
        seconds = max(1, int(duration_minutes * 60))

        def _fire() -> None:
            try:
                self.stop(
                    detail="auto-stopped after duration (storage overflow guard)",
                    expected_run_id=run_id,
                )
            except Exception:  # noqa: BLE001 — timer must not raise into thread
                pass

        self._timer = threading.Timer(seconds, _fire)
        self._timer.daemon = True
        self._timer.start()

    def _down_if_present(self) -> str:
        """Stop previous lab project before restage/up. Returns detail fragment."""
        if not self.compose_file.is_file():
            return ""
        proc = self._run("down", check=False, timeout=180)
        detail = (proc.stderr or proc.stdout or "").strip()
        if proc.returncode != 0:
            return f"compose down exit {proc.returncode}: {detail}"
        return detail

    def _clear_runtime(self) -> None:
        self._gateway_ip = None
        self._sensors = []
        self._duration_minutes = None
        self._started_at = None
        self._stops_at = None

    def _status_unlocked(self, *, detail: str = "") -> FakeSensorStatus:
        ps_out = ""
        running = False
        if self.compose_file.is_file():
            try:
                proc = self._run("ps", check=False, timeout=60)
                ps_out = (proc.stdout or "").strip()
                running = proc.returncode == 0 and any(
                    tok in ps_out.lower() for tok in ("running", "up ")
                )
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
                return FakeSensorStatus(
                    running=False,
                    gateway_ip=self._gateway_ip,
                    sensors=list(self._sensors),
                    duration_minutes=self._duration_minutes,
                    started_at=self._started_at,
                    stops_at=self._stops_at,
                    warning=STORAGE_OVERFLOW_WARNING,
                    compose_ps="",
                    staged_root=str(self._staged) if self._staged else None,
                    detail=f"status probe failed: {exc}",
                )
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

    def start(
        self,
        *,
        gateway_ip: str,
        duration_minutes: int = DEFAULT_DURATION_MINUTES,
        sensors: Sequence[str] | None = None,
    ) -> FakeSensorStatus:
        """Down previous run, stage HOST, ``compose up -d --build``, schedule auto-stop.

        Always rebuilds: sensor images COPY scripts at build time, so templated
        HOST only takes effect with ``--build``.
        """
        ip = _parse_gateway_ipv4(gateway_ip)
        mins = int(duration_minutes)
        if mins < 1 or mins > MAX_DURATION_MINUTES:
            raise ValueError(
                f"duration_minutes must be 1..{MAX_DURATION_MINUTES} (got {mins})"
            )
        selected = list(sensors) if sensors else list(DEFAULT_SENSORS)
        if not selected:
            raise ValueError("sensors list empty")
        for name in selected:
            if not _SENSOR_NAME_RE.fullmatch(name.strip()):
                raise ValueError(f"invalid sensor name: {name!r}")

        with self._lock:
            # Invalidate any auto-stop already past cancel() and blocked on this lock.
            self._run_id += 1
            self._cancel_timer()
            self._clear_runtime()
            down_detail = self._down_if_present()

            staged = _stage_fake_sensor_tree(
                self.source_dir, self.staged_dir, gateway_ip=ip
            )
            self._staged = staged

            up_args = ["up", "-d", "--build", *selected]
            try:
                proc = self._run(*up_args)
            except Exception:
                self._down_if_present()
                self._clear_runtime()
                raise

            now = time.time()
            self._gateway_ip = ip
            self._sensors = selected
            self._duration_minutes = mins
            self._started_at = now
            self._stops_at = now + mins * 60
            self._schedule_stop(mins, self._run_id)

            detail = (proc.stdout or proc.stderr or "").strip() or "started"
            if down_detail:
                detail = f"{detail}; prior down: {down_detail}"
            return self._status_unlocked(detail=detail)

    def stop(
        self,
        *,
        detail: str = "stopped",
        expected_run_id: int | None = None,
    ) -> FakeSensorStatus:
        with self._lock:
            if expected_run_id is not None and expected_run_id != self._run_id:
                return self._status_unlocked(
                    detail=f"stale auto-stop ignored (run_id {expected_run_id}!={self._run_id})"
                )
            self._cancel_timer()
            if not self.compose_file.is_file():
                self._clear_runtime()
                return FakeSensorStatus(
                    running=False, warning=STORAGE_OVERFLOW_WARNING, detail="no compose"
                )
            down_detail = self._down_if_present()
            self._clear_runtime()
            return FakeSensorStatus(
                running=False,
                warning=STORAGE_OVERFLOW_WARNING,
                compose_ps="",
                detail=f"{detail}; {down_detail}".strip("; "),
            )

    def status(self, *, detail: str = "") -> FakeSensorStatus:
        with self._lock:
            return self._status_unlocked(detail=detail)
