"""Start/stop/status for app-managed Loki + Prometheus via generated compose."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .compose import (
    PROJECT_NAME,
    ComposeProfile,
    generate_compose_yaml,
    write_stack_files,
)
from .readiness import ProbeResult, check_loki, check_prometheus, wait_ready
from .scrape import render_prometheus_scrape


@dataclass
class BackendStatus:
    running: bool
    compose_ps: str
    loki: ProbeResult | None = None
    prometheus: ProbeResult | None = None
    detail: str = ""


class TelemetryManager:
    """Lifecycle manager: generate compose under ``root``, then docker compose ops."""

    def __init__(
        self,
        root: Path | str,
        *,
        profile: ComposeProfile | str = ComposeProfile.LINUX_HOST,
        project_name: str = PROJECT_NAME,
        docker_bin: str | None = None,
    ):
        self.root = Path(root)
        self.profile = ComposeProfile(profile)
        self.project_name = project_name
        self.docker_bin = docker_bin or shutil.which("docker") or "docker"
        self.compose_file = self.root / "docker-compose.yaml"

    def ensure_files(
        self,
        *,
        gateway_ip: str,
        cadvisor_port: int | str = 8080,
        prometheus_yml: str | None = None,
    ) -> Path:
        """Write compose + Loki config + rendered Prometheus scrape file."""
        yml = prometheus_yml or render_prometheus_scrape(
            gateway_ip, cadvisor_port=cadvisor_port
        )
        return write_stack_files(
            self.root, profile=self.profile, prometheus_yml=yml
        )

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
        self, *args: str, check: bool = True, timeout: float | None = 120
    ) -> subprocess.CompletedProcess[str]:
        if not self.compose_file.is_file():
            raise FileNotFoundError(
                f"compose file missing — call ensure_files() first: {self.compose_file}"
            )
        proc = subprocess.run(
            self._compose_cmd(*args),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(self.root),
        )
        if check and proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(
                f"docker compose {' '.join(args)} failed (exit {proc.returncode}): {err}"
            )
        return proc

    def start(
        self,
        *,
        gateway_ip: str | None = None,
        cadvisor_port: int | str = 8080,
        wait: bool = True,
        wait_timeout_s: float = 90.0,
        loki_url: str = "http://127.0.0.1:3100",
        prometheus_url: str = "http://127.0.0.1:9090",
    ) -> BackendStatus:
        """Generate (if gateway_ip given) and ``compose up -d`` Loki/Prometheus."""
        if gateway_ip:
            self.ensure_files(gateway_ip=gateway_ip, cadvisor_port=cadvisor_port)
        elif not self.compose_file.is_file():
            # Still write compose skeleton with placeholder scrape so up works.
            self.ensure_files(gateway_ip="127.0.0.1", cadvisor_port=cadvisor_port)
        proc = self._run("up", "-d")
        status = self.status(loki_url=loki_url, prometheus_url=prometheus_url)
        status.detail = (proc.stdout or proc.stderr or "").strip()
        if wait:
            ready = wait_ready(
                loki_url=loki_url,
                prometheus_url=prometheus_url,
                timeout_s=wait_timeout_s,
            )
            status.loki = ready.get("loki")
            status.prometheus = ready.get("prometheus")
            status.running = all(r.ok for r in ready.values()) if ready else status.running
        return status

    def stop(self, *, timeout: float | None = 120) -> BackendStatus:
        """``compose down`` for the app-managed project."""
        if not self.compose_file.is_file():
            return BackendStatus(running=False, compose_ps="", detail="no compose file")
        proc = self._run("down", check=False, timeout=timeout)
        return BackendStatus(
            running=False,
            compose_ps="",
            detail=(proc.stdout or proc.stderr or "").strip(),
        )

    def status(
        self,
        *,
        loki_url: str = "http://127.0.0.1:3100",
        prometheus_url: str = "http://127.0.0.1:9090",
        probe: bool = True,
    ) -> BackendStatus:
        """``compose ps`` plus optional local readiness probes."""
        if not self.compose_file.is_file():
            return BackendStatus(running=False, compose_ps="", detail="no compose file")
        proc = self._run("ps", check=False)
        ps_out = (proc.stdout or "").strip()
        running = proc.returncode == 0 and any(
            token in ps_out.lower() for token in ("running", "up ")
        )
        loki = prom = None
        if probe:
            loki = check_loki(loki_url)
            prom = check_prometheus(prometheus_url)
            running = bool(loki.ok and prom.ok)
        return BackendStatus(
            running=running,
            compose_ps=ps_out,
            loki=loki,
            prometheus=prom,
        )

    def render_compose_preview(self) -> str:
        """Return compose YAML for the configured profile (no disk write)."""
        return generate_compose_yaml(self.profile)
