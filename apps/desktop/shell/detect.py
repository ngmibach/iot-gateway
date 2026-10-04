"""Docker engine + WSL / localhostForwarding detection for Setup Wizard."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class DockerStatus:
    present: bool
    healthy: bool
    version: str = ""
    error: str = ""
    hint: str = ""


@dataclass(frozen=True)
class WslStatus:
    on_windows: bool
    in_wsl: bool
    distro: str = ""
    wsl_ip: str = ""
    localhost_forwarding_note: str = ""


def in_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as f:
            text = f.read().lower()
    except OSError:
        return False
    return "microsoft" in text or "wsl" in text


def detect_docker() -> DockerStatus:
    """Run ``docker info`` — healthy only when daemon responds."""
    exe = shutil.which("docker")
    if not exe:
        os_name = platform.system().lower()
        if os_name == "windows" or in_wsl():
            hint = (
                "Install Docker inside WSL2 Ubuntu (recommended) or Docker Desktop. "
                "You will not run compose by hand; the app manages containers."
            )
        else:
            hint = (
                "Install Docker Engine (e.g. apt install docker.io) and ensure your "
                "user can run docker without sudo. The app manages compose for you."
            )
        return DockerStatus(present=False, healthy=False, hint=hint)

    try:
        ver = subprocess.run(
            [exe, "version", "--format", "{{.Server.Version}}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        info = subprocess.run(
            [exe, "info"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return DockerStatus(
            present=True,
            healthy=False,
            error=str(e),
            hint="Docker CLI found but daemon did not respond.",
        )

    version = (ver.stdout or "").strip() if ver.returncode == 0 else ""
    if info.returncode != 0:
        err = (info.stderr or info.stdout or "docker info failed").strip()
        return DockerStatus(
            present=True,
            healthy=False,
            version=version,
            error=err.splitlines()[-1] if err else "docker info failed",
            hint="Start the Docker daemon / Docker Desktop, then retry.",
        )
    return DockerStatus(present=True, healthy=True, version=version or "unknown")


def _wsl_eth0_ip() -> str:
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", "eth0"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    if proc.returncode != 0 or not proc.stdout.strip():
        return ""
    # ``2: eth0    inet 172.28.x.x/20 ...``
    parts = proc.stdout.split()
    for i, tok in enumerate(parts):
        if tok == "inet" and i + 1 < len(parts):
            return parts[i + 1].split("/")[0]
    return ""


def detect_wsl() -> WslStatus:
    on_windows = platform.system().lower() == "windows" or os.name == "nt"
    inside = in_wsl()
    distro = os.environ.get("WSL_DISTRO_NAME", "")
    wsl_ip = _wsl_eth0_ip() if inside else ""
    note = ""
    if inside or on_windows:
        note = (
            "Tauri / WebView → FastAPI :9137 and Streamlit :8501 require Windows "
            "localhostForwarding (default on modern Win11). Set in %UserProfile%\\.wslconfig:\n"
            "[wsl2]\nlocalhostForwarding=true\n"
            "Then run: wsl --shutdown and relaunch. "
            "Do NOT use netsh portproxy for :9137/:8501 — only Loki :3100 uses the "
            "guided portproxy/firewall checklist."
        )
    return WslStatus(
        on_windows=on_windows or inside,
        in_wsl=inside,
        distro=distro,
        wsl_ip=wsl_ip,
        localhost_forwarding_note=note,
    )


def environment_snapshot() -> dict[str, Any]:
    docker = detect_docker()
    wsl = detect_wsl()
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "docker": asdict(docker),
        "wsl": asdict(wsl),
    }
