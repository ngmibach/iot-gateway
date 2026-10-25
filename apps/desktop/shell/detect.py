"""Runtime detection for the Setup Wizard (no Docker; WSL not required)."""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import asdict, dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class WslStatus:
    on_windows: bool
    in_wsl: bool
    distro: str = ""
    wsl_ip: str = ""
    note: str = ""


def in_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as f:
            text = f.read().lower()
    except OSError:
        return False
    return "microsoft" in text or "wsl" in text


def operator_runtime() -> Literal["windows", "wsl", "linux"]:
    """Which operator-PC path the wizard should use."""
    if in_wsl():
        return "wsl"
    if os.name == "nt" or platform.system().lower() == "windows":
        return "windows"
    return "linux"


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
    if inside:
        note = (
            "Running inside WSL. Prefer the native Windows .exe — "
            "WSL is not required for the packaged app."
        )
    elif on_windows:
        note = "WSL is not required. Loki and Prometheus run as native Windows processes."
    return WslStatus(
        on_windows=on_windows or inside,
        in_wsl=inside,
        distro=distro,
        wsl_ip=wsl_ip,
        note=note,
    )


def environment_snapshot() -> dict[str, Any]:
    wsl = detect_wsl()
    runtime = operator_runtime()
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "runtime": runtime,
        "docker_required": False,
        "wsl_required": False,
        "wsl": asdict(wsl),
    }
