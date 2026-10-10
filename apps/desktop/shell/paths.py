"""App data / settings paths (Linux + Windows).

Supports both source-tree runs and PyInstaller frozen builds (``sys._MEIPASS``).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


APP_NAME_LINUX = "iot-gateway-monitor"
APP_NAME_WIN = "IoTGatewayMonitor"

CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 9137
STREAMLIT_PORT = 8501
WIZARD_PORT = 9138


def is_frozen() -> bool:
    """True when running inside a PyInstaller (or similar) bundle."""
    return bool(getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"))


def bundle_root() -> Path | None:
    """PyInstaller extract/dir root, or None when running from source."""
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return None


def data_dir() -> Path:
    override = os.environ.get("IOTGW_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / APP_NAME_WIN
    return Path.home() / ".local" / "share" / APP_NAME_LINUX


def ensure_data_dir() -> Path:
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def settings_path() -> Path:
    return ensure_data_dir() / "settings.json"


def known_hosts_path() -> Path:
    return ensure_data_dir() / "known_hosts"


def ssh_keys_dir() -> Path:
    d = ensure_data_dir() / "ssh"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_settings() -> dict[str, Any]:
    path = settings_path()
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(data: dict[str, Any]) -> None:
    path = settings_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def repo_root() -> Path:
    """Repo root (source) or frozen bundle root (contains ``gateway/``, ``tools/``)."""
    env = os.environ.get("IOTGW_REPO_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    bundled = bundle_root()
    if bundled is not None:
        return bundled
    # apps/desktop/shell/paths.py → repo root (four parents up from file).
    return Path(__file__).resolve().parents[3]


def control_service_dir() -> Path:
    bundled = bundle_root()
    if bundled is not None:
        # Packaged layout: control-service/ next to ui/ and gateway/.
        return bundled / "control-service"
    return repo_root() / "apps" / "control-service"


def streamlit_app_dir() -> Path:
    bundled = bundle_root()
    if bundled is not None:
        return bundled / "streamlit"
    return repo_root() / "monitoring" / "build" / "streamlit"


def desktop_ui_dir() -> Path:
    bundled = bundle_root()
    if bundled is not None:
        return bundled / "ui"
    return Path(__file__).resolve().parents[1] / "ui"
