"""Shared app state and FastAPI dependencies."""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, ContextManager, Generator, Iterator, Optional

from fastapi import Depends, Header, HTTPException, Request, status

from registry.registry import Registry

from .cert_cache import CertBundleCache
from .settings import Settings

OpenSSH = Callable[[dict[str, Any]], ContextManager[Any]]

# OpenSSH public-key bodies (ed25519/rsa) often start with AAAA… — never show to UI.
_SSH_KEY_BODY_RE = re.compile(r"\bAAAA[A-Za-z0-9+/]{20,}={0,2}\b")
_SHA256_FP_RE = re.compile(r"\bSHA256:[A-Za-z0-9+/=]+")


def sanitize_user_error(message: str, *, fallback: str = "operation failed") -> str:
    """Strip SSH key / fingerprint material from operator-facing text."""
    text = (message or "").strip() or fallback
    text = _SSH_KEY_BODY_RE.sub("[redacted]", text)
    text = _SHA256_FP_RE.sub("[redacted]", text)
    # Drop leftover "got <blob>" style suffixes if any remain.
    text = re.sub(r":\s*got\s+\S+\s*$", "", text, flags=re.IGNORECASE).strip()
    return text or fallback


def _looks_like_raw_host_key_b64(value: str) -> bool:
    """True when ``value`` is OpenSSH key base64, not a SHA256 fingerprint label."""
    v = (value or "").strip()
    if not v or v.upper().startswith("SHA256:"):
        return False
    # Raw host-key bodies are long base64; fingerprints are labeled SHA256:…
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+=*", v)) and len(v) >= 32


def _pin_base64_from_settings_file(
    data_dir: Path, host: str, *, port: int = 22
) -> Optional[str]:
    """Read wizard ``ssh_host_pins`` base64 for host (same file desktop uses)."""
    path = Path(data_dir) / "settings.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    pins = data.get("ssh_host_pins") if isinstance(data, dict) else None
    if not isinstance(pins, dict):
        return None
    for key in (f"{host}:{int(port)}", host):
        pin = pins.get(key)
        if isinstance(pin, dict):
            b64 = str(pin.get("base64") or "").strip()
            if b64:
                return b64
    return None


def resolve_ssh_host_pin(
    settings: Settings, gateway: dict[str, Any]
) -> tuple[Optional[str], list[str]]:
    """Return (host_key_base64, known_hosts_paths) for a registry gateway row.

    Registry ``fingerprint`` is often a SHA256 label for display — that must not
    be passed to Paramiko as ``host_key_base64``. Prefer the wizard pin base64
    and the app ``known_hosts`` file under the data dir.
    """
    host = str(gateway.get("host") or "").strip()
    port = int(gateway.get("ssh_port") or gateway.get("port") or 22)
    known = Path(settings.data_dir) / "known_hosts"
    known_paths = [str(known)] if known.is_file() else []

    pin_b64 = _pin_base64_from_settings_file(settings.data_dir, host, port=port)
    if pin_b64:
        return pin_b64, known_paths

    fp = str(gateway.get("fingerprint") or "").strip()
    if _looks_like_raw_host_key_b64(fp):
        return fp, known_paths

    # SHA256 fingerprint or empty: rely on known_hosts / allow_unknown_host.
    return None, known_paths


@dataclass
class AppState:
    settings: Settings
    registry: Registry
    cert_cache: CertBundleCache = field(default_factory=CertBundleCache)
    open_ssh: Optional[OpenSSH] = None
    # Background fake-sensor cert renewer (started from app lifespan).
    fake_cert_renewer: Any = None


def get_state(request: Request) -> AppState:
    state = getattr(request.app.state, "control", None)
    if state is None:
        raise RuntimeError("control AppState not configured")
    return state


def require_token(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_token: Optional[str] = Header(default=None, alias="X-API-Token"),
) -> None:
    state = get_state(request)
    expected = state.settings.api_token
    if not expected:
        return
    bearer = None
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()
    got = x_api_token or bearer
    if got != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing API token",
        )


def get_registry(state: AppState = Depends(get_state)) -> Registry:
    return state.registry


def get_cert_cache(state: AppState = Depends(get_state)) -> CertBundleCache:
    return state.cert_cache


def default_open_ssh(settings: Settings) -> OpenSSH:
    """Build Paramiko sessions from registry gateway rows + env credentials."""

    @contextmanager
    def _open(gateway: dict[str, Any]) -> Iterator[Any]:
        from actions.ssh import SSHClient, SSHTarget

        pin_b64, known_paths = resolve_ssh_host_pin(settings, gateway)
        target = SSHTarget(
            host=gateway["host"],
            username=gateway["ssh_user"],
            password=settings.ssh_password,
            key_filename=settings.ssh_key_path,
            host_key_base64=pin_b64,
            known_hosts_paths=known_paths or None,
            allow_unknown_host=settings.allow_unknown_host and not pin_b64,
        )
        client = SSHClient(target)
        client.connect()
        try:
            yield client
        finally:
            client.close()

    return _open


def open_ssh_for(
    state: AppState,
    gateway: dict[str, Any],
) -> ContextManager[Any]:
    factory = state.open_ssh or default_open_ssh(state.settings)
    return factory(gateway)


def require_gateway(registry: Registry, gid: str) -> dict[str, Any]:
    gw = registry.get_gateway(gid)
    if gw is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"gateway {gid!r} not found",
        )
    return gw


def http_400(exc: ValueError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
