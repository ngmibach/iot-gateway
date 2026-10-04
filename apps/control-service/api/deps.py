"""Shared app state and FastAPI dependencies."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, ContextManager, Generator, Iterator, Optional

from fastapi import Depends, Header, HTTPException, Request, status

from registry.registry import Registry

from .cert_cache import CertBundleCache
from .settings import Settings

OpenSSH = Callable[[dict[str, Any]], ContextManager[Any]]


@dataclass
class AppState:
    settings: Settings
    registry: Registry
    cert_cache: CertBundleCache = field(default_factory=CertBundleCache)
    open_ssh: Optional[OpenSSH] = None


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

        target = SSHTarget(
            host=gateway["host"],
            username=gateway["ssh_user"],
            password=settings.ssh_password,
            key_filename=settings.ssh_key_path,
            host_key_base64=gateway.get("fingerprint") or None,
            allow_unknown_host=settings.allow_unknown_host
            and not gateway.get("fingerprint"),
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
