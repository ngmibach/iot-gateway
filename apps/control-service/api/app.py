"""FastAPI application factory — bind 127.0.0.1:9137 in __main__."""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI

from registry.registry import Registry

from .cert_cache import CertBundleCache
from .deps import AppState, OpenSSH, default_open_ssh
from .devices import router as devices_router
from .schemas import HealthResponse
from .settings import Settings


def create_app(
    *,
    settings: Optional[Settings] = None,
    registry: Optional[Registry] = None,
    open_ssh: Optional[OpenSSH] = None,
    cert_cache: Optional[CertBundleCache] = None,
) -> FastAPI:
    cfg = settings or Settings.from_env()
    reg = registry or Registry(str(cfg.registry_path))
    state = AppState(
        settings=cfg,
        registry=reg,
        cert_cache=cert_cache or CertBundleCache(),
        open_ssh=open_ssh or default_open_ssh(cfg),
    )

    app = FastAPI(title="iot-gateway-control", version="0.1.0")
    app.state.control = state
    app.include_router(devices_router, prefix="/api/v1")

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    @app.get("/api/v1/health", response_model=HealthResponse)
    def health_v1() -> HealthResponse:
        return HealthResponse(status="ok")

    return app
