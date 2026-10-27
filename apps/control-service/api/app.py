"""FastAPI application factory — bind 127.0.0.1:9137 in __main__."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from registry.registry import Registry

from .actions import router as actions_router
from .cert_cache import CertBundleCache
from .deps import AppState, OpenSSH, default_open_ssh
from .devices import public_router, router as devices_router
from .fake_cert_renewer import FakeCertRenewer
from .query import router as query_router
from .schemas import HealthResponse
from .settings import Settings


def create_app(
    *,
    settings: Optional[Settings] = None,
    registry: Optional[Registry] = None,
    open_ssh: Optional[OpenSSH] = None,
    cert_cache: Optional[CertBundleCache] = None,
    start_fake_cert_renewer: bool | None = None,
) -> FastAPI:
    cfg = settings or Settings.from_env()
    reg = registry or Registry(str(cfg.registry_path))
    ssh_factory = open_ssh or default_open_ssh(cfg)
    state = AppState(
        settings=cfg,
        registry=reg,
        cert_cache=cert_cache or CertBundleCache(),
        open_ssh=ssh_factory,
    )
    renewer_enabled = (
        cfg.fake_cert_renewer_enabled
        if start_fake_cert_renewer is None
        else bool(start_fake_cert_renewer)
    )
    state.fake_cert_renewer = FakeCertRenewer(
        registry=reg,
        open_ssh=ssh_factory,
        settings_ca=cfg.ca_passphrase,
        data_dir=cfg.data_dir,
        client_cert_days=cfg.client_cert_days,
        renew_window_s=cfg.fake_cert_renew_window_s,
        interval_s=cfg.fake_cert_renew_interval_s,
        enabled=renewer_enabled,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        from .query import close_http_client

        renewer = state.fake_cert_renewer
        if renewer is not None and renewer.enabled:
            renewer.start()
        try:
            yield
        finally:
            if renewer is not None:
                renewer.stop()
            close_http_client()

    app = FastAPI(title="iot-gateway-control", version="0.1.0", lifespan=lifespan)
    app.state.control = state
    # Desktop Actions chrome (:9138) + Tauri WebView call this API cross-origin.
    # Monitoring uses the wizard same-origin /api/v1 proxy; Actions still hits :9137 directly.
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"https?://(127\.0\.0\.1|localhost)(:\d+)?|tauri://localhost",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(devices_router, prefix="/api/v1")
    app.include_router(actions_router, prefix="/api/v1")
    app.include_router(public_router, prefix="/api/v1")
    app.include_router(query_router, prefix="/api/v1")

    @app.get("/health", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(status="ok")

    return app
