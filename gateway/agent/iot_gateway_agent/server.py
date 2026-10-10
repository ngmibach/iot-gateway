"""HTTP server: /v1/health, /v1/info, /metrics (Prometheus text)."""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def make_handler(
    health_fn: Callable[[], dict[str, Any]],
    info_fn: Callable[[], dict[str, Any]],
    metrics_fn: Callable[[], str] | None = None,
    reload_fn: Callable[[], dict[str, Any]] | None = None,
) -> type[BaseHTTPRequestHandler]:
    class AgentHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def _send_json(self, code: int, payload: dict[str, Any], *, allow: str | None = None) -> None:
            body = _json_bytes(payload)
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if allow is not None:
                self.send_header("Allow", allow)
            self.end_headers()
            self.wfile.write(body)

        def _send_text(self, code: int, body: str, content_type: str) -> None:
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/v1/health":
                self._send_json(200, health_fn())
                return
            if path == "/v1/info":
                self._send_json(200, info_fn())
                return
            if path == "/metrics" and metrics_fn is not None:
                self._send_text(200, metrics_fn(), "text/plain; version=0.0.4; charset=utf-8")
                return
            self._send_json(404, {"error": "not found"})

        def do_HEAD(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path in ("/v1/health", "/v1/info") or (
                path == "/metrics" and metrics_fn is not None
            ):
                self.send_response(200)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/v1/reload" and reload_fn is not None:
                try:
                    self._send_json(200, reload_fn())
                except Exception as e:  # noqa: BLE001
                    self._send_json(500, {"error": str(e)})
                return
            self._send_json(
                405,
                {"error": "read-only agent; use POST /v1/reload or SSH"},
                allow="GET, HEAD, POST",
            )

        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST

    return AgentHandler


def create_server(
    host: str,
    port: int,
    health_fn: Callable[[], dict[str, Any]],
    info_fn: Callable[[], dict[str, Any]],
    metrics_fn: Callable[[], str] | None = None,
    reload_fn: Callable[[], dict[str, Any]] | None = None,
) -> ThreadingHTTPServer:
    handler = make_handler(health_fn, info_fn, metrics_fn=metrics_fn, reload_fn=reload_fn)
    return ThreadingHTTPServer((host, port), handler)
