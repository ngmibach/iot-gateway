"""Stdlib HTTP server: read-only GET /v1/health and GET /v1/info."""

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

        def _reject_mutation(self) -> None:
            self._send_json(
                405,
                {"error": "read-only agent; mutations via SSH"},
                allow="GET, HEAD",
            )

        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/v1/health":
                self._send_json(200, health_fn())
                return
            if path == "/v1/info":
                self._send_json(200, info_fn())
                return
            self._send_json(404, {"error": "not found"})

        def do_HEAD(self) -> None:  # noqa: N802
            # Mirror GET routing without a body.
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path in ("/v1/health", "/v1/info"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Allow", "GET, HEAD")
                self.end_headers()
                return
            self.send_response(404)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()

        do_POST = _reject_mutation
        do_PUT = _reject_mutation
        do_DELETE = _reject_mutation
        do_PATCH = _reject_mutation

    return AgentHandler


def create_server(
    host: str,
    port: int,
    health_fn: Callable[[], dict[str, Any]],
    info_fn: Callable[[], dict[str, Any]],
) -> ThreadingHTTPServer:
    handler = make_handler(health_fn, info_fn)
    return ThreadingHTTPServer((host, port), handler)
