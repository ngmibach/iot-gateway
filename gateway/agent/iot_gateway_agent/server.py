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

        def _send_json(self, code: int, payload: dict[str, Any]) -> None:
            body = _json_bytes(payload)
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_error_json(self, code: int, message: str) -> None:
            self._send_json(code, {"error": message})

        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/v1/health":
                self._send_json(200, health_fn())
                return
            if path == "/v1/info":
                self._send_json(200, info_fn())
                return
            if path in ("/", "/health"):
                self._send_json(200, health_fn())
                return
            self._send_error_json(404, "not found")

        def do_POST(self) -> None:  # noqa: N802
            self._send_error_json(405, "read-only agent; mutations via SSH")

        def do_PUT(self) -> None:  # noqa: N802
            self._send_error_json(405, "read-only agent; mutations via SSH")

        def do_DELETE(self) -> None:  # noqa: N802
            self._send_error_json(405, "read-only agent; mutations via SSH")

        def do_PATCH(self) -> None:  # noqa: N802
            self._send_error_json(405, "read-only agent; mutations via SSH")

    return AgentHandler


def create_server(
    host: str,
    port: int,
    health_fn: Callable[[], dict[str, Any]],
    info_fn: Callable[[], dict[str, Any]],
) -> ThreadingHTTPServer:
    handler = make_handler(health_fn, info_fn)
    server = ThreadingHTTPServer((host, port), handler)
    return server
