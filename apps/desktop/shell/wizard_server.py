"""HTTP Setup Wizard UI + JSON API (stdlib).

Serves ``ui/`` and exposes wizard steps that shell out to detect / nic /
checklist / ssh_setup / launcher. Firewall commands are display-only (K18).
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import detect, ssh_setup
from .launcher import ProcessManager, open_in_browser, wait_http
from .paths import (
    CONTROL_HOST,
    STREAMLIT_PORT,
    WIZARD_PORT,
    control_service_dir,
    desktop_ui_dir,
    load_settings,
    save_settings,
)

logger = logging.getLogger(__name__)

# Ensure control-service packages importable for nic/checklist/actions.
_CS = str(control_service_dir())
if _CS not in sys.path:
    sys.path.insert(0, _CS)


class WizardState:
    def __init__(self) -> None:
        self.manager = ProcessManager()
        self.firewall_confirmed = False
        self.lock = threading.Lock()


STATE = WizardState()


def _json_response(handler: BaseHTTPRequestHandler, code: int, body: Any) -> None:
    raw = json.dumps(body).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(raw)


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or "0")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("JSON body must be an object")
    return data


def _handle_api(
    handler: BaseHTTPRequestHandler,
    method: str,
    path: str,
    *,
    query: str = "",
) -> None:
    try:
        qs = parse_qs(query)

        if method == "GET" and path == "/api/wizard/env":
            _json_response(handler, 200, detect.environment_snapshot())
            return

        if method == "GET" and path == "/api/wizard/nics":
            from telemetry.nic import (  # type: ignore[import-not-found]
                list_ipv4_candidates,
                pick_default_monitoring_ip,
            )

            settings = load_settings()
            mode_q = (qs.get("windows_net_mode") or [None])[0]
            mode = mode_q if mode_q not in (None, "") else settings.get("windows_net_mode")
            if mode_q == "":
                mode = None
            cands = list_ipv4_candidates(windows_net_mode=mode)
            default = pick_default_monitoring_ip(
                cands, gateway_ip=settings.get("gateway_ip")
            )
            _json_response(
                handler,
                200,
                {
                    "candidates": [
                        {"name": c.name, "ip": c.ip, "prefix": c.prefix} for c in cands
                    ],
                    "default": (
                        {"name": default.name, "ip": default.ip, "prefix": default.prefix}
                        if default
                        else None
                    ),
                    "windows_net_mode": mode,
                },
            )
            return

        if method == "POST" and path == "/api/wizard/nics/select":
            body = _read_json(handler)
            ip = str(body.get("monitoring_ip") or "").strip()
            nic = str(body.get("nic_name") or "").strip()
            if not ip:
                _json_response(handler, 400, {"error": "monitoring_ip required"})
                return
            settings = load_settings()
            settings["monitoring_ip"] = ip
            if nic:
                settings["nic_name"] = nic
            if body.get("windows_net_mode"):
                settings["windows_net_mode"] = body["windows_net_mode"]
            if body.get("gateway_ip"):
                settings["gateway_ip"] = str(body["gateway_ip"]).strip()
            save_settings(settings)
            _json_response(handler, 200, {"ok": True, "settings": settings})
            return

        if method == "GET" and path == "/api/wizard/checklist":
            from telemetry.checklist import (  # type: ignore[import-not-found]
                format_checklist_for_display,
                generate_wsl2_nat_checklist,
                refresh_checklist_on_wsl_ip_change,
            )

            settings = load_settings()
            wsl = detect.detect_wsl()
            wsl_ip = str(settings.get("wsl2_ip") or wsl.wsl_ip or "").strip()
            monitoring_ip = str(settings.get("monitoring_ip") or "").strip() or None
            if not wsl_ip:
                _json_response(
                    handler,
                    200,
                    {
                        "applicable": False,
                        "reason": "No WSL2 IP detected — checklist is for Windows NAT path only.",
                        "items": [],
                        "display": "",
                        "localhost_forwarding_note": wsl.localhost_forwarding_note,
                    },
                )
                return
            prev = str(settings.get("wsl2_ip_prev") or "")
            if prev and prev != wsl_ip:
                items = refresh_checklist_on_wsl_ip_change(
                    prev, wsl_ip, monitoring_ip=monitoring_ip
                )
            else:
                items = generate_wsl2_nat_checklist(
                    wsl2_ip=wsl_ip, monitoring_ip=monitoring_ip
                )
            settings["wsl2_ip"] = wsl_ip
            save_settings(settings)
            payload_items = [
                {
                    "id": i.id,
                    "title": i.title,
                    "command": i.command,
                    "notes": i.notes,
                }
                for i in items
            ]
            _json_response(
                handler,
                200,
                {
                    "applicable": True,
                    "wsl2_ip": wsl_ip,
                    "monitoring_ip": monitoring_ip,
                    "items": payload_items,
                    "display": format_checklist_for_display(items),
                    "auto_apply": False,
                    "note": (
                        "Display only — run elevated yourself; the app will not "
                        "apply firewall/portproxy rules (K18)."
                    ),
                    "localhost_forwarding_note": wsl.localhost_forwarding_note,
                    "confirmed": STATE.firewall_confirmed,
                },
            )
            return

        if method == "POST" and path == "/api/wizard/checklist/confirm":
            STATE.firewall_confirmed = True
            settings = load_settings()
            settings["firewall_checklist_confirmed"] = True
            # Remember current WSL IP so a later change re-shows checklist.
            wsl = detect.detect_wsl()
            if wsl.wsl_ip:
                settings["wsl2_ip_prev"] = settings.get("wsl2_ip") or wsl.wsl_ip
                settings["wsl2_ip"] = wsl.wsl_ip
            save_settings(settings)
            _json_response(handler, 200, {"ok": True, "confirmed": True})
            return

        if method == "POST" and path == "/api/wizard/ssh/fetch-host-key":
            body = _read_json(handler)
            host = str(body.get("host") or "").strip()
            port = int(body.get("port") or 22)
            if not host:
                _json_response(handler, 400, {"error": "host required"})
                return
            info = ssh_setup.fetch_host_key(host, port=port)
            _json_response(handler, 200, ssh_setup.host_key_info_dict(info))
            return

        if method == "POST" and path == "/api/wizard/ssh/pin-host-key":
            body = _read_json(handler)
            required = ("host", "port", "key_type", "fingerprint_sha256", "base64")
            if any(k not in body for k in required):
                _json_response(handler, 400, {"error": f"need {required}"})
                return
            info = ssh_setup.HostKeyInfo(
                host=str(body["host"]),
                port=int(body["port"]),
                key_type=str(body["key_type"]),
                fingerprint_sha256=str(body["fingerprint_sha256"]),
                base64=str(body["base64"]),
            )
            ssh_setup.pin_host_key(info)
            _json_response(handler, 200, {"ok": True, "pinned": info.fingerprint_sha256})
            return

        if method == "POST" and path == "/api/wizard/ssh/install-key":
            body = _read_json(handler)
            host = str(body.get("host") or "").strip()
            username = str(body.get("username") or "").strip()
            password = str(body.get("password") or "")
            gateway_id = str(body.get("gateway_id") or host or "default").strip()
            port = int(body.get("port") or 22)
            host_key_b64 = body.get("host_key_base64")
            if not host or not username or not password:
                _json_response(
                    handler, 400, {"error": "host, username, password required"}
                )
                return
            # Pin is mandatory — reject TOFU / WarningPolicy password installs.
            try:
                ssh_setup.resolve_required_pin(
                    host,
                    port,
                    str(host_key_b64) if host_key_b64 else None,
                )
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
                return
            result = ssh_setup.install_pubkey(
                host,
                username,
                password,
                gateway_id,
                port=port,
                host_key_base64=str(host_key_b64) if host_key_b64 else None,
            )
            settings = load_settings()
            settings["default_gateway_id"] = gateway_id
            save_settings(settings)
            _json_response(handler, 200, result)
            return

        if method == "POST" and path == "/api/wizard/services/start":
            body = _read_json(handler)
            start_st = bool(body.get("streamlit", True))
            with STATE.lock:
                ctrl = STATE.manager.start_control_service()
                ok_ctrl = wait_http(ctrl.url, timeout=45, path="/health")
                st_ok = None
                st_url = None
                st_error = None
                if start_st:
                    try:
                        st = STATE.manager.start_streamlit(control_url=ctrl.url)
                        st_url = st.url
                        st_ok = wait_http(st.url, timeout=90)
                    except FileNotFoundError as e:
                        st_error = str(e)
                        st_ok = False
            _json_response(
                handler,
                200,
                {
                    "control": {
                        "url": ctrl.url,
                        "healthy": ok_ctrl,
                        "status": STATE.manager.status()["control"],
                    },
                    "streamlit": {
                        "url": st_url,
                        "healthy": st_ok,
                        "error": st_error,
                        "status": STATE.manager.status()["streamlit"],
                    },
                },
            )
            return

        if method == "GET" and path == "/api/wizard/services/status":
            _json_response(handler, 200, STATE.manager.status())
            return

        if method == "POST" and path == "/api/wizard/services/stop":
            STATE.manager.stop_all()
            _json_response(handler, 200, {"ok": True})
            return

        if method == "POST" and path == "/api/wizard/open-streamlit":
            body = _read_json(handler)
            url = str(body.get("url") or f"http://{CONTROL_HOST}:{STREAMLIT_PORT}")
            open_in_browser(url)
            _json_response(handler, 200, {"ok": True, "url": url})
            return

        _json_response(handler, 404, {"error": f"unknown api {method} {path}"})
    except Exception as e:  # noqa: BLE001 — surface to wizard UI
        logger.exception("wizard api error")
        _json_response(handler, 500, {"error": str(e)})


class WizardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s - " + fmt, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            _handle_api(self, "GET", parsed.path, query=parsed.query)
            return
        self._serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            _handle_api(self, "POST", parsed.path, query=parsed.query)
            return
        self.send_error(405)

    def _serve_static(self, path: str) -> None:
        ui = desktop_ui_dir()
        if path in ("", "/"):
            path = "/wizard.html"
        # Prevent path traversal
        rel = path.lstrip("/").replace("..", "")
        file_path = (ui / rel).resolve()
        if not str(file_path).startswith(str(ui.resolve())) or not file_path.is_file():
            self.send_error(404)
            return
        content_type = "text/plain"
        if file_path.suffix == ".html":
            content_type = "text/html; charset=utf-8"
        elif file_path.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif file_path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def serve(
    host: str = CONTROL_HOST,
    port: int = WIZARD_PORT,
    *,
    open_browser: bool = True,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), WizardHandler)
    url = f"http://{host}:{port}/wizard.html"
    logger.info("Setup Wizard at %s", url)
    if open_browser:
        threading.Timer(0.5, lambda: open_in_browser(url)).start()
    return server


def run_forever(
    host: str = CONTROL_HOST,
    port: int = WIZARD_PORT,
    *,
    open_browser: bool = True,
) -> None:
    server = serve(host, port, open_browser=open_browser)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        STATE.manager.stop_all()
        server.server_close()
