"""HTTP Setup Wizard UI + JSON API (stdlib).

Serves ``ui/`` and exposes wizard steps that shell out to detect / nic /
checklist / ssh_setup / launcher. Firewall commands are display-only (K18).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import admin_auth, detect, keyring_store, ssh_setup
from .launcher import ProcessManager, open_in_browser, wait_http
from .paths import (
    CONTROL_HOST,
    CONTROL_PORT,
    STREAMLIT_PORT,
    WIZARD_PORT,
    control_service_dir,
    desktop_ui_dir,
    ensure_data_dir,
    load_settings,
    save_settings,
)

logger = logging.getLogger(__name__)

# Ensure control-service packages importable for nic/checklist/actions/signing.
_CS = str(control_service_dir())
if _CS not in sys.path:
    sys.path.insert(0, _CS)


class WizardState:
    def __init__(self) -> None:
        self.manager = ProcessManager()
        self.firewall_confirmed = False
        self.lock = threading.Lock()
        self.admin = admin_auth.AdminGate()


STATE = WizardState()
_LAB_MANAGER = None


def _lab_manager():
    """Lazy LabFakeSensorManager under app data (optional demos)."""
    global _LAB_MANAGER
    if _LAB_MANAGER is None:
        from lab.lifecycle import LabFakeSensorManager  # type: ignore[import-not-found]

        from .paths import ensure_data_dir

        _LAB_MANAGER = LabFakeSensorManager(ensure_data_dir() / "lab")
    return _LAB_MANAGER


def _lab_status_dict(st: Any) -> dict[str, Any]:
    from dataclasses import asdict

    return asdict(st)


def _admin_token(handler: BaseHTTPRequestHandler) -> str | None:
    return handler.headers.get("X-Admin-Session") or None


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

        if method == "GET" and path == "/api/wizard/control":
            # Actions chrome uses this to target FastAPI (CORS-enabled).
            import os

            settings = load_settings()
            url = (
                str(settings.get("control_url") or "").strip()
                or f"http://{CONTROL_HOST}:{CONTROL_PORT}"
            )
            token = (
                str(settings.get("api_token") or "").strip()
                or os.environ.get("IOTGW_API_TOKEN", "").strip()
                or None
            )
            _json_response(
                handler,
                200,
                {
                    "url": url,
                    "api_token": token,
                },
            )
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
            # Omit streamlit → False so API clients match the native-Monitoring default.
            start_st = bool(body.get("streamlit", False))
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
            st_status = STATE.manager.status().get("streamlit") or {}
            if not st_status.get("running"):
                _json_response(
                    handler,
                    400,
                    {
                        "error": "Streamlit is not running — start services with streamlit:true first",
                        "status": st_status,
                    },
                )
                return
            url = str(body.get("url") or f"http://{CONTROL_HOST}:{STREAMLIT_PORT}")
            open_in_browser(url)
            _json_response(handler, 200, {"ok": True, "url": url})
            return

        # --- Lab (optional fake_sensor; not production) ---
        if method == "GET" and path == "/api/lab/defaults":
            settings = load_settings()
            from lab.lifecycle import (  # type: ignore[import-not-found]
                DEFAULT_DURATION_MINUTES,
                STORAGE_OVERFLOW_WARNING,
            )

            _json_response(
                handler,
                200,
                {
                    "gateway_ip": settings.get("gateway_ip") or "",
                    "duration_minutes": DEFAULT_DURATION_MINUTES,
                    "warning": STORAGE_OVERFLOW_WARNING,
                },
            )
            return

        if method == "GET" and path == "/api/lab/fake-sensors/status":
            _json_response(handler, 200, _lab_status_dict(_lab_manager().status()))
            return

        if method == "POST" and path == "/api/lab/fake-sensors/start":
            body = _read_json(handler)
            gw = str(body.get("gateway_ip") or "").strip()
            if not gw:
                _json_response(handler, 400, {"error": "gateway_ip required"})
                return
            sensors = body.get("sensors")
            if isinstance(sensors, str):
                sensors = [s.strip() for s in sensors.split(",") if s.strip()]
            raw_dur = body.get("duration_minutes", 10)
            if raw_dur is None or raw_dur == "":
                duration_minutes = 10
            else:
                try:
                    duration_minutes = int(raw_dur)
                except (TypeError, ValueError):
                    _json_response(handler, 400, {"error": "duration_minutes must be an integer"})
                    return
            try:
                st = _lab_manager().start(
                    gateway_ip=gw,
                    duration_minutes=duration_minutes,
                    sensors=sensors,
                )
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
                return
            except (FileNotFoundError, RuntimeError) as e:
                _json_response(handler, 502, {"error": str(e)})
                return
            settings = load_settings()
            settings["gateway_ip"] = gw
            save_settings(settings)
            _json_response(handler, 200, _lab_status_dict(st))
            return

        if method == "POST" and path == "/api/lab/fake-sensors/stop":
            _json_response(handler, 200, _lab_status_dict(_lab_manager().stop()))
        # --- Admin unlock + Code Signing (K16) ---
        if method == "GET" and path == "/api/admin/status":
            _json_response(handler, 200, STATE.admin.status(_admin_token(handler)))
            return

        if method == "POST" and path == "/api/admin/pin/set":
            body = _read_json(handler)
            pin = str(body.get("pin") or "")
            # First-time set is open; changing PIN requires an unlocked session.
            if STATE.admin.status()["has_pin"]:
                try:
                    STATE.admin.require(_admin_token(handler))
                except PermissionError as e:
                    _json_response(handler, 403, {"error": str(e)})
                    return
            try:
                token = STATE.admin.set_pin(pin, unlock=True)
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
                return
            _json_response(
                handler,
                200,
                {"ok": True, "session": token, **STATE.admin.status(token)},
            )
            return

        if method == "POST" and path == "/api/admin/unlock":
            body = _read_json(handler)
            try:
                token = STATE.admin.unlock(str(body.get("pin") or ""))
            except ValueError as e:
                _json_response(handler, 403, {"error": str(e)})
                return
            _json_response(
                handler,
                200,
                {"ok": True, "session": token, **STATE.admin.status(token)},
            )
            return

        if method == "POST" and path == "/api/admin/lock":
            STATE.admin.lock()
            _json_response(handler, 200, {"ok": True, **STATE.admin.status(None)})
            return

        if path.startswith("/api/admin/signing"):
            try:
                STATE.admin.require(_admin_token(handler))
            except PermissionError as e:
                _json_response(handler, 403, {"error": str(e)})
                return
            _handle_admin_signing(handler, method, path)
            return

        _json_response(handler, 404, {"error": f"unknown api {method} {path}"})
    except Exception as e:  # noqa: BLE001 — surface to wizard UI
        logger.exception("wizard api error")
        _json_response(handler, 500, {"error": str(e)})


def _proxy_control(
    handler: BaseHTTPRequestHandler,
    method: str,
    path: str,
    *,
    query: str = "",
) -> None:
    """Same-origin proxy to control-service; injects IOTGW_API_TOKEN when set."""
    target = f"http://{CONTROL_HOST}:{CONTROL_PORT}{path}"
    if query:
        target = f"{target}?{query}"
    headers: dict[str, str] = {}
    ctype = handler.headers.get("Content-Type")
    if ctype:
        headers["Content-Type"] = ctype
    token = os.environ.get("IOTGW_API_TOKEN", "").strip()
    if token:
        headers["X-API-Token"] = token
    body = b""
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        length = int(handler.headers.get("Content-Length") or "0")
        if length > 0:
            body = handler.rfile.read(length)
    req = urllib.request.Request(target, data=body or None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            handler.send_response(resp.status)
            ct = resp.headers.get("Content-Type", "application/json")
            handler.send_header("Content-Type", ct)
            handler.send_header("Content-Length", str(len(raw)))
            handler.send_header("Cache-Control", "no-store")
            handler.end_headers()
            handler.wfile.write(raw)
    except urllib.error.HTTPError as e:
        raw = e.read()
        handler.send_response(e.code)
        handler.send_header(
            "Content-Type", e.headers.get("Content-Type", "application/json")
        )
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)
    except urllib.error.URLError as e:
        _json_response(
            handler,
            502,
            {"error": f"control-service unreachable: {e}"},
        )
def _handle_admin_signing(
    handler: BaseHTTPRequestHandler,
    method: str,
    path: str,
) -> None:
    """Code Signing tab APIs — require admin unlock (checked by caller)."""
    from pathlib import Path

    from registry.registry import Registry  # type: ignore[import-not-found]
    from signing.service import (  # type: ignore[import-not-found]
        SignRequest,
        SigningIdentity,
        list_signable_artifacts,
        sign_artifacts,
    )
    from signing.tools import detect_signing_tools  # type: ignore[import-not-found]

    if method == "GET" and path == "/api/admin/signing/tools":
        _json_response(handler, 200, detect_signing_tools().as_dict())
        return

    if method == "GET" and path == "/api/admin/signing/identity":
        settings = load_settings()
        ident = settings.get("admin_signing") or {}
        # Never return stored passphrases
        _json_response(
            handler,
            200,
            {
                "pfx_path": ident.get("pfx_path"),
                "thumbprint": ident.get("thumbprint"),
                "gpg_key_id": ident.get("gpg_key_id"),
                "platform": ident.get("platform") or "auto",
            },
        )
        return

    if method == "POST" and path == "/api/admin/signing/identity":
        body = _read_json(handler)
        settings = load_settings()
        ident = {
            "platform": str(body.get("platform") or "auto"),
            "pfx_path": (str(body["pfx_path"]).strip() if body.get("pfx_path") else None),
            "thumbprint": (
                str(body["thumbprint"]).strip() if body.get("thumbprint") else None
            ),
            "gpg_key_id": (
                str(body["gpg_key_id"]).strip() if body.get("gpg_key_id") else None
            ),
        }
        settings["admin_signing"] = ident
        save_settings(settings)
        # Optional: stash passphrases in keyring (never in settings.json)
        if body.get("pfx_passphrase"):
            keyring_store.set_secret(
                "signing-pfx", str(body["pfx_passphrase"]), kind="signing"
            )
        if body.get("gpg_passphrase"):
            keyring_store.set_secret(
                "signing-gpg", str(body["gpg_passphrase"]), kind="signing"
            )
        _json_response(handler, 200, {"ok": True, "identity": ident})
        return

    if method == "POST" and path == "/api/admin/signing/list-artifacts":
        body = _read_json(handler)
        folder = str(body.get("folder") or "").strip()
        if not folder:
            _json_response(handler, 400, {"error": "folder required"})
            return
        try:
            items = list_signable_artifacts(Path(folder))
        except FileNotFoundError as e:
            _json_response(handler, 404, {"error": str(e)})
            return
        _json_response(handler, 200, {"artifacts": items})
        return

    if method == "POST" and path == "/api/admin/signing/sign":
        body = _read_json(handler)
        settings = load_settings()
        saved = settings.get("admin_signing") or {}

        pfx_pass = body.get("pfx_passphrase")
        if pfx_pass is None:
            pfx_pass = keyring_store.get_secret("signing-pfx", kind="signing")
        gpg_pass = body.get("gpg_passphrase")
        if gpg_pass is None:
            gpg_pass = keyring_store.get_secret("signing-gpg", kind="signing")

        identity = SigningIdentity(
            platform=str(body.get("platform") or saved.get("platform") or "auto"),
            pfx_path=body.get("pfx_path") or saved.get("pfx_path"),
            pfx_passphrase=pfx_pass,
            thumbprint=body.get("thumbprint") or saved.get("thumbprint"),
            gpg_key_id=body.get("gpg_key_id") or saved.get("gpg_key_id"),
            gpg_passphrase=gpg_pass,
        )
        artifacts = body.get("artifacts") or []
        if not isinstance(artifacts, list) or not artifacts:
            _json_response(handler, 400, {"error": "artifacts list required"})
            return
        export_dir = body.get("export_dir")
        if not export_dir:
            export_dir = str(ensure_data_dir() / "signed-export")

        result = sign_artifacts(
            SignRequest(
                artifacts=[str(a) for a in artifacts],
                identity=identity,
                export_dir=str(export_dir),
                actor="admin",
            )
        )
        # Persist audit via registry.sqlite (no secrets in detail)
        reg_path = ensure_data_dir() / "registry.sqlite"
        reg = Registry(str(reg_path))
        try:
            row = reg.audit(
                "code_sign" if result.ok else "code_sign_failed",
                actor="admin",
                detail=result.audit_detail,
            )
            audit_id = row.get("id")
        finally:
            reg.close()

        payload = result.as_dict()
        payload["audit_id"] = audit_id
        _json_response(handler, 200 if result.ok else 400, payload)
        return

    if method == "POST" and path == "/api/admin/signing/open-export":
        body = _read_json(handler)
        folder = str(body.get("folder") or "").strip()
        if not folder:
            _json_response(handler, 400, {"error": "folder required"})
            return
        path_obj = Path(folder)
        if not path_obj.is_dir():
            _json_response(handler, 404, {"error": f"not a directory: {folder}"})
            return
        # file:// open via browser helper
        open_in_browser(path_obj.resolve().as_uri())
        _json_response(handler, 200, {"ok": True, "folder": str(path_obj.resolve())})
        return

    _json_response(handler, 404, {"error": f"unknown api {method} {path}"})


class WizardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info("%s - " + fmt, self.address_string(), *args)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            _proxy_control(self, "GET", parsed.path, query=parsed.query)
            return
        if parsed.path.startswith("/api/"):
            _handle_api(self, "GET", parsed.path, query=parsed.query)
            return
        self._serve_static(parsed.path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            _proxy_control(self, "POST", parsed.path, query=parsed.query)
            return
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
