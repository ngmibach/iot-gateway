"""HTTP Setup Wizard UI + JSON API (stdlib).

Serves ``ui/`` and exposes wizard steps that shell out to detect / nic /
checklist / ssh_setup / launcher. Native Windows applies Loki :3100 firewall when elevated.
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

from . import (
    admin_auth,
    ca_passphrase,
    detect,
    discover,
    firewall_apply,
    keyring_store,
    registry_gateways,
    ssh_setup,
    uninstall as uninstall_mod,
)
from .launcher import ProcessManager, open_in_browser, wait_http
from .paths import (
    CONTROL_HOST,
    CONTROL_PORT,
    WIZARD_PORT,
    control_service_dir,
    desktop_ui_dir,
    ensure_data_dir,
    load_settings,
    load_ui_state,
    save_settings,
    save_ui_state,
)

logger = logging.getLogger(__name__)

# Ensure control-service packages importable for nic/checklist/actions/signing.
_CS = str(control_service_dir())
if _CS not in sys.path:
    sys.path.insert(0, _CS)


def resolve_gateway_ip(
    settings: dict[str, Any] | None = None,
    *,
    override: str | None = None,
) -> str:
    """Resolve Prometheus scrape target host for the registered gateway.

    Prefer an explicit override, then top-level ``gateway_ip``, then the
    default (or first) entry under ``gateways.*.host``. Falling back to
    ``127.0.0.1`` scrapes the operator PC and leaves Gateway Metric empty.
    """
    raw = (override or "").strip()
    if raw:
        return raw
    cfg = settings if isinstance(settings, dict) else load_settings()
    top = str(cfg.get("gateway_ip") or "").strip()
    if top:
        return top
    gateways = cfg.get("gateways")
    if isinstance(gateways, dict) and gateways:
        default_id = str(cfg.get("default_gateway_id") or "").strip()
        ordered: list[Any] = []
        if default_id and default_id in gateways:
            ordered.append(gateways[default_id])
        ordered.extend(v for k, v in gateways.items() if k != default_id)
        for entry in ordered:
            if not isinstance(entry, dict):
                continue
            host = str(entry.get("host") or entry.get("gateway_ip") or "").strip()
            if host:
                return host
    return "127.0.0.1"


class WizardState:
    def __init__(self) -> None:
        self.manager = ProcessManager()
        self.firewall_confirmed = False
        self.lock = threading.Lock()
        self.admin = admin_auth.AdminGate()
        self.last_signing_export: str | None = None
        self._telemetry = None
        # Background Install monitoring job (avoids long-blocking HTTP fetches).
        self._telemetry_job: dict[str, Any] = {
            "state": "idle",  # idle | running | ok | error
            "detail": "",
            "error": None,
        }
        self._telemetry_thread: threading.Thread | None = None

    @property
    def telemetry(self):
        """Lazy native Loki/Prometheus manager (no Docker on the operator PC)."""
        if self._telemetry is None:
            from telemetry.native import (  # type: ignore[import-not-found]
                NativeTelemetryManager,
            )

            from .paths import ensure_data_dir

            self._telemetry = NativeTelemetryManager(ensure_data_dir() / "telemetry")
        return self._telemetry

    def telemetry_job_snapshot(self) -> dict[str, Any]:
        with self.lock:
            return dict(self._telemetry_job)

    def start_telemetry_job(
        self, *, gateway_ip: str | None = None, force: bool = False
    ) -> dict[str, Any]:
        """Kick off download+start on a daemon thread; poll via telemetry_job_snapshot."""
        with self.lock:
            if self._telemetry_job.get("state") == "running":
                return {"started": False, "job": dict(self._telemetry_job)}
            self._telemetry_job = {
                "state": "running",
                "detail": "Installing monitoring…",
                "error": None,
            }

        def _run() -> None:
            try:
                tel = self.telemetry
                settings = load_settings()
                gw = resolve_gateway_ip(settings, override=gateway_ip)
                # Fast path: already healthy → mark ok without re-downloading,
                # but still pin Prometheus to the registered gateway IP.
                snap0 = tel.snapshot()
                if snap0.ready and not force:
                    try:
                        tel.apply_scrape_target(gw)
                    except Exception as scrape_err:  # noqa: BLE001
                        logger.warning(
                            "telemetry scrape refresh failed: %s", scrape_err
                        )
                    with self.lock:
                        self._telemetry_job = {
                            "state": "ok",
                            "detail": snap0.detail
                            or "Loki, Prometheus, and Grafana are running.",
                            "error": None,
                        }
                    return
                # start() downloads binaries only when ports are free / not ready.
                st = tel.start(
                    gateway_ip=gw, wait=True, ensure_bins=True
                )
                if force and not st.running:
                    # Force path: re-fetch then retry once.
                    tel.ensure_binaries(force=True)
                    st = tel.start(
                        gateway_ip=gw, wait=True, ensure_bins=False
                    )
                snap = tel.snapshot()
                ready = bool(st.running) or bool(snap.ready)
                detail = st.detail or snap.detail or ""
                with self.lock:
                    self._telemetry_job = {
                        "state": "ok" if ready else "error",
                        "detail": detail
                        if ready
                        else (detail or "Install failed."),
                        "error": None if ready else (detail or "Install failed."),
                    }
            except Exception as e:  # noqa: BLE001
                with self.lock:
                    self._telemetry_job = {
                        "state": "error",
                        "detail": str(e),
                        "error": str(e),
                    }

        thread = threading.Thread(
            target=_run, name="iotgw-telemetry-ensure", daemon=True
        )
        self._telemetry_thread = thread
        thread.start()
        return {"started": True, "job": self.telemetry_job_snapshot()}


STATE = WizardState()


def _admin_token(handler: BaseHTTPRequestHandler) -> str | None:
    return handler.headers.get("X-Admin-Session") or None


def _normalize_platform(value: object) -> str:
    plat = str(value or "auto").strip().lower()
    return plat if plat in ("windows", "linux", "auto") else "auto"


def _require_abs_path(raw: str, *, label: str) -> str:
    """Admin signing paths: absolute, no NUL. Unlocked admin ≡ local FS access."""
    text = (raw or "").strip()
    if not text or "\x00" in text:
        raise ValueError(f"{label}: empty or invalid path")
    from pathlib import Path

    p = Path(text)
    if not p.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    return str(p)


def _json_response(handler: BaseHTTPRequestHandler, code: int, body: Any) -> None:
    raw = json.dumps(body).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(raw)


def _file_response(
    handler: BaseHTTPRequestHandler,
    data: bytes,
    *,
    content_type: str,
    filename: str,
    status: int = 200,
) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header(
        "Content-Disposition", f'attachment; filename="{filename}"'
    )
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def _grafana_open_url_allowed(url: str) -> bool:
    """Allow only https://127.0.0.1:9140/... and https://localhost:9140/..."""
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return False
    if parsed.scheme != "https":
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.hostname not in ("127.0.0.1", "localhost"):
        return False
    if parsed.port != 9140:
        return False
    return True


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
            snap = detect.environment_snapshot()
            settings = load_settings()
            try:
                tel = STATE.telemetry.snapshot()
                job = STATE.telemetry_job_snapshot()
                snap["telemetry"] = {
                    "backend": "native",
                    "ready": tel.ready,
                    "binaries_present": tel.binaries_present,
                    "loki_running": tel.loki_running,
                    "prometheus_running": tel.prometheus_running,
                    "detail": tel.detail,
                    "progress": tel.progress,
                    "job": job,
                    "hint": (
                        "Loki, Prometheus, and Grafana are running."
                        if tel.ready
                        else "Install monitoring to download and start Loki, Prometheus, and Grafana."
                    ),
                }
            except Exception as e:  # noqa: BLE001
                snap["telemetry"] = {
                    "backend": "native",
                    "ready": False,
                    "detail": str(e),
                    "hint": "Monitoring is unavailable.",
                    "job": STATE.telemetry_job_snapshot(),
                }
            # Packaged path: native Loki/Prometheus (no Docker / WSL required).
            snap["docker_required"] = False
            snap["wsl_required"] = False
            # First-run vs returning operator: wizard only until setup finishes.
            setup_complete = bool(settings.get("setup_complete"))
            tel_ready = bool((snap.get("telemetry") or {}).get("ready"))
            snap["setup_complete"] = setup_complete or tel_ready
            snap["entry"] = "app" if snap["setup_complete"] else "wizard"
            _json_response(handler, 200, snap)
            return

        if method == "GET" and path == "/api/wizard/ui-state":
            _json_response(handler, 200, load_ui_state())
            return

        if method == "PUT" and path == "/api/wizard/ui-state":
            length = int(handler.headers.get("Content-Length") or 0)
            raw = handler.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                _json_response(handler, 400, {"error": "invalid JSON"})
                return
            if not isinstance(body, dict):
                _json_response(handler, 400, {"error": "ui-state must be an object"})
                return
            current = load_ui_state()
            # Shallow merge top-level keys; simulate drafts replace per key.
            merged = dict(current)
            for key, value in body.items():
                if key == "simulate" and isinstance(value, dict):
                    sim = dict(merged.get("simulate") or {})
                    if not isinstance(sim, dict):
                        sim = {}
                    for draft_key, draft_val in value.items():
                        if draft_val is None:
                            sim.pop(str(draft_key), None)
                        else:
                            sim[str(draft_key)] = draft_val
                    merged["simulate"] = sim
                else:
                    merged[key] = value
            save_ui_state(merged)
            _json_response(handler, 200, merged)
            return

        if method == "POST" and path == "/api/wizard/setup/complete":
            settings = load_settings()
            settings["setup_complete"] = True
            save_settings(settings)
            _json_response(
                handler,
                200,
                {"ok": True, "setup_complete": True, "entry": "app"},
            )
            return

        if method == "POST" and path == "/api/wizard/telemetry/ensure":
            body = _read_json(handler)
            gateway_ip = str(body.get("gateway_ip") or "").strip() or None
            force = bool(body.get("force", False))
            # background=True (Wizard default): return immediately and poll status.
            # background=False: block until ready (tests / automation).
            background = bool(body.get("background", False))
            if background:
                out = STATE.start_telemetry_job(gateway_ip=gateway_ip, force=force)
                tel = STATE.telemetry.snapshot()
                job = out["job"]
                _json_response(
                    handler,
                    200,
                    {
                        "ok": True,
                        "background": True,
                        "started": out["started"],
                        "job": job,
                        "telemetry": {
                            "backend": "native",
                            "ready": tel.ready,
                            "binaries_present": tel.binaries_present,
                            "loki_running": tel.loki_running,
                            "prometheus_running": tel.prometheus_running,
                            "detail": job.get("detail") or tel.detail,
                            "progress": tel.progress,
                        },
                    },
                )
                return
            try:
                settings = load_settings()
                gw = resolve_gateway_ip(settings, override=gateway_ip)
                # start() probes first, then downloads only if needed.
                st = STATE.telemetry.start(
                    gateway_ip=gw, wait=True, ensure_bins=True
                )
                if force:
                    STATE.telemetry.stop()
                    STATE.telemetry.ensure_binaries(force=True)
                    st = STATE.telemetry.start(
                        gateway_ip=gw, wait=True, ensure_bins=False
                    )
                # Prefer start() result — snapshot used to overwrite Ready with
                # binary-fetch progress ("already present") while child handles
                # were unset after a previous session.
                tel = STATE.telemetry.snapshot()
                ready = bool(st.running) or bool(tel.ready)
                detail = st.detail or tel.detail or ""
                with STATE.lock:
                    STATE._telemetry_job = {
                        "state": "ok" if ready else "error",
                        "detail": detail,
                        "error": None if ready else detail,
                    }
                _json_response(
                    handler,
                    200,
                    {
                        "ok": ready,
                        "background": False,
                        "telemetry": {
                            "backend": "native",
                            "ready": ready,
                            "binaries_present": tel.binaries_present,
                            "loki_running": tel.loki_running
                            or bool(getattr(st.loki, "ok", False)),
                            "prometheus_running": tel.prometheus_running
                            or bool(getattr(st.prometheus, "ok", False)),
                            "detail": detail,
                            "progress": tel.progress,
                        },
                        "job": STATE.telemetry_job_snapshot(),
                    },
                )
            except Exception as e:  # noqa: BLE001
                with STATE.lock:
                    STATE._telemetry_job = {
                        "state": "error",
                        "detail": str(e),
                        "error": str(e),
                    }
                _json_response(handler, 500, {"error": str(e), "ok": False})
            return

        if method == "POST" and path == "/api/wizard/telemetry/stop":
            STATE.telemetry.stop()
            with STATE.lock:
                if STATE._telemetry_job.get("state") != "running":
                    STATE._telemetry_job = {
                        "state": "idle",
                        "detail": "Stopped.",
                        "error": None,
                    }
            _json_response(handler, 200, {"ok": True})
            return

        if method == "GET" and path == "/api/wizard/uninstall/targets":
            try:
                _json_response(handler, 200, uninstall_mod.uninstall_targets())
            except Exception as e:  # noqa: BLE001
                logger.exception("uninstall targets failed")
                _json_response(handler, 500, {"ok": False, "error": str(e)})
            return

        if method == "POST" and path == "/api/wizard/uninstall":
            body = _read_json(handler)
            do_gateway = bool(body.get("gateway", False))
            do_monitoring = bool(body.get("monitoring", False))
            # Coupling: Monitoring always removes every registered gateway.
            if do_monitoring:
                do_gateway = True
            sudo_password = str(body.get("sudo_password") or "").strip()
            gateway_id = str(body.get("gateway_id") or "").strip() or None
            if not sudo_password:
                # Prefer the targeted gateway; else default / first registered.
                settings = load_settings()
                lookup_id = gateway_id or str(
                    settings.get("default_gateway_id") or "gateway"
                ).strip()
                sudo_password = (
                    keyring_store.get_secret(lookup_id, kind="sudo") or ""
                ).strip()
            try:
                out = uninstall_mod.run_uninstall(
                    gateway=do_gateway,
                    monitoring=do_monitoring,
                    sudo_password=sudo_password,
                    gateway_id=None if do_monitoring else gateway_id,
                    stop_telemetry=lambda: STATE.telemetry.stop(),
                    stop_services=lambda: STATE.manager.stop_all(),
                    telemetry_uninstall=lambda: STATE.telemetry.uninstall(),
                    reset_telemetry_mgr=lambda: setattr(STATE, "_telemetry", None),
                )
                with STATE.lock:
                    STATE._telemetry_job = {
                        "state": "idle",
                        "detail": "Uninstalled." if out.get("ok") else "Uninstall finished with errors.",
                        "error": None if out.get("ok") else "uninstall errors",
                    }
                    STATE.firewall_confirmed = False
                # Never echo sudo password back.
                sudo_password = ""
                _json_response(handler, 200 if out.get("ok") else 207, out)
            except uninstall_mod.UninstallError as e:
                _json_response(handler, 409, {"ok": False, "error": str(e)})
            except Exception as e:  # noqa: BLE001
                logger.exception("uninstall failed")
                _json_response(handler, 500, {"ok": False, "error": str(e)})
            return

        if method == "GET" and path == "/api/wizard/telemetry/status":
            job = STATE.telemetry_job_snapshot()
            # While installing, avoid slow HTTP probes so download progress stays fresh.
            if job.get("state") == "running":
                tel_mgr = STATE.telemetry
                progress = str(getattr(tel_mgr, "last_progress", "") or "")
                bins = False
                bin_fn = getattr(tel_mgr, "_bin", None)
                if callable(bin_fn):
                    try:
                        bins = bool(
                            bin_fn("loki").is_file() and bin_fn("prometheus").is_file()
                        )
                    except Exception:  # noqa: BLE001
                        bins = False
                _json_response(
                    handler,
                    200,
                    {
                        "backend": "native",
                        "ready": False,
                        "binaries_present": bins,
                        "loki_running": False,
                        "prometheus_running": False,
                        "grafana_running": False,
                        "detail": progress or job.get("detail") or "Installing…",
                        "progress": progress,
                        "job": job,
                    },
                )
                return
            tel = STATE.telemetry.snapshot()
            detail = tel.detail
            if job.get("state") == "error":
                detail = job.get("detail") or detail
            _json_response(
                handler,
                200,
                {
                    "backend": "native",
                    "ready": tel.ready,
                    "binaries_present": tel.binaries_present,
                    "loki_running": tel.loki_running,
                    "prometheus_running": tel.prometheus_running,
                    "grafana_running": bool(
                        getattr(tel, "grafana_running", False)
                    ),
                    "detail": detail,
                    "progress": tel.progress,
                    "job": job,
                },
            )
            return

        if method == "GET" and path == "/api/wizard/grafana/status":
            tel = STATE.telemetry
            try:
                snap = tel.snapshot()
                running = bool(getattr(snap, "grafana_running", False))
                detail = snap.detail or ""
            except Exception as e:  # noqa: BLE001
                running = False
                detail = str(e)
            cert = tel.grafana_cert_public_meta()
            _json_response(
                handler,
                200,
                {
                    "running": running,
                    "url": "https://127.0.0.1:9140/",
                    "cert": cert,
                    "detail": detail,
                },
            )
            return

        if method == "GET" and path == "/api/wizard/grafana/cert":
            cert_path = STATE.telemetry.certs_dir / "grafana.crt"
            if not cert_path.is_file() or cert_path.stat().st_size <= 0:
                _json_response(
                    handler,
                    404,
                    {"error": "Grafana certificate is not present yet."},
                )
                return
            _file_response(
                handler,
                cert_path.read_bytes(),
                content_type="application/x-x509-ca-cert",
                filename="iot-gateway-grafana.crt",
            )
            return

        if method == "POST" and path == "/api/wizard/grafana/cert/regenerate":
            try:
                out = STATE.telemetry.regenerate_grafana_certs()
                _json_response(handler, 200, out)
            except Exception as e:  # noqa: BLE001
                logger.exception("grafana cert regenerate failed")
                _json_response(handler, 500, {"error": str(e)})
            return

        if method == "POST" and path == "/api/wizard/open-url":
            body = _read_json(handler)
            url = str(body.get("url") or "").strip()
            if not url or not _grafana_open_url_allowed(url):
                _json_response(
                    handler,
                    400,
                    {
                        "error": (
                            "URL not allowed. Only https://127.0.0.1:9140 "
                            "and https://localhost:9140 (and paths) are permitted."
                        )
                    },
                )
                return
            open_in_browser(url)
            _json_response(handler, 200, {"ok": True, "url": url})
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
            gateway_ip = str(body.get("gateway_ip") or "").strip()
            if not ip and not gateway_ip:
                _json_response(
                    handler, 400, {"error": "monitoring_ip or gateway_ip required"}
                )
                return
            settings = load_settings()
            if ip:
                settings["monitoring_ip"] = ip
            if nic:
                settings["nic_name"] = nic
            if body.get("windows_net_mode"):
                settings["windows_net_mode"] = body["windows_net_mode"]
            if gateway_ip:
                settings["gateway_ip"] = gateway_ip
            save_settings(settings)
            _json_response(handler, 200, {"ok": True, "settings": settings})
            return

        if method == "POST" and path == "/api/wizard/settings/gateway":
            body = _read_json(handler)
            settings = load_settings()
            gid = str(body.get("gateway_id") or "").strip()
            host = str(body.get("ssh_host") or body.get("gateway_ip") or "").strip()
            if not host:
                _json_response(handler, 400, {"error": "ssh_host or gateway_ip required"})
                return
            if gid:
                settings["default_gateway_id"] = gid
            settings["gateway_ip"] = str(body.get("gateway_ip") or host).strip()
            settings["ssh_host"] = host
            if body.get("ssh_user") is not None:
                settings["ssh_user"] = str(body.get("ssh_user") or "ubuntu").strip()
            if body.get("ssh_port") is not None:
                try:
                    settings["ssh_port"] = int(body.get("ssh_port") or 22)
                except (TypeError, ValueError):
                    _json_response(handler, 400, {"error": "invalid ssh_port"})
                    return
            # Optional: persist gateway sudo (same value as SSH login password).
            sudo_pw = str(body.get("sudo_password") or body.get("password") or "").strip()
            if sudo_pw and gid:
                keyring_store.set_secret(gid, sudo_pw, kind="sudo")
                sudo_pw = ""
            save_settings(settings)
            _json_response(handler, 200, {"ok": True, "settings": settings})
            return

        if method == "GET" and path == "/api/wizard/secrets/sudo-status":
            gid = (qs.get("gateway_id") or [""])[0].strip()
            if not gid:
                _json_response(handler, 400, {"error": "gateway_id required"})
                return
            present = bool(keyring_store.get_secret(gid, kind="sudo"))
            _json_response(handler, 200, {"present": present, "gateway_id": gid})
            return

        if method == "PUT" and path == "/api/wizard/secrets/sudo":
            body = _read_json(handler)
            gid = str(body.get("gateway_id") or "").strip()
            sudo_pw = str(body.get("sudo_password") or body.get("password") or "").strip()
            if not gid:
                _json_response(handler, 400, {"error": "gateway_id required"})
                return
            if not sudo_pw:
                _json_response(handler, 400, {"error": "sudo_password required"})
                return
            keyring_store.set_secret(gid, sudo_pw, kind="sudo")
            sudo_pw = ""
            _json_response(
                handler, 200, {"ok": True, "gateway_id": gid, "present": True}
            )
            return

        if method == "DELETE" and path == "/api/wizard/secrets/sudo":
            gid = (qs.get("gateway_id") or [""])[0].strip()
            if not gid:
                _json_response(handler, 400, {"error": "gateway_id required"})
                return
            keyring_store.delete_secret(gid, kind="sudo")
            _json_response(
                handler, 200, {"ok": True, "gateway_id": gid, "present": False}
            )
            return

        if method == "GET" and path == "/api/wizard/secrets/ca-status":
            gid = (qs.get("gateway_id") or [""])[0].strip()
            if not gid:
                _json_response(handler, 400, {"error": "gateway_id required"})
                return
            present = bool(keyring_store.get_secret(gid, kind="ca"))
            _json_response(handler, 200, {"present": present, "gateway_id": gid})
            return

        if method == "PUT" and path == "/api/wizard/secrets/ca":
            body = _read_json(handler)
            gid = str(body.get("gateway_id") or "").strip()
            passphrase = body.get("ca_passphrase")
            if not gid:
                _json_response(handler, 400, {"error": "gateway_id required"})
                return
            if not isinstance(passphrase, str) or not passphrase.strip():
                _json_response(handler, 400, {"error": "ca_passphrase required"})
                return
            if passphrase.strip() == "admin":
                _json_response(
                    handler,
                    400,
                    {"error": "production profile refuses CA passphrase 'admin'"},
                )
                return
            keyring_store.set_secret(gid, passphrase.strip(), kind="ca")
            _json_response(handler, 200, {"ok": True, "gateway_id": gid, "present": True})
            return

        if method == "POST" and path == "/api/wizard/secrets/ca-ensure":
            # Registration helper: reuse keyring CA, store an explicit passphrase,
            # or auto-generate from sudo (+ optional device password) when absent.
            body = _read_json(handler)
            gid = str(body.get("gateway_id") or "").strip()
            if not gid:
                _json_response(handler, 400, {"error": "gateway_id required"})
                return
            if keyring_store.get_secret(gid, kind="ca"):
                _json_response(
                    handler,
                    200,
                    {
                        "ok": True,
                        "gateway_id": gid,
                        "present": True,
                        "created": False,
                        "source": "keyring",
                    },
                )
                return
            explicit = body.get("ca_passphrase")
            generate = bool(body.get("generate"))
            try:
                if isinstance(explicit, str) and explicit.strip():
                    ca_pass = ca_passphrase.validate_ca_passphrase(explicit)
                    source = "explicit"
                elif generate:
                    sudo_password = str(body.get("sudo_password") or "").strip()
                    if not sudo_password:
                        sudo_password = (
                            keyring_store.get_secret(gid, kind="sudo") or ""
                        ).strip()
                    device_password = str(body.get("device_password") or "")
                    ca_pass = ca_passphrase.generate_ca_passphrase(
                        sudo_password=sudo_password,
                        gateway_id=gid,
                        device_password=device_password,
                    )
                    source = "generated"
                else:
                    _json_response(
                        handler,
                        400,
                        {
                            "error": (
                                "CA passphrase required — enter it, or enable "
                                "Generate CA passphrase with the gateway sudo password"
                            )
                        },
                    )
                    return
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
                return
            keyring_store.set_secret(gid, ca_pass, kind="ca")
            ca_pass = ""  # drop local reference
            _json_response(
                handler,
                200,
                {
                    "ok": True,
                    "gateway_id": gid,
                    "present": True,
                    "created": True,
                    "source": source,
                },
            )
            return

        if method == "DELETE" and path == "/api/wizard/secrets/ca":
            gid = (qs.get("gateway_id") or [""])[0].strip()
            if not gid:
                _json_response(handler, 400, {"error": "gateway_id required"})
                return
            keyring_store.delete_secret(gid, kind="ca")
            _json_response(handler, 200, {"ok": True, "gateway_id": gid, "present": False})
            return

        if method == "POST" and path == "/api/wizard/discover/gateways":
            body = _read_json(handler)
            try:
                port = int(body.get("port") or discover.DEFAULT_SSH_PORT)
            except (TypeError, ValueError):
                _json_response(handler, 400, {"error": "invalid port"})
                return
            try:
                timeout_s = float(body.get("timeout_s") or discover.DEFAULT_TIMEOUT_S)
            except (TypeError, ValueError):
                timeout_s = discover.DEFAULT_TIMEOUT_S
            monitoring_ip = str(body.get("monitoring_ip") or "").strip() or None
            prefix = body.get("prefix")
            try:
                pref = int(prefix) if prefix is not None and prefix != "" else None
            except (TypeError, ValueError):
                _json_response(handler, 400, {"error": "invalid prefix"})
                return
            try:
                out = discover.discover_gateways(
                    monitoring_ip=monitoring_ip,
                    prefix=pref,
                    port=port,
                    timeout_s=timeout_s,
                )
                _json_response(handler, 200, out)
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001
                logger.exception("gateway discover failed")
                _json_response(handler, 500, {"error": str(e)})
            return

        if method == "GET" and path == "/api/wizard/firewall/status":
            try:
                st = firewall_apply.firewall_status()
                st["confirmed"] = STATE.firewall_confirmed or bool(
                    st.get("rule_present")
                )
                _json_response(handler, 200, st)
            except Exception as e:  # noqa: BLE001
                logger.exception("firewall status failed")
                _json_response(handler, 500, {"error": str(e)})
            return

        if method == "POST" and path == "/api/wizard/firewall/apply":
            try:
                out = firewall_apply.apply_loki_firewall()
                if out.get("ok"):
                    STATE.firewall_confirmed = True
                    settings = load_settings()
                    settings["firewall_checklist_confirmed"] = True
                    save_settings(settings)
                _json_response(handler, 200, out)
            except firewall_apply.FirewallError as e:
                _json_response(handler, 403, {"ok": False, "error": str(e)})
            except Exception as e:  # noqa: BLE001
                logger.exception("firewall apply failed")
                _json_response(handler, 500, {"ok": False, "error": str(e)})
            return

        if method == "GET" and path == "/api/wizard/checklist":
            from telemetry.checklist import (  # type: ignore[import-not-found]
                format_checklist_for_display,
                generate_windows_native_checklist,
            )

            settings = load_settings()
            wsl = detect.detect_wsl()
            runtime = detect.operator_runtime()
            monitoring_ip = str(settings.get("monitoring_ip") or "").strip() or None
            fw = firewall_apply.firewall_status()

            # Packaged Windows .exe: native Loki on 0.0.0.0:3100 — firewall only.
            if runtime == "windows":
                items = generate_windows_native_checklist(monitoring_ip=monitoring_ip)
                payload_items = [
                    {
                        "id": i.id,
                        "title": i.title,
                        "command": i.command,
                        "notes": i.notes,
                    }
                    for i in items
                ]
                confirmed = STATE.firewall_confirmed or bool(fw.get("rule_present"))
                _json_response(
                    handler,
                    200,
                    {
                        "applicable": True,
                        "path": "windows_native",
                        "monitoring_ip": monitoring_ip,
                        "items": payload_items,
                        "display": format_checklist_for_display(items),
                        "auto_apply": True,
                        "elevated": fw.get("elevated"),
                        "rule_present": fw.get("rule_present"),
                        "note": (
                            "The app applies the Windows Firewall rule when run as "
                            "Administrator (inbound TCP 3100). WSL is not required."
                        ),
                        "wsl_note": wsl.note,
                        "confirmed": confirmed,
                    },
                )
                return

            _json_response(
                handler,
                200,
                {
                    "applicable": False,
                    "path": runtime,
                    "reason": (
                        "Firewall checklist is for Windows. On Linux, allow "
                        "TCP 3100 on MONITORING_IP if the gateway is remote."
                    ),
                    "items": [],
                    "display": "",
                    "wsl_note": wsl.note,
                },
            )
            return

        if method == "POST" and path == "/api/wizard/checklist/confirm":
            STATE.firewall_confirmed = True
            settings = load_settings()
            settings["firewall_checklist_confirmed"] = True
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
            with STATE.lock:
                ctrl = STATE.manager.start_control_service()
                ok_ctrl = wait_http(ctrl.url, timeout=45, path="/health")
            _json_response(
                handler,
                200,
                {
                    "control": {
                        "url": ctrl.url,
                        "healthy": ok_ctrl,
                        "status": STATE.manager.status()["control"],
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

        if method == "POST" and path == "/api/wizard/provision":
            # Monolithic agent install over SSH (uses pinned key from Gateways flow).
            body = _read_json(handler)
            settings = load_settings()
            host = str(body.get("host") or settings.get("ssh_host") or "").strip()
            username = str(
                body.get("username") or settings.get("ssh_user") or "ubuntu"
            ).strip()
            port = int(body.get("port") or settings.get("ssh_port") or 22)
            gateway_id = str(
                body.get("gateway_id") or settings.get("default_gateway_id") or "gateway"
            ).strip()
            monitoring_ip = str(
                body.get("monitoring_ip") or settings.get("monitoring_ip") or ""
            ).strip()
            gateway_ip = str(
                body.get("gateway_ip") or settings.get("gateway_ip") or host
            ).strip()
            # Sudo is never written to settings.json / logs; keyring only after success.
            sudo_password = str(body.get("sudo_password") or "")
            generate_ca = bool(body.get("generate_ca_passphrase"))
            ca_pass = ""
            if not host:
                _json_response(handler, 400, {"error": "SSH host required (complete step 3)"})
                return
            if not monitoring_ip:
                _json_response(
                    handler,
                    400,
                    {"error": "MONITORING_IP required (complete step 2)"},
                )
                return
            if not sudo_password.strip():
                _json_response(
                    handler,
                    400,
                    {
                        "error": "Gateway sudo password required — used for apt/systemd install only",
                    },
                )
                return
            try:
                if generate_ca:
                    # Reinstall: keep the keyring CA so we can unlock an existing
                    # remote ca.key. Generating a new passphrase here left the old
                    # encrypted key on the Pi and failed decrypt cert signing.
                    existing_ca = keyring_store.get_secret(gateway_id, kind="ca")
                    if isinstance(existing_ca, str) and existing_ca.strip():
                        ca_pass = ca_passphrase.validate_ca_passphrase(existing_ca)
                    else:
                        ca_pass = ca_passphrase.generate_ca_passphrase(
                            sudo_password=sudo_password,
                            gateway_id=gateway_id,
                        )
                else:
                    ca_pass = ca_passphrase.validate_ca_passphrase(
                        str(body.get("ca_passphrase") or "")
                    )
            except ValueError as e:
                sudo_password = ""
                ca_pass = ""
                _json_response(handler, 400, {"error": str(e)})
                return
            key_path = ssh_setup.key_paths_for(gateway_id).private
            if not key_path.is_file():
                sudo_password = ""
                ca_pass = ""
                _json_response(
                    handler,
                    400,
                    {
                        "error": "SSH key not installed yet — pin host key and install ed25519 first",
                    },
                )
                return
            try:
                from provisioner.provision import (  # type: ignore[import-not-found]
                    ProvisionConfig,
                    provision,
                )
                from provisioner.ssh import ParamikoSSHSession  # type: ignore[import-not-found]

                ssh = ParamikoSSHSession(
                    host,
                    username,
                    key_filename=str(key_path),
                    port=port,
                )
                try:
                    result = provision(
                        ssh,
                        ProvisionConfig(
                            gateway_ip=gateway_ip or host,
                            monitoring_ip=monitoring_ip,
                            sudo_password=sudo_password,
                            ca_passphrase=ca_pass,
                        ),
                    )
                finally:
                    ssh.close()
                # Persist CA + sudo after successful provision (sensor certs / fake netns).
                try:
                    keyring_store.set_secret(gateway_id, ca_pass, kind="ca")
                    if sudo_password.strip():
                        keyring_store.set_secret(
                            gateway_id, sudo_password.strip(), kind="sudo"
                        )
                finally:
                    ca_pass = ""
                    sudo_password = ""  # drop local reference ASAP
                settings["gateway_ip"] = gateway_ip or host
                settings["ssh_host"] = host
                settings["ssh_user"] = username
                settings["ssh_port"] = port
                settings["provision_backend"] = "agent"
                settings["default_gateway_id"] = gateway_id
                gws = settings.get("gateways")
                if not isinstance(gws, dict):
                    gws = {}
                row = dict(gws.get(gateway_id) or {})
                row.update(
                    {
                        "host": host,
                        "username": username,
                        "port": port,
                        "install_root": result.install_root,
                    }
                )
                gws[gateway_id] = row
                settings["gateways"] = gws
                save_settings(settings)
                # Monitoring Metrics/Activities read registry.sqlite, not settings.json.
                try:
                    fp = registry_gateways.fingerprint_from_settings(
                        settings, host, port
                    )
                    registry_gateways.upsert_local_gateway(
                        gateway_id=gateway_id,
                        host=gateway_ip or host,
                        ssh_user=username,
                        fingerprint=fp,
                        install_root=result.install_root,
                        monitoring_ip=monitoring_ip,
                        agent_url=f"http://{gateway_ip or host}:9139",
                        password_auth_enabled=False,
                        status="provisioned",
                    )
                except Exception as reg_err:  # noqa: BLE001
                    logger.warning("registry upsert after provision failed: %s", reg_err)
                # Point Prometheus at the new gateway (Install monitoring may have
                # left 127.0.0.1:9139 from before Create Gateway).
                try:
                    STATE.telemetry.apply_scrape_target(gateway_ip or host)
                except Exception as scrape_err:  # noqa: BLE001
                    logger.warning(
                        "prometheus scrape refresh after provision failed: %s",
                        scrape_err,
                    )
                _json_response(
                    handler,
                    200,
                    {
                        "ok": True,
                        "backend": result.backend,
                        "install_root": result.install_root,
                        "agent_installed": result.agent_installed,
                        "notes": result.notes,
                        "probes": result.probes,
                    },
                )
            except Exception as e:  # noqa: BLE001
                ca_pass = ""
                sudo_password = ""
                _json_response(handler, 500, {"error": str(e), "ok": False})
            return

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


def _gateway_id_from_v1_path(path: str) -> str | None:
    """Extract gateway id from ``/api/v1/gateways/{gid}/...``."""
    parts = [p for p in (path or "").split("/") if p]
    # api, v1, gateways, {gid}, ...
    if len(parts) >= 4 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "gateways":
        gid = parts[3].strip()
        return gid or None
    return None


def _should_inject_ca(method: str, path: str) -> bool:
    """Device register / fake create / update / reissue / feed-cert.

    Skips discover and cert-bundle GET.
    """
    if method == "POST" and path.endswith("/reissue-cert"):
        return True
    if method == "POST" and path.endswith("/fake/feed-cert"):
        return True
    if method == "POST" and path.endswith("/devices/fake"):
        return True
    if method == "PATCH" and "/devices/" in path:
        return True
    if method == "POST" and path.endswith("/devices"):
        return True
    return False


def _should_inject_sudo(method: str, path: str) -> bool:
    """Playbooks that need gateway sudo (Mosquitto ACL/passwords or fake netns)."""
    if method == "POST" and path.endswith("/devices/fake"):
        return True
    if method == "POST" and path.endswith("/devices"):
        return True
    if method == "POST" and path.endswith("/fake/feed-cert"):
        return True
    if method == "POST" and path.endswith("/fake/start"):
        return True
    if method == "POST" and path.endswith("/fake/stop"):
        return True
    if method == "PATCH" and path.endswith("/fake"):
        return True
    # Reissue signs with mosquitto-owned ca.key under sudo.
    if method == "POST" and path.endswith("/reissue-cert"):
        return True
    # Real-sensor View update re-runs register (ACL/password writes).
    if method == "PATCH" and "/devices/" in path and not path.endswith("/fake"):
        return True
    # Unregister / fake teardown needs sudo for Mosquitto secrets + netns.
    if method == "DELETE" and "/devices/" in path:
        return True
    # Control tab: block/unblock rewrite Mosquitto ACL; purge may need broker access.
    if method == "POST" and (
        path.endswith("/control/block")
        or path.endswith("/control/unblock")
        or path.endswith("/control/purge-kafka")
    ):
        return True
    return False


def _inject_json_secret(
    body: bytes,
    gateway_id: str,
    *,
    field: str,
    kind: str,
) -> tuple[bytes, str | None]:
    """Merge a keyring secret into JSON when ``field`` is absent.

    Returns (body_bytes, content_type_override). Never logs the secret.
    """
    if not gateway_id:
        return body, None
    try:
        data = json.loads(body.decode("utf-8") if body else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body, None
    if not isinstance(data, dict):
        return body, None
    existing = data.get(field)
    if isinstance(existing, str) and existing.strip():
        return body, None
    secret = keyring_store.get_secret(gateway_id, kind=kind)
    if not secret:
        return body, None
    data[field] = secret
    out = json.dumps(data).encode("utf-8")
    return out, "application/json"


def _inject_ca_passphrase(body: bytes, gateway_id: str) -> tuple[bytes, str | None]:
    """Merge keyring CA into JSON body when ``ca_passphrase`` is absent."""
    return _inject_json_secret(
        body, gateway_id, field="ca_passphrase", kind="ca"
    )


def _inject_sudo_password(body: bytes, gateway_id: str) -> tuple[bytes, str | None]:
    """Merge keyring sudo into JSON body when ``sudo_password`` is absent."""
    return _inject_json_secret(
        body, gateway_id, field="sudo_password", kind="sudo"
    )


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
    gid = _gateway_id_from_v1_path(path) if (
        _should_inject_ca(method, path) or _should_inject_sudo(method, path)
    ) else None
    if gid and _should_inject_ca(method, path):
        body, ct_override = _inject_ca_passphrase(body, gid)
        if ct_override:
            headers["Content-Type"] = ct_override
    if gid and _should_inject_sudo(method, path):
        body, ct_override = _inject_sudo_password(body, gid)
        if ct_override:
            headers["Content-Type"] = ct_override
    req = urllib.request.Request(target, data=body or None, headers=headers, method=method)
    # Device register/update/delete SSH playbooks can exceed 30s.
    # GET summaries fan out many Prom/Loki queries; keep headroom above that.
    timeout = 120 if method in ("POST", "PUT", "PATCH", "DELETE") else 60
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
    """Code Signing tab APIs — require admin unlock (checked by caller).

    Trust boundary: an unlocked admin session may read/sign absolute paths on
    the local machine (intentional for build folders). ``open-export`` is
    confined to the app data dir or the last successful sign export.
    """
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
                "platform": _normalize_platform(ident.get("platform")),
            },
        )
        return

    if method == "POST" and path == "/api/admin/signing/identity":
        body = _read_json(handler)
        settings = load_settings()
        pfx_path = None
        if body.get("pfx_path"):
            try:
                pfx_path = _require_abs_path(str(body["pfx_path"]), label="pfx_path")
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
                return
        ident = {
            "platform": _normalize_platform(body.get("platform")),
            "pfx_path": pfx_path,
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
        try:
            folder = _require_abs_path(str(body.get("folder") or ""), label="folder")
        except ValueError as e:
            _json_response(handler, 400, {"error": str(e)})
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

        pfx_path = body.get("pfx_path") or saved.get("pfx_path")
        if pfx_path:
            try:
                pfx_path = _require_abs_path(str(pfx_path), label="pfx_path")
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
                return

        identity = SigningIdentity(
            platform=_normalize_platform(  # type: ignore[arg-type]
                body.get("platform") or saved.get("platform") or "auto"
            ),
            pfx_path=pfx_path,
            pfx_passphrase=pfx_pass,
            thumbprint=body.get("thumbprint") or saved.get("thumbprint"),
            gpg_key_id=body.get("gpg_key_id") or saved.get("gpg_key_id"),
            gpg_passphrase=gpg_pass,
        )
        artifacts = body.get("artifacts") or []
        if not isinstance(artifacts, list) or not artifacts:
            _json_response(handler, 400, {"error": "artifacts list required"})
            return
        try:
            artifact_paths = [
                _require_abs_path(str(a), label="artifact") for a in artifacts
            ]
        except ValueError as e:
            _json_response(handler, 400, {"error": str(e)})
            return
        export_dir = body.get("export_dir")
        if export_dir:
            try:
                export_dir = _require_abs_path(str(export_dir), label="export_dir")
            except ValueError as e:
                _json_response(handler, 400, {"error": str(e)})
                return
        else:
            export_dir = str(ensure_data_dir() / "signed-export")

        result = sign_artifacts(
            SignRequest(
                artifacts=artifact_paths,
                identity=identity,
                export_dir=str(export_dir),
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

        if result.ok and result.export_dir:
            STATE.last_signing_export = result.export_dir

        payload = result.as_dict()
        payload["audit_id"] = audit_id
        _json_response(handler, 200 if result.ok else 400, payload)
        return

    if method == "POST" and path == "/api/admin/signing/open-export":
        body = _read_json(handler)
        try:
            folder = _require_abs_path(str(body.get("folder") or ""), label="folder")
        except ValueError as e:
            _json_response(handler, 400, {"error": str(e)})
            return
        path_obj = Path(folder).resolve()
        if not path_obj.is_dir():
            _json_response(handler, 404, {"error": f"not a directory: {folder}"})
            return
        # Confine open-export to app data tree or last successful sign export.
        data_root = ensure_data_dir().resolve()
        allowed = [data_root]
        if STATE.last_signing_export:
            allowed.append(Path(STATE.last_signing_export).resolve())
        if not any(
            path_obj == root or root in path_obj.parents for root in allowed
        ):
            _json_response(
                handler,
                403,
                {
                    "error": (
                        "open-export confined to app data dir or last sign export"
                    )
                },
            )
            return
        open_in_browser(path_obj.as_uri())
        _json_response(handler, 200, {"ok": True, "folder": str(path_obj)})
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

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            _proxy_control(self, "PUT", parsed.path, query=parsed.query)
            return
        if parsed.path.startswith("/api/"):
            _handle_api(self, "PUT", parsed.path, query=parsed.query)
            return
        self.send_error(405)

    def do_PATCH(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            _proxy_control(self, "PATCH", parsed.path, query=parsed.query)
            return
        self.send_error(405)

    def do_DELETE(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/v1/"):
            _proxy_control(self, "DELETE", parsed.path, query=parsed.query)
            return
        if parsed.path.startswith("/api/"):
            _handle_api(self, "DELETE", parsed.path, query=parsed.query)
            return
        self.send_error(405)

    def _serve_static(self, path: str) -> None:
        ui = desktop_ui_dir()
        if path in ("", "/"):
            path = "/splash.html"
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


def maybe_autostart_telemetry() -> dict[str, Any]:
    """Start Loki/Prometheus in the background when first-run setup is done.

    Monitoring Metrics/Activities proxy Loki+Prometheus. After reboot or app
    restart those processes are gone unless we bring them back on launch.
    """
    settings = load_settings()
    if not settings.get("setup_complete"):
        return {"started": False, "reason": "setup_incomplete"}
    try:
        out = STATE.start_telemetry_job(force=False)
        logger.info(
            "Autostart monitoring: started=%s job=%s",
            out.get("started"),
            (out.get("job") or {}).get("state"),
        )
        return out
    except Exception as e:  # noqa: BLE001
        logger.warning("Telemetry autostart failed: %s", e)
        return {"started": False, "reason": str(e)}


def serve(
    host: str = CONTROL_HOST,
    port: int = WIZARD_PORT,
    *,
    open_browser: bool = True,
    autostart_telemetry: bool | None = None,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), WizardHandler)
    url = f"http://{host}:{port}/splash.html"
    logger.info("IoT Gateway Monitor UI at %s", url)
    if open_browser:
        threading.Timer(0.5, lambda: open_in_browser(url)).start()
    do_auto = autostart_telemetry
    if do_auto is None:
        do_auto = bool(load_settings().get("setup_complete"))
    if do_auto:
        # Background job — do not block the UI thread on Loki ready.
        threading.Thread(
            target=maybe_autostart_telemetry,
            name="iotgw-telemetry-autostart",
            daemon=True,
        ).start()
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
