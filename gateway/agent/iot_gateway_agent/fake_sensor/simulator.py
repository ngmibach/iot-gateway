"""Fake sensor publish loop (MQTTS :8883 + optional Fernet wrapper)."""

from __future__ import annotations

import json
import logging
import os
import ssl
import time
from pathlib import Path
from typing import Any

from iot_gateway_agent.encrypt import corrupt_wrapper_payload, encrypt_wrapper_payload

logger = logging.getLogger(__name__)

DEFAULT_BEHAVIORS = {
    "omit_client_cert": False,
    "wrong_client_cert": False,
    "skip_encryption": False,
    "bad_encryption": False,
    "wrong_password": False,
    "wrong_topic": False,
}


def device_dir(data_dir: str, device_id: str) -> Path:
    return Path(data_dir) / "fake" / device_id


def load_config(data_dir: str, device_id: str) -> dict[str, Any]:
    path = device_dir(data_dir, device_id) / "config.json"
    with path.open("r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not isinstance(cfg, dict):
        raise ValueError(f"invalid config.json for {device_id}")
    behaviors = cfg.get("behaviors") if isinstance(cfg.get("behaviors"), dict) else {}
    merged = dict(DEFAULT_BEHAVIORS)
    for key in DEFAULT_BEHAVIORS:
        if key in behaviors:
            merged[key] = bool(behaviors[key])
    cfg["behaviors"] = merged
    cfg.setdefault("device_id", device_id)
    cfg.setdefault("broker_host", "10.255.0.1")
    cfg.setdefault("broker_port", 8883)
    cfg.setdefault("mqtt_user", device_id)
    cfg.setdefault("topic", f"sensors/{device_id}/process")
    cfg.setdefault("send_interval_ms", 1000)
    return cfg


def load_payload(data_dir: str, device_id: str) -> Any:
    path = device_dir(data_dir, device_id) / "payload.json"
    if not path.is_file():
        return {"device_id": device_id, "hello": 1}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _build_message(payload: Any, behaviors: dict[str, bool]) -> str:
    if behaviors.get("skip_encryption"):
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, ensure_ascii=False)
    if behaviors.get("bad_encryption"):
        return corrupt_wrapper_payload(payload)
    return encrypt_wrapper_payload(payload)


def _ssl_context(
    certs_dir: Path,
    *,
    omit_client_cert: bool,
    wrong_client_cert: bool,
) -> ssl.SSLContext | None:
    """Build client TLS context. Returns None when omitting client cert entirely
    is requested without a CA (broker will reject — intentional attack mode).
    """
    ca = certs_dir / "ca.crt"
    crt = certs_dir / "client.crt"
    key = certs_dir / "client.key"
    wrong_dir = certs_dir.parent / "wrong-certs"

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if ca.is_file():
        ctx.load_verify_locations(cafile=str(ca))
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if omit_client_cert:
        return ctx

    if wrong_client_cert:
        w_crt = wrong_dir / "client.crt"
        w_key = wrong_dir / "client.key"
        if w_crt.is_file() and w_key.is_file():
            ctx.load_cert_chain(certfile=str(w_crt), keyfile=str(w_key))
            return ctx
        # No planted wrong certs — still attempt without a client cert so the
        # broker rejects (same observable as omit for lab toggles).
        return ctx

    if crt.is_file() and key.is_file():
        ctx.load_cert_chain(certfile=str(crt), keyfile=str(key))
    return ctx


def _resolve_topic(cfg: dict[str, Any]) -> str:
    behaviors = cfg.get("behaviors") or {}
    topic = str(cfg.get("topic") or f"sensors/{cfg.get('device_id')}/process")
    if behaviors.get("wrong_topic"):
        return f"sensors/__denied__/{cfg.get('device_id')}/process"
    return topic


def _resolve_password(cfg: dict[str, Any]) -> str:
    behaviors = cfg.get("behaviors") or {}
    password = str(cfg.get("mqtt_password") or "")
    if behaviors.get("wrong_password"):
        return password + "__wrong__" if password else "__wrong__"
    return password


def run_simulator(
    *,
    device_id: str,
    data_dir: str = "/var/lib/iot-gateway-agent",
    once: bool = False,
) -> int:
    """Connect over MQTTS and publish on an interval. Returns process exit code."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s fake_sensor[%(device_id)s]: %(message)s",
    )
    # Bind device_id into log records via LoggerAdapter
    log = logging.LoggerAdapter(logger, {"device_id": device_id})

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log.error("paho-mqtt is required")
        return 2

    base = device_dir(data_dir, device_id)
    if not base.is_dir():
        log.error("device dir missing: %s", base)
        return 1

    cfg = load_config(data_dir, device_id)
    behaviors = cfg["behaviors"]
    host = str(cfg["broker_host"])
    port = int(cfg["broker_port"])
    user = str(cfg.get("mqtt_user") or device_id)
    password = _resolve_password(cfg)
    topic = _resolve_topic(cfg)
    interval_ms = max(100, int(cfg.get("send_interval_ms") or 1000))
    certs_dir = base / "certs"

    client_id = f"iotgw-fake-{device_id}"
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=mqtt.MQTTv311,
        )
    except (AttributeError, TypeError):
        # paho-mqtt 1.x
        client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)

    client.username_pw_set(user, password)
    tls_ctx = _ssl_context(
        certs_dir,
        omit_client_cert=bool(behaviors.get("omit_client_cert")),
        wrong_client_cert=bool(behaviors.get("wrong_client_cert")),
    )
    if tls_ctx is not None:
        client.tls_set_context(tls_ctx)

    connected = {"ok": False}

    def on_connect(client, userdata, flags, reason_code, properties=None):  # noqa: ANN001
        # paho v2 passes reason_code; v1 passes rc as int.
        rc = getattr(reason_code, "value", reason_code)
        connected["ok"] = rc == 0
        if rc != 0:
            log.warning("MQTT connect failed rc=%s", rc)
        else:
            log.info("connected to %s:%s as %s", host, port, user)

    client.on_connect = on_connect

    try:
        client.connect(host, port, keepalive=60)
    except Exception as exc:
        log.error("connect error: %s", exc)
        return 1

    client.loop_start()
    deadline = time.time() + 15.0
    while time.time() < deadline and not connected["ok"]:
        time.sleep(0.1)
    if not connected["ok"]:
        log.error("MQTT connect timed out")
        client.loop_stop()
        return 1

    try:
        while True:
            # Reload config/payload each cycle so feed-cert + Simulate Apply
            # take effect after unit restart; mid-cycle file edits need restart
            # for TLS material, but interval/topic/behaviors refresh here too.
            try:
                cfg = load_config(data_dir, device_id)
                behaviors = cfg["behaviors"]
                topic = _resolve_topic(cfg)
                interval_ms = max(100, int(cfg.get("send_interval_ms") or 1000))
                payload = load_payload(data_dir, device_id)
            except Exception as exc:
                log.warning("reload failed: %s", exc)
                payload = {"device_id": device_id, "error": "reload_failed"}

            body = _build_message(payload, behaviors)
            info = client.publish(topic, body, qos=0)
            if info.rc != 0:
                log.warning("publish rc=%s topic=%s", info.rc, topic)
            else:
                log.info("published %d bytes to %s", len(body), topic)

            if once:
                break
            time.sleep(interval_ms / 1000.0)
    finally:
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass
    return 0
