"""Fake sensor publish loop (MQTTS :8883 + Fernet or envelope v1)."""

from __future__ import annotations

import json
import logging
import os
import ssl
import time
from pathlib import Path
from typing import Any

from iot_gateway_agent.day_crypto import load_day_public_key
from iot_gateway_agent.encrypt import corrupt_wrapper_payload, encrypt_wrapper_payload
from iot_gateway_agent.envelope_v1 import (
    DeviceSecrets,
    corrupt_stamp,
    data_topic,
    key_topic,
    seal,
    today_day_id,
)

logger = logging.getLogger(__name__)

DEFAULT_BEHAVIORS = {
    "omit_client_cert": False,
    "wrong_client_cert": False,
    "skip_encryption": False,
    "bad_encryption": False,
    "wrong_password": False,
    "wrong_topic": False,
    # Envelope v1 lab attacks
    "key_only": False,
    "data_only": False,
    "stamp_mismatch_key": False,
    "stamp_mismatch_data": False,
    "swapped_msg_id": False,
    "wrong_day_id": False,
    "missing_day_material": False,
    "schema_missing_field": False,
    "schema_wrong_type": False,
    "schema_extra_field": False,
    "wrong_schema_id": False,
    "legacy_fernet_wrapper": False,
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
    cfg.setdefault("crypto_mode", "envelope")  # envelope | fernet
    cfg.setdefault("schema_id", "default")
    return cfg


def load_payload(data_dir: str, device_id: str) -> Any:
    path = device_dir(data_dir, device_id) / "payload.json"
    if not path.is_file():
        return {"device_id": device_id, "hello": 1}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_device_secrets_file(data_dir: str, device_id: str) -> DeviceSecrets | None:
    # Prefer gateway crypto store (shared data_dir); fall back to fake-local copy.
    for path in (
        Path(data_dir) / "crypto" / "devices" / f"{device_id}.json",
        device_dir(data_dir, device_id) / "crypto.json",
    ):
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return DeviceSecrets.from_json_dict(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("crypto load failed %s: %s", path, exc)
    return None


def _mutate_payload_for_schema_attack(payload: Any, behaviors: dict[str, bool]) -> Any:
    if not isinstance(payload, dict):
        return payload
    out = dict(payload)
    if behaviors.get("schema_missing_field"):
        out.pop("hello", None)
        out.pop("temp_c", None)
        out.pop("ts_ms", None)
    if behaviors.get("schema_wrong_type") and "hello" in out:
        out["hello"] = "not-an-int"
    elif behaviors.get("schema_wrong_type") and "temp_c" in out:
        out["temp_c"] = "warm"
    if behaviors.get("schema_extra_field"):
        out["__extra_attack"] = 1
    return out


def _build_fernet_message(payload: Any, behaviors: dict[str, bool]) -> str:
    if behaviors.get("skip_encryption"):
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, ensure_ascii=False)
    if behaviors.get("bad_encryption"):
        return corrupt_wrapper_payload(payload)
    return encrypt_wrapper_payload(payload)


def _build_envelope_pubs(
    payload: Any,
    behaviors: dict[str, bool],
    *,
    secrets: DeviceSecrets,
    data_dir: str,
) -> list[tuple[str, str]]:
    """Return list of (topic, body) publications for envelope mode."""
    device_id = secrets.device_id
    if behaviors.get("legacy_fernet_wrapper"):
        return [(f"sensors/{device_id}/process", encrypt_wrapper_payload(payload))]
    if behaviors.get("skip_encryption"):
        body = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
        return [(f"sensors/{device_id}/process", body)]

    payload = _mutate_payload_for_schema_attack(payload, behaviors)
    day_id = today_day_id()
    if behaviors.get("wrong_day_id"):
        day_id = "19990101"

    day_pub = None
    if secrets.profile == "v1-ecdhe":
        if behaviors.get("missing_day_material"):
            raise RuntimeError("missing_day_material")
        day_pub = load_day_public_key(data_dir, day_id)
        if day_pub is None and not behaviors.get("wrong_day_id"):
            # Try today explicitly
            day_pub = load_day_public_key(data_dir, today_day_id())
        if day_pub is None:
            raise RuntimeError("day public key unavailable")

    seal_secrets = secrets
    if behaviors.get("wrong_schema_id"):
        seal_secrets = DeviceSecrets(
            device_id=secrets.device_id,
            profile=secrets.profile,
            mac_key=secrets.mac_key,
            schema_id="__wrong_schema__",
            wrap_secret=secrets.wrap_secret,
        )

    sealed = seal(payload, seal_secrets, day_id=day_id, day_public_key=day_pub)
    key_part = dict(sealed.key_part)
    data_part = dict(sealed.data_part)

    if behaviors.get("bad_encryption") or behaviors.get("stamp_mismatch_data"):
        data_part = corrupt_stamp(data_part)
    if behaviors.get("stamp_mismatch_key"):
        key_part = corrupt_stamp(key_part)
    if behaviors.get("swapped_msg_id"):
        data_part = dict(data_part)
        data_part["msg_id"] = "AAAAAAAAAAAAAAAAAAAAAA"

    pubs: list[tuple[str, str]] = []
    if not behaviors.get("data_only"):
        pubs.append((key_topic(device_id), json.dumps(key_part, separators=(",", ":"))))
    if not behaviors.get("key_only"):
        pubs.append((data_topic(device_id), json.dumps(data_part, separators=(",", ":"))))
    return pubs


def _ssl_context(
    certs_dir: Path,
    *,
    omit_client_cert: bool,
    wrong_client_cert: bool,
) -> ssl.SSLContext | None:
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
    crypto_mode = str(cfg.get("crypto_mode") or "envelope").lower()

    client_id = f"iotgw-fake-{device_id}"
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            protocol=mqtt.MQTTv311,
        )
    except (AttributeError, TypeError):
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
            try:
                cfg = load_config(data_dir, device_id)
                behaviors = cfg["behaviors"]
                topic = _resolve_topic(cfg)
                interval_ms = max(100, int(cfg.get("send_interval_ms") or 1000))
                crypto_mode = str(cfg.get("crypto_mode") or "envelope").lower()
                payload = load_payload(data_dir, device_id)
            except Exception as exc:
                log.warning("reload failed: %s", exc)
                payload = {"device_id": device_id, "error": "reload_failed"}

            try:
                use_envelope = crypto_mode == "envelope" and not behaviors.get(
                    "legacy_fernet_wrapper"
                )
                # Force fernet path when explicitly requested or no secrets yet.
                secrets = load_device_secrets_file(data_dir, device_id)
                if use_envelope and secrets is None:
                    log.warning("no device crypto; falling back to Fernet wrapper")
                    use_envelope = False

                if use_envelope and secrets is not None:
                    pubs = _build_envelope_pubs(
                        payload,
                        behaviors,
                        secrets=secrets,
                        data_dir=data_dir,
                    )
                else:
                    body = _build_fernet_message(payload, behaviors)
                    pubs = [(topic, body)]

                for pub_topic, body in pubs:
                    info = client.publish(pub_topic, body, qos=0)
                    if info.rc != 0:
                        log.warning("publish rc=%s topic=%s", info.rc, pub_topic)
                    else:
                        log.info("published %d bytes to %s", len(body), pub_topic)
            except Exception as exc:
                log.warning("seal/publish failed: %s", exc)

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
