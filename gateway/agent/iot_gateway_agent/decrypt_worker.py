"""MQTT subscribe → decrypt (legacy Fernet or envelope v1) → log → Kafka."""

from __future__ import annotations

import json
import logging
import os
import ssl
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

from .day_crypto import ensure_day_material, resolve_day_private_key
from .decrypt import decrypt_wrapper_payload
from .device_crypto import load_device_secrets, validate_cleartext
from .envelope_v1 import (
    EnvelopeError,
    allowed_day_ids_for,
    open_envelope,
    parse_envelope_topic,
    today_day_id,
)

# reason attribute is set on Envelope* subclasses
from .kafka_store import kafka_topic_name
from .schema_validate import SchemaError

if TYPE_CHECKING:
    from .deny_log import DenyLog
    from .kafka_producer import SensorKafkaProducer

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class DeviceCounters:
    messages_ok: int = 0
    messages_fail: int = 0
    denied: int = 0
    ids: int = 0
    delay_ms_sum: float = 0.0
    delay_ms_count: int = 0
    last_delay_ms: Optional[float] = None
    deny_reasons: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def observe_delay(self, delay_ms: float) -> None:
        self.last_delay_ms = delay_ms
        self.delay_ms_sum += delay_ms
        self.delay_ms_count += 1

    @property
    def avg_delay_ms(self) -> Optional[float]:
        if self.delay_ms_count <= 0:
            return None
        return self.delay_ms_sum / self.delay_ms_count


@dataclass
class _PendingHalf:
    kind: str  # key | data
    part: dict[str, Any]
    received_ms: int


def device_id_from_mqtt_topic(topic: str) -> str:
    """Extract device id from ``sensors/<device_id>/…`` (else first path segment)."""
    parts = [p for p in (topic or "").split("/") if p]
    if not parts:
        return "unknown"
    if parts[0] == "sensors" and len(parts) >= 2:
        return parts[1]
    return parts[0]


# Reject absurd delays (e.g. ts_ms=0 → epoch-sized "delay" like 1.7e12 ms).
_MAX_DELAY_MS = 24 * 60 * 60 * 1000.0  # 24h


def _delay_ms_from_payload(clear_json: str, *, received_ms: int) -> Optional[float]:
    """Prefer explicit delay; else derive from sensor timestamp fields."""
    try:
        obj = json.loads(clear_json)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    if "delay" in obj:
        try:
            delay = float(obj["delay"])
        except (TypeError, ValueError):
            delay = None
        else:
            if 0.0 <= delay <= _MAX_DELAY_MS:
                return delay
    for key in ("ts_ms", "timestamp_ms", "sent_ms"):
        if key not in obj:
            continue
        try:
            ts = float(obj[key])
        except (TypeError, ValueError):
            continue
        # Missing/zero timestamps produce wall-clock epoch delays — ignore them.
        if ts <= 0:
            continue
        delay = float(received_ms) - ts
        if 0.0 <= delay <= _MAX_DELAY_MS:
            return delay
    for key in ("ts", "timestamp", "sent_at"):
        if key not in obj:
            continue
        raw = obj[key]
        try:
            ts = float(raw)
        except (TypeError, ValueError):
            continue
        if ts <= 0:
            continue
        if ts > 1e12:
            delay = float(received_ms) - ts
        elif ts > 1e9:
            delay = float(received_ms) - ts * 1000.0
        else:
            continue
        if 0.0 <= delay <= _MAX_DELAY_MS:
            return delay
    return None


def _tls_version() -> int:
    if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
        return int(ssl.PROTOCOL_TLS_CLIENT)
    if hasattr(ssl, "PROTOCOL_TLSv1_2"):
        return int(ssl.PROTOCOL_TLSv1_2)
    return int(ssl.PROTOCOL_TLS)


class DecryptWorker:
    """Background MQTT client that writes cleartext sensor lines to a log file."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 1883,
        topic: str = "sensors/#",
        username: str = "nodered",
        password: str = "",
        log_path: Path,
        kafka: Optional["SensorKafkaProducer"] = None,
        tls_ca: PathLike | None = None,
        tls_cert: PathLike | None = None,
        tls_key: PathLike | None = None,
        data_dir: PathLike | None = None,
        envelope_enabled: bool | None = None,
        envelope_require: bool | None = None,
        pair_timeout_s: float = 5.0,
        replay_cache_size: int = 4096,
        deny_log: "DenyLog | None" = None,
        gateway_id: str = "",
    ):
        self.host = host
        self.port = port
        self.topic = topic
        self.username = username
        self.password = password
        self.log_path = Path(log_path)
        self.kafka = kafka
        self.tls_ca = Path(tls_ca) if tls_ca else None
        self.tls_cert = Path(tls_cert) if tls_cert else None
        self.tls_key = Path(tls_key) if tls_key else None
        self.data_dir = Path(data_dir) if data_dir else self.log_path.parent.parent
        self.deny_log = deny_log
        self.gateway_id = (gateway_id or "").strip()
        self.envelope_enabled = (
            _env_flag("IOTGW_ENVELOPE_V1", True)
            if envelope_enabled is None
            else envelope_enabled
        )
        self.envelope_require = (
            _env_flag("IOTGW_ENVELOPE_REQUIRE", False)
            if envelope_require is None
            else envelope_require
        )
        self.pair_timeout_s = float(
            os.environ.get("IOTGW_ENVELOPE_PAIR_TIMEOUT", pair_timeout_s)
        )
        self.replay_cache_size = int(
            os.environ.get("IOTGW_ENVELOPE_REPLAY_CACHE", replay_cache_size)
        )
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._janitor: Optional[threading.Thread] = None
        self.messages_ok = 0
        self.messages_fail = 0
        self.envelope_ok = 0
        self.envelope_fail = 0
        self.legacy_ok = 0
        self._by_device: dict[str, DeviceCounters] = defaultdict(DeviceCounters)
        self._lock = threading.Lock()
        self._pending: dict[str, _PendingHalf] = {}
        self._replay: dict[str, float] = {}
        self._day_key_cache: dict = {}

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_ca and self.tls_cert and self.tls_key)

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def device_snapshot(self) -> dict[str, DeviceCounters]:
        with self._lock:
            return {
                k: DeviceCounters(
                    messages_ok=v.messages_ok,
                    messages_fail=v.messages_fail,
                    denied=v.denied,
                    ids=v.ids,
                    delay_ms_sum=v.delay_ms_sum,
                    delay_ms_count=v.delay_ms_count,
                    last_delay_ms=v.last_delay_ms,
                    deny_reasons=dict(v.deny_reasons),
                )
                for k, v in self._by_device.items()
            }

    def bump_denied(
        self,
        device_id: str,
        *,
        n: int = 1,
        reason: str = "acl_deny",
        source_ip: str = "",
        detail: str = "",
        count_as_message: bool = False,
    ) -> None:
        did = (device_id or "unknown").strip() or "unknown"
        with self._lock:
            ctr = self._by_device[did]
            ctr.denied += n
            if count_as_message:
                self.messages_fail += n
                ctr.messages_fail += n
            if reason:
                ctr.deny_reasons[reason] = ctr.deny_reasons.get(reason, 0) + n
        if self.deny_log is not None:
            for _ in range(max(1, int(n))):
                self.deny_log.record(
                    reason=reason or "acl_deny",
                    device_id=did,
                    source_ip=source_ip,
                    gateway_id=self.gateway_id,
                    detail=detail,
                )

    def bump_ids(self, device_id: str, *, n: int = 1) -> None:
        did = (device_id or "unknown").strip() or "unknown"
        with self._lock:
            self._by_device[did].ids += n

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            ensure_day_material(self.data_dir)
        except Exception as exc:  # noqa: BLE001
            logger.warning("day material ensure failed: %s", exc)
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="decrypt-worker", daemon=True
        )
        self._thread.start()
        self._janitor = threading.Thread(
            target=self._janitor_loop, name="decrypt-pair-janitor", daemon=True
        )
        self._janitor.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._janitor:
            self._janitor.join(timeout=2)
        self._thread = None
        self._janitor = None

    def _fail(
        self,
        device_id: str,
        reason: str,
        *,
        detail: str = "",
        envelope: bool = True,
    ) -> None:
        self.messages_fail += 1
        if envelope:
            self.envelope_fail += 1
        with self._lock:
            ctr = self._by_device[device_id]
            ctr.messages_fail += 1
            ctr.denied += 1
            ctr.deny_reasons[reason] = ctr.deny_reasons.get(reason, 0) + 1
        if self.deny_log is not None:
            self.deny_log.record(
                reason=reason or "decrypt",
                device_id=device_id,
                gateway_id=self.gateway_id,
                detail=detail,
            )
        logger.warning("decrypt deny device=%s reason=%s", device_id, reason)

    def _accept_clear(
        self,
        device_id: str,
        clear: str,
        *,
        received_ms: int,
        path: str,
        process_t0: float | None = None,
    ) -> None:
        """Accept cleartext, optional Kafka produce, and record processing delay.

        ``process_t0`` is ``time.perf_counter()`` at the start of decrypt/unwrap
        when available. Delay includes Kafka handoff only when produce succeeds
        so a down broker (``max_block_ms``) does not inflate the gauge.
        """
        t0 = float(process_t0) if process_t0 is not None else time.perf_counter()
        line = f"{received_ms}: {clear}\n"
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line)
            self.messages_ok += 1
            if path == "envelope":
                self.envelope_ok += 1
            else:
                self.legacy_ok += 1
            with self._lock:
                self._by_device[device_id].messages_ok += 1
        except OSError as e:
            logger.warning("sensor_data.log write failed: %s", e)
            self.messages_fail += 1
            with self._lock:
                self._by_device[device_id].messages_fail += 1
            return

        t_pre_kafka = time.perf_counter()
        kafka_ok = True
        if self.kafka is not None:
            kafka_ok = bool(self.kafka.produce(kafka_topic_name(device_id), clear))
        t_done = time.perf_counter() if kafka_ok else t_pre_kafka
        proc_delay = (t_done - t0) * 1000.0
        if 0.0 <= proc_delay <= _MAX_DELAY_MS:
            with self._lock:
                self._by_device[device_id].observe_delay(proc_delay)

    def _replay_seen(self, device_id: str, msg_id: str) -> bool:
        if self.replay_cache_size <= 0:
            return False
        key = f"{device_id}:{msg_id}"
        now = time.time()
        with self._lock:
            if key in self._replay:
                return True
            self._replay[key] = now
            if len(self._replay) > self.replay_cache_size:
                # Drop oldest ~12.5%.
                items = sorted(self._replay.items(), key=lambda kv: kv[1])
                for k, _ in items[: max(1, len(items) // 8)]:
                    self._replay.pop(k, None)
        return False

    def _complete_envelope(
        self,
        device_id: str,
        key_part: dict[str, Any],
        data_part: dict[str, Any],
        *,
        received_ms: int,
    ) -> None:
        process_t0 = time.perf_counter()
        msg_id = str(key_part.get("msg_id") or "")
        if msg_id and self._replay_seen(device_id, msg_id):
            self._fail(device_id, "replay")
            return

        secrets = load_device_secrets(self.data_dir, device_id)
        if secrets is None:
            self._fail(device_id, "no_device_crypto")
            return

        day_id = str(key_part.get("day_id") or today_day_id())
        day_priv = None
        if secrets.profile == "v1-ecdhe":
            day_priv = resolve_day_private_key(
                self.data_dir, day_id, cache=self._day_key_cache
            )
            if day_priv is None:
                # Try ensuring today's material then reload.
                try:
                    ensure_day_material(self.data_dir, day_id=day_id)
                except Exception:  # noqa: BLE001
                    pass
                day_priv = resolve_day_private_key(
                    self.data_dir, day_id, cache=self._day_key_cache
                )
            if day_priv is None:
                self._fail(device_id, "day")
                return

        try:
            plain = open_envelope(
                key_part,
                data_part,
                secrets,
                day_private_key=day_priv,
                allowed_day_ids=allowed_day_ids_for(),
            )
        except EnvelopeError as exc:
            self._fail(device_id, getattr(exc, "reason", "envelope"))
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("envelope open error: %s", exc)
            self._fail(device_id, "unwrap")
            return

        try:
            text = plain.decode("utf-8")
        except UnicodeDecodeError:
            self._fail(device_id, "encoding")
            return

        schema_id = str(key_part.get("schema_id") or secrets.schema_id)
        try:
            validate_cleartext(
                self.data_dir,
                device_id=device_id,
                schema_id=schema_id,
                clear_json=text,
                require_schema_file=schema_id != "default",
            )
        except SchemaError as exc:
            self._fail(
                device_id,
                getattr(exc, "reason", "schema"),
                detail=str(exc)[:200],
            )
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("schema validate error: %s", exc)
            self._fail(device_id, "schema", detail=str(exc)[:200])
            return

        self._accept_clear(
            device_id,
            text,
            received_ms=received_ms,
            path="envelope",
            process_t0=process_t0,
        )

    def _handle_envelope_half(
        self, device_id: str, kind: str, payload: bytes, *, received_ms: int
    ) -> None:
        if not self.envelope_enabled:
            self._fail(device_id, "envelope_disabled")
            return
        try:
            part = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._fail(device_id, "format")
            return
        if not isinstance(part, dict):
            self._fail(device_id, "format")
            return
        msg_id = str(part.get("msg_id") or "")
        if not msg_id:
            self._fail(device_id, "format")
            return

        pending_key = f"{device_id}:{msg_id}"
        with self._lock:
            other = self._pending.pop(pending_key, None)
            if other is None:
                self._pending[pending_key] = _PendingHalf(
                    kind=kind, part=part, received_ms=received_ms
                )
                return
            if other.kind == kind:
                # Duplicate half — replace and wait.
                self._pending[pending_key] = _PendingHalf(
                    kind=kind, part=part, received_ms=received_ms
                )
                return

        if kind == "key":
            key_part, data_part = part, other.part
        else:
            key_part, data_part = other.part, part
        self._complete_envelope(
            device_id, key_part, data_part, received_ms=received_ms
        )

    def _handle_legacy(self, device_id: str, payload: bytes, *, received_ms: int) -> None:
        if self.envelope_require:
            self._fail(device_id, "legacy")
            return
        process_t0 = time.perf_counter()
        clear = decrypt_wrapper_payload(payload)
        if clear is None:
            self._fail(device_id, "fernet", envelope=False)
            return
        self._accept_clear(
            device_id,
            clear,
            received_ms=received_ms,
            path="legacy",
            process_t0=process_t0,
        )

    def _handle_message(self, topic: str, payload: bytes) -> None:
        device_id = device_id_from_mqtt_topic(topic)
        received_ms = int(time.time() * 1000)
        parsed = parse_envelope_topic(topic)
        if parsed is not None:
            _did, kind = parsed
            self._handle_envelope_half(
                _did, kind, payload, received_ms=received_ms
            )
            return
        self._handle_legacy(device_id, payload, received_ms=received_ms)

    def _janitor_loop(self) -> None:
        while not self._stop.wait(0.5):
            now_ms = int(time.time() * 1000)
            timeout_ms = int(self.pair_timeout_s * 1000)
            expired: list[tuple[str, str]] = []
            with self._lock:
                for key, half in list(self._pending.items()):
                    if now_ms - half.received_ms >= timeout_ms:
                        expired.append((key, half.kind))
                        self._pending.pop(key, None)
            for key, kind in expired:
                device_id = key.split(":", 1)[0]
                reason = "key_only" if kind == "key" else "data_only"
                self._fail(device_id, reason)

    def _run(self) -> None:
        try:
            import paho.mqtt.client as mqtt
        except ImportError:
            logger.error("paho-mqtt not installed — decrypt worker idle")
            return

        def on_message(_client: Any, _userdata: Any, msg: Any) -> None:
            try:
                self._handle_message(str(msg.topic or ""), msg.payload)
            except Exception as exc:  # noqa: BLE001
                logger.warning("decrypt on_message error: %s", exc)
                self.messages_fail += 1

        try:
            client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2, client_id="iotgw-decrypt"
            )
        except AttributeError:
            client = mqtt.Client(client_id="iotgw-decrypt")
        if self.username:
            client.username_pw_set(self.username, self.password or None)
        if self.tls_enabled:
            assert self.tls_ca and self.tls_cert and self.tls_key
            # Broker cert SAN is the gateway LAN IP; decrypt connects to
            # 127.0.0.1 so hostname verification would fail. Match fake-sensor
            # client: verify the CA chain, skip hostname match for IP connect.
            ctx = ssl.SSLContext(_tls_version())
            strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
            if strict:
                ctx.verify_flags &= ~strict
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = False
            ctx.load_verify_locations(cafile=str(self.tls_ca))
            ctx.load_cert_chain(certfile=str(self.tls_cert), keyfile=str(self.tls_key))
            client.tls_set_context(ctx)
            logger.info(
                "decrypt worker TLS enabled ca=%s cert=%s (hostname check off)",
                self.tls_ca,
                self.tls_cert,
            )
        client.on_message = on_message

        while not self._stop.is_set():
            try:
                client.connect(self.host, self.port, keepalive=30)
                client.subscribe(self.topic)
                logger.info(
                    "decrypt worker subscribed %s:%s topic=%s → %s envelope=%s require=%s",
                    self.host,
                    self.port,
                    self.topic,
                    self.log_path,
                    self.envelope_enabled,
                    self.envelope_require,
                )
                while not self._stop.is_set():
                    client.loop(timeout=1.0)
                client.disconnect()
                break
            except Exception as e:  # noqa: BLE001
                logger.warning("decrypt worker reconnecting: %s", e)
                time.sleep(2.0)
