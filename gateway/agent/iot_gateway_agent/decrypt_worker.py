"""MQTT subscribe → decrypt → append sensor_data.log → optional Kafka produce."""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

from .decrypt import decrypt_wrapper_payload
from .kafka_store import kafka_topic_name

if TYPE_CHECKING:
    from .kafka_producer import SensorKafkaProducer

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


@dataclass
class DeviceCounters:
    messages_ok: int = 0
    messages_fail: int = 0
    denied: int = 0
    ids: int = 0
    delay_ms_sum: float = 0.0
    delay_ms_count: int = 0
    last_delay_ms: Optional[float] = None

    def observe_delay(self, delay_ms: float) -> None:
        self.last_delay_ms = delay_ms
        self.delay_ms_sum += delay_ms
        self.delay_ms_count += 1

    @property
    def avg_delay_ms(self) -> Optional[float]:
        if self.delay_ms_count <= 0:
            return None
        return self.delay_ms_sum / self.delay_ms_count


def device_id_from_mqtt_topic(topic: str) -> str:
    """Extract device id from ``sensors/<device_id>/…`` (else first path segment)."""
    parts = [p for p in (topic or "").split("/") if p]
    if not parts:
        return "unknown"
    if parts[0] == "sensors" and len(parts) >= 2:
        return parts[1]
    return parts[0]


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
            return float(obj["delay"])
        except (TypeError, ValueError):
            pass
    for key in ("ts_ms", "timestamp_ms", "sent_ms"):
        if key in obj:
            try:
                return max(0.0, float(received_ms) - float(obj[key]))
            except (TypeError, ValueError):
                pass
    for key in ("ts", "timestamp", "sent_at"):
        if key not in obj:
            continue
        raw = obj[key]
        try:
            ts = float(raw)
        except (TypeError, ValueError):
            continue
        # Seconds vs milliseconds heuristic.
        if ts > 1e12:
            return max(0.0, float(received_ms) - ts)
        if ts > 1e9:
            return max(0.0, float(received_ms) - ts * 1000.0)
    return None


def _tls_version() -> int:
    """Prefer TLS 1.2+ (PROTOCOL_TLS_CLIENT negotiates the highest available)."""
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
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.messages_ok = 0
        self.messages_fail = 0
        self._by_device: dict[str, DeviceCounters] = defaultdict(DeviceCounters)
        self._lock = threading.Lock()

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_ca and self.tls_cert and self.tls_key)

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def device_snapshot(self) -> dict[str, DeviceCounters]:
        with self._lock:
            return {k: DeviceCounters(
                messages_ok=v.messages_ok,
                messages_fail=v.messages_fail,
                denied=v.denied,
                ids=v.ids,
                delay_ms_sum=v.delay_ms_sum,
                delay_ms_count=v.delay_ms_count,
                last_delay_ms=v.last_delay_ms,
            ) for k, v in self._by_device.items()}

    def bump_denied(self, device_id: str, *, n: int = 1) -> None:
        did = (device_id or "unknown").strip() or "unknown"
        with self._lock:
            self._by_device[did].denied += n

    def bump_ids(self, device_id: str, *, n: int = 1) -> None:
        did = (device_id or "unknown").strip() or "unknown"
        with self._lock:
            self._by_device[did].ids += n

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="decrypt-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def _handle_message(self, topic: str, payload: bytes) -> None:
        device_id = device_id_from_mqtt_topic(topic)
        received_ms = int(time.time() * 1000)
        clear = decrypt_wrapper_payload(payload)
        if clear is None:
            self.messages_fail += 1
            with self._lock:
                self._by_device[device_id].messages_fail += 1
            return
        line = f"{received_ms}: {clear}\n"
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line)
            self.messages_ok += 1
            delay = _delay_ms_from_payload(clear, received_ms=received_ms)
            with self._lock:
                ctr = self._by_device[device_id]
                ctr.messages_ok += 1
                if delay is not None:
                    ctr.observe_delay(delay)
        except OSError as e:
            logger.warning("sensor_data.log write failed: %s", e)
            self.messages_fail += 1
            with self._lock:
                self._by_device[device_id].messages_fail += 1
            return

        if self.kafka is not None:
            self.kafka.produce(kafka_topic_name(device_id), clear)

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
            client.tls_set(
                ca_certs=str(self.tls_ca),
                certfile=str(self.tls_cert),
                keyfile=str(self.tls_key),
                tls_version=_tls_version(),
            )
            logger.info(
                "decrypt worker TLS enabled ca=%s cert=%s",
                self.tls_ca,
                self.tls_cert,
            )
        client.on_message = on_message

        while not self._stop.is_set():
            try:
                client.connect(self.host, self.port, keepalive=30)
                client.subscribe(self.topic)
                logger.info(
                    "decrypt worker subscribed %s:%s topic=%s → %s",
                    self.host,
                    self.port,
                    self.topic,
                    self.log_path,
                )
                while not self._stop.is_set():
                    client.loop(timeout=1.0)
                client.disconnect()
                break
            except Exception as e:  # noqa: BLE001
                logger.warning("decrypt worker reconnecting: %s", e)
                time.sleep(2.0)
