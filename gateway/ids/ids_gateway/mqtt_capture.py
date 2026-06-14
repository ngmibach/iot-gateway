from __future__ import annotations

from collections import defaultdict
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import paho.mqtt.client as mqtt  # type: ignore
except Exception:
    mqtt = None  # type: ignore

from .capture import PacketRecord

_MQTT_FALLBACK_PORTS = {1883, 18883, 8883}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_iso_ts(value: Any) -> Optional[float]:
    if not value:
        return None
    try:
        s = str(value).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


class MQTTCapture:
    def __init__(
        self,
        broker: str = "localhost",
        port: int = 1883,
        topic: str = "ids/packets/#",
        client_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_mac: bool = False,
    ) -> None:
        if mqtt is None:
            raise RuntimeError(
                "paho-mqtt not installed. Install with 'pip install paho-mqtt'"
            )
        self.broker = broker
        self.port = int(port)
        self.topic = topic
        self.client_id = client_id
        self.use_mac = use_mac
        self.buffer: Dict[str, List[PacketRecord]] = defaultdict(list)
        client_kwargs: dict = {"client_id": client_id}
        callback_api_version = getattr(mqtt, "CallbackAPIVersion", None)
        if callback_api_version is not None:
            client_kwargs["callback_api_version"] = callback_api_version.VERSION2
        self._client = mqtt.Client(**client_kwargs)
        if username:
            self._client.username_pw_set(username=username, password=password)
        self._client.on_message = self._on_message
        self._client.on_connect = self._on_connect
        self._connected = False
        self._client.connect(self.broker, self.port)
        self._client.loop_start()
        time.sleep(0.5)

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        self._connected = True
        client.subscribe(self.topic)

    @staticmethod
    def _device_id_from_topic(topic: str) -> str:
        parts = topic.split("/")
        if len(parts) >= 3 and parts[0] == "sensors":
            return parts[1]
        return ""

    def _on_message(self, client, userdata, msg):
        try:
            obj = json.loads(msg.payload.decode("utf-8"))
        except Exception:
            return

        mqtt_topic = str(obj.get("topic", msg.topic) or "")
        mqtt_device_id = self._device_id_from_topic(mqtt_topic)
        if not mqtt_device_id and obj.get("deviceId"):
            mqtt_device_id = str(obj["deviceId"])

        payload_obj = obj.get("payload")
        if payload_obj is None:
            payload_obj = obj

        gateway_received_at = str(obj.get("gateway_received_at", "") or "")
        device_reported_at = str(
            obj.get("device_reported_at", obj.get("timestamp", "")) or ""
        )
        test_phase = ""
        if isinstance(payload_obj, dict):
            test_phase = str(payload_obj.get("testPhase", "") or "")
        delay = _safe_float(obj.get("delay"), 0.0)

        src_ip = str(obj.get("src_ip", "") or "")
        src_mac = obj.get("src_mac")

        if src_ip:
            capture_mode = "mqtt_json"
            semantic_quality = "HIGH"

            raw_ts = obj.get("ts")
            if raw_ts is not None:
                try:
                    ts = float(raw_ts)
                    event_ts_source = "json_field"
                except Exception:
                    ts = time.time()
                    event_ts_source = "fallback_now"
                    semantic_quality = "MEDIUM"
            else:
                ts = (
                    _parse_iso_ts(gateway_received_at)
                    or _parse_iso_ts(device_reported_at)
                    or time.time()
                )
                event_ts_source = (
                    "gateway_received_at"
                    if gateway_received_at
                    else "device_reported_at"
                    if device_reported_at
                    else "fallback_now"
                )
                if event_ts_source == "fallback_now":
                    semantic_quality = "MEDIUM"

            dst_ip = str(obj.get("dst_ip", obj.get("gateway", "")) or "")
            src_port = int(obj.get("src_port", 0) or 0)
            dst_port = int(obj.get("dst_port", 0) or 0)
            if dst_port <= 0:
                dst_port = min(_MQTT_FALLBACK_PORTS)
            proto = str(obj.get("proto", "TCP") or "TCP").upper()
            pkt_len = int(obj.get("pkt_len", len(msg.payload)) or len(msg.payload))
            tcp_flags = str(obj.get("tcp_flags", "") or "").upper()

            if proto == "TCP" and not tcp_flags:
                semantic_quality = "MEDIUM"
        else:
            src_ip = str(obj.get("source_ip", "") or "")
            if not src_ip:
                return

            dst_ip = str(obj.get("gateway", "gateway") or "gateway")
            src_port = int(obj.get("src_port", 0) or 0)
            dst_port = int(obj.get("dst_port", 1883) or 1883)
            proto = str(obj.get("proto", "TCP") or "TCP").upper()
            pkt_len = int(obj.get("pkt_len", len(msg.payload)) or len(msg.payload))
            tcp_flags = str(obj.get("tcp_flags", "") or "").upper()
            src_mac = None

            ts = (
                _parse_iso_ts(gateway_received_at)
                or _parse_iso_ts(device_reported_at)
                or time.time()
            )
            event_ts_source = (
                "gateway_received_at"
                if gateway_received_at
                else "device_reported_at"
                if device_reported_at
                else "fallback_now"
            )
            capture_mode = "mqtt_fallback"
            semantic_quality = "MEDIUM" if gateway_received_at or device_reported_at else "LOW"

        rec = PacketRecord(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            pkt_len=pkt_len,
            tcp_flags=tcp_flags,
            observed_src_ip=src_ip,
            mqtt_topic=mqtt_topic,
            mqtt_device_id=mqtt_device_id,
            mqtt_payload=payload_obj,
            mqtt_delay=delay,
            gateway_received_at=gateway_received_at,
            device_reported_at=device_reported_at,
            test_phase=test_phase,
            capture_mode=capture_mode,
            semantic_quality=semantic_quality,
            event_ts_source=event_ts_source,
            extra={"raw_message_topic": msg.topic},
        )
        key = src_mac if (self.use_mac and src_mac) else src_ip
        if not key:
            key = msg.topic
        self.buffer[key].append(rec)

    def sniff_once(self, timeout: int = 2) -> Dict[str, List[PacketRecord]]:
        start = time.time()
        while time.time() - start < timeout:
            time.sleep(0.05)
        data = dict(self.buffer)
        self.buffer.clear()
        return data