from __future__ import annotations

import json
from typing import Dict, List

import numpy as np

from .records import PacketRecord
from .utils import safe_float


FEATURE_NAMES = [
    "msg_count",
    "topic_unique_count",
    "topic_flood_ratio",
    "avg_payload_len",
    "std_payload_len",
    "min_payload_len",
    "max_payload_len",
    "mean_inter_arrival_ms",
    "std_inter_arrival_ms",
    "avg_delay",
    "max_delay",
    "attack_blob_ratio",
]


def empty_feature_vector() -> Dict[str, float]:
    return {name: 0.0 for name in FEATURE_NAMES}


def _extract_topic(record: PacketRecord) -> str:
    topic = getattr(record, "mqtt_topic", None)
    if topic is None:
        topic = getattr(record, "mqtttopic", None)
    return str(topic or "").strip()


def _extract_payload(record: PacketRecord):
    payload = getattr(record, "mqtt_payload", None)
    if payload is None:
        payload = getattr(record, "mqttpayload", None)
    return payload


def _extract_delay(record: PacketRecord) -> float:
    for attr in ("mqtt_delay", "delay", "mqttdelay"):
        if hasattr(record, attr):
            value = getattr(record, attr)
            f = safe_float(value, default=np.nan)
            if not np.isnan(f):
                return float(f)
    return 0.0


def _payload_len(payload) -> int:
    if payload is None:
        return 0
    if isinstance(payload, (bytes, bytearray)):
        return len(payload)
    if isinstance(payload, str):
        return len(payload)
    try:
        return len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    except Exception:
        return len(str(payload))


def _has_attack_blob(payload) -> bool:
    if isinstance(payload, dict):
        debug = payload.get("debug")
        if isinstance(debug, dict):
            blob = debug.get("attack_blob")
            if not blob:
                blob = debug.get("attackblob")
            return bool(blob)
    return False

def build_feature_vector(records: List[PacketRecord]) -> Dict[str, float]:
    if not records:
        return empty_feature_vector()

    ordered = sorted(records, key=lambda r: safe_float(getattr(r, "ts", 0.0), 0.0))

    topics: List[str] = []
    payload_lens: List[float] = []
    delays: List[float] = []
    timestamps: List[float] = []
    attack_blob_hits = 0

    for record in ordered:
        topic = _extract_topic(record)
        payload = _extract_payload(record)

        topics.append(topic)
        payload_lens.append(float(_payload_len(payload)))
        delays.append(float(max(_extract_delay(record), 0.0)))

        ts = safe_float(getattr(record, "ts", 0.0), 0.0)
        timestamps.append(ts)

        if _has_attack_blob(payload):
            attack_blob_hits += 1

    iat_ms: List[float] = []
    if len(timestamps) > 1:
        for t1, t2 in zip(timestamps[:-1], timestamps[1:]):
            delta_ms = max((t2 - t1) * 1000.0, 0.0)
            iat_ms.append(delta_ms)

    msg_count = float(len(ordered))
    topic_unique_count = float(len(set(t for t in topics if t)))

    flood_topic_count = sum(1 for t in topics if "flood" in t.lower())
    topic_flood_ratio = float(flood_topic_count / len(topics)) if topics else 0.0

    payload_arr = np.asarray(payload_lens, dtype=float) if payload_lens else np.asarray([0.0], dtype=float)
    delay_arr = np.asarray(delays, dtype=float) if delays else np.asarray([0.0], dtype=float)
    iat_arr = np.asarray(iat_ms, dtype=float) if iat_ms else np.asarray([], dtype=float)

    return {
        "msg_count": msg_count,
        "topic_unique_count": topic_unique_count,
        "topic_flood_ratio": topic_flood_ratio,
        "avg_payload_len": float(np.mean(payload_arr)) if payload_lens else 0.0,
        "std_payload_len": float(np.std(payload_arr)) if payload_lens else 0.0,
        "min_payload_len": float(np.min(payload_arr)) if payload_lens else 0.0,
        "max_payload_len": float(np.max(payload_arr)) if payload_lens else 0.0,
        "mean_inter_arrival_ms": float(np.mean(iat_arr)) if len(iat_ms) > 0 else 0.0,
        "std_inter_arrival_ms": float(np.std(iat_arr)) if len(iat_ms) > 0 else 0.0,
        "avg_delay": float(np.mean(delay_arr)) if delays else 0.0,
        "max_delay": float(np.max(delay_arr)) if delays else 0.0,
        "attack_blob_ratio": float(attack_blob_hits / len(ordered)) if ordered else 0.0,
    }