from __future__ import annotations

from typing import Any, Dict, Optional

SUSPICION_CATALOG: Dict[str, Dict[str, str]] = {
    "source_ip_baseline": {
        "suspicion": "Impersonation from unexpected IP",
        "suspicion_category": "Identity spoofing",
        "description": "Accepted sensor traffic originated from an IP outside the device's known baseline.",
    },
    "source_ip_not_allowed": {
        "suspicion": "Traffic from non-whitelisted IP",
        "suspicion_category": "Identity spoofing",
        "description": "Accepted sensor traffic originated from an IP outside the gateway allowed-IP list.",
    },
    "unknown_acl_user": {
        "suspicion": "Unregistered MQTT identity",
        "suspicion_category": "Identity spoofing",
        "description": "Accepted sensor traffic used a device identity that is not defined in the Mosquitto ACL.",
    },
    "high_message_rate": {
        "suspicion": "Message flooding",
        "suspicion_category": "Traffic flooding",
        "description": "Message rate exceeded the normal production baseline for this device.",
    },
    "accelerated_publishing": {
        "suspicion": "Accelerated publishing burst",
        "suspicion_category": "Traffic flooding",
        "description": "Messages arrived faster than the normal inter-arrival timing seen in benign traffic.",
    },
    "rapid_fire": {
        "suspicion": "Extreme rapid-fire burst",
        "suspicion_category": "Traffic flooding",
        "description": "Sustained ultra-fast message burst indicative of automated flooding.",
    },
    "clock_skew_anomaly": {
        "suspicion": "Stale or replayed message",
        "suspicion_category": "Replay / timing anomaly",
        "description": "Device timestamp lagged too far behind gateway receive time.",
    },
    "payload_reject_storm": {
        "suspicion": "Active payload manipulation campaign",
        "suspicion_category": "Coordinated attack",
        "description": "Repeated Node-RED payload rejections for the same device while traffic continues.",
    },
    "mqtt_connect_churn": {
        "suspicion": "MQTT reconnect storm",
        "suspicion_category": "Connection abuse",
        "description": "Abnormally high MQTT reconnect rate compared with benign sensor behavior.",
    },
    "mqtt_multi_ip_connect": {
        "suspicion": "Credential sharing or multi-host abuse",
        "suspicion_category": "Identity spoofing",
        "description": "The same MQTT device identity connected from multiple source IPs.",
    },
    "cross_ip_identity": {
        "suspicion": "Accepted traffic from multiple IPs",
        "suspicion_category": "Identity spoofing",
        "description": "Accepted sensor_data for one device identity was observed from more than one source IP.",
    },
    "deny_accept_ratio": {
        "suspicion": "High denied-to-accepted ratio",
        "suspicion_category": "Coordinated attack",
        "description": "A large fraction of this device's events were denied by Node-RED while accepted traffic continues.",
    },
    "connect_publish_ratio": {
        "suspicion": "MQTT reconnect without publish",
        "suspicion_category": "Connection abuse",
        "description": "MQTT connect count is high relative to process-topic publishes, indicating reconnect churn.",
    },
    "undersize_payload_campaign": {
        "suspicion": "Undersize payload probing",
        "suspicion_category": "Coordinated attack",
        "description": "Repeated denied payloads smaller than the normal sensor profile were observed.",
    },
    "denied_probe_burst": {
        "suspicion": "Probe-only publish burst",
        "suspicion_category": "Coordinated attack",
        "description": "Multiple consecutive denied events occurred without any accepted sensor_data in between.",
    },
    "ssl_handshake_storm": {
        "suspicion": "TLS / cert probing",
        "suspicion_category": "Connection abuse",
        "description": "HAProxy logged a burst of SSL handshake failures from the same source IP.",
    },
    "ephemeral_client_churn": {
        "suspicion": "Ephemeral MQTT client rotation",
        "suspicion_category": "Connection abuse",
        "description": "The device identity connected with far more unique auto-generated client IDs than publishes.",
    },
    "attack_triad": {
        "suspicion": "Coordinated multi-vector attack",
        "suspicion_category": "Coordinated attack",
        "description": "Denied ratio, MQTT reconnect churn, and TLS handshake failures spiked together.",
    },
    "inactive_sensor_traffic": {
        "suspicion": "Traffic from inactive sensor",
        "suspicion_category": "Identity spoofing",
        "description": "Accepted sensor_data arrived for a device that is not in the active sensors list.",
    },
    "accepted_size_drift": {
        "suspicion": "Accepted payload size drift",
        "suspicion_category": "Payload manipulation",
        "description": "Accepted payload size fell outside the known benign size profile.",
    },
    "future_timestamp": {
        "suspicion": "Future-dated message",
        "suspicion_category": "Replay / timing anomaly",
        "description": "Device timestamp was ahead of gateway receive time.",
    },
    "message_pattern_anomaly": {
        "suspicion": "Abnormal message pattern",
        "suspicion_category": "ML behavioral anomaly",
        "description": "Machine learning model detected sustained anomalous timing, volume, or payload statistics.",
    },
}


def build_alert_payload(
    *,
    device_id: str,
    source_ip: str,
    topic: str,
    alert_type: str,
    detection: str,
    severity: str,
    message: str,
    score: float,
    score_type: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    meta = SUSPICION_CATALOG.get(
        detection,
        {
            "suspicion": detection.replace("_", " ").title(),
            "suspicion_category": "Unknown",
        },
    )

    payload: Dict[str, Any] = {
        "device_id": device_id,
        "source_ip": source_ip,
        "topic": topic,
        "alert_type": alert_type,
        "suspicion": meta["suspicion"],
        "suspicion_category": meta["suspicion_category"],
        "severity": severity,
        "message": message,
        "score": round(float(score), 6),
        "score_type": score_type,
    }
    if extra:
        payload.update(extra)
    return payload