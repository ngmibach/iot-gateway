"""Monolithic IoT gateway agent (MQTT + decrypt + metrics + Loki shipper + mDNS)."""

__version__ = "0.2.0"
# HTTP control /metrics /health — Prometheus scrapes GATEWAY_IP:9139/metrics
AGENT_PORT = 9139
MQTT_TLS_PORT = 8883
MQTT_PORT = 1883
SERVICE_TYPE = "_iot-gateway._tcp.local."
HEALTH_PATH = "/v1/health"
