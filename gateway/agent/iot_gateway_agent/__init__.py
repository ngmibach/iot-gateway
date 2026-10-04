"""Read-only IoT gateway discovery agent (mDNS + /v1/health)."""

__version__ = "0.1.0"
AGENT_PORT = 9138
MQTT_TLS_PORT = 8883
SERVICE_TYPE = "_iot-gateway._tcp.local."
HEALTH_PATH = "/v1/health"
