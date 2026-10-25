"""Agent Prometheus exposition includes per-application status metrics."""

from __future__ import annotations

import unittest
from unittest import mock

from iot_gateway_agent.metrics import AgentMetrics


class _FakeBroker:
    def __init__(self, *, running: bool = True, pid: int | None = 4242):
        self._running = running
        self._pid = pid

    def running(self) -> bool:
        return self._running

    @property
    def pid(self) -> int | None:
        return self._pid if self._running else None


class _FakeWorker:
    def __init__(self, *, alive: bool = True, ok: int = 3, fail: int = 1):
        self._alive = alive
        self.messages_ok = ok
        self.messages_fail = fail

    @property
    def alive(self) -> bool:
        return self._alive

    def device_snapshot(self) -> dict:
        return {}


class _FakeShipper:
    def __init__(self, *, alive: bool = True, sent: int = 9):
        self._alive = alive
        self.lines_sent = sent

    @property
    def alive(self) -> bool:
        return self._alive


class AgentMetricsTests(unittest.TestCase):
    def test_render_includes_app_up_and_activity(self) -> None:
        metrics = AgentMetrics(
            broker=_FakeBroker(),  # type: ignore[arg-type]
            decrypt_worker=_FakeWorker(),  # type: ignore[arg-type]
            shipper=_FakeShipper(alive=False),  # type: ignore[arg-type]
        )
        with mock.patch(
            "iot_gateway_agent.metrics._read_proc_cpu_seconds", return_value=1.5
        ), mock.patch(
            "iot_gateway_agent.metrics._read_proc_rss_bytes", return_value=1024 * 1024
        ), mock.patch(
            "iot_gateway_agent.metrics.tcp_open", return_value=False
        ):
            text = metrics.render()

        self.assertIn('iotgw_app_up{app="agent"} 1', text)
        self.assertIn('iotgw_app_up{app="mqtt"} 1', text)
        self.assertIn('iotgw_app_up{app="decrypt"} 1', text)
        self.assertIn('iotgw_app_up{app="shipper"} 0', text)
        self.assertIn('iotgw_app_up{app="kafka"} 0', text)
        self.assertIn('iotgw_decrypt_messages_total{result="ok"} 3', text)
        self.assertIn("iotgw_loki_lines_sent_total 9", text)
        self.assertIn("iotgw_denied_publishes_total 0", text)
        self.assertIn("iotgw_kafka_up 0", text)
        self.assertIn('iotgw_kafka_produce_total{result="ok"} 0', text)
        self.assertIn('iotgw_app_cpu_seconds_total{app="agent"}', text)
        self.assertIn('iotgw_app_memory_bytes{app="mqtt"}', text)

    def test_mqtt_up_via_port_probe_when_child_down(self) -> None:
        metrics = AgentMetrics(
            broker=_FakeBroker(running=False),  # type: ignore[arg-type]
            mqtt_port=1883,
        )
        with mock.patch(
            "iot_gateway_agent.metrics.tcp_open", return_value=True
        ) as probe, mock.patch(
            "iot_gateway_agent.metrics.find_mosquitto_pid", return_value=99
        ), mock.patch(
            "iot_gateway_agent.metrics._read_proc_cpu_seconds", return_value=0.5
        ), mock.patch(
            "iot_gateway_agent.metrics._read_proc_rss_bytes", return_value=2048
        ):
            text = metrics.render()

        probe.assert_called()
        self.assertIn('iotgw_app_up{app="mqtt"} 1', text)
        self.assertIn("iotgw_mqtt_up 1", text)
        self.assertIn('iotgw_app_memory_bytes{app="mqtt"}', text)

    def test_mqtt_down_when_child_and_port_fail(self) -> None:
        metrics = AgentMetrics(broker=_FakeBroker(running=False))  # type: ignore[arg-type]
        with mock.patch("iot_gateway_agent.metrics.tcp_open", return_value=False):
            self.assertFalse(metrics.refresh_mqtt_up())
            text = metrics.render()
        self.assertIn('iotgw_app_up{app="mqtt"} 0', text)
        self.assertIn("iotgw_mqtt_up 0", text)


if __name__ == "__main__":
    unittest.main()
