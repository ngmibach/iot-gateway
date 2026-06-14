from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List

from scapy.all import ICMP, IP, Raw, TCP, UDP, get_if_list, sniff  # type: ignore


@dataclass
class PacketRecord:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    pkt_len: int
    tcp_flags: str
    observed_src_ip: str = ""
    mqtt_topic: str = ""
    mqtt_device_id: str = ""
    mqtt_payload: Any = None
    mqtt_delay: float = 0.0
    gateway_received_at: str = ""
    device_reported_at: str = ""
    test_phase: str = ""
    capture_mode: str = "pcap"
    semantic_quality: str = "HIGH"
    event_ts_source: str = "packet"
    extra: Dict[str, Any] = field(default_factory=dict)


class PacketCapture:
    def __init__(self, interface: str, bpf_filter: str = "") -> None:
        self.interface = self._resolve_interface(interface)
        self.bpf_filter = bpf_filter
        self._mqtt_ports: set[int] = self._ports_from_bpf(bpf_filter)
        self.buffer: Dict[str, List[PacketRecord]] = defaultdict(list)
        self._flow_source_map: Dict[tuple[str, int, str, int], str] = {}
        self._flow_topic_map: Dict[tuple[str, int, str, int], str] = {}

    @staticmethod
    def _ports_from_bpf(bpf: str) -> set[int]:
        import re
        return {int(p) for p in re.findall(r"port\s+(\d+)", bpf or "")}

    @staticmethod
    def _tcp_payload(pkt: Any) -> bytes:
        if Raw in pkt:
            return bytes(pkt[Raw].load)
        if TCP in pkt:
            return bytes(pkt[TCP].payload)
        return b""

    @staticmethod
    def _strip_proxy_header(payload: bytes) -> tuple[str, bytes]:
        if not payload.startswith(b"PROXY "):
            return "", payload
        header, separator, rest = payload.partition(b"\r\n")
        if not separator:
            return "", payload
        try:
            parts = header.decode("ascii", errors="ignore").split()
        except Exception:
            return "", rest
        if len(parts) < 6:
            return "", rest
        return parts[2], rest

    @staticmethod
    def _parse_mqtt_topic(payload: bytes) -> str:
        if not payload:
            return ""
        packet_type = payload[0] >> 4
        if packet_type != 3:
            return ""
        index = 1
        multiplier = 1
        remaining_length = 0
        while True:
            if index >= len(payload):
                return ""
            encoded = payload[index]
            index += 1
            remaining_length += (encoded & 127) * multiplier
            if encoded & 128 == 0:
                break
            multiplier *= 128
            if multiplier > 128**4:
                return ""
        if remaining_length <= 0 or index + 2 > len(payload):
            return ""
        topic_length = int.from_bytes(payload[index:index + 2], "big")
        index += 2
        if topic_length <= 0 or index + topic_length > len(payload):
            return ""
        return payload[index:index + topic_length].decode("utf-8", errors="ignore")

    @staticmethod
    def _device_id_from_topic(topic: str) -> str:
        if not topic:
            return ""
        parts = topic.split("/")
        if len(parts) >= 3 and parts[0] == "sensors":
            return parts[1]
        return ""

    def _resolve_interface(self, requested: str):
        interfaces = get_if_list()
        normalized = (requested or "").strip().lower()
        if normalized in {"", "any", "auto", "*"}:
            selected: list[str] = []
            if "eth0" in interfaces:
                selected.append("eth0")
            else:
                for iface in interfaces:
                    if iface != "lo":
                        selected.append(iface)
                        break
            if "lo" in interfaces:
                selected.append("lo")
            if selected:
                print(f"[IDS] capture interface auto-selected: {selected}")
                return selected[0] if len(selected) == 1 else selected
            print("[IDS] capture interface fallback to loopback: lo")
            return "lo"
        if requested in interfaces:
            print(f"[IDS] capture interface configured: {requested}")
            return requested
        for candidate in interfaces:
            if candidate != "lo":
                print(f"[IDS] capture interface '{requested}' not found, fallback to {candidate}")
                return candidate
        print(f"[IDS] capture interface '{requested}' not found, fallback to loopback: lo")
        return "lo"

    def _parse_packet(self, pkt: Any) -> PacketRecord | None:
        if IP not in pkt:
            return None

        ip = pkt[IP]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)
        pkt_len = int(len(pkt))

        raw_ts = getattr(pkt, "time", None)
        try:
            ts = float(raw_ts) if raw_ts is not None else 0.0
        except Exception:
            ts = 0.0
        if ts <= 0.0:
            return None
        event_ts_source = "packet"

        dst_port = 0
        src_port = 0
        proto = "OTHER"
        flags = ""
        observed_src_ip = src_ip
        mqtt_topic = ""
        mqtt_device_id = ""
        semantic_quality = "HIGH"
        flow_key = (src_ip, 0, dst_ip, 0)

        if TCP in pkt:
            proto = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
            flow_key = (src_ip, src_port, dst_ip, dst_port)
            payload = self._tcp_payload(pkt)
            cached_src_ip = self._flow_source_map.get(flow_key)
            cached_topic = self._flow_topic_map.get(flow_key)

            if payload:
                proxy_src_ip, mqtt_payload = self._strip_proxy_header(payload)
                if proxy_src_ip:
                    observed_src_ip = src_ip
                    src_ip = proxy_src_ip
                    self._flow_source_map[flow_key] = proxy_src_ip
                elif cached_src_ip:
                    src_ip = cached_src_ip

                mqtt_topic = self._parse_mqtt_topic(mqtt_payload)
                if mqtt_topic:
                    self._flow_topic_map[flow_key] = mqtt_topic
                elif cached_topic:
                    mqtt_topic = cached_topic
            else:
                if cached_src_ip:
                    src_ip = cached_src_ip
                if cached_topic:
                    mqtt_topic = cached_topic

            mqtt_device_id = self._device_id_from_topic(mqtt_topic)
            if mqtt_topic and not flags:
                semantic_quality = "MEDIUM"

        elif UDP in pkt:
            proto = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"

        return PacketRecord(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto,
            pkt_len=pkt_len,
            tcp_flags=flags,
            observed_src_ip=observed_src_ip,
            mqtt_topic=mqtt_topic,
            mqtt_device_id=mqtt_device_id,
            mqtt_payload=None,
            mqtt_delay=0.0,
            gateway_received_at="",
            device_reported_at="",
            test_phase="",
            capture_mode="pcap",
            semantic_quality=semantic_quality,
            event_ts_source=event_ts_source,
        )

    def _on_packet(self, pkt: Any) -> None:
        rec = self._parse_packet(pkt)
        if rec is None:
            return
        if (
            self._mqtt_ports
            and rec.dst_port not in self._mqtt_ports
            and rec.src_port not in self._mqtt_ports
        ):
            return
        self.buffer[rec.src_ip].append(rec)

    def sniff_once(self, timeout: int = 2) -> Dict[str, List[PacketRecord]]:
        kwargs: Dict[str, Any] = dict(
            iface=self.interface, prn=self._on_packet, store=False, timeout=timeout
        )
        if self.bpf_filter:
            try:
                from scapy.arch.common import compile_filter
                compile_filter(self.bpf_filter)
                kwargs["filter"] = self.bpf_filter
                print(f"[IDS] BPF kernel filter active: {self.bpf_filter!r}")
            except Exception:
                print(
                    "[IDS] libpcap unavailable — BPF filter disabled, "
                    f"using Python port filter: {sorted(self._mqtt_ports)}"
                )
        sniff(**kwargs)
        data = dict(self.buffer)
        self.buffer.clear()
        return data