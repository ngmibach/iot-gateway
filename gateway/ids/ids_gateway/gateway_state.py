"""Read live gateway ACL, allowed IPs, and active sensor state."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set

_PROM_METRIC_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)$"
)
_PROM_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


@dataclass(frozen=True)
class GatewayState:
    allowed_ips: frozenset[str] = field(default_factory=frozenset)
    acl_users: frozenset[str] = field(default_factory=frozenset)
    device_source_ips: Dict[str, str] = field(default_factory=dict)
    source: str = "empty"

    def expected_ip_for(self, device_id: str) -> Optional[str]:
        return self.device_source_ips.get(device_id)

    def is_acl_user(self, device_id: str) -> bool:
        if not self.acl_users:
            return True
        return device_id in self.acl_users

    def is_ip_allowed(self, ip: str) -> bool:
        if not ip or not self.allowed_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.allowed_ips:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False


def _parse_prom_labels(raw: str) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    for match in _PROM_LABEL_RE.finditer(raw):
        labels[match.group(1)] = match.group(2).replace('\\"', '"')
    return labels


def _parse_prom_lines(text: str) -> Iterable[tuple[str, Dict[str, str], float]]:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _PROM_METRIC_RE.match(stripped)
        if not match:
            continue
        name = match.group("name")
        labels = _parse_prom_labels(match.group("labels") or "")
        yield name, labels, float(match.group("value"))


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _state_from_active_sensors_prom(path: Path) -> Dict[str, str]:
    device_ips: Dict[str, str] = {}
    for name, labels, value in _parse_prom_lines(_read_text(path)):
        if name != "mqtt_connected_sensor" or value < 1:
            continue
        device_id = labels.get("device_id", "").strip()
        source_ip = labels.get("source_ip", "").strip()
        if device_id and source_ip:
            device_ips[device_id] = source_ip
    return device_ips


def _state_from_allowed_ips_prom(path: Path) -> tuple[Set[str], Set[str]]:
    allowed_ips: Set[str] = set()
    acl_users: Set[str] = set()
    for name, labels, value in _parse_prom_lines(_read_text(path)):
        if value < 1:
            continue
        if name == "allowed_ip":
            ip = labels.get("ip", "").strip()
            if ip:
                allowed_ips.add(ip)
        elif name == "acl":
            user = labels.get("user", "").strip()
            permission = labels.get("permission", "").strip()
            if user and permission != "none":
                acl_users.add(user)
    return allowed_ips, acl_users


def _iter_log_events(text: str) -> Iterable[Dict[str, Any]]:
    """Yield dict events from gateway-state.log, including pretty-printed JSON."""
    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)

    while idx < length:
        while idx < length and text[idx] in " \t\r\n":
            idx += 1
        if idx >= length:
            break

        try:
            event, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            next_brace = text.find("{", idx + 1)
            if next_brace == -1:
                break
            idx = next_brace
            continue

        idx = end
        if isinstance(event, dict):
            yield event


def _latest_log_snapshots(path: Path) -> tuple[Dict[str, Any], Dict[str, Any]]:
    allowed_snapshot: Dict[str, Any] = {}
    connected_snapshot: Dict[str, Any] = {}
    if not path.exists():
        return allowed_snapshot, connected_snapshot

    for event in _iter_log_events(_read_text(path)):
        if event.get("event_type") != "state_snapshot":
            continue
        state_type = event.get("state_type")
        if state_type == "allowed_ips_acl":
            allowed_snapshot = event
        elif state_type == "connected_sensors":
            connected_snapshot = event
    return allowed_snapshot, connected_snapshot


def _device_ips_from_connected_snapshot(snapshot: Dict[str, Any]) -> Dict[str, str]:
    device_ips: Dict[str, str] = {}
    details = snapshot.get("details") or {}
    if isinstance(details, dict):
        for device_id, info in details.items():
            if not isinstance(info, dict):
                continue
            ip = str(info.get("ip", "")).strip()
            if device_id and ip:
                device_ips[str(device_id)] = ip
    return device_ips


def _state_from_allowed_snapshot(snapshot: Dict[str, Any]) -> tuple[Set[str], Set[str]]:
    allowed_ips: Set[str] = set()
    acl_users: Set[str] = set()

    for ip in snapshot.get("allowed_ips") or []:
        ip_text = str(ip).strip()
        if ip_text:
            allowed_ips.add(ip_text)

    acl = snapshot.get("acl") or {}
    if isinstance(acl, dict):
        for user, perms in acl.items():
            if not isinstance(perms, dict):
                continue
            has_access = any(perms.get(key) for key in ("read", "readwrite"))
            if has_access:
                acl_users.add(str(user))

    return allowed_ips, acl_users


def load_gateway_state(
    *,
    active_sensors_prom: str | Path,
    allowed_ips_prom: str | Path,
    gateway_state_log: str | Path,
) -> GatewayState:
    active_path = Path(active_sensors_prom)
    allowed_path = Path(allowed_ips_prom)
    log_path = Path(gateway_state_log)

    allowed_ips: Set[str] = set()
    acl_users: Set[str] = set()
    device_ips: Dict[str, str] = {}
    sources: list[str] = []

    prom_allowed, prom_acl = _state_from_allowed_ips_prom(allowed_path)
    if prom_allowed:
        allowed_ips.update(prom_allowed)
        sources.append("allowed_ips.prom")
    if prom_acl:
        acl_users.update(prom_acl)
        sources.append("allowed_ips.prom")

    prom_devices = _state_from_active_sensors_prom(active_path)
    if prom_devices:
        device_ips.update(prom_devices)
        sources.append("active_sensors.prom")

    log_allowed_snapshot, log_connected_snapshot = _latest_log_snapshots(log_path)
    if log_allowed_snapshot:
        log_allowed, log_acl = _state_from_allowed_snapshot(log_allowed_snapshot)
        if log_allowed and not allowed_ips:
            allowed_ips.update(log_allowed)
            sources.append("gateway-state.log")
        if log_acl and not acl_users:
            acl_users.update(log_acl)
            sources.append("gateway-state.log")

    log_devices = _device_ips_from_connected_snapshot(log_connected_snapshot)
    for device_id, ip in log_devices.items():
        device_ips.setdefault(device_id, ip)
    if log_devices and "gateway-state.log" not in sources:
        sources.append("gateway-state.log")

    return GatewayState(
        allowed_ips=frozenset(allowed_ips),
        acl_users=frozenset(acl_users),
        device_source_ips=device_ips,
        source="+".join(dict.fromkeys(sources)) or "empty",
    )


class GatewayStateReader:
    def __init__(
        self,
        *,
        active_sensors_prom: str | Path,
        allowed_ips_prom: str | Path,
        gateway_state_log: str | Path,
        refresh_interval_seconds: float = 1.0,
    ) -> None:
        self.active_sensors_prom = Path(active_sensors_prom)
        self.allowed_ips_prom = Path(allowed_ips_prom)
        self.gateway_state_log = Path(gateway_state_log)
        self.refresh_interval_seconds = max(float(refresh_interval_seconds), 0.1)
        self._state = GatewayState()
        self._last_refresh = 0.0

    def refresh_if_needed(self, force: bool = False) -> GatewayState:
        now = time.time()
        if force or (now - self._last_refresh) >= self.refresh_interval_seconds:
            self._state = load_gateway_state(
                active_sensors_prom=self.active_sensors_prom,
                allowed_ips_prom=self.allowed_ips_prom,
                gateway_state_log=self.gateway_state_log,
            )
            self._last_refresh = now
        return self._state

    @property
    def state(self) -> GatewayState:
        return self._state