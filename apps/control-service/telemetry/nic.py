"""NIC / IPv4 candidate selection for MONITORING_IP.

Default exclusions: loopback, docker0/br-/veth, WSL/Hyper-V vEthernet adapters.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Iterable, Sequence

# Interface name patterns excluded by default (Linux + Windows).
_DEFAULT_NAME_EXCLUDE = (
    re.compile(r"^lo$", re.I),
    re.compile(r"^docker\d*$", re.I),
    re.compile(r"^br-", re.I),
    re.compile(r"^veth", re.I),
    re.compile(r"^vEthernet \(WSL", re.I),
    re.compile(r"^vEthernet \(Default Switch\)$", re.I),
    re.compile(r"^vEthernet \(.*Hyper-V.*\)$", re.I),
    re.compile(r"^WSL$", re.I),
)


@dataclass(frozen=True)
class NicCandidate:
    name: str
    ip: str
    prefix: int | None = None

    @property
    def cidr(self) -> str | None:
        if self.prefix is None:
            return None
        return f"{self.ip}/{self.prefix}"


def _is_loopback_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return True


def _is_link_local(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return True


def name_excluded(
    name: str,
    *,
    extra_patterns: Sequence[re.Pattern[str]] | None = None,
) -> bool:
    """True if interface name matches default (or extra) exclusion patterns."""
    patterns = list(_DEFAULT_NAME_EXCLUDE)
    if extra_patterns:
        patterns.extend(extra_patterns)
    return any(p.search(name) for p in patterns)


def filter_nic_candidates(
    candidates: Iterable[NicCandidate],
    *,
    exclude_docker_wsl: bool = True,
    exclude_loopback: bool = True,
    exclude_link_local: bool = True,
    extra_name_patterns: Sequence[re.Pattern[str]] | None = None,
) -> list[NicCandidate]:
    """Filter IPv4 NIC candidates for MONITORING_IP selection."""
    out: list[NicCandidate] = []
    for c in candidates:
        if exclude_loopback and _is_loopback_ip(c.ip):
            continue
        if exclude_link_local and _is_link_local(c.ip):
            continue
        if exclude_docker_wsl and name_excluded(
            c.name, extra_patterns=extra_name_patterns
        ):
            continue
        out.append(c)
    return out


def _parse_ip_json(payload: str) -> list[NicCandidate]:
    data = json.loads(payload)
    found: list[NicCandidate] = []
    for iface in data:
        name = str(iface.get("ifname") or iface.get("name") or "")
        for addr_info in iface.get("addr_info") or []:
            family = addr_info.get("family")
            if family is not None and family != "inet":
                continue
            local = addr_info.get("local")
            if not local:
                continue
            try:
                if ipaddress.ip_address(local).version != 4:
                    continue
            except ValueError:
                continue
            prefix = addr_info.get("prefixlen")
            found.append(
                NicCandidate(
                    name=name,
                    ip=str(local),
                    prefix=int(prefix) if prefix is not None else None,
                )
            )
    return found


def _parse_ip_dash_o(text: str) -> list[NicCandidate]:
    # Example: ``2: eth0    inet 192.168.1.10/24 brd ... scope global eth0``
    found: list[NicCandidate] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        name = parts[1].rstrip(":")
        cidr = parts[3]
        try:
            iface = ipaddress.ip_interface(cidr)
        except ValueError:
            continue
        if iface.version != 4:
            continue
        found.append(
            NicCandidate(name=name, ip=str(iface.ip), prefix=iface.network.prefixlen)
        )
    return found


def list_ipv4_candidates(
    *,
    exclude_docker_wsl: bool = True,
    apply_defaults: bool = True,
) -> list[NicCandidate]:
    """Enumerate host IPv4 addresses (Linux ``ip``; empty list if unavailable)."""
    raw = _collect_raw_candidates()
    if not apply_defaults:
        return raw
    return filter_nic_candidates(raw, exclude_docker_wsl=exclude_docker_wsl)


def _collect_raw_candidates() -> list[NicCandidate]:
    # Prefer JSON (iproute2); fall back to ``ip -4 -o addr``.
    for args, parser in (
        (["ip", "-j", "-4", "addr"], _parse_ip_json),
        (["ip", "-4", "-o", "addr"], _parse_ip_dash_o),
    ):
        try:
            proc = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
        if proc.returncode != 0 or not proc.stdout.strip():
            continue
        try:
            return parser(proc.stdout)
        except (json.JSONDecodeError, ValueError, KeyError, TypeError):
            continue
    return []


def pick_default_monitoring_ip(
    candidates: Sequence[NicCandidate],
    *,
    gateway_ip: str | None = None,
) -> NicCandidate | None:
    """Prefer NIC sharing a subnet with gateway_ip; else first filtered candidate."""
    if not candidates:
        return None
    if gateway_ip:
        try:
            gw = ipaddress.ip_address(gateway_ip)
        except ValueError:
            gw = None
        if gw is not None:
            for c in candidates:
                if c.prefix is None:
                    continue
                try:
                    net = ipaddress.ip_network(f"{c.ip}/{c.prefix}", strict=False)
                except ValueError:
                    continue
                if gw in net:
                    return c
    return candidates[0]
