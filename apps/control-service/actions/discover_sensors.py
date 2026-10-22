"""Discover LAN neighbor IPs on a gateway (sensor candidates)."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    from .ssh import SSHClient

_IP_NEIGH_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+.*?(?:lladdr\s+(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}))?"
    r".*?\b(?P<state>REACHABLE|STALE|DELAY|PROBE|PERMANENT|NOARP|INCOMPLETE|FAILED)\b",
    re.I,
)
_ARP_RE = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+"
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|incomplete|\*)\s+",
    re.I,
)
_ADDR_IP_RE = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?")


def _is_skipped_ip(ip: str, gateway_ips: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return True
    own = {str(ipaddress.ip_address(x)) for x in gateway_ips if x}
    return str(addr) in own


def parse_gateway_ips(addr_text: str, hostname_i: str = "") -> list[str]:
    """IPv4 addresses belonging to the gateway itself."""
    found: list[str] = []
    seen: set[str] = set()
    for m in _ADDR_IP_RE.finditer(addr_text or ""):
        ip = m.group(1)
        if ip not in seen and not _is_skipped_ip(ip, []):
            seen.add(ip)
            found.append(ip)
    for tok in (hostname_i or "").split():
        tok = tok.strip()
        if not tok or tok in seen:
            continue
        try:
            addr = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if addr.version == 4 and not addr.is_loopback and not addr.is_link_local:
            seen.add(str(addr))
            found.append(str(addr))
    return found


def _mac_from_parts(parts: list[str]) -> str:
    if "lladdr" not in parts:
        return ""
    i = parts.index("lladdr")
    if i + 1 >= len(parts):
        return ""
    return parts[i + 1].lower()


def parse_ip_neigh(text: str, *, gateway_ips: Iterable[str] = ()) -> list[dict[str, str]]:
    """Parse ``ip -4 neigh show`` output into candidate hosts."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        m = _IP_NEIGH_RE.search(line)
        if not m:
            if not parts:
                continue
            ip = parts[0]
            state = parts[-1].upper() if parts else ""
            mac = _mac_from_parts(parts)
        else:
            ip = m.group("ip")
            state = (m.group("state") or "").upper()
            # Named mac group is optional and often skipped by the engine; prefer tokens.
            mac = _mac_from_parts(parts) or (m.group("mac") or "").lower()
        if state in ("INCOMPLETE", "FAILED"):
            continue
        if _is_skipped_ip(ip, gateway_ips):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        row = {"ip": ip, "state": state or "UNKNOWN"}
        if mac and mac not in ("incomplete", "*"):
            row["mac"] = mac.lower()
        out.append(row)
    return out


def parse_proc_arp(text: str, *, gateway_ips: Iterable[str] = ()) -> list[dict[str, str]]:
    """Parse ``/proc/net/arp`` (skip header)."""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    lines = (text or "").splitlines()
    for line in lines[1:] if lines else []:
        m = _ARP_RE.match(line.strip())
        if not m:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip, mac = parts[0], parts[3]
        else:
            ip, mac = m.group("ip"), m.group("mac")
        mac_l = (mac or "").lower()
        if mac_l in ("incomplete", "*", "00:00:00:00:00:00"):
            continue
        if _is_skipped_ip(ip, gateway_ips):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        out.append({"ip": ip, "mac": mac_l, "state": "ARP"})
    return out


def merge_hosts(*groups: list[dict[str, str]]) -> list[dict[str, str]]:
    by_ip: dict[str, dict[str, str]] = {}
    for group in groups:
        for row in group:
            ip = row.get("ip")
            if not ip:
                continue
            cur = by_ip.get(ip, {"ip": ip})
            for k, v in row.items():
                if v and (k not in cur or not cur.get(k)):
                    cur[k] = v
            by_ip[ip] = cur
    return sorted(by_ip.values(), key=lambda r: tuple(int(x) for x in r["ip"].split(".")))


def discover_sensor_hosts(ssh: "SSHClient") -> dict[str, Any]:
    """SSH to gateway; return neighbor hosts excluding the gateway itself."""
    addr = ssh.run("ip -4 -o addr show 2>/dev/null || true", timeout=15.0)
    host_i = ssh.run("hostname -I 2>/dev/null || true", timeout=10.0)
    gateway_ips = parse_gateway_ips(addr.stdout or "", host_i.stdout or "")

    neigh = ssh.run("ip -4 neigh show 2>/dev/null || true", timeout=15.0)
    arp = ssh.run("cat /proc/net/arp 2>/dev/null || true", timeout=10.0)

    hosts = merge_hosts(
        parse_ip_neigh(neigh.stdout or "", gateway_ips=gateway_ips),
        parse_proc_arp(arp.stdout or "", gateway_ips=gateway_ips),
    )
    return {"hosts": hosts, "gateway_ips": gateway_ips}
