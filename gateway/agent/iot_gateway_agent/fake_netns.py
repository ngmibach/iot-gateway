"""Ensure fake-sensor bridge + netns exist (survives /run/netns tmpfs reboot).

Used by ``iotgw-fake@.service`` ExecStartPre so enabled units come back after
reboot without the desktop app. Reads allocation from
``$IOTGW_AGENT_DATA/fake/ip-map.json``.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

FAKE_BRIDGE = "iotgw-fake"
FAKE_GATEWAY_IP = "10.255.0.1"
FAKE_PREFIXLEN = 24


def _ip_bin() -> str:
    for candidate in ("/usr/sbin/ip", "/sbin/ip", "ip"):
        if candidate == "ip":
            found = shutil.which("ip")
            if found:
                return found
            continue
        if Path(candidate).is_file():
            return candidate
    return "ip"


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        text=True,
        capture_output=True,
    )


def _netns_name(device_id: str) -> str:
    return f"iotgw-fake-{device_id}"


def _host_if(host_num: int) -> str:
    return f"vf{int(host_num)}"


def _ns_if(host_num: int) -> str:
    return f"vn{int(host_num)}"


def _read_allocation(data_dir: Path, device_id: str) -> dict[str, Any]:
    ip_map_path = data_dir / "fake" / "ip-map.json"
    if not ip_map_path.is_file():
        raise SystemExit(
            f"fake ip-map missing at {ip_map_path}; recreate the fake sensor"
        )
    raw = json.loads(ip_map_path.read_text(encoding="utf-8"))
    devices = raw.get("devices") if isinstance(raw, dict) else None
    if not isinstance(devices, dict):
        raise SystemExit(f"invalid ip-map at {ip_map_path}")
    entry = devices.get(device_id)
    if not isinstance(entry, dict) or not entry.get("ip") or not entry.get("host_num"):
        raise SystemExit(
            f"no allocation for {device_id} in {ip_map_path}; recreate the fake sensor"
        )
    host_num = int(entry["host_num"])
    return {
        "device_id": device_id,
        "ip": str(entry["ip"]),
        "host_num": host_num,
        "host_if": str(entry.get("host_if") or _host_if(host_num)),
        "ns_if": str(entry.get("ns_if") or _ns_if(host_num)),
        "netns": str(entry.get("netns") or _netns_name(device_id)),
        "bridge": str(entry.get("bridge") or FAKE_BRIDGE),
    }


def _ensure_bridge(ip: str) -> None:
    show = _run([ip, "link", "show", FAKE_BRIDGE], check=False)
    if show.returncode != 0:
        _run([ip, "link", "add", "name", FAKE_BRIDGE, "type", "bridge"])
        _run(
            [
                ip,
                "addr",
                "add",
                f"{FAKE_GATEWAY_IP}/{FAKE_PREFIXLEN}",
                "dev",
                FAKE_BRIDGE,
            ],
            check=False,  # may already exist on race
        )
    _run([ip, "link", "set", FAKE_BRIDGE, "up"])


def _netns_ready(ip: str, alloc: dict[str, Any]) -> bool:
    ns = str(alloc["netns"])
    path = Path("/run/netns") / ns
    if not path.exists():
        return False
    # Confirm the ns iface still has the expected address.
    addr = _run(
        [ip, "-n", ns, "-br", "addr", "show", str(alloc["ns_if"])],
        check=False,
    )
    if addr.returncode != 0:
        return False
    return str(alloc["ip"]) in (addr.stdout or "")


def ensure_netns(device_id: str, *, data_dir: str | Path | None = None) -> dict[str, Any]:
    """Idempotently create bridge + netns + veth for ``device_id``."""
    root = Path(
        data_dir
        or os.environ.get("IOTGW_AGENT_DATA")
        or "/var/lib/iot-gateway-agent"
    )
    alloc = _read_allocation(root, device_id)
    ip = _ip_bin()
    _ensure_bridge(ip)
    if _netns_ready(ip, alloc):
        return alloc

    ns = str(alloc["netns"])
    host_if = str(alloc["host_if"])
    ns_if = str(alloc["ns_if"])
    # Tear down stale names, then recreate (same as control-service create_netns).
    _run([ip, "netns", "del", ns], check=False)
    _run([ip, "link", "del", host_if], check=False)
    _run([ip, "netns", "add", ns])
    _run([ip, "link", "add", host_if, "type", "veth", "peer", "name", ns_if])
    _run([ip, "link", "set", ns_if, "netns", ns])
    _run([ip, "link", "set", host_if, "master", str(alloc["bridge"])])
    _run([ip, "link", "set", host_if, "up"])
    _run(
        [
            ip,
            "-n",
            ns,
            "addr",
            "add",
            f"{alloc['ip']}/{FAKE_PREFIXLEN}",
            "dev",
            ns_if,
        ]
    )
    _run([ip, "-n", ns, "link", "set", ns_if, "up"])
    _run([ip, "-n", ns, "link", "set", "lo", "up"])
    _run(
        [
            ip,
            "-n",
            ns,
            "route",
            "replace",
            "default",
            "via",
            FAKE_GATEWAY_IP,
        ]
    )
    return alloc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ensure fake sensor netns exists")
    parser.add_argument("command", choices=("ensure",), help="ensure netns for device")
    parser.add_argument("device_id", help="Fake device id (systemd %%i)")
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("IOTGW_AGENT_DATA", "/var/lib/iot-gateway-agent"),
    )
    args = parser.parse_args(argv)
    if args.command == "ensure":
        alloc = ensure_netns(args.device_id, data_dir=args.data_dir)
        print(f"netns {alloc['netns']} ready ({alloc['ip']})", flush=True)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
