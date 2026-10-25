"""Gateway-side fake sensor runtime playbooks (bridge, netns, unit, cert feed).

Fake sensors run on a private ``iotgw-fake`` bridge with one network namespace
per device so MQTTS source IPs are distinct. Privileged steps use ``sudo -S``
when ``sudo_password`` is provided, otherwise ``sudo -n`` (NOPASSWD).
"""

from __future__ import annotations

import json
import ipaddress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from .paths import DEFAULT_AGENT_DATA, DEFAULT_INSTALL_ROOT, GatewayPaths
from .shellutil import shell_quote
from .validate import validate_user_id

if TYPE_CHECKING:
    from .ssh import CommandResult, SSHClient

FAKE_BRIDGE = "iotgw-fake"
FAKE_SUBNET = "10.255.0.0/24"
FAKE_GATEWAY_IP = "10.255.0.1"
FAKE_PREFIXLEN = 24
FAKE_FIRST_HOST = 2
FAKE_LAST_HOST = 254
FAKE_UNIT_TEMPLATE = "iotgw-fake@.service"
DEFAULT_BROKER_PORT = 8883

DEFAULT_BEHAVIORS: dict[str, bool] = {
    "omit_client_cert": False,
    "wrong_client_cert": False,
    "skip_encryption": False,
    "bad_encryption": False,
    "wrong_password": False,
    "wrong_topic": False,
}

# Installed under /etc/systemd/system/iotgw-fake@.service
FAKE_UNIT_BODY = """[Unit]
Description=IoT Gateway fake sensor %i
Documentation=file:///opt/iot-gateway-agent
After=network-online.target mosquitto.service
Wants=network-online.target

[Service]
Type=simple
NetworkNamespacePath=/run/netns/iotgw-fake-%i
Environment=IOTGW_AGENT_DATA=/var/lib/iot-gateway-agent
EnvironmentFile=-/etc/iot-gateway-agent.env
ExecStart=/opt/iot-gateway-agent/venv/bin/python -m iot_gateway_agent.fake_sensor --device-id %i
Restart=on-failure
RestartSec=3
WorkingDirectory=/var/lib/iot-gateway-agent/fake/%i
StandardOutput=append:/var/lib/iot-gateway-agent/fake/%i/run.log
StandardError=append:/var/lib/iot-gateway-agent/fake/%i/run.log

[Install]
WantedBy=multi-user.target
"""


@dataclass
class FakePlaybookResult:
    ok: bool
    status: str = "ok"  # ok | degraded | failed
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FakeAllocation:
    device_id: str
    ip: str
    host_num: int
    host_if: str
    ns_if: str
    netns: str
    unit: str
    bridge: str = FAKE_BRIDGE


def _paths(
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> GatewayPaths:
    return GatewayPaths(
        install_root=install_root,
        data_dir=data_dir if data_dir is not None else DEFAULT_AGENT_DATA,
    )


def netns_name(device_id: str) -> str:
    return f"iotgw-fake-{validate_user_id(device_id)}"


def unit_instance(device_id: str) -> str:
    return f"iotgw-fake@{validate_user_id(device_id)}"


def host_if_name(host_num: int) -> str:
    return f"vf{int(host_num)}"


def ns_if_name(host_num: int) -> str:
    return f"vn{int(host_num)}"


def _sudo(
    ssh: "SSHClient",
    command: str,
    *,
    sudo_password: str | None = None,
    timeout: float | None = 60.0,
) -> "CommandResult":
    """Run ``command`` as root via sudo (password on stdin when provided)."""
    quoted = shell_quote(command)
    if sudo_password:
        return ssh.run(
            f"sudo -S -p '' -- sh -c {quoted}",
            timeout=timeout,
            stdin=sudo_password,
        )
    return ssh.run(f"sudo -n -- sh -c {quoted}", timeout=timeout)


def _empty_ip_map() -> dict[str, Any]:
    return {
        "version": 1,
        "bridge": FAKE_BRIDGE,
        "subnet": FAKE_SUBNET,
        "gateway_ip": FAKE_GATEWAY_IP,
        "devices": {},
    }


def _read_ip_map(ssh: "SSHClient", paths: GatewayPaths) -> dict[str, Any]:
    try:
        raw = ssh.read_text(paths.fake_ip_map)
    except FileNotFoundError:
        return _empty_ip_map()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _empty_ip_map()
    if not isinstance(data, dict):
        return _empty_ip_map()
    devices = data.get("devices")
    if not isinstance(devices, dict):
        data["devices"] = {}
    data.setdefault("version", 1)
    data.setdefault("bridge", FAKE_BRIDGE)
    data.setdefault("subnet", FAKE_SUBNET)
    data.setdefault("gateway_ip", FAKE_GATEWAY_IP)
    return data


def _write_ip_map(ssh: "SSHClient", paths: GatewayPaths, data: dict[str, Any]) -> None:
    ssh.run(f"mkdir -p {shell_quote(paths.fake_dir)}")
    body = json.dumps(data, indent=2, sort_keys=True) + "\n"
    ssh.write_text(paths.fake_ip_map, body, mode=0o644)


def _used_host_nums(ip_map: dict[str, Any]) -> set[int]:
    used: set[int] = set()
    devices = ip_map.get("devices") or {}
    if not isinstance(devices, dict):
        return used
    for entry in devices.values():
        if not isinstance(entry, dict):
            continue
        if "host_num" in entry:
            try:
                used.add(int(entry["host_num"]))
                continue
            except (TypeError, ValueError):
                pass
        ip = entry.get("ip")
        if isinstance(ip, str) and ip:
            try:
                host = int(ipaddress.ip_address(ip)) & 0xFF
                if FAKE_FIRST_HOST <= host <= FAKE_LAST_HOST:
                    used.add(host)
            except ValueError:
                continue
    return used


def _allocation_from_entry(device_id: str, entry: dict[str, Any]) -> FakeAllocation:
    host_num = int(entry["host_num"])
    return FakeAllocation(
        device_id=device_id,
        ip=str(entry["ip"]),
        host_num=host_num,
        host_if=str(entry.get("host_if") or host_if_name(host_num)),
        ns_if=str(entry.get("ns_if") or ns_if_name(host_num)),
        netns=str(entry.get("netns") or netns_name(device_id)),
        unit=str(entry.get("unit") or unit_instance(device_id)),
        bridge=str(entry.get("bridge") or FAKE_BRIDGE),
    )


def ensure_fake_bridge(
    ssh: "SSHClient",
    *,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Create and bring up the ``iotgw-fake`` bridge with gateway IP if missing."""
    del install_root  # reserved for future path overrides
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    cmd = (
        f"if ! ip link show {shell_quote(FAKE_BRIDGE)} >/dev/null 2>&1; then "
        f"ip link add name {shell_quote(FAKE_BRIDGE)} type bridge && "
        f"ip addr add {shell_quote(FAKE_GATEWAY_IP + '/' + str(FAKE_PREFIXLEN))} "
        f"dev {shell_quote(FAKE_BRIDGE)}; "
        f"fi && "
        f"ip link set {shell_quote(FAKE_BRIDGE)} up"
    )
    result = _sudo(ssh, cmd, sudo_password=sudo_password, timeout=60.0)
    if result.exit_code != 0:
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message=(
                "failed to ensure fake bridge: "
                + (result.stderr or result.stdout or "").strip()[:300]
            ),
            details={"bridge": FAKE_BRIDGE},
        )
    ssh.run(f"mkdir -p {shell_quote(paths.fake_dir)}")
    ip_map = _read_ip_map(ssh, paths)
    if not ssh.exists(paths.fake_ip_map):
        _write_ip_map(ssh, paths, ip_map)
    return FakePlaybookResult(
        ok=True,
        message=f"bridge {FAKE_BRIDGE} ready ({FAKE_GATEWAY_IP}/{FAKE_PREFIXLEN})",
        details={
            "bridge": FAKE_BRIDGE,
            "gateway_ip": FAKE_GATEWAY_IP,
            "subnet": FAKE_SUBNET,
        },
    )


def allocate_fake_ip(
    ssh: "SSHClient",
    device_id: str,
    *,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakeAllocation:
    """Reserve the next free ``10.255.0.N`` for ``device_id`` (idempotent)."""
    del install_root
    device_id = validate_user_id(device_id)
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    ssh.run(f"mkdir -p {shell_quote(paths.fake_dir)}")
    ip_map = _read_ip_map(ssh, paths)
    devices = ip_map.setdefault("devices", {})
    existing = devices.get(device_id)
    if isinstance(existing, dict) and existing.get("ip") and existing.get("host_num"):
        return _allocation_from_entry(device_id, existing)

    used = _used_host_nums(ip_map)
    host_num: int | None = None
    for n in range(FAKE_FIRST_HOST, FAKE_LAST_HOST + 1):
        if n not in used:
            host_num = n
            break
    if host_num is None:
        raise RuntimeError(
            f"fake sensor subnet exhausted ({FAKE_SUBNET}; "
            f"hosts {FAKE_FIRST_HOST}–{FAKE_LAST_HOST})"
        )

    ip = f"10.255.0.{host_num}"
    entry = {
        "ip": ip,
        "host_num": host_num,
        "host_if": host_if_name(host_num),
        "ns_if": ns_if_name(host_num),
        "netns": netns_name(device_id),
        "unit": unit_instance(device_id),
        "bridge": FAKE_BRIDGE,
    }
    devices[device_id] = entry
    _write_ip_map(ssh, paths, ip_map)
    return _allocation_from_entry(device_id, entry)


def create_netns(
    ssh: "SSHClient",
    device_id: str,
    ip: str | None = None,
    *,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Create netns + veth pair for ``device_id`` and attach to the fake bridge."""
    del install_root
    device_id = validate_user_id(device_id)
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    bridge = ensure_fake_bridge(
        ssh, sudo_password=sudo_password, data_dir=paths.data_dir
    )
    if not bridge.ok:
        return bridge

    alloc = allocate_fake_ip(ssh, device_id, data_dir=paths.data_dir)
    if ip is not None and ip != alloc.ip:
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message=f"IP mismatch for {device_id}: allocated {alloc.ip}, requested {ip}",
            details={"allocation": alloc.__dict__},
        )

    # Idempotent: tear down stale links/ns with the same names, then recreate.
    setup = (
        f"ip netns del {shell_quote(alloc.netns)} 2>/dev/null || true; "
        f"ip link del {shell_quote(alloc.host_if)} 2>/dev/null || true; "
        f"ip netns add {shell_quote(alloc.netns)} && "
        f"ip link add {shell_quote(alloc.host_if)} type veth "
        f"peer name {shell_quote(alloc.ns_if)} && "
        f"ip link set {shell_quote(alloc.ns_if)} "
        f"netns {shell_quote(alloc.netns)} && "
        f"ip link set {shell_quote(alloc.host_if)} master {shell_quote(alloc.bridge)} && "
        f"ip link set {shell_quote(alloc.host_if)} up && "
        f"ip -n {shell_quote(alloc.netns)} addr add "
        f"{shell_quote(alloc.ip + '/' + str(FAKE_PREFIXLEN))} "
        f"dev {shell_quote(alloc.ns_if)} && "
        f"ip -n {shell_quote(alloc.netns)} link set {shell_quote(alloc.ns_if)} up && "
        f"ip -n {shell_quote(alloc.netns)} link set lo up && "
        f"ip -n {shell_quote(alloc.netns)} route replace default "
        f"via {shell_quote(FAKE_GATEWAY_IP)}"
    )
    result = _sudo(ssh, setup, sudo_password=sudo_password, timeout=90.0)
    if result.exit_code != 0:
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message=(
                "failed to create fake netns: "
                + (result.stderr or result.stdout or "").strip()[:300]
            ),
            details={"allocation": alloc.__dict__},
        )
    return FakePlaybookResult(
        ok=True,
        message=f"netns {alloc.netns} ready ({alloc.ip})",
        details={"allocation": alloc.__dict__},
    )


def ensure_fake_unit_installed(
    ssh: "SSHClient",
    *,
    sudo_password: str | None = None,
    unit_body: str | None = None,
) -> FakePlaybookResult:
    """Install the ``iotgw-fake@.service`` template and daemon-reload."""
    body = unit_body if unit_body is not None else FAKE_UNIT_BODY
    remote_tmp = "/tmp/iotgw-fake@.service"
    ssh.write_text(remote_tmp, body if body.endswith("\n") else body + "\n", mode=0o644)
    result = _sudo(
        ssh,
        f"cp {shell_quote(remote_tmp)} /etc/systemd/system/{FAKE_UNIT_TEMPLATE} && "
        f"chmod 644 /etc/systemd/system/{FAKE_UNIT_TEMPLATE} && "
        "systemctl daemon-reload",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    ssh.run(f"rm -f {shell_quote(remote_tmp)}")
    if result.exit_code != 0:
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message=(
                "failed to install fake unit template: "
                + (result.stderr or result.stdout or "").strip()[:300]
            ),
        )
    return FakePlaybookResult(
        ok=True,
        message=f"unit template {FAKE_UNIT_TEMPLATE} installed",
        details={"unit_template": FAKE_UNIT_TEMPLATE},
    )


def ensure_fake_runtime(
    ssh: "SSHClient",
    *,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Ensure bridge + unit template exist (lazy first-fake / re-provision hook)."""
    bridge = ensure_fake_bridge(
        ssh,
        sudo_password=sudo_password,
        install_root=install_root,
        data_dir=data_dir,
    )
    if not bridge.ok:
        return bridge
    unit = ensure_fake_unit_installed(ssh, sudo_password=sudo_password)
    if not unit.ok:
        return unit
    return FakePlaybookResult(
        ok=True,
        message="fake sensor runtime ready",
        details={**bridge.details, **unit.details},
    )


def _normalize_behaviors(behaviors: dict[str, Any] | None) -> dict[str, bool]:
    out = dict(DEFAULT_BEHAVIORS)
    if not behaviors:
        return out
    for key in DEFAULT_BEHAVIORS:
        if key in behaviors:
            out[key] = bool(behaviors[key])
    return out


def install_fake_files(
    ssh: "SSHClient",
    device_id: str,
    *,
    config: dict[str, Any],
    payload: Any = None,
    ca_pem: bytes | str | None = None,
    client_crt_pem: bytes | str | None = None,
    client_key_pem: bytes | str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Write config/payload (and optional certs) under ``fake/<device_id>/``."""
    del install_root
    device_id = validate_user_id(device_id)
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    device_dir = paths.fake_device_dir(device_id)
    certs_dir = paths.fake_certs_dir(device_id)
    ssh.run(f"mkdir -p {shell_quote(certs_dir)}")

    cfg = dict(config)
    cfg.setdefault("device_id", device_id)
    cfg.setdefault("broker_host", FAKE_GATEWAY_IP)
    cfg.setdefault("broker_port", DEFAULT_BROKER_PORT)
    cfg.setdefault("mqtt_user", device_id)
    cfg.setdefault("topic", f"sensors/{device_id}/process")
    cfg.setdefault("send_interval_ms", 1000)
    cfg["behaviors"] = _normalize_behaviors(
        cfg.get("behaviors") if isinstance(cfg.get("behaviors"), dict) else None
    )
    ssh.write_text(
        paths.fake_config_path(device_id),
        json.dumps(cfg, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )

    if payload is None:
        payload_obj: Any = {"device_id": device_id, "hello": 1}
    elif isinstance(payload, (bytes, bytearray)):
        payload_obj = json.loads(payload.decode("utf-8"))
    elif isinstance(payload, str):
        payload_obj = json.loads(payload) if payload.strip() else {"hello": 1}
    else:
        payload_obj = payload
    ssh.write_text(
        paths.fake_payload_path(device_id),
        json.dumps(payload_obj, indent=2, ensure_ascii=False) + "\n",
        mode=0o644,
    )

    if ca_pem is not None and client_crt_pem is not None and client_key_pem is not None:
        feed = feed_fake_certs(
            ssh,
            device_id,
            ca_pem=ca_pem,
            client_crt_pem=client_crt_pem,
            client_key_pem=client_key_pem,
            restart=False,
            data_dir=paths.data_dir,
        )
        if not feed.ok:
            return feed

    return FakePlaybookResult(
        ok=True,
        message=f"fake files installed under {device_dir}",
        details={
            "device_dir": device_dir,
            "config": paths.fake_config_path(device_id),
            "payload": paths.fake_payload_path(device_id),
        },
    )


def feed_fake_certs(
    ssh: "SSHClient",
    device_id: str,
    *,
    ca_pem: bytes | str,
    client_crt_pem: bytes | str,
    client_key_pem: bytes | str,
    restart: bool = True,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Atomically write mTLS material into ``fake/<id>/certs`` and optionally restart."""
    del install_root
    device_id = validate_user_id(device_id)
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    certs_dir = paths.fake_certs_dir(device_id)
    ssh.run(f"mkdir -p {shell_quote(certs_dir)}")

    def _as_bytes(value: bytes | str) -> bytes:
        if isinstance(value, bytes):
            return value
        return value.encode("utf-8")

    ca_b = _as_bytes(ca_pem)
    crt_b = _as_bytes(client_crt_pem)
    key_b = _as_bytes(client_key_pem)
    if not ca_b.strip() or not crt_b.strip() or not key_b.strip():
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message="feed_fake_certs requires non-empty ca/client cert/key PEM",
        )

    # SSHClient.write_bytes already writes via temp + rename (atomic per file).
    ssh.write_bytes(f"{certs_dir}/ca.crt", ca_b, mode=0o644)
    ssh.write_bytes(f"{certs_dir}/client.crt", crt_b, mode=0o644)
    ssh.write_bytes(f"{certs_dir}/client.key", key_b, mode=0o600)
    ssh.run(
        f"chmod 644 {shell_quote(certs_dir + '/ca.crt')} "
        f"{shell_quote(certs_dir + '/client.crt')} && "
        f"chmod 600 {shell_quote(certs_dir + '/client.key')}"
    )

    details: dict[str, Any] = {
        "certs_dir": certs_dir,
        "ca_crt": f"{certs_dir}/ca.crt",
        "client_crt": f"{certs_dir}/client.crt",
        "client_key": f"{certs_dir}/client.key",
    }
    if restart:
        restarted = restart_fake_unit(
            ssh, device_id, sudo_password=sudo_password, data_dir=paths.data_dir
        )
        details["restart"] = restarted.details
        if not restarted.ok:
            return FakePlaybookResult(
                ok=False,
                status="degraded",
                message=(
                    "certs written but unit restart failed: " + restarted.message
                ),
                details=details,
            )
    return FakePlaybookResult(
        ok=True,
        message=f"fed certs for {device_id}",
        details=details,
    )


def update_fake_config(
    ssh: "SSHClient",
    device_id: str,
    *,
    updates: dict[str, Any],
    restart: bool = True,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Merge keys into ``config.json`` (behaviors shallow-merged) and optionally restart."""
    del install_root
    device_id = validate_user_id(device_id)
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    cfg_path = paths.fake_config_path(device_id)
    try:
        current = json.loads(ssh.read_text(cfg_path))
    except FileNotFoundError:
        current = {"device_id": device_id}
    except json.JSONDecodeError:
        current = {"device_id": device_id}
    if not isinstance(current, dict):
        current = {"device_id": device_id}

    merged = dict(current)
    for key, value in updates.items():
        if key == "behaviors" and isinstance(value, dict):
            prev = merged.get("behaviors") if isinstance(merged.get("behaviors"), dict) else {}
            merged["behaviors"] = _normalize_behaviors({**prev, **value})
        else:
            merged[key] = value
    if "behaviors" not in merged:
        merged["behaviors"] = _normalize_behaviors(None)
    else:
        merged["behaviors"] = _normalize_behaviors(
            merged["behaviors"] if isinstance(merged["behaviors"], dict) else None
        )

    ssh.write_text(
        cfg_path,
        json.dumps(merged, indent=2, sort_keys=True) + "\n",
        mode=0o600,
    )
    details: dict[str, Any] = {"config": cfg_path, "merged_keys": sorted(updates.keys())}
    if restart:
        restarted = restart_fake_unit(
            ssh, device_id, sudo_password=sudo_password, data_dir=paths.data_dir
        )
        details["restart"] = restarted.details
        if not restarted.ok:
            return FakePlaybookResult(
                ok=False,
                status="degraded",
                message="config written but unit restart failed: " + restarted.message,
                details=details,
            )
    return FakePlaybookResult(ok=True, message=f"updated config for {device_id}", details=details)


def enable_and_start_unit(
    ssh: "SSHClient",
    device_id: str,
    *,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Enable and start ``iotgw-fake@<device_id>``."""
    del install_root, data_dir
    device_id = validate_user_id(device_id)
    unit = unit_instance(device_id)
    result = _sudo(
        ssh,
        f"systemctl enable {shell_quote(unit)} && "
        f"systemctl restart {shell_quote(unit)}",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if result.exit_code != 0:
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message=(
                f"failed to start {unit}: "
                + (result.stderr or result.stdout or "").strip()[:300]
            ),
            details={"unit": unit},
        )
    return FakePlaybookResult(
        ok=True,
        message=f"{unit} started",
        details={"unit": unit, "action": "enable+restart"},
    )


def stop_fake_unit(
    ssh: "SSHClient",
    device_id: str,
    *,
    sudo_password: str | None = None,
) -> FakePlaybookResult:
    device_id = validate_user_id(device_id)
    unit = unit_instance(device_id)
    result = _sudo(
        ssh,
        f"systemctl stop {shell_quote(unit)} 2>/dev/null || true",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if result.exit_code != 0:
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message=(
                f"failed to stop {unit}: "
                + (result.stderr or result.stdout or "").strip()[:300]
            ),
            details={"unit": unit},
        )
    return FakePlaybookResult(
        ok=True,
        message=f"{unit} stopped",
        details={"unit": unit, "action": "stop"},
    )


def restart_fake_unit(
    ssh: "SSHClient",
    device_id: str,
    *,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    del install_root, data_dir
    device_id = validate_user_id(device_id)
    unit = unit_instance(device_id)
    result = _sudo(
        ssh,
        f"systemctl restart {shell_quote(unit)}",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if result.exit_code != 0:
        return FakePlaybookResult(
            ok=False,
            status="failed",
            message=(
                f"failed to restart {unit}: "
                + (result.stderr or result.stdout or "").strip()[:300]
            ),
            details={"unit": unit},
        )
    return FakePlaybookResult(
        ok=True,
        message=f"{unit} restarted",
        details={"unit": unit, "action": "restart"},
    )


def teardown_fake(
    ssh: "SSHClient",
    device_id: str,
    *,
    sudo_password: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> FakePlaybookResult:
    """Stop unit, delete netns/veth, remove files, free IP allocation."""
    del install_root
    device_id = validate_user_id(device_id)
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    ip_map = _read_ip_map(ssh, paths)
    devices = ip_map.get("devices") if isinstance(ip_map.get("devices"), dict) else {}
    entry = devices.get(device_id) if isinstance(devices, dict) else None
    if isinstance(entry, dict) and entry.get("host_num") is not None:
        alloc = _allocation_from_entry(device_id, entry)
    else:
        # Best-effort names when map entry is missing.
        alloc = FakeAllocation(
            device_id=device_id,
            ip="",
            host_num=0,
            host_if="",
            ns_if="",
            netns=netns_name(device_id),
            unit=unit_instance(device_id),
        )

    cleanup_parts = [
        f"systemctl stop {shell_quote(alloc.unit)} 2>/dev/null || true",
        f"systemctl disable {shell_quote(alloc.unit)} 2>/dev/null || true",
    ]
    if alloc.host_if:
        cleanup_parts.append(
            f"ip link del {shell_quote(alloc.host_if)} 2>/dev/null || true"
        )
    cleanup_parts.append(
        f"ip netns del {shell_quote(alloc.netns)} 2>/dev/null || true"
    )
    result = _sudo(
        ssh,
        "; ".join(cleanup_parts),
        sudo_password=sudo_password,
        timeout=90.0,
    )
    # Always try to remove files + free IP even if some sudo steps failed.
    device_dir = paths.fake_device_dir(device_id)
    ssh.run(f"rm -rf {shell_quote(device_dir)}")
    if isinstance(devices, dict) and device_id in devices:
        devices.pop(device_id, None)
        ip_map["devices"] = devices
        _write_ip_map(ssh, paths, ip_map)

    if result.exit_code != 0:
        return FakePlaybookResult(
            ok=False,
            status="degraded",
            message=(
                "teardown partially failed: "
                + (result.stderr or result.stdout or "").strip()[:300]
            ),
            details={"allocation": alloc.__dict__, "removed_dir": device_dir},
        )
    return FakePlaybookResult(
        ok=True,
        message=f"torn down fake sensor {device_id}",
        details={"allocation": alloc.__dict__, "removed_dir": device_dir},
    )


def read_fake_allocation(
    ssh: "SSHClient",
    device_id: str,
    *,
    data_dir: str | None = None,
) -> Optional[FakeAllocation]:
    """Return the persisted allocation for ``device_id``, or None."""
    device_id = validate_user_id(device_id)
    paths = _paths(DEFAULT_INSTALL_ROOT, data_dir)
    ip_map = _read_ip_map(ssh, paths)
    devices = ip_map.get("devices") or {}
    if not isinstance(devices, dict):
        return None
    entry = devices.get(device_id)
    if not isinstance(entry, dict) or not entry.get("ip"):
        return None
    return _allocation_from_entry(device_id, entry)
