"""Auto prevent policy push and firewall quarantine lift on the gateway."""

from __future__ import annotations

import json
import shlex
import time
from typing import TYPE_CHECKING, Any

from .paths import DEFAULT_INSTALL_ROOT, GatewayPaths
from .playbooks import PlaybookResult, _paths
from .validate import validate_ip_or_cidr, validate_user_id

if TYPE_CHECKING:
    from .ssh import SSHClient

HELPER_REL = "bin/iotgw-auto-prevent"
POLICY_FILENAME = "auto_prevent.json"


def _sudo(
    ssh: "SSHClient",
    cmd: str,
    *,
    sudo_password: str | None,
    timeout: float = 60.0,
):
    from .fake_sensors import _sudo as fake_sudo

    return fake_sudo(ssh, cmd, sudo_password=sudo_password, timeout=timeout)


def _read_policy(ssh: "SSHClient", paths: GatewayPaths) -> dict[str, Any]:
    try:
        raw = ssh.read_text(paths.auto_prevent_policy)
    except FileNotFoundError:
        return {"devices": {}}
    except Exception:  # noqa: BLE001
        return {"devices": {}}
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {"devices": {}}
    if not isinstance(data, dict):
        return {"devices": {}}
    devices = data.get("devices")
    if not isinstance(devices, dict):
        data["devices"] = {}
    return data


def _write_policy(
    ssh: "SSHClient",
    paths: GatewayPaths,
    policy: dict[str, Any],
    *,
    sudo_password: str | None,
) -> None:
    body = json.dumps(policy, indent=2, sort_keys=True) + "\n"
    # Write via SFTP tmp then sudo mv (data dir is often root-owned).
    tmp_name = f"/tmp/iotgw-ap-{int(time.time() * 1000)}.json"
    ssh.write_text(tmp_name, body, mode=0o644)
    dest = shlex.quote(paths.auto_prevent_policy)
    parent = shlex.quote(f"{paths.data_dir}")
    cmd = (
        f"mkdir -p {parent} && "
        f"mv {shlex.quote(tmp_name)} {dest} && "
        f"chmod 644 {dest}"
    )
    result = _sudo(ssh, cmd, sudo_password=sudo_password, timeout=30.0)
    if not result.ok:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or "failed to write auto_prevent.json"
        )


def push_device_policy(
    ssh: "SSHClient",
    *,
    user_id: str,
    enabled: bool,
    limit: int,
    window_s: int,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    sudo_password: str | None = None,
) -> PlaybookResult:
    """Upsert one device into gateway ``auto_prevent.json`` for the agent."""
    try:
        user_id = validate_user_id(user_id)
        limit = max(1, min(int(limit), 100000))
        window_s = max(60, min(int(window_s), 86400))
        paths = _paths(install_root, data_dir)
        policy = _read_policy(ssh, paths)
        devices = policy.setdefault("devices", {})
        if not isinstance(devices, dict):
            devices = {}
            policy["devices"] = devices
        devices[user_id] = {
            "enabled": bool(enabled),
            "limit": limit,
            "window_s": window_s,
        }
        _write_policy(ssh, paths, policy, sudo_password=sudo_password)
        return PlaybookResult(
            ok=True,
            message="auto prevent policy saved on gateway",
            details={
                "user_id": user_id,
                "enabled": bool(enabled),
                "limit": limit,
                "window_s": window_s,
                "path": paths.auto_prevent_policy,
            },
        )
    except Exception as exc:  # noqa: BLE001
        return PlaybookResult(ok=False, status="failed", message=str(exc))


def lift_device_quarantine(
    ssh: "SSHClient",
    *,
    user_id: str,
    quarantine_ip: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    sudo_password: str | None = None,
) -> PlaybookResult:
    """Remove firewall DROP for a quarantined sensor IP via the agent helper."""
    try:
        user_id = validate_user_id(user_id)
        paths = _paths(install_root, data_dir)
        ip = (quarantine_ip or "").strip()
        if ip:
            # validate_ip_or_cidr accepts host IPs; reject networks for DROP lift.
            validate_ip_or_cidr(ip)
            if "/" in ip:
                raise ValueError("quarantine_ip must be a single host address")
        helper = f"{paths.install_root}/{HELPER_REL}"
        if ip:
            cmd = (
                f"test -x {shlex.quote(helper)} && "
                f"{shlex.quote(helper)} lift {shlex.quote(ip)} {shlex.quote(user_id)}"
            )
        else:
            cmd = (
                f"test -x {shlex.quote(helper)} && "
                f"{shlex.quote(helper)} lift-device {shlex.quote(user_id)}"
            )
        result = _sudo(ssh, cmd, sudo_password=sudo_password, timeout=45.0)
        # Helper may be missing on older agents — treat as soft failure with message.
        if not result.ok:
            # Fallback: best-effort clear state file entry so agent can re-arm.
            _clear_state_entry(
                ssh, paths, user_id, sudo_password=sudo_password
            )
            return PlaybookResult(
                ok=False,
                status="failed",
                message=(
                    result.stderr.strip()
                    or result.stdout.strip()
                    or "auto-prevent lift helper failed "
                    "(update/reinstall the gateway agent for firewall quarantine)"
                ),
                details={"helper": helper, "exit_code": result.exit_code},
            )
        return PlaybookResult(
            ok=True,
            message="auto prevent quarantine lifted",
            details={"user_id": user_id, "ip": ip or None},
        )
    except Exception as exc:  # noqa: BLE001
        return PlaybookResult(ok=False, status="failed", message=str(exc))


def _clear_state_entry(
    ssh: "SSHClient",
    paths: GatewayPaths,
    user_id: str,
    *,
    sudo_password: str | None,
) -> None:
    """Best-effort remove device from auto_prevent_state.json."""
    try:
        raw = ssh.read_text(paths.auto_prevent_state)
        data = json.loads(raw or "{}")
    except Exception:  # noqa: BLE001
        return
    if not isinstance(data, dict):
        return
    devices = data.get("devices")
    if not isinstance(devices, dict) or user_id not in devices:
        return
    devices.pop(user_id, None)
    try:
        _write_json_sudo(
            ssh,
            paths.auto_prevent_state,
            data,
            sudo_password=sudo_password,
        )
    except Exception:  # noqa: BLE001
        return


def _write_json_sudo(
    ssh: "SSHClient",
    dest: str,
    data: dict[str, Any],
    *,
    sudo_password: str | None,
) -> None:
    body = json.dumps(data, indent=2, sort_keys=True) + "\n"
    tmp_name = f"/tmp/iotgw-ap-state-{int(time.time() * 1000)}.json"
    ssh.write_text(tmp_name, body, mode=0o644)
    cmd = (
        f"mv {shlex.quote(tmp_name)} {shlex.quote(dest)} && "
        f"chmod 644 {shlex.quote(dest)}"
    )
    result = _sudo(ssh, cmd, sudo_password=sudo_password, timeout=30.0)
    if not result.ok:
        raise RuntimeError(result.stderr.strip() or "state write failed")


def build_policy_map_from_registry_devices(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build gateway policy file body from registry device rows."""
    from api.device_meta import auto_prevent_block, normalize_auto_prevent

    devices: dict[str, Any] = {}
    for row in rows:
        did = str(row.get("id") or "").strip()
        if not did:
            continue
        meta_raw = row.get("meta_json")
        block = auto_prevent_block(
            meta_raw if isinstance(meta_raw, dict) else None
        )
        if block is None and isinstance(meta_raw, str):
            from api.device_meta import parse_meta

            block = auto_prevent_block(parse_meta(meta_raw))
        if not block:
            continue
        norm = normalize_auto_prevent(block)
        devices[did] = {
            "enabled": bool(norm.get("enabled")),
            "limit": int(norm.get("limit") or 10),
            "window_s": int(norm.get("window_s") or 300),
        }
    return {"devices": devices}
