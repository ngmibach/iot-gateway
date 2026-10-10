"""Docker-free gateway install: native mosquitto + monolithic Python agent."""

from __future__ import annotations

import shlex
import time
from pathlib import Path
from typing import Optional

from .ssh import SSHSession

DEFAULT_AGENT_ROOT = "/opt/iot-gateway-agent"
DEFAULT_AGENT_DATA = "/var/lib/iot-gateway-agent"


class AgentInstallError(RuntimeError):
    """Monolithic agent provision failed."""


def ensure_mosquitto(ssh: SSHSession) -> str:
    """Install mosquitto via apt if ``mosquitto`` is missing (not Docker)."""
    check = ssh.run("command -v mosquitto >/dev/null && echo OK", timeout=15.0)
    if check.ok and "OK" in check.stdout:
        return "mosquitto already present"
    # Noninteractive apt — passwordless sudo preferred; fall back to sudo -n.
    cmds = [
        "sudo -n true",
        "sudo -n apt-get update -qq",
        "sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mosquitto mosquitto-clients",
    ]
    for cmd in cmds:
        result = ssh.run(cmd, timeout=300.0)
        if not result.ok and "sudo -n true" in cmd:
            raise AgentInstallError(
                "sudo without password is required to install mosquitto on the gateway. "
                "Enable NOPASSWD for this user or install mosquitto once, then re-run provision."
            )
        if not result.ok and "apt-get" in cmd:
            raise AgentInstallError(
                f"apt install mosquitto failed: {result.stderr or result.stdout}"
            )
    check2 = ssh.run("command -v mosquitto >/dev/null && echo OK", timeout=15.0)
    if not check2.ok or "OK" not in check2.stdout:
        raise AgentInstallError("mosquitto still missing after apt install")
    return "installed mosquitto via apt"


def _upload_agent_tree(ssh: SSHSession, agent_src: Path, remote_root: str) -> None:
    """Upload iot_gateway_agent package + requirements + unit file."""
    if not agent_src.is_dir():
        raise AgentInstallError(f"agent source missing: {agent_src}")
    ssh.run(f"sudo -n mkdir -p {shlex.quote(remote_root)}", timeout=30.0)
    ssh.run(
        f"sudo -n chown -R $(id -u):$(id -g) {shlex.quote(remote_root)}",
        timeout=30.0,
    )
    # Upload package directory
    pkg = agent_src / "iot_gateway_agent"
    if not pkg.is_dir():
        raise AgentInstallError(f"missing package dir: {pkg}")
    ssh.upload_tree(pkg, f"{remote_root}/iot_gateway_agent")
    req = agent_src / "requirements.txt"
    if req.is_file():
        ssh.upload_file(req, f"{remote_root}/requirements.txt")
    unit = agent_src / "iot-gateway-agent.service"
    if unit.is_file():
        ssh.upload_file(unit, f"{remote_root}/iot-gateway-agent.service")


def _ensure_venv(ssh: SSHSession, remote_root: str) -> None:
    py = ssh.run("command -v python3", timeout=15.0)
    if not py.ok:
        raise AgentInstallError("python3 not found on gateway")
    venv = f"{remote_root}/venv"
    ssh.run(
        f"test -x {shlex.quote(venv)}/bin/python || python3 -m venv {shlex.quote(venv)}",
        timeout=120.0,
    )
    pip = f"{venv}/bin/pip"
    ssh.run(
        f"{shlex.quote(pip)} install -q -U pip && "
        f"{shlex.quote(pip)} install -q -r {shlex.quote(remote_root)}/requirements.txt",
        timeout=300.0,
    )


def _write_env(
    ssh: SSHSession,
    *,
    monitoring_ip: str,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> None:
    import tempfile

    content = (
        f"MONITORING_IP={monitoring_ip}\n"
        f"IOTGW_AGENT_DATA={data_dir}\n"
        f"LOKI_URL=http://{monitoring_ip}:3100\n"
    )
    with tempfile.NamedTemporaryFile(
        "w", suffix=".env", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(content)
        local = Path(tmp.name)
    try:
        remote = "/tmp/iotgw-agent.env"
        ssh.upload_file(local, remote, mode=0o644)
        ssh.run(
            f"sudo -n mkdir -p {shlex.quote(data_dir)} && "
            f"sudo -n mv {shlex.quote(remote)} /etc/iot-gateway-agent.env && "
            f"sudo -n chmod 644 /etc/iot-gateway-agent.env",
            timeout=30.0,
        )
    finally:
        local.unlink(missing_ok=True)


def _install_systemd(ssh: SSHSession, remote_root: str) -> None:
    unit_src = f"{remote_root}/iot-gateway-agent.service"
    ssh.run(
        f"sudo -n cp {shlex.quote(unit_src)} /etc/systemd/system/iot-gateway-agent.service && "
        "sudo -n systemctl daemon-reload && "
        "sudo -n systemctl enable --now iot-gateway-agent",
        timeout=60.0,
    )


def _probe_agent(ssh: SSHSession, *, port: int = 9139, retries: int = 15) -> None:
    for _ in range(retries):
        r = ssh.run(
            f"curl -fsS http://127.0.0.1:{port}/v1/health || true",
            timeout=10.0,
        )
        if r.ok and '"status":"ok"' in r.stdout.replace(" ", ""):
            return
        if r.ok and '"status": "ok"' in r.stdout:
            return
        time.sleep(1.0)
    raise AgentInstallError(
        f"agent /v1/health did not become ready on 127.0.0.1:{port}"
    )


def provision_monolithic_agent(
    ssh: SSHSession,
    *,
    monitoring_ip: str,
    gateway_ip: str,
    agent_src: Path,
    remote_root: str = DEFAULT_AGENT_ROOT,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> list[str]:
    """Install mosquitto (apt) + agent venv + systemd. Returns notes."""
    notes: list[str] = []
    notes.append(ensure_mosquitto(ssh))
    _upload_agent_tree(ssh, agent_src, remote_root)
    notes.append(f"uploaded agent to {remote_root}")
    _ensure_venv(ssh, remote_root)
    notes.append("python venv + agent deps installed")
    _write_env(ssh, monitoring_ip=monitoring_ip, data_dir=data_dir)
    _install_systemd(ssh, remote_root)
    notes.append("systemd iot-gateway-agent enabled")
    _probe_agent(ssh)
    notes.append(f"agent healthy; MQTT on gateway {gateway_ip}:1883, metrics :9139")
    return notes
