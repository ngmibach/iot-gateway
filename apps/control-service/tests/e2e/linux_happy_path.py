"""Documented Linux register/provision happy path (CI mocks; live Pi optional).

Happy path (operator PC → gateway over SSH)
-------------------------------------------
1. Discover / enter gateway IP (mDNS agent optional; first install uses manual IP).
2. SSH with device password or key.
3. Provision (agent-only, no Docker on the gateway):
   a. Preflight: free disk ≥ 2 GiB under install root parent
   b. apt mosquitto + python3-venv (sudo)
   c. Configure system Mosquitto conf.d + agent data dirs
   d. Upload monolithic agent to ``/opt/iot-gateway-agent``
   e. venv + systemd unit; probe ``:9139/v1/health`` and MQTT ``:1883``
4. Register device via control API / playbook:
   ACL + hashed mosquitto password + CSR/sign mTLS cert; systemctl reload mosquitto
5. Open Monitoring / Actions dashboard (desktop app)

CI: this module drives FakeSSH / mocked steps — no real Pi.
Live (manual): see ``run_live_checklist()`` docstring; requires reachable host +
``provisioner`` package on PYTHONPATH.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from actions.csr import generate_client_key_and_csr
from actions.playbooks import RegisterResult, register_device
from actions.ssh import CommandResult
from tests.cert_helpers import local_self_sign_for_tests
from tests.fake_ssh import FakeSSH

ROOT = "/opt/iot-gateway-agent"
DATA = "/var/lib/iot-gateway-agent"
ACL = f"{DATA}/mosquitto/acl"
PW = f"{DATA}/mosquitto/passwords"
CA = f"{DATA}/certs/ca.crt"

PROVISION_STEPS = (
    "preflight_disk",
    "ensure_mosquitto",
    "configure_mosquitto",
    "upload_agent",
    "venv_deps",
    "systemd_enable",
    "probe_agent_health",
)


@dataclass
class MockProvisionResult:
    ok: bool
    install_root: str = ROOT
    steps_completed: list[str] = field(default_factory=list)
    probes: dict[str, str] = field(default_factory=dict)
    agent_installed: bool = False
    notes: list[str] = field(default_factory=list)
    message: str = ""


def _base_gateway_files() -> dict[str, str]:
    """Seed FakeSSH with files the register playbook expects."""
    return {
        ACL: (
            "user nodered\n"
            "topic readwrite #\n"
            "\n"
            "user sensor1\n"
            "topic readwrite sensors/sensor1/#\n"
            "topic read alerts/+\n"
            "\n"
            "user anonymous\n"
            "topic none\n"
        ),
        PW: "nodered:$7$1000$aaa$bbb\nsensor1:$7$1000$ccc$ddd\n",
        CA: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        f"{DATA}/certs/ca.key": (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n"
            "-----END ENCRYPTED PRIVATE KEY-----\n"
        ),
    }


def mock_provision(
    ssh: FakeSSH,
    *,
    gateway_ip: str,
    monitoring_ip: str,
    install_root: str = ROOT,
    fail_at: Optional[str] = None,
) -> MockProvisionResult:
    """Simulate agent-only provisioner happy path against FakeSSH."""
    completed: list[str] = []
    notes: list[str] = []
    probes: dict[str, str] = {}

    def step(name: str, fn: Callable[[], None]) -> None:
        if fail_at == name:
            raise RuntimeError(f"injected failure at {name}")
        fn()
        completed.append(name)

    def preflight_disk() -> None:
        ssh.run(f"df -Pk {install_root}")

    def ensure_mosquitto() -> None:
        ssh.run("command -v mosquitto || test -x /usr/sbin/mosquitto")
        notes.append("mosquitto present")

    def configure_mosquitto() -> None:
        ssh.run("systemctl enable --now mosquitto")
        notes.append("system mosquitto configured")

    def upload_agent() -> None:
        for path, content in _base_gateway_files().items():
            if path not in ssh.files:
                ssh.write_text(path, content)
        ssh.write_text(
            f"{install_root}/iot_gateway_agent/__init__.py",
            "# agent\n",
        )
        notes.append(f"uploaded agent to {install_root}")
        notes.append(f"GATEWAY_IP={gateway_ip} MONITORING_IP={monitoring_ip}")

    def venv_deps() -> None:
        ssh.run(f"python3 -m venv {install_root}/.venv")
        notes.append("python venv + agent deps installed")

    def systemd_enable() -> None:
        ssh.run("systemctl enable --now iot-gateway-agent")
        notes.append("systemd iot-gateway-agent enabled")

    def probe_agent() -> None:
        ssh.run("curl -sf --max-time 5 http://127.0.0.1:9139/v1/health")
        probes["agent_health"] = "ok"
        probes["mqtt"] = f"{gateway_ip}:1883"
        notes.append("agent installed")

    try:
        step("preflight_disk", preflight_disk)
        step("ensure_mosquitto", ensure_mosquitto)
        step("configure_mosquitto", configure_mosquitto)
        step("upload_agent", upload_agent)
        step("venv_deps", venv_deps)
        step("systemd_enable", systemd_enable)
        step("probe_agent_health", probe_agent)
    except Exception as exc:
        return MockProvisionResult(
            ok=False,
            install_root=install_root,
            steps_completed=completed,
            probes=probes,
            notes=notes,
            message=str(exc),
        )

    return MockProvisionResult(
        ok=True,
        install_root=install_root,
        steps_completed=completed,
        probes=probes,
        agent_installed=True,
        notes=notes,
        message="provision ok",
    )


def _register_sign_handler(ssh: FakeSSH, signed_pem: bytes):
    def run_handler(cmd: str) -> CommandResult:
        if "openssl x509 -req" in cmd:
            parts = cmd.split()
            out_path = parts[parts.index("-out") + 1].strip("'")
            ssh.files[out_path] = signed_pem
        return CommandResult(argv=cmd, exit_code=0, stdout="", stderr="")

    return run_handler


def mock_register(
    ssh: FakeSSH,
    *,
    user_id: str = "sensor9",
    password: str = "hunter2-ok",
    ip: str = "10.0.0.9",
    ca_passphrase: str = "test-ca-secret",
) -> RegisterResult:
    """Run real register_device playbook against FakeSSH."""
    mat = generate_client_key_and_csr(user_id)
    signed = local_self_sign_for_tests(mat)
    ssh._run_handler = _register_sign_handler(ssh, signed.client_crt_pem)
    return register_device(
        ssh,  # type: ignore[arg-type]
        user_id=user_id,
        password=password,
        ip=ip,
        topic_rw=f"sensors/{user_id}/#",
        topic_r="alerts/+",
        ca_passphrase=ca_passphrase,
        key_material=mat,
    )


def run_linux_happy_path_mocked(
    *,
    gateway_ip: str = "192.168.1.50",
    monitoring_ip: str = "192.168.1.20",
    user_id: str = "sensor9",
) -> dict[str, Any]:
    """Full mocked discover→provision→register sequence for CI."""
    ssh = FakeSSH()
    prov = mock_provision(
        ssh, gateway_ip=gateway_ip, monitoring_ip=monitoring_ip
    )
    if not prov.ok:
        return {"ok": False, "phase": "provision", "provision": prov}

    reg = mock_register(ssh, user_id=user_id)
    return {
        "ok": bool(prov.ok and reg.ok),
        "phase": "done" if reg.ok else "register",
        "provision": prov,
        "register": reg,
        "ssh_commands": list(ssh.commands),
        "acl_has_user": f"user {user_id}" in ssh.read_text(ACL),
        "mosquitto_reloaded": any(
            "systemctl reload mosquitto" in c or "systemctl restart mosquitto" in c
            for c in ssh.commands
        ),
        "password_not_plaintext": "hunter2" not in ssh.read_text(PW),
        "agent_installed": prov.agent_installed,
    }


def run_live_checklist() -> str:
    """Return the manual live-Pi checklist (not executed in CI)."""
    return """
# Live Linux E2E (manual / future CI with a Pi runner)
# Requires: provisioner package, SSH to gateway. No Docker on the device.

export GATEWAY_IP=192.168.x.y
export MONITORING_IP=192.168.x.z
export IOTGW_SSH_PASSWORD=...   # or IOTGW_SSH_KEY=
export IOTGW_CA_PASSPHRASE=...

# 1) Provision (agent-only)
PYTHONPATH=apps/control-service python -m provisioner provision \\
  --host "$GATEWAY_IP" --user ubuntu \\
  --gateway-ip "$GATEWAY_IP" --monitoring-ip "$MONITORING_IP" \\
  --sudo-password "$SUDO_PASSWORD"

# 2) Control API + register
PYTHONPATH=apps/control-service python -m api
# Then: POST /api/v1/gateways/{gid}/devices

# 3) Confirm agent + system mosquitto
ssh ubuntu@$GATEWAY_IP 'systemctl is-active iot-gateway-agent mosquitto && curl -sf http://127.0.0.1:9139/v1/health'
"""
