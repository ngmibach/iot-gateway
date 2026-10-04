"""Documented Linux register/provision happy path (CI mocks; live Pi optional).

Happy path (operator PC → gateway over SSH)
-------------------------------------------
1. Discover / enter gateway IP (mDNS agent optional; first install uses manual IP).
2. SSH with device password or key.
3. Provision:
   a. Preflight: ``docker info``, free disk ≥ 2 GiB under install root parent
   b. Optional ``docker load`` from ``--with-images`` tarball
   c. Backup existing ``/opt/iot-gateway`` → ``/opt/iot-gateway.bak-<epoch>``
   d. Stage + upload gateway bundle (templated GATEWAY_IP / MONITORING_IP)
   e. ``docker compose up -d`` (Node-RED is mandatory — K17)
   f. Probe node-exporter :9100, cAdvisor :8080, Loki :3100/ready from gateway
   g. Install gateway-agent last (optional until agent files present)
4. Register device via control API / playbook:
   ACL + hashed mosquitto password + HAProxy allow-list + CSR/sign mTLS cert
5. Open Monitoring / Actions dashboard (Streamlit Phase-0 or Tauri Phase-1)

CI: this module drives FakeSSH / mocked steps — no real Pi.
Live (manual): see ``run_live_checklist()`` docstring; requires reachable host +
``provisioner`` package (PR 5) on PYTHONPATH.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from actions.csr import generate_client_key_and_csr
from actions.playbooks import RegisterResult, register_device
from actions.ssh import CommandResult
from tests.cert_helpers import local_self_sign_for_tests
from tests.fake_ssh import FakeSSH

ROOT = "/opt/iot-gateway"
ACL = f"{ROOT}/mosquitto/config/acl"
PW = f"{ROOT}/mosquitto/config/passwords"
IPS = f"{ROOT}/haproxy/allowed-ips.txt"
CA = f"{ROOT}/certs/ca.crt"

PROVISION_STEPS = (
    "preflight_docker",
    "preflight_disk",
    "optional_image_load",
    "backup_existing",
    "stage_upload_bundle",
    "compose_up",
    "probe_exporters",
    "probe_loki_from_gateway",
    "install_agent_last",
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
        IPS: "10.0.0.1\n",
        CA: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n",
        f"{ROOT}/certs/ca.key": (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nX\n"
            "-----END ENCRYPTED PRIVATE KEY-----\n"
        ),
        f"{ROOT}/docker-compose.yaml": "services:\n  nodered:\n    image: nodered\n",
    }


def mock_provision(
    ssh: FakeSSH,
    *,
    gateway_ip: str,
    monitoring_ip: str,
    install_root: str = ROOT,
    with_images: bool = False,
    fail_at: Optional[str] = None,
) -> MockProvisionResult:
    """Simulate provisioner happy path against FakeSSH (no live Docker/SSH)."""
    completed: list[str] = []
    notes: list[str] = []
    probes: dict[str, str] = {}

    def step(name: str, fn: Callable[[], None]) -> None:
        if fail_at == name:
            raise RuntimeError(f"injected failure at {name}")
        fn()
        completed.append(name)

    def preflight_docker() -> None:
        r = ssh.run("docker info")
        if r.exit_code != 0:
            raise RuntimeError("docker not available")

    def preflight_disk() -> None:
        ssh.run(f"df -Pk {install_root}")

    def optional_image_load() -> None:
        if with_images:
            ssh.run("docker load -i /tmp/iotgw-images.tar")
            notes.append("loaded images tarball")
        else:
            notes.append("cold pull (no --with-images)")

    def backup_existing() -> None:
        if ssh.exists(install_root) or any(
            p.startswith(install_root + "/") for p in ssh.files
        ):
            bak = f"{install_root}.bak.mock"
            # Mark backup presence without cloning whole tree
            ssh.files[bak] = b"backup-marker"
            notes.append(f"backup={bak}")

    def stage_upload() -> None:
        # Ensure compose + Node-RED (K17) present after "upload"
        for path, content in _base_gateway_files().items():
            if path not in ssh.files:
                ssh.write_text(path, content)
        ssh.write_text(
            f"{install_root}/promtail/config/promtail-config.yaml",
            f"clients:\n  - url: http://{monitoring_ip}:3100/loki/api/v1/push\n",
        )
        notes.append(f"GATEWAY_IP={gateway_ip} MONITORING_IP={monitoring_ip}")

    def compose_up() -> None:
        ssh.run(
            f"docker compose -f {install_root}/docker-compose.yaml "
            "up -d --remove-orphans"
        )
        # Node-RED mandatory — assert compose file mentions it
        compose = ssh.read_text(f"{install_root}/docker-compose.yaml")
        if "nodered" not in compose.lower() and "node-red" not in compose.lower():
            raise RuntimeError("Node-RED missing from gateway compose (K17)")

    def probe_exporters() -> None:
        for port, name in ((9100, "node_exporter"), (8080, "cadvisor")):
            ssh.run(f"curl -sf --max-time 5 http://{gateway_ip}:{port}/metrics")
            probes[name] = "ok"

    def probe_loki() -> None:
        ssh.run(
            f"curl -sf --max-time 5 http://{monitoring_ip}:3100/ready"
        )
        probes["loki"] = "ok"

    def install_agent() -> None:
        agent_unit = f"{install_root}/agent/iot-gateway-agent.service"
        if agent_unit in ssh.files or ssh.exists(
            f"{install_root}/agent/docker-compose.agent.yaml"
        ):
            ssh.run("systemctl enable --now iot-gateway-agent || true")
            notes.append("agent installed")
            return
        notes.append("agent skipped (files not present)")

    try:
        step("preflight_docker", preflight_docker)
        step("preflight_disk", preflight_disk)
        step("optional_image_load", optional_image_load)
        step("backup_existing", backup_existing)
        step("stage_upload_bundle", stage_upload)
        step("compose_up", compose_up)
        step("probe_exporters", probe_exporters)
        step("probe_loki_from_gateway", probe_loki)
        step("install_agent_last", install_agent)
    except Exception as exc:
        return MockProvisionResult(
            ok=False,
            install_root=install_root,
            steps_completed=completed,
            probes=probes,
            notes=notes,
            message=str(exc),
        )

    agent_installed = any("agent installed" in n for n in notes)
    return MockProvisionResult(
        ok=True,
        install_root=install_root,
        steps_completed=completed,
        probes=probes,
        agent_installed=agent_installed,
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
        "allowlist_has_ip": "10.0.0.9" in ssh.read_text(IPS),
        "password_not_plaintext": "hunter2" not in ssh.read_text(PW),
        "nodered_in_compose": "nodered" in ssh.read_text(
            f"{ROOT}/docker-compose.yaml"
        ).lower(),
    }


def run_live_checklist() -> str:
    """Return the manual live-Pi checklist (not executed in CI)."""
    return """
# Live Linux E2E (manual / future CI with a Pi runner)
# Requires: provisioner package (PR 5), SSH to gateway, Docker on device.

export GATEWAY_IP=192.168.x.y
export MONITORING_IP=192.168.x.z
export IOTGW_SSH_PASSWORD=...   # or IOTGW_SSH_KEY=
export IOTGW_CA_PASSPHRASE=...

# 1) Provision
PYTHONPATH=apps/control-service python -m provisioner provision \\
  --host "$GATEWAY_IP" --user ubuntu \\
  --gateway-ip "$GATEWAY_IP" --monitoring-ip "$MONITORING_IP"

# 2) Control API + register
PYTHONPATH=apps/control-service python -m api
# Then: POST /api/v1/gateways/{gid}/devices  (or Streamlit Control Plane)

# 3) Confirm Node-RED container is up (mandatory K17)
ssh ubuntu@$GATEWAY_IP 'docker ps --format "{{.Names}}" | grep -i nodered'
"""
