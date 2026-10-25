"""Docker-free gateway install: native mosquitto + monolithic Python agent."""

from __future__ import annotations

import shlex
import tempfile
import time
from pathlib import Path
from typing import Optional

from .ssh import CommandResult, SSHSession

DEFAULT_AGENT_ROOT = "/opt/iot-gateway-agent"
DEFAULT_AGENT_DATA = "/var/lib/iot-gateway-agent"

# Packages installed once via apt (sudo). python3-venv is required for the agent venv.
_APT_PACKAGES = (
    "mosquitto",
    "mosquitto-clients",
    "python3-venv",
    "python3-pip",
)


class AgentInstallError(RuntimeError):
    """Monolithic agent provision failed."""


def sudo_run(
    ssh: SSHSession,
    command: str,
    *,
    sudo_password: str,
    timeout: float = 120.0,
) -> CommandResult:
    """Run ``command`` under ``sudo -S`` with the password on stdin (not argv).

    The remote shell must not see bare ``sudo cmd && other`` — only ``cmd`` would
    run as root. Wrap with ``sh -c`` so ``&&`` / ``;`` chains stay privileged.
    """
    if not sudo_password:
        raise AgentInstallError("sudo password is required for gateway package install")
    # -p '' suppresses the prompt so logs stay clean; -S reads password from stdin.
    # Everything after -- is the command argv, so VAR=value prefixes must use env(1),
    # e.g. ``env DEBIAN_FRONTEND=noninteractive apt-get …`` — not ``VAR=value cmd``.
    wrapped = f"sudo -S -p '' -- sh -c {shlex.quote(command)}"
    return ssh.run(wrapped, timeout=timeout, stdin=sudo_password)


def _mosquitto_present(ssh: SSHSession) -> bool:
    """True when the mosquitto broker binary is installed.

    Debian/Ubuntu put it in ``/usr/sbin/mosquitto``, which is often absent from a
    normal login PATH, so ``command -v mosquitto`` alone is not enough.

    Use a single ``if …; then echo OK; fi`` so a missing ``/usr/bin`` path does not
    make the remote shell exit non-zero after a successful ``/usr/sbin`` hit.
    """
    check = ssh.run(
        "if command -v mosquitto >/dev/null 2>&1 || "
        "test -x /usr/sbin/mosquitto || "
        "test -x /usr/bin/mosquitto; then echo OK; fi",
        timeout=15.0,
    )
    return "OK" in (check.stdout or "")


def ensure_mosquitto(ssh: SSHSession, *, sudo_password: str) -> str:
    """Install mosquitto + python3-venv via apt using the UI-provided sudo password."""
    venv_ok = ssh.run(
        "python3 -c 'import ensurepip, venv' >/dev/null 2>&1 && echo OK",
        timeout=15.0,
    )
    if _mosquitto_present(ssh) and venv_ok.ok and "OK" in venv_ok.stdout:
        return "mosquitto and python3-venv already present"

    # Verify sudo password early with a cheap command.
    probe = sudo_run(ssh, "true", sudo_password=sudo_password, timeout=30.0)
    if not probe.ok:
        raise AgentInstallError(
            "sudo password rejected on the gateway "
            f"(exit {probe.exit_code}): {(probe.stderr or probe.stdout or '').strip()[:200]}"
        )

    pkgs = " ".join(_APT_PACKAGES)
    # Use env(1): sudo -- treats the next token as the command name, so a bare
    # DEBIAN_FRONTEND=… prefix becomes "command not found".
    update = sudo_run(
        ssh,
        "env DEBIAN_FRONTEND=noninteractive apt-get update -qq",
        sudo_password=sudo_password,
        timeout=300.0,
    )
    if not update.ok:
        raise AgentInstallError(
            f"apt-get update failed: {(update.stderr or update.stdout).strip()[:400]}"
        )
    install = sudo_run(
        ssh,
        f"env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {pkgs}",
        sudo_password=sudo_password,
        timeout=600.0,
    )
    if not install.ok:
        raise AgentInstallError(
            f"apt-get install failed: {(install.stderr or install.stdout).strip()[:400]}"
        )

    # Broker package installs the binary under /usr/sbin; start the service too.
    enable = sudo_run(
        ssh,
        "systemctl enable --now mosquitto 2>/dev/null || "
        "service mosquitto start 2>/dev/null || true",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if not _mosquitto_present(ssh):
        detail = (install.stderr or install.stdout or "").strip()[:300]
        enable_detail = (enable.stderr or enable.stdout or "").strip()[:200]
        raise AgentInstallError(
            "mosquitto still missing after apt install"
            + (f": {detail}" if detail else "")
            + (f" ({enable_detail})" if enable_detail else "")
        )
    return f"installed via apt: {pkgs}"


_BASIC_ACL = """# Managed by iot-gateway-agent / control-service playbooks
user anonymous
topic none
"""

_MOSQUITTO_CONF_D = "/etc/mosquitto/conf.d/iot-gateway-agent.conf"


def configure_system_mosquitto(
    ssh: SSHSession,
    *,
    sudo_password: str,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> str:
    """Create agent mosquitto dirs + conf.d so system Mosquitto reads ACL/passwords.

    Idempotent: empty ``passwords`` and a basic ``acl`` are created only when missing.
    """
    mosq_dir = f"{data_dir}/mosquitto"
    certs_dir = f"{data_dir}/certs"
    passwords = f"{mosq_dir}/passwords"
    acl = f"{mosq_dir}/acl"
    conf_body = (
        "listener 1883 0.0.0.0\n"
        "allow_anonymous false\n"
        f"password_file {passwords}\n"
        f"acl_file {acl}\n"
    )

    with tempfile.NamedTemporaryFile(
        "w", suffix=".conf", delete=False, encoding="utf-8"
    ) as tmp_conf:
        tmp_conf.write(conf_body)
        local_conf = Path(tmp_conf.name)
    with tempfile.NamedTemporaryFile(
        "w", suffix=".acl", delete=False, encoding="utf-8"
    ) as tmp_acl:
        tmp_acl.write(_BASIC_ACL)
        local_acl = Path(tmp_acl.name)

    remote_conf = "/tmp/iotgw-mosquitto-agent.conf"
    remote_acl = "/tmp/iotgw-mosquitto-acl"
    try:
        ssh.upload_file(local_conf, remote_conf, mode=0o644)
        ssh.upload_file(local_acl, remote_acl, mode=0o600)
        result = sudo_run(
            ssh,
            f"mkdir -p {shlex.quote(mosq_dir)}/log "
            f"{shlex.quote(certs_dir)} {shlex.quote(data_dir)}/logs "
            f"/etc/mosquitto/conf.d && "
            f"if [ ! -f {shlex.quote(passwords)} ]; then "
            f": > {shlex.quote(passwords)}; fi && "
            f"if [ ! -f {shlex.quote(acl)} ]; then "
            f"mv {shlex.quote(remote_acl)} {shlex.quote(acl)}; "
            f"else rm -f {shlex.quote(remote_acl)}; fi && "
            f"mv {shlex.quote(remote_conf)} {_MOSQUITTO_CONF_D} && "
            f"chmod 600 {shlex.quote(passwords)} {shlex.quote(acl)} && "
            f"chmod 644 {_MOSQUITTO_CONF_D} && "
            f"(chown -R mosquitto:mosquitto {shlex.quote(mosq_dir)} 2>/dev/null || true) && "
            "systemctl enable --now mosquitto && "
            "(systemctl reload mosquitto || systemctl restart mosquitto)",
            sudo_password=sudo_password,
            timeout=90.0,
        )
        if not result.ok:
            raise AgentInstallError(
                "configuring system mosquitto failed: "
                f"{(result.stderr or result.stdout).strip()[:400]}"
            )
    finally:
        local_conf.unlink(missing_ok=True)
        local_acl.unlink(missing_ok=True)
        # Best-effort cleanup if sudo mv did not consume the temps.
        ssh.run(f"rm -f {shlex.quote(remote_conf)} {shlex.quote(remote_acl)}", timeout=15.0)

    return f"system mosquitto configured ({_MOSQUITTO_CONF_D})"


def _remote_login_owner(ssh: SSHSession) -> str:
    """Return ``user:group`` for the SSH login (never expand id under sudo sh -c)."""
    who = ssh.run("printf '%s:%s\\n' \"$(id -un)\" \"$(id -gn)\"", timeout=15.0)
    owner = (who.stdout or "").strip()
    if not who.ok or not owner or ":" not in owner:
        raise AgentInstallError(
            "could not resolve remote login user:group "
            f"({(who.stderr or who.stdout or '').strip()[:200]})"
        )
    return owner


def _upload_agent_tree(
    ssh: SSHSession,
    agent_src: Path,
    remote_root: str,
    *,
    sudo_password: str,
) -> None:
    """Upload iot_gateway_agent package + requirements + unit file."""
    if not agent_src.is_dir():
        raise AgentInstallError(f"agent source missing: {agent_src}")
    owner = _remote_login_owner(ssh)
    pkg_remote = f"{remote_root}/iot_gateway_agent"
    # Resolve owner outside sudo: under ``sudo sh -c``, ``$(id -un)`` is root and
    # leaves /opt/iot-gateway-agent root-owned so the login user cannot extract.
    # Wipe the package dir so retries are not blocked by leftover root files.
    prepare = sudo_run(
        ssh,
        f"mkdir -p {shlex.quote(remote_root)} && "
        f"rm -rf {shlex.quote(pkg_remote)} && "
        f"mkdir -p {shlex.quote(pkg_remote)} && "
        f"chown -R {shlex.quote(owner)} {shlex.quote(remote_root)}",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if not prepare.ok:
        raise AgentInstallError(
            f"prepare {remote_root} failed: "
            f"{(prepare.stderr or prepare.stdout).strip()[:200]}"
        )
    pkg = agent_src / "iot_gateway_agent"
    if not pkg.is_dir():
        raise AgentInstallError(f"missing package dir: {pkg}")
    ssh.upload_tree(pkg, pkg_remote)
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
    created = ssh.run(
        f"test -x {shlex.quote(venv)}/bin/python || python3 -m venv {shlex.quote(venv)}",
        timeout=120.0,
    )
    if not created.ok:
        raise AgentInstallError(
            "python3 -m venv failed — ensure python3-venv is installed "
            f"({(created.stderr or created.stdout).strip()[:200]})"
        )
    pip = f"{venv}/bin/pip"
    deps = ssh.run(
        f"{shlex.quote(pip)} install -q -U pip && "
        f"{shlex.quote(pip)} install -q -r {shlex.quote(remote_root)}/requirements.txt",
        timeout=300.0,
    )
    if not deps.ok:
        raise AgentInstallError(
            f"pip install agent deps failed: {(deps.stderr or deps.stdout).strip()[:400]}"
        )


def _write_env(
    ssh: SSHSession,
    *,
    monitoring_ip: str,
    sudo_password: str,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> None:
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
        result = sudo_run(
            ssh,
            f"mkdir -p {shlex.quote(data_dir)} && "
            f"mv {shlex.quote(remote)} /etc/iot-gateway-agent.env && "
            f"chmod 644 /etc/iot-gateway-agent.env",
            sudo_password=sudo_password,
            timeout=30.0,
        )
        if not result.ok:
            raise AgentInstallError(
                f"writing /etc/iot-gateway-agent.env failed: "
                f"{(result.stderr or result.stdout).strip()[:200]}"
            )
    finally:
        local.unlink(missing_ok=True)


def _install_systemd(
    ssh: SSHSession, remote_root: str, *, sudo_password: str
) -> None:
    unit_src = f"{remote_root}/iot-gateway-agent.service"
    result = sudo_run(
        ssh,
        f"cp {shlex.quote(unit_src)} /etc/systemd/system/iot-gateway-agent.service && "
        "systemctl daemon-reload && "
        "systemctl enable iot-gateway-agent && "
        # enable --now does not restart an already-active unit with a new ExecStart.
        "systemctl restart iot-gateway-agent",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if not result.ok:
        raise AgentInstallError(
            f"systemd enable failed: {(result.stderr or result.stdout).strip()[:400]}"
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
    sudo_password: str,
    remote_root: str = DEFAULT_AGENT_ROOT,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> list[str]:
    """Install packages (sudo) + agent venv + systemd. Returns notes.

    ``sudo_password`` comes from the Setup Wizard UI and is never written to disk
    or placed on remote argv (only ``sudo -S`` stdin).
    """
    if not (sudo_password or "").strip():
        raise AgentInstallError(
            "sudo password required — enter it in the Setup Wizard before Install"
        )
    notes: list[str] = []
    notes.append(ensure_mosquitto(ssh, sudo_password=sudo_password))
    notes.append(
        configure_system_mosquitto(
            ssh, sudo_password=sudo_password, data_dir=data_dir
        )
    )
    _upload_agent_tree(ssh, agent_src, remote_root, sudo_password=sudo_password)
    notes.append(f"uploaded agent to {remote_root}")
    _ensure_venv(ssh, remote_root)
    notes.append("python venv + agent deps installed")
    _write_env(
        ssh,
        monitoring_ip=monitoring_ip,
        sudo_password=sudo_password,
        data_dir=data_dir,
    )
    _install_systemd(ssh, remote_root, sudo_password=sudo_password)
    notes.append("systemd iot-gateway-agent enabled")
    _probe_agent(ssh)
    notes.append(
        f"agent healthy; system mosquitto MQTT on gateway {gateway_ip}:1883, "
        "agent metrics :9139 (--no-broker)"
    )
    return notes


def uninstall_monolithic_agent(
    ssh: SSHSession,
    *,
    sudo_password: str,
    remote_root: str = DEFAULT_AGENT_ROOT,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> list[str]:
    """Stop/disable the agent unit and remove install + data dirs.

    Leaves apt ``mosquitto`` packages installed. Idempotent when already gone.
    ``sudo_password`` is only passed on ``sudo -S`` stdin (never argv / disk).
    """
    if not (sudo_password or "").strip():
        raise AgentInstallError(
            "sudo password required — enter it before Uninstall Gateway"
        )
    notes: list[str] = []
    stop = sudo_run(
        ssh,
        "systemctl stop iot-gateway-agent 2>/dev/null || true; "
        "systemctl disable iot-gateway-agent 2>/dev/null || true; "
        "rm -f /etc/systemd/system/iot-gateway-agent.service; "
        "systemctl daemon-reload 2>/dev/null || true",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if not stop.ok:
        raise AgentInstallError(
            "failed to stop/disable iot-gateway-agent: "
            f"{(stop.stderr or stop.stdout).strip()[:300]}"
        )
    notes.append("systemd iot-gateway-agent stopped and disabled")

    cleanup = sudo_run(
        ssh,
        f"rm -rf {shlex.quote(remote_root)} {shlex.quote(data_dir)} "
        f"/etc/iot-gateway-agent.env",
        sudo_password=sudo_password,
        timeout=60.0,
    )
    if not cleanup.ok:
        raise AgentInstallError(
            "failed to remove agent files: "
            f"{(cleanup.stderr or cleanup.stdout).strip()[:300]}"
        )
    notes.append(f"removed {remote_root}, {data_dir}, /etc/iot-gateway-agent.env")
    return notes
