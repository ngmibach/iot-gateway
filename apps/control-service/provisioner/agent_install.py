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

user nodered
topic readwrite sensors/#
"""

_MOSQUITTO_CONF_D = "/etc/mosquitto/conf.d/iot-gateway-agent.conf"
MQTT_TLS_PORT = 8883


def _mqtts_conf_body(*, data_dir: str) -> str:
    """Mosquitto conf.d body: MQTTS :8883 mTLS + password/ACL only (no :1883).

    ``log_type debug`` is required on Mosquitto 2.0.21 so ACL ``Denied PUBLISH``
    lines appear in the log (they are emitted at DEBUG, not notice). The agent
    denied_watcher tails that log for Monitoring invalid-message tables.
    """
    mosq_dir = f"{data_dir}/mosquitto"
    certs_dir = f"{data_dir}/certs"
    return (
        f"listener {MQTT_TLS_PORT} 0.0.0.0\n"
        "allow_anonymous false\n"
        f"cafile {certs_dir}/ca.crt\n"
        f"certfile {certs_dir}/server.crt\n"
        f"keyfile {certs_dir}/server.key\n"
        "require_certificate true\n"
        f"password_file {mosq_dir}/passwords\n"
        f"acl_file {mosq_dir}/acl\n"
        "connection_messages true\n"
        "log_type error\n"
        "log_type warning\n"
        "log_type notice\n"
        "log_type information\n"
        "log_type debug\n"
    )


def _reject_ca_admin(passphrase: str) -> str:
    value = (passphrase or "").strip()
    if not value:
        raise AgentInstallError("CA passphrase required for MQTTS bootstrap")
    if value == "admin":
        raise AgentInstallError("CA passphrase must not be 'admin'")
    return value


def ensure_gateway_ca_and_server_cert(
    ssh: SSHSession,
    *,
    sudo_password: str,
    gateway_ip: str,
    ca_passphrase: str,
    data_dir: str = DEFAULT_AGENT_DATA,
    ca_days: int = 3650,
    server_days: int = 730,
) -> str:
    """Create CA + server cert (IP SAN) under ``data_dir/certs`` when missing.

    Uses remote OpenSSL with ``-passin/-passout file:`` only (passphrase never on argv).
    Idempotent when ``ca.crt`` / ``server.crt`` already exist.
    """
    import ipaddress
    import secrets as _secrets

    ca_passphrase = _reject_ca_admin(ca_passphrase)
    gateway_ip = (gateway_ip or "").strip()
    if not gateway_ip:
        raise AgentInstallError("gateway_ip required for server certificate SAN")
    try:
        ipaddress.ip_address(gateway_ip)
    except ValueError as exc:
        raise AgentInstallError(
            f"gateway_ip must be a single IP (not CIDR): {gateway_ip!r}"
        ) from exc

    certs_dir = f"{data_dir}/certs"
    ca_crt = f"{certs_dir}/ca.crt"
    ca_key = f"{certs_dir}/ca.key"
    server_crt = f"{certs_dir}/server.crt"
    server_key = f"{certs_dir}/server.key"
    token = _secrets.token_hex(8)
    remote_pass = f"/tmp/iotgw-ca-pass-{token}"
    remote_ext = f"/tmp/iotgw-server-ext-{token}"
    notes: list[str] = []

    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp_pass:
        tmp_pass.write(ca_passphrase.encode("utf-8"))
        local_pass = Path(tmp_pass.name)
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp_ext:
        # LAN IP for sensors + loopback for the on-box decrypt worker.
        tmp_ext.write(
            f"subjectAltName=IP:{gateway_ip},IP:127.0.0.1,DNS:localhost\n"
        )
        local_ext = Path(tmp_ext.name)

    try:
        ssh.upload_file(local_pass, remote_pass, mode=0o600)
        ssh.upload_file(local_ext, remote_ext, mode=0o600)
        # OpenSSL 3.5+ ``req -x509`` rejects ``-extfile`` ("Extra unknown options").
        # Use ``-addext`` for CA basics (VERIFY_X509_STRICT / keyCertSign).
        ca_script = (
            f"mkdir -p {shlex.quote(certs_dir)} && "
            f"if [ ! -f {shlex.quote(ca_crt)} ] || [ ! -f {shlex.quote(ca_key)} ]; then "
            f"openssl genrsa -aes256 -passout file:{remote_pass} "
            f"-out {shlex.quote(ca_key)} 2048 && "
            f"openssl req -new -x509 -days {int(ca_days)} "
            f"-key {shlex.quote(ca_key)} -passin file:{remote_pass} "
            f"-out {shlex.quote(ca_crt)} "
            f"-subj '/C=VN/ST=Hanoi/L=Hanoi/O=My IOT Org/OU=IOT Devices/CN=My IOT CA Root' "
            f"-addext 'basicConstraints=critical,CA:TRUE' "
            f"-addext 'keyUsage=critical,keyCertSign,cRLSign' "
            f"-addext 'subjectKeyIdentifier=hash' && "
            f"chmod 600 {shlex.quote(ca_key)} && chmod 644 {shlex.quote(ca_crt)} && "
            "echo CA_CREATED; "
            # Existing encrypted ca.key: refuse wrong passphrase before decrypt cert sign.
            f"elif openssl pkey -in {shlex.quote(ca_key)} -passin file:{remote_pass} "
            f"-noout >/dev/null 2>&1; then echo CA_EXISTS; "
            "else echo CA_PASS_MISMATCH; exit 42; fi"
        )
        ca_res = sudo_run(
            ssh, ca_script, sudo_password=sudo_password, timeout=120.0
        )
        combined = f"{ca_res.stdout or ''}{ca_res.stderr or ''}"
        if "CA_PASS_MISMATCH" in combined:
            raise AgentInstallError(
                "Existing gateway CA could not be unlocked with this passphrase. "
                "Uncheck auto-generate and enter the original CA passphrase, or use "
                "Clean up gateway and reinstall to create a new CA."
            )
        if not ca_res.ok:
            raise AgentInstallError(
                "creating gateway CA failed: "
                f"{(ca_res.stderr or ca_res.stdout).strip()[:400]}"
            )
        if "CA_CREATED" in (ca_res.stdout or ""):
            notes.append("gateway CA created")
        else:
            notes.append("gateway CA already present")

        # Server cert with IP SAN (once)
        server_script = (
            f"if [ ! -f {shlex.quote(server_crt)} ] || [ ! -f {shlex.quote(server_key)} ]; then "
            f"openssl genrsa -out {shlex.quote(server_key)} 2048 && "
            f"openssl req -new -key {shlex.quote(server_key)} "
            f"-out /tmp/iotgw-server-{token}.csr "
            f"-subj '/C=VN/ST=Hanoi/L=Hanoi/O=My IOT Org/OU=Broker/CN={gateway_ip}' && "
            f"openssl x509 -req -in /tmp/iotgw-server-{token}.csr "
            f"-CA {shlex.quote(ca_crt)} -CAkey {shlex.quote(ca_key)} "
            f"-passin file:{remote_pass} -CAcreateserial "
            f"-out {shlex.quote(server_crt)} -days {int(server_days)} "
            f"-extfile {remote_ext} && "
            f"cat {shlex.quote(server_crt)} {shlex.quote(server_key)} "
            f"> {shlex.quote(certs_dir)}/server.pem && "
            f"chmod 600 {shlex.quote(server_key)} && "
            f"chmod 644 {shlex.quote(server_crt)} {shlex.quote(certs_dir)}/server.pem && "
            f"rm -f /tmp/iotgw-server-{token}.csr && "
            "echo SERVER_CREATED; "
            "else echo SERVER_EXISTS; fi && "
            f"(chown -R mosquitto:mosquitto {shlex.quote(certs_dir)} 2>/dev/null || true)"
        )
        srv_res = sudo_run(
            ssh, server_script, sudo_password=sudo_password, timeout=120.0
        )
        if not srv_res.ok:
            raise AgentInstallError(
                "creating MQTT server certificate failed: "
                f"{(srv_res.stderr or srv_res.stdout).strip()[:400]}"
            )
        if "SERVER_CREATED" in (srv_res.stdout or ""):
            notes.append(f"server cert created (SAN IP:{gateway_ip})")
        else:
            notes.append("server cert already present")
    finally:
        local_pass.unlink(missing_ok=True)
        local_ext.unlink(missing_ok=True)
        ssh.run(
            f"rm -f {shlex.quote(remote_pass)} {shlex.quote(remote_ext)}",
            timeout=15.0,
        )

    return "; ".join(notes)


def ensure_decrypt_mqtt_identity(
    ssh: SSHSession,
    *,
    sudo_password: str,
    ca_passphrase: str,
    data_dir: str = DEFAULT_AGENT_DATA,
    decrypt_password: str | None = None,
    cert_days: int = 730,
) -> str:
    """Ensure ``nodered`` MQTT user + mTLS client cert for the decrypt worker.

    Returns the plaintext decrypt password (caller writes it into agent env).
    """
    import secrets as _secrets

    from actions.csr import generate_client_key_and_csr  # type: ignore[import-not-found]
    from actions.files import merge_password_line, upsert_user_acl  # type: ignore[import-not-found]
    from actions.mosquitto_hash import hash_password_line  # type: ignore[import-not-found]

    ca_passphrase = _reject_ca_admin(ca_passphrase)
    password = (decrypt_password or "").strip() or _secrets.token_urlsafe(24)
    mosq_dir = f"{data_dir}/mosquitto"
    passwords_path = f"{mosq_dir}/passwords"
    acl_path = f"{mosq_dir}/acl"
    certs_dir = f"{data_dir}/certs"
    decrypt_crt = f"{certs_dir}/decrypt.crt"
    decrypt_key = f"{certs_dir}/decrypt.key"
    ca_crt = f"{certs_dir}/ca.crt"
    ca_key = f"{certs_dir}/ca.key"

    # Ensure ACL + password files exist, then upsert nodered.
    material = generate_client_key_and_csr(cn="nodered", org_unit="Broker")
    hash_line = hash_password_line("nodered", password)
    token = _secrets.token_hex(8)
    remote_pass = f"/tmp/iotgw-ca-pass-{token}"
    remote_csr = f"/tmp/iotgw-decrypt-{token}.csr"
    remote_crt_tmp = f"/tmp/iotgw-decrypt-{token}.crt"
    remote_key_tmp = f"/tmp/iotgw-decrypt-{token}.key"

    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp_pass:
        tmp_pass.write(ca_passphrase.encode("utf-8"))
        local_pass = Path(tmp_pass.name)
    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp_csr:
        tmp_csr.write(material.csr_pem)
        local_csr = Path(tmp_csr.name)
    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp_key:
        tmp_key.write(material.private_key_pem)
        local_key = Path(tmp_key.name)

    local_acl: Path | None = None
    local_pw: Path | None = None
    try:
        # Read current ACL/passwords via cat (provisioner SSH has no read_text).
        acl_res = ssh.run(
            f"cat {shlex.quote(acl_path)} 2>/dev/null || true", timeout=15.0
        )
        pw_res = ssh.run(
            f"cat {shlex.quote(passwords_path)} 2>/dev/null || true", timeout=15.0
        )
        acl_body = upsert_user_acl(
            acl_res.stdout or _BASIC_ACL,
            "nodered",
            topic_rw="sensors/#",
        )
        pw_body = merge_password_line(pw_res.stdout or "", hash_line)

        with tempfile.NamedTemporaryFile(
            "w", suffix=".acl", delete=False, encoding="utf-8"
        ) as tmp_acl:
            tmp_acl.write(acl_body)
            local_acl = Path(tmp_acl.name)
        with tempfile.NamedTemporaryFile(
            "w", suffix=".pw", delete=False, encoding="utf-8"
        ) as tmp_pw:
            tmp_pw.write(pw_body if pw_body.endswith("\n") else pw_body + "\n")
            local_pw = Path(tmp_pw.name)

        remote_acl = f"/tmp/iotgw-acl-{token}"
        remote_pw = f"/tmp/iotgw-pw-{token}"
        ssh.upload_file(local_acl, remote_acl, mode=0o600)
        ssh.upload_file(local_pw, remote_pw, mode=0o600)
        ssh.upload_file(local_pass, remote_pass, mode=0o600)
        ssh.upload_file(local_csr, remote_csr, mode=0o600)
        ssh.upload_file(local_key, remote_key_tmp, mode=0o600)

        sign_script = (
            f"mkdir -p {shlex.quote(mosq_dir)}/log {shlex.quote(certs_dir)} && "
            f"mv {shlex.quote(remote_acl)} {shlex.quote(acl_path)} && "
            f"mv {shlex.quote(remote_pw)} {shlex.quote(passwords_path)} && "
            f"chmod 600 {shlex.quote(acl_path)} {shlex.quote(passwords_path)} && "
            f"openssl x509 -req -in {remote_csr} "
            f"-CA {shlex.quote(ca_crt)} -CAkey {shlex.quote(ca_key)} "
            f"-passin file:{remote_pass} -CAcreateserial "
            f"-out {remote_crt_tmp} -days {int(cert_days)} && "
            f"mv {remote_crt_tmp} {shlex.quote(decrypt_crt)} && "
            f"mv {remote_key_tmp} {shlex.quote(decrypt_key)} && "
            f"chmod 644 {shlex.quote(decrypt_crt)} && "
            f"chmod 600 {shlex.quote(decrypt_key)} && "
            f"(chown -R mosquitto:mosquitto {shlex.quote(mosq_dir)} "
            f"{shlex.quote(certs_dir)} 2>/dev/null || true) && "
            "echo DECRYPT_OK"
        )
        res = sudo_run(
            ssh, sign_script, sudo_password=sudo_password, timeout=120.0
        )
        combined = f"{res.stdout or ''}{res.stderr or ''}"
        if not res.ok or "DECRYPT_OK" not in (res.stdout or ""):
            hint = ""
            if "bad decrypt" in combined.lower() or "pkcs12" in combined.lower():
                hint = (
                    " (often a wrong CA passphrase for an existing ca.key — "
                    "enter the original passphrase or Clean up gateway first)"
                )
            raise AgentInstallError(
                "decrypt worker MQTT identity failed: "
                f"{(res.stderr or res.stdout).strip()[:400]}{hint}"
            )
    finally:
        local_pass.unlink(missing_ok=True)
        local_csr.unlink(missing_ok=True)
        local_key.unlink(missing_ok=True)
        if local_acl is not None:
            local_acl.unlink(missing_ok=True)
        if local_pw is not None:
            local_pw.unlink(missing_ok=True)
        ssh.run(
            f"rm -f {shlex.quote(remote_pass)} {shlex.quote(remote_csr)} "
            f"{remote_crt_tmp} {remote_key_tmp}",
            timeout=15.0,
        )
    return password


def configure_system_mosquitto(
    ssh: SSHSession,
    *,
    sudo_password: str,
    data_dir: str = DEFAULT_AGENT_DATA,
    gateway_ip: str | None = None,
    ca_passphrase: str | None = None,
) -> tuple[str, str | None]:
    """Create agent mosquitto dirs + MQTTS :8883 conf.d (mTLS + password/ACL).

    When ``gateway_ip`` and ``ca_passphrase`` are provided, bootstraps CA + server
    cert and the decrypt worker client identity before writing conf.

    Returns ``(notes, decrypt_password_or_none)``.
    Idempotent for ACL/passwords files that already exist.
    """
    mosq_dir = f"{data_dir}/mosquitto"
    certs_dir = f"{data_dir}/certs"
    passwords = f"{mosq_dir}/passwords"
    acl = f"{mosq_dir}/acl"
    notes: list[str] = []
    decrypt_password: str | None = None

    if gateway_ip and ca_passphrase:
        notes.append(
            ensure_gateway_ca_and_server_cert(
                ssh,
                sudo_password=sudo_password,
                gateway_ip=gateway_ip,
                ca_passphrase=ca_passphrase,
                data_dir=data_dir,
            )
        )
        decrypt_password = ensure_decrypt_mqtt_identity(
            ssh,
            sudo_password=sudo_password,
            ca_passphrase=ca_passphrase,
            data_dir=data_dir,
        )
        notes.append("decrypt MQTT identity ready")

    conf_body = _mqtts_conf_body(data_dir=data_dir)

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
            f"(chown -R mosquitto:mosquitto {shlex.quote(mosq_dir)} "
            f"{shlex.quote(certs_dir)} 2>/dev/null || true) && "
            "systemctl enable --now mosquitto && "
            "(systemctl restart mosquitto || systemctl reload mosquitto)",
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

    notes.append(f"system mosquitto MQTTS :{MQTT_TLS_PORT} ({_MOSQUITTO_CONF_D})")
    return "; ".join(notes), decrypt_password


_EMPTY_KAFKA_CATALOG = """{
  "version": 1,
  "retention_bytes_default": 1073741824,
  "safety_ratio": 0.7,
  "topics": {}
}
"""


def ensure_kafka_layout(
    ssh: SSHSession,
    *,
    sudo_password: str,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> str:
    """Create Kafka topic catalog dir used for per-sensor retention caps.

    Seeds an empty ``topics.json`` when missing. A Kafka-compatible broker that
    applies ``retention.bytes`` from this catalog is installed in a follow-up;
    registration already reserves topics against the 70% disk budget.
    """
    kafka_dir = f"{data_dir}/kafka"
    catalog = f"{kafka_dir}/topics.json"
    # Own kafka/ as the SSH login user so day-2 SFTP catalog updates work
    # (atomic write creates topics.json.tmp.* beside the file).
    owner = _remote_login_owner(ssh)
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(_EMPTY_KAFKA_CATALOG)
        local_catalog = Path(tmp.name)
    remote_tmp = "/tmp/iotgw-kafka-topics.json"
    try:
        ssh.upload_file(local_catalog, remote_tmp, mode=0o644)
        result = sudo_run(
            ssh,
            f"mkdir -p {shlex.quote(kafka_dir)} && "
            f"if [ ! -f {shlex.quote(catalog)} ]; then "
            f"mv {shlex.quote(remote_tmp)} {shlex.quote(catalog)}; "
            f"else rm -f {shlex.quote(remote_tmp)}; fi && "
            f"chmod 644 {shlex.quote(catalog)} && "
            f"chown -R {shlex.quote(owner)} {shlex.quote(kafka_dir)}",
            sudo_password=sudo_password,
            timeout=60.0,
        )
        if not result.ok:
            raise AgentInstallError(
                "creating kafka topic catalog failed: "
                f"{(result.stderr or result.stdout).strip()[:400]}"
            )
    finally:
        local_catalog.unlink(missing_ok=True)
        ssh.run(f"rm -f {shlex.quote(remote_tmp)}", timeout=15.0)
    return f"kafka topic catalog ready ({catalog})"


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
    fake_unit = agent_src / "iotgw-fake@.service"
    if fake_unit.is_file():
        ssh.upload_file(fake_unit, f"{remote_root}/iotgw-fake@.service")


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
    decrypt_password: str | None = None,
    mqtt_port: int = MQTT_TLS_PORT,
) -> None:
    lines = [
        f"MONITORING_IP={monitoring_ip}",
        f"IOTGW_AGENT_DATA={data_dir}",
        f"LOKI_URL=http://{monitoring_ip}:3100",
        f"MQTT_PORT={int(mqtt_port)}",
        "IOTGW_DECRYPT_USER=nodered",
        f"IOTGW_MQTT_CA={data_dir}/certs/ca.crt",
        f"IOTGW_MQTT_CERT={data_dir}/certs/decrypt.crt",
        f"IOTGW_MQTT_KEY={data_dir}/certs/decrypt.key",
    ]
    if decrypt_password:
        lines.append(f"IOTGW_DECRYPT_PASSWORD={decrypt_password}")
    content = "\n".join(lines) + "\n"
    # newline="\n" so Windows hosts do not emit CRLF into the Pi env file
    # (systemd would keep trailing \\r on values and break MQTT auth/ACL).
    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".env",
        delete=False,
        encoding="utf-8",
        newline="\n",
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
    fake_unit_src = f"{remote_root}/iotgw-fake@.service"
    # Install agent unit + optional fake-sensor template (netns simulators).
    install_cmd = (
        f"cp {shlex.quote(unit_src)} /etc/systemd/system/iot-gateway-agent.service && "
        f"if [ -f {shlex.quote(fake_unit_src)} ]; then "
        f"cp {shlex.quote(fake_unit_src)} /etc/systemd/system/iotgw-fake@.service; "
        f"fi && "
        "systemctl daemon-reload && "
        "systemctl enable iot-gateway-agent && "
        # enable --now does not restart an already-active unit with a new ExecStart.
        "systemctl restart iot-gateway-agent"
    )
    result = sudo_run(
        ssh,
        install_cmd,
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
    ca_passphrase: str | None = None,
) -> list[str]:
    """Install packages (sudo) + agent venv + systemd. Returns notes.

    ``sudo_password`` comes from the Setup Wizard UI / keyring and is never
    written to the gateway disk or placed on remote argv (only ``sudo -S`` stdin).

    ``ca_passphrase`` bootstraps the gateway CA + MQTTS server cert and decrypt
    worker client identity. Required for MQTTS-only installs.
    """
    if not (sudo_password or "").strip():
        raise AgentInstallError(
            "sudo password required — enter it in the Setup Wizard before Install"
        )
    if not (ca_passphrase or "").strip():
        raise AgentInstallError(
            "CA passphrase required — generate automatically or enter on Install"
        )
    notes: list[str] = []
    notes.append(ensure_mosquitto(ssh, sudo_password=sudo_password))
    mosq_note, decrypt_password = configure_system_mosquitto(
        ssh,
        sudo_password=sudo_password,
        data_dir=data_dir,
        gateway_ip=gateway_ip,
        ca_passphrase=ca_passphrase,
    )
    notes.append(mosq_note)
    notes.append(
        ensure_kafka_layout(ssh, sudo_password=sudo_password, data_dir=data_dir)
    )
    try:
        from .kafka_install import ensure_kafka_kraft

        notes.append(
            ensure_kafka_kraft(
                ssh,
                sudo_password=sudo_password,
                data_dir=data_dir,
                advertise_host=gateway_ip,
            )
        )
    except Exception as exc:  # noqa: BLE001 — Kafka is best-effort on first install
        notes.append(f"kafka KRaft install deferred: {exc}")
    _upload_agent_tree(ssh, agent_src, remote_root, sudo_password=sudo_password)
    notes.append(f"uploaded agent to {remote_root}")
    _ensure_venv(ssh, remote_root)
    notes.append("python venv + agent deps installed")
    _write_env(
        ssh,
        monitoring_ip=monitoring_ip,
        sudo_password=sudo_password,
        data_dir=data_dir,
        decrypt_password=decrypt_password,
        mqtt_port=MQTT_TLS_PORT,
    )
    _install_systemd(ssh, remote_root, sudo_password=sudo_password)
    notes.append("systemd iot-gateway-agent enabled")
    _probe_agent(ssh)
    notes.append(
        f"agent healthy; system mosquitto MQTTS on gateway {gateway_ip}:{MQTT_TLS_PORT}, "
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

    Also tears down every gateway-side fake sensor (``iotgw-fake@`` units,
    ``iotgw-fake-*`` netns, ``iotgw-fake`` bridge) so uninstall leaves no orphans.
    """
    if not (sudo_password or "").strip():
        raise AgentInstallError(
            "sudo password required — enter it before Uninstall Gateway"
        )
    notes: list[str] = []

    # Prefer the playbook so netns / veth / unit enumeration stays correct.
    try:
        from actions.fake_sensors import teardown_all_fakes  # type: ignore[import-not-found]

        torn = teardown_all_fakes(
            ssh,  # type: ignore[arg-type]
            sudo_password=sudo_password,
            data_dir=data_dir,
            remove_unit_template=True,
        )
        if torn.ok:
            notes.append("fake sensors / iotgw-fake bridge torn down")
        else:
            notes.append(
                f"fake sensor teardown degraded: {(torn.message or '')[:200]}"
            )
    except Exception as exc:  # noqa: BLE001 — uninstall must continue
        notes.append(f"fake sensor teardown skipped: {exc}"[:240])

    stop = sudo_run(
        ssh,
        "systemctl stop iot-gateway-agent 2>/dev/null || true; "
        "systemctl disable iot-gateway-agent 2>/dev/null || true; "
        "systemctl stop iotgw-kafka 2>/dev/null || true; "
        "systemctl disable iotgw-kafka 2>/dev/null || true; "
        # Belt-and-suspenders if playbook import/path failed above.
        "for u in $(systemctl list-units --type=service --all --no-legend "
        "'iotgw-fake@*' 2>/dev/null | awk '{print $1}'); do "
        "systemctl stop \"$u\" 2>/dev/null || true; "
        "systemctl disable \"$u\" 2>/dev/null || true; done; "
        "for ns in $(ip netns list 2>/dev/null | awk '{print $1}'); do "
        "case \"$ns\" in iotgw-fake-*) ip netns del \"$ns\" 2>/dev/null || true ;; "
        "esac; done; "
        "ip link del iotgw-fake 2>/dev/null || true; "
        "rm -f /etc/systemd/system/iot-gateway-agent.service "
        "/etc/systemd/system/iotgw-kafka.service "
        "/etc/systemd/system/iotgw-fake@.service; "
        "systemctl daemon-reload 2>/dev/null || true",
        sudo_password=sudo_password,
        timeout=90.0,
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
        f"/opt/kafka /etc/iot-gateway-agent.env",
        sudo_password=sudo_password,
        timeout=120.0,
    )
    if not cleanup.ok:
        raise AgentInstallError(
            "failed to remove agent files: "
            f"{(cleanup.stderr or cleanup.stdout).strip()[:300]}"
        )
    notes.append(
        f"removed {remote_root}, {data_dir}, /opt/kafka, /etc/iot-gateway-agent.env"
    )
    return notes
