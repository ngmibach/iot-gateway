"""SSH playbooks ported from Gitea workflows (secret-safe, compensating)."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Optional

from . import files as fileops
from .csr import (
    ClientKeyMaterial,
    SignedClientCert,
    generate_client_key_and_csr,
    sign_csr_on_gateway,
)
from .device_crypto import (
    DEFAULT_SCHEMA,
    assemble_cert_bundle,
    provision_device_crypto,
)
from .kafka_capacity import (
    DEFAULT_TOPIC_RETENTION_BYTES,
    CapacityPlan,
    plan_capacity,
    probe_total_storage_bytes,
)
from .kafka_topics import CapacityExceededError, TopicCatalog
from .mosquitto_ctl import reload_mosquitto
from .mosquitto_hash import hash_password_line, zeroize_str
from .paths import DEFAULT_AGENT_DATA, DEFAULT_INSTALL_ROOT, GatewayPaths
from .shellutil import shell_quote
from .validate import (
    split_csv,
    validate_ip_or_cidr,
    validate_topic,
    validate_user_id,
)

if TYPE_CHECKING:
    from .ssh import CommandResult, SSHClient


@dataclass
class PlaybookResult:
    ok: bool
    status: str = "ok"  # ok | degraded | failed
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RegisterResult(PlaybookResult):
    cert_bundle: Optional[bytes] = None
    client_key_pem: Optional[bytes] = None
    client_crt_pem: Optional[bytes] = None
    ca_crt_pem: Optional[bytes] = None
    cert_fingerprint: Optional[str] = None
    cert_expires_at: Optional[str] = None


def _paths(
    install_root: str,
    data_dir: str | None = None,
) -> GatewayPaths:
    return GatewayPaths(
        install_root=install_root,
        data_dir=data_dir if data_dir is not None else DEFAULT_AGENT_DATA,
    )


def _read_kafka_catalog(ssh: "SSHClient", paths: GatewayPaths) -> TopicCatalog:
    try:
        return TopicCatalog.from_json(ssh.read_text(paths.kafka_topics_catalog))
    except FileNotFoundError:
        return TopicCatalog()


def _write_kafka_catalog(
    ssh: "SSHClient",
    paths: GatewayPaths,
    catalog: TopicCatalog,
    *,
    sudo_password: str | None = None,
) -> None:
    """Write topics.json; chown kafka/ when root-owned so SFTP temp files work.

    Install leaves ``kafka/`` root-owned; atomic SFTP write creates
    ``topics.json.tmp.*`` beside the catalog and fails with
    ``[Errno 13] Permission denied`` unless the directory is writable.
    """
    err = _ensure_data_subdir_writable(
        ssh, paths.kafka_dir, sudo_password=sudo_password
    )
    body = catalog.to_json()
    if err is None:
        try:
            ssh.write_text(paths.kafka_topics_catalog, body, mode=0o644)
            return
        except (OSError, IOError, PermissionError):
            pass
    # Fallback: stage under /tmp and sudo mv (same pattern as Mosquitto secrets).
    token = secrets.token_hex(8)
    remote_tmp = f"/tmp/iotgw-kafka-topics-{token}.json"
    ssh.write_text(remote_tmp, body, mode=0o644)
    owner = _login_owner(ssh)
    result = _sudo(
        ssh,
        f"mkdir -p {shell_quote(paths.kafka_dir)} && "
        f"mv {shell_quote(remote_tmp)} {shell_quote(paths.kafka_topics_catalog)} && "
        f"chmod 644 {shell_quote(paths.kafka_topics_catalog)} && "
        f"chown {shell_quote(owner)} {shell_quote(paths.kafka_dir)} "
        f"{shell_quote(paths.kafka_topics_catalog)}",
        sudo_password=sudo_password,
        timeout=30.0,
    )
    if result.exit_code != 0:
        ssh.run(f"rm -f {shell_quote(remote_tmp)}")
        detail = (result.stderr or result.stdout or err or "").strip()[:300]
        raise PermissionError(
            f"cannot write {paths.kafka_topics_catalog}: "
            f"{detail or 'permission denied'}"
        )


def gateway_kafka_capacity(
    ssh: "SSHClient",
    *,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    total_storage_bytes: int | None = None,
) -> CapacityPlan:
    """Probe gateway disk + topic catalog and return the sensor capacity plan."""
    paths = _paths(install_root, data_dir)
    catalog = _read_kafka_catalog(ssh, paths)
    total = (
        int(total_storage_bytes)
        if total_storage_bytes is not None
        else probe_total_storage_bytes(ssh, paths.data_dir)
    )
    return plan_capacity(
        total_storage_bytes=total,
        registered_sensors=catalog.count,
        topic_retention_bytes=catalog.retention_bytes_default,
        safety_ratio=catalog.safety_ratio,
    )


def _ensure_kafka_topic_slot(
    ssh: "SSHClient",
    paths: GatewayPaths,
    *,
    user_id: str,
    topic_retention_bytes: int | None,
    total_storage_bytes: int | None,
    sudo_password: str | None = None,
) -> tuple[TopicCatalog, dict[str, Any]]:
    """Reserve a Kafka topic for ``user_id`` or raise CapacityExceededError."""
    catalog = _read_kafka_catalog(ssh, paths)
    existing = catalog.get_by_device(user_id)
    retention = int(
        topic_retention_bytes
        if topic_retention_bytes is not None
        else catalog.retention_bytes_default or DEFAULT_TOPIC_RETENTION_BYTES
    )
    total = (
        int(total_storage_bytes)
        if total_storage_bytes is not None
        else probe_total_storage_bytes(ssh, paths.data_dir)
    )
    # Re-register of an existing sensor does not consume an extra slot.
    counted = catalog.count if existing is None else max(0, catalog.count - 1)
    plan = plan_capacity(
        total_storage_bytes=total,
        registered_sensors=counted,
        topic_retention_bytes=retention,
        safety_ratio=catalog.safety_ratio,
    )
    if existing is None and plan.remaining_slots <= 0:
        raise CapacityExceededError(
            (
                f"gateway Kafka capacity full: {plan.registered_sensors}/"
                f"{plan.max_sensors} sensors "
                f"(topic cap {retention} bytes, disk {total} bytes, "
                f"safety {catalog.safety_ratio:.0%})"
            ),
            max_sensors=plan.max_sensors,
            registered_sensors=plan.registered_sensors,
            topic_retention_bytes=retention,
            total_storage_bytes=total,
        )
    record = catalog.upsert_device(user_id, retention_bytes=retention)
    _write_kafka_catalog(
        ssh, paths, catalog, sudo_password=sudo_password
    )
    # Apply retention on the local KRaft broker when installed.
    try:
        from provisioner.kafka_install import create_or_update_topic, kafka_present

        if kafka_present(ssh):  # type: ignore[arg-type]
            create_or_update_topic(
                ssh,  # type: ignore[arg-type]
                topic=record.topic,
                retention_bytes=record.retention_bytes,
            )
    except Exception:
        # Catalog still reserved; broker sync can retry on next provision/register.
        pass
    return catalog, {
        "kafka_topic": record.topic,
        "kafka_retention_bytes": record.retention_bytes,
        "kafka_capacity": {
            "total_storage_bytes": plan.total_storage_bytes,
            "topic_retention_bytes": plan.topic_retention_bytes,
            "safety_ratio": plan.safety_ratio,
            "budget_bytes": plan.budget_bytes,
            "max_sensors": plan.max_sensors,
            "registered_sensors": catalog.count,
            "remaining_slots": max(0, plan.max_sensors - catalog.count),
        },
    }


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


def _login_owner(ssh: "SSHClient") -> str:
    """Resolve ``user:group`` for the SSH login (not root under sudo sh -c)."""
    who = ssh.run(
        "printf '%s:%s\\n' \"$(id -un)\" \"$(id -gn)\"",
        timeout=15.0,
    )
    owner = (who.stdout or "").strip().splitlines()
    if who.exit_code == 0 and owner and ":" in owner[0]:
        return owner[0].strip()
    return "root:root"


def _ensure_data_subdir_writable(
    ssh: "SSHClient",
    directory: str,
    *,
    sudo_password: str | None = None,
) -> str | None:
    """mkdir ``directory`` and chown to the SSH login user.

    Returns an error message on failure, or ``None`` on success.
    ``/var/lib/iot-gateway-agent`` subdirs are often root-owned after Install,
    so SFTP atomic writes (``.tmp.*`` beside the target) raise Errno 13.
    """
    owner = _login_owner(ssh)
    result = _sudo(
        ssh,
        f"mkdir -p {shell_quote(directory)} && "
        f"chown -R {shell_quote(owner)} {shell_quote(directory)}",
        sudo_password=sudo_password,
        timeout=30.0,
    )
    if result.exit_code != 0:
        return (result.stderr or result.stdout or "").strip()[:300] or (
            f"failed to prepare {directory}"
        )
    return None


def _backup_kafka_catalog(
    ssh: "SSHClient",
    paths: GatewayPaths,
    *,
    sudo_password: str | None = None,
) -> str | None:
    """Backup topics.json beside itself when writable; else under ``/tmp``."""
    if not ssh.exists(paths.kafka_topics_catalog):
        return None
    _ensure_data_subdir_writable(
        ssh, paths.kafka_dir, sudo_password=sudo_password
    )
    try:
        return ssh.backup(paths.kafka_topics_catalog)
    except (OSError, IOError, PermissionError):
        pass
    content = ssh.read_text(paths.kafka_topics_catalog)
    bak = (
        f"/tmp/iotgw-bak-kafka-topics."
        f"{int(time.time())}.{secrets.token_hex(3)}"
    )
    body = content if content.endswith("\n") else content + "\n"
    ssh.write_text(bak, body, mode=0o644)
    return bak


def _read_mosquitto_secret(
    ssh: "SSHClient",
    path: str,
    *,
    sudo_password: str | None = None,
) -> str:
    """Read ACL/passwords; fall back to ``sudo cat`` when SFTP is denied."""
    try:
        return ssh.read_text(path)
    except (OSError, IOError, PermissionError):
        pass
    result = _sudo(
        ssh,
        f"cat {shell_quote(path)}",
        sudo_password=sudo_password,
        timeout=30.0,
    )
    if result.exit_code != 0:
        err = (result.stderr or result.stdout or "").strip()[:200]
        raise PermissionError(
            f"cannot read {path}: {err or 'permission denied'}"
        )
    return result.stdout or ""


def _write_mosquitto_secret(
    ssh: "SSHClient",
    path: str,
    content: str,
    *,
    sudo_password: str | None = None,
) -> None:
    """Install ACL/passwords via /tmp + sudo mv (same pattern as Install).

    Day-2 SFTP as the SSH login user fails with ``[Errno 13] Permission denied``
    after Install chowns these files to ``mosquitto:mosquitto``.
    """
    body = content if content.endswith("\n") else content + "\n"
    token = secrets.token_hex(8)
    remote_tmp = f"/tmp/iotgw-mosq-{PurePosixPath(path).name}-{token}"
    ssh.write_text(remote_tmp, body, mode=0o600)
    result = _sudo(
        ssh,
        f"mv {shell_quote(remote_tmp)} {shell_quote(path)} && "
        f"chmod 600 {shell_quote(path)} && "
        f"chown mosquitto:mosquitto {shell_quote(path)}",
        sudo_password=sudo_password,
        timeout=30.0,
    )
    if result.exit_code != 0:
        ssh.run(f"rm -f {shell_quote(remote_tmp)}")
        err = (result.stderr or result.stdout or "").strip()[:300]
        raise PermissionError(
            f"cannot write {path} via sudo: {err or 'permission denied'}"
        )


def _backup_mosquitto_secret(
    ssh: "SSHClient",
    path: str,
    *,
    sudo_password: str | None = None,
) -> str:
    """Copy ``path`` beside itself when writable; otherwise backup under ``/tmp``."""
    try:
        return ssh.backup(path)
    except (OSError, IOError, PermissionError):
        pass
    content = _read_mosquitto_secret(ssh, path, sudo_password=sudo_password)
    bak = (
        f"/tmp/iotgw-bak-{PurePosixPath(path).name}."
        f"{int(time.time())}.{secrets.token_hex(3)}"
    )
    body = content if content.endswith("\n") else content + "\n"
    ssh.write_text(bak, body, mode=0o600)
    return bak


def _restore_mosquitto_secret(
    ssh: "SSHClient",
    path: str,
    bak_path: str,
    *,
    sudo_password: str | None = None,
) -> None:
    """Restore a Mosquitto secret from ``bak_path`` (sidecar or /tmp)."""
    try:
        ssh.restore_backup(path, bak_path)
        _chmod_mosquitto_secrets(ssh, path, sudo_password=sudo_password)
        return
    except (OSError, IOError, PermissionError):
        pass
    content = ssh.read_text(bak_path)
    _write_mosquitto_secret(
        ssh, path, content, sudo_password=sudo_password
    )


def _chmod_mosquitto_secrets(
    ssh: "SSHClient",
    paths_or_file: GatewayPaths | str,
    *,
    sudo_password: str | None = None,
) -> None:
    """Best-effort ``chmod 600`` + ``chown mosquitto`` via sudo."""
    if isinstance(paths_or_file, str):
        targets = [paths_or_file]
    else:
        targets = [paths_or_file.passwords, paths_or_file.acl]
    quoted = " ".join(shell_quote(p) for p in targets)
    _sudo(
        ssh,
        f"chmod 600 {quoted} && "
        f"chown mosquitto:mosquitto {quoted} 2>/dev/null || true",
        sudo_password=sudo_password,
        timeout=30.0,
    )


def _restore_backups(
    ssh: "SSHClient",
    *,
    bak_acl: str | None = None,
    bak_pw: str | None = None,
    paths: GatewayPaths,
    sudo_password: str | None = None,
) -> None:
    if bak_pw:
        _restore_mosquitto_secret(
            ssh, paths.passwords, bak_pw, sudo_password=sudo_password
        )
    if bak_acl:
        _restore_mosquitto_secret(
            ssh, paths.acl, bak_acl, sudo_password=sudo_password
        )


def _cert_fields(
    material: ClientKeyMaterial,
    signed: SignedClientCert | None,
    *,
    crypto_json: dict[str, Any] | None = None,
    schema_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if signed is None:
        return {
            "client_key_pem": material.private_key_pem,
            "client_crt_pem": None,
            "ca_crt_pem": None,
            "cert_fingerprint": None,
            "cert_expires_at": None,
            "cert_bundle": None,
        }
    return {
        "client_key_pem": material.private_key_pem,
        "client_crt_pem": signed.client_crt_pem,
        "ca_crt_pem": signed.ca_crt_pem,
        "cert_fingerprint": signed.fingerprint_sha256,
        "cert_expires_at": (
            signed.not_valid_after.isoformat() if signed.not_valid_after else None
        ),
        "cert_bundle": assemble_cert_bundle(
            ca_crt_pem=signed.ca_crt_pem,
            client_crt_pem=signed.client_crt_pem,
            client_key_pem=material.private_key_pem,
            crypto_json=crypto_json,
            schema_json=schema_json,
        ),
    }


def register_device(
    ssh: "SSHClient",
    *,
    user_id: str,
    password: str,
    ip: str,
    topic_rw: str | None = None,
    topic_r: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    ca_passphrase: str,
    cert_days: int = 730,
    reject_default_admin_passphrase: bool = True,
    key_material: ClientKeyMaterial | None = None,
    topic_retention_bytes: int | None = None,
    total_storage_bytes: int | None = None,
    crypto_profile: str = "v1-psk",
    schema_id: str = "default",
    schema: dict[str, Any] | None = None,
    provision_crypto: bool = True,
    also_fake_crypto_copy: bool = False,
    sudo_password: str | None = None,
) -> RegisterResult:
    """Register MQTT user + Kafka topic: ACL upsert + hashed passwd + CSR/sign.

    Before Mosquitto changes, reserves a retention-capped Kafka topic for the
    sensor when capacity remains (70% of gateway disk / per-topic cap).
    Compensating restores on failure through CSR sign. After Mosquitto reload,
    failures return ``ok=True, status="degraded"`` without rolling back live
    ACL/password files. ``ip`` is validated for registry metadata only (no
    HAProxy allow-list on the packaged agent).
    """
    bak_acl = bak_pw = None
    bak_kafka = None
    signed: SignedClientCert | None = None
    paths = _paths(install_root, data_dir)
    kafka_meta: dict[str, Any] = {}

    try:
        user_id = validate_user_id(user_id)
        ip = validate_ip_or_cidr(ip)
        if topic_rw:
            topic_rw = validate_topic(topic_rw)
        if topic_r:
            topic_r = validate_topic(topic_r)

        hash_line = hash_password_line(user_id, password)
        zeroize_str(password)

        material = key_material or generate_client_key_and_csr(cn=user_id)

        # 0 Kafka topic slot (storage-capped) — fail closed before MQTT writes.
        # kafka/ is often root-owned; chown before SFTP backup/write (Errno 13).
        catalog_before = _read_kafka_catalog(ssh, paths)
        try:
            bak_kafka = _backup_kafka_catalog(
                ssh, paths, sudo_password=sudo_password
            )
            _, kafka_meta = _ensure_kafka_topic_slot(
                ssh,
                paths,
                user_id=user_id,
                topic_retention_bytes=topic_retention_bytes,
                total_storage_bytes=total_storage_bytes,
                sudo_password=sudo_password,
            )
        except CapacityExceededError as exc:
            return RegisterResult(
                ok=False,
                status="failed",
                message=str(exc),
                details={
                    "user_id": user_id,
                    "ip": ip,
                    "kafka_capacity": {
                        "max_sensors": exc.max_sensors,
                        "registered_sensors": exc.registered_sensors,
                        "topic_retention_bytes": exc.topic_retention_bytes,
                        "total_storage_bytes": exc.total_storage_bytes,
                    },
                },
            )

        def _restore_kafka() -> None:
            if bak_kafka:
                try:
                    ssh.restore_backup(paths.kafka_topics_catalog, bak_kafka)
                except (OSError, IOError, PermissionError):
                    content = ssh.read_text(bak_kafka)
                    _write_kafka_catalog(
                        ssh,
                        paths,
                        TopicCatalog.from_json(content),
                        sudo_password=sudo_password,
                    )
            else:
                _write_kafka_catalog(
                    ssh,
                    paths,
                    catalog_before,
                    sudo_password=sudo_password,
                )

        # 1 Backup (SFTP when writable; else /tmp via sudo cat)
        bak_acl = _backup_mosquitto_secret(
            ssh, paths.acl, sudo_password=sudo_password
        )
        bak_pw = _backup_mosquitto_secret(
            ssh, paths.passwords, sudo_password=sudo_password
        )

        # 2 ACL upsert (replace block if user already exists)
        try:
            acl = fileops.upsert_user_acl(
                _read_mosquitto_secret(
                    ssh, paths.acl, sudo_password=sudo_password
                ),
                user_id,
                topic_rw=topic_rw,
                topic_r=topic_r,
            )
            _write_mosquitto_secret(
                ssh, paths.acl, acl, sudo_password=sudo_password
            )
        except Exception:
            _restore_backups(
                ssh,
                bak_acl=bak_acl,
                paths=paths,
                sudo_password=sudo_password,
            )
            _restore_kafka()
            raise

        # 3 Password hash line
        try:
            pw = fileops.merge_password_line(
                _read_mosquitto_secret(
                    ssh, paths.passwords, sudo_password=sudo_password
                ),
                hash_line,
            )
            _write_mosquitto_secret(
                ssh, paths.passwords, pw, sudo_password=sudo_password
            )
        except Exception:
            _restore_backups(
                ssh,
                bak_acl=bak_acl,
                bak_pw=bak_pw,
                paths=paths,
                sudo_password=sudo_password,
            )
            _restore_kafka()
            raise

        # 4 CSR sign (sudo: ca.key / ca.srl are mosquitto-owned after Install)
        try:
            signed = sign_csr_on_gateway(
                ssh,
                paths,
                material.csr_pem,
                ca_passphrase,
                days=cert_days,
                reject_default_admin_passphrase=reject_default_admin_passphrase,
                sudo_password=sudo_password,
            )
        except Exception:
            _restore_backups(
                ssh,
                bak_acl=bak_acl,
                bak_pw=bak_pw,
                paths=paths,
                sudo_password=sudo_password,
            )
            _restore_kafka()
            raise

        _chmod_mosquitto_secrets(ssh, paths, sudo_password=sudo_password)

        crypto_meta: dict[str, Any] = {}
        crypto_json: dict[str, Any] | None = None
        schema_json: dict[str, Any] | None = None
        if provision_crypto:
            try:
                # crypto/ and schemas/ are root-owned after Install; chown first.
                _ensure_data_subdir_writable(
                    ssh,
                    f"{paths.data_dir}/crypto/devices",
                    sudo_password=sudo_password,
                )
                _ensure_data_subdir_writable(
                    ssh,
                    f"{paths.data_dir}/schemas",
                    sudo_password=sudo_password,
                )
                if also_fake_crypto_copy:
                    _ensure_data_subdir_writable(
                        ssh,
                        f"{paths.data_dir}/fake/{user_id}",
                        sudo_password=sudo_password,
                    )
                provisioned = provision_device_crypto(
                    ssh,
                    user_id,
                    profile=crypto_profile,
                    schema_id=schema_id or "default",
                    schema=schema,
                    install_root=install_root,
                    data_dir=paths.data_dir,
                    also_fake_copy=also_fake_crypto_copy,
                )
                crypto_json = provisioned.get("secrets")
                schema_json = dict(schema) if isinstance(schema, dict) else dict(DEFAULT_SCHEMA)
                schema_json["schema_id"] = provisioned.get("schema_id") or schema_id or "default"
                crypto_meta = {
                    "crypto_profile": provisioned.get("profile"),
                    "schema_id": provisioned.get("schema_id"),
                    "crypto_path": provisioned.get("crypto_path"),
                }
            except Exception as exc:  # noqa: BLE001
                crypto_meta = {"crypto_error": str(exc)}

        cert_kw = _cert_fields(
            material, signed, crypto_json=crypto_json, schema_json=schema_json
        )
        backups = {"acl": bak_acl, "passwords": bak_pw, "kafka": bak_kafka}

        # 5 Reload mosquitto — files stay; do not roll back on failure.
        try:
            mosq_mode = reload_mosquitto(ssh, sudo_password=sudo_password)
        except Exception as exc:
            return RegisterResult(
                ok=True,
                status="degraded",
                message=f"files written but mosquitto reload failed: {exc}",
                details={
                    "user_id": user_id,
                    "ip": ip,
                    "backups": backups,
                    **kafka_meta,
                    **crypto_meta,
                },
                **cert_kw,
            )

        return RegisterResult(
            ok=True,
            status="ok",
            message="device registered",
            details={
                "user_id": user_id,
                "ip": ip,
                "mosquitto": mosq_mode,
                "backups": backups,
                **kafka_meta,
                **crypto_meta,
            },
            **cert_kw,
        )
    except Exception as exc:
        return RegisterResult(
            ok=False,
            status="failed",
            message=str(exc),
            details={"user_id": user_id, "ip": ip, **kafka_meta},
        )


def reissue_device_cert(
    ssh: "SSHClient",
    *,
    user_id: str,
    ca_passphrase: str,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    cert_days: int = 730,
    reject_default_admin_passphrase: bool = True,
    key_material: ClientKeyMaterial | None = None,
    sudo_password: str | None = None,
) -> RegisterResult:
    """Sign a fresh client cert for an existing device (no ACL/password changes)."""
    paths = _paths(install_root, data_dir)
    try:
        user_id = validate_user_id(user_id)
        material = key_material or generate_client_key_and_csr(cn=user_id)
        signed = sign_csr_on_gateway(
            ssh,
            paths,
            material.csr_pem,
            ca_passphrase,
            days=cert_days,
            reject_default_admin_passphrase=reject_default_admin_passphrase,
            sudo_password=sudo_password,
        )
        cert_kw = _cert_fields(material, signed)
        return RegisterResult(
            ok=True,
            status="ok",
            message="client certificate reissued",
            details={"user_id": user_id},
            **cert_kw,
        )
    except Exception as exc:  # noqa: BLE001
        return RegisterResult(ok=False, status="failed", message=str(exc))


def update_acl(
    ssh: "SSHClient",
    *,
    user_id: str,
    add_rw: list[str] | str | None = None,
    add_r: list[str] | str | None = None,
    delete_rw: list[str] | str | None = None,
    delete_r: list[str] | str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    sudo_password: str | None = None,
) -> PlaybookResult:
    """Update topics for an existing Mosquitto ACL user block."""
    try:
        user_id = validate_user_id(user_id)
        paths = _paths(install_root, data_dir)

        def _list(v: list[str] | str | None) -> list[str]:
            if v is None:
                return []
            if isinstance(v, str):
                return [validate_topic(t) for t in split_csv(v)]
            return [validate_topic(t) for t in v]

        add_rw_l, add_r_l = _list(add_rw), _list(add_r)
        del_rw_l, del_r_l = _list(delete_rw), _list(delete_r)

        bak = _backup_mosquitto_secret(
            ssh, paths.acl, sudo_password=sudo_password
        )
        try:
            content = _read_mosquitto_secret(
                ssh, paths.acl, sudo_password=sudo_password
            )
            updated = fileops.update_user_acl(
                content,
                user_id,
                add_rw=add_rw_l,
                add_r=add_r_l,
                delete_rw=del_rw_l,
                delete_r=del_r_l,
            )
            _write_mosquitto_secret(
                ssh, paths.acl, updated, sudo_password=sudo_password
            )
            _chmod_mosquitto_secrets(ssh, paths, sudo_password=sudo_password)
            mosq_mode = reload_mosquitto(ssh, sudo_password=sudo_password)
            return PlaybookResult(
                ok=True,
                message="ACL updated",
                details={"user_id": user_id, "backup": bak, "mosquitto": mosq_mode},
            )
        except Exception:
            try:
                _restore_mosquitto_secret(
                    ssh, paths.acl, bak, sudo_password=sudo_password
                )
            except Exception:
                pass
            raise
    except Exception as exc:
        return PlaybookResult(ok=False, status="failed", message=str(exc))


def unregister_device(
    ssh: "SSHClient",
    *,
    user_id: str,
    ip: str | None = None,
    remove_ip: bool = False,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    sudo_password: str | None = None,
) -> PlaybookResult:
    """Remove ACL block + password line + Kafka topic catalog entry.

    ``remove_ip`` is retained for API compatibility; the packaged agent has no
    HAProxy allow-list file, so IP removal is a no-op for remote files.
    """
    paths = _paths(install_root, data_dir)
    bak_acl = bak_pw = bak_kafka = None
    mosquitto_reloaded = False
    removed_topic: str | None = None

    try:
        user_id = validate_user_id(user_id)
        if ip is not None:
            ip = validate_ip_or_cidr(ip)

        bak_acl = _backup_mosquitto_secret(
            ssh, paths.acl, sudo_password=sudo_password
        )
        bak_pw = _backup_mosquitto_secret(
            ssh, paths.passwords, sudo_password=sudo_password
        )
        bak_kafka = _backup_kafka_catalog(
            ssh, paths, sudo_password=sudo_password
        )

        acl = fileops.remove_user_acl(
            _read_mosquitto_secret(
                ssh, paths.acl, sudo_password=sudo_password
            ),
            user_id,
        )
        _write_mosquitto_secret(
            ssh, paths.acl, acl, sudo_password=sudo_password
        )

        pw = fileops.remove_password_user(
            _read_mosquitto_secret(
                ssh, paths.passwords, sudo_password=sudo_password
            ),
            user_id,
        )
        _write_mosquitto_secret(
            ssh, paths.passwords, pw, sudo_password=sudo_password
        )

        catalog = _read_kafka_catalog(ssh, paths)
        removed = catalog.remove_device(user_id)
        if removed is not None:
            removed_topic = removed.topic
            _write_kafka_catalog(
                ssh, paths, catalog, sudo_password=sudo_password
            )
            try:
                from provisioner.kafka_install import delete_topic, kafka_present

                if kafka_present(ssh):  # type: ignore[arg-type]
                    delete_topic(ssh, topic=removed_topic)  # type: ignore[arg-type]
            except Exception:
                # Catalog already updated; broker delete can retry on next sync.
                pass

        _chmod_mosquitto_secrets(ssh, paths, sudo_password=sudo_password)
        mosq_mode = reload_mosquitto(ssh, sudo_password=sudo_password)
        mosquitto_reloaded = True

        return PlaybookResult(
            ok=True,
            message="device unregistered",
            details={
                "user_id": user_id,
                "removed_ip": ip if remove_ip else None,
                "mosquitto": mosq_mode,
                "kafka_topic_removed": removed_topic,
                "backups": {
                    "acl": bak_acl,
                    "passwords": bak_pw,
                    "kafka": bak_kafka,
                },
            },
        )
    except Exception as exc:
        if not mosquitto_reloaded:
            try:
                _restore_backups(
                    ssh,
                    bak_acl=bak_acl,
                    bak_pw=bak_pw,
                    paths=paths,
                    sudo_password=sudo_password,
                )
            except Exception:
                pass
            if bak_kafka:
                try:
                    ssh.restore_backup(paths.kafka_topics_catalog, bak_kafka)
                except Exception:
                    pass
            return PlaybookResult(ok=False, status="failed", message=str(exc))
        return PlaybookResult(
            ok=True,
            status="degraded",
            message=f"mosquitto updated but later step failed: {exc}",
            details={"user_id": user_id},
        )


def clear_logs(
    ssh: "SSHClient",
    *,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
) -> PlaybookResult:
    """Truncate agent-relevant Mosquitto and sensor data logs."""
    paths = _paths(install_root, data_dir)
    truncated: list[str] = []
    errors: list[str] = []
    for path in paths.log_paths():
        # Truncate in place so inodes watched by Promtail stay valid.
        result = ssh.run(
            f": > {shell_quote(path)} || truncate -s 0 {shell_quote(path)}"
        )
        if result.exit_code == 0:
            truncated.append(path)
        else:
            errors.append(f"{path}: {result.stderr.strip() or result.stdout.strip()}")
    if errors and not truncated:
        return PlaybookResult(
            ok=False,
            status="failed",
            message="; ".join(errors),
        )
    return PlaybookResult(
        ok=True,
        status="degraded" if errors else "ok",
        message="logs cleared" if not errors else "partial clear",
        details={"truncated": truncated, "errors": errors},
    )
