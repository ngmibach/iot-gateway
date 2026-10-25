"""SSH playbooks ported from Gitea workflows (secret-safe, compensating)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from . import files as fileops
from .csr import (
    ClientKeyMaterial,
    SignedClientCert,
    assemble_cert_bundle,
    generate_client_key_and_csr,
    sign_csr_on_gateway,
)
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
    from .ssh import SSHClient


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


def _chmod_mosquitto_secrets(ssh: "SSHClient", paths: GatewayPaths) -> None:
    ssh.run(
        f"chmod 0600 {shell_quote(paths.passwords)} {shell_quote(paths.acl)} || true"
    )
    ssh.run(
        f"chown mosquitto:mosquitto {shell_quote(paths.passwords)} "
        f"{shell_quote(paths.acl)} 2>/dev/null || true"
    )


def _restore_backups(
    ssh: "SSHClient",
    *,
    bak_acl: str | None = None,
    bak_pw: str | None = None,
    paths: GatewayPaths,
) -> None:
    if bak_pw:
        ssh.restore_backup(paths.passwords, bak_pw)
    if bak_acl:
        ssh.restore_backup(paths.acl, bak_acl)


def _cert_fields(
    material: ClientKeyMaterial,
    signed: SignedClientCert | None,
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
) -> RegisterResult:
    """Register MQTT user: ACL upsert + hashed passwd + CSR/sign.

    Compensating restores on failure through CSR sign. After Mosquitto reload,
    failures return ``ok=True, status="degraded"`` without rolling back live
    ACL/password files. ``ip`` is validated for registry metadata only (no
    HAProxy allow-list on the packaged agent).
    """
    bak_acl = bak_pw = None
    signed: SignedClientCert | None = None
    paths = _paths(install_root, data_dir)

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

        # 1 Backup
        bak_acl = ssh.backup(paths.acl)
        bak_pw = ssh.backup(paths.passwords)

        # 2 ACL upsert (replace block if user already exists)
        try:
            acl = fileops.upsert_user_acl(
                ssh.read_text(paths.acl),
                user_id,
                topic_rw=topic_rw,
                topic_r=topic_r,
            )
            ssh.write_text(paths.acl, acl, mode=0o600)
        except Exception:
            _restore_backups(ssh, bak_acl=bak_acl, paths=paths)
            raise

        # 3 Password hash line
        try:
            pw = fileops.merge_password_line(ssh.read_text(paths.passwords), hash_line)
            ssh.write_text(paths.passwords, pw, mode=0o600)
        except Exception:
            _restore_backups(ssh, bak_acl=bak_acl, bak_pw=bak_pw, paths=paths)
            raise

        # 4 CSR sign
        try:
            signed = sign_csr_on_gateway(
                ssh,
                paths,
                material.csr_pem,
                ca_passphrase,
                days=cert_days,
                reject_default_admin_passphrase=reject_default_admin_passphrase,
            )
        except Exception:
            _restore_backups(ssh, bak_acl=bak_acl, bak_pw=bak_pw, paths=paths)
            raise

        _chmod_mosquitto_secrets(ssh, paths)
        cert_kw = _cert_fields(material, signed)
        backups = {"acl": bak_acl, "passwords": bak_pw}

        # 5 Reload mosquitto — files stay; do not roll back on failure.
        try:
            mosq_mode = reload_mosquitto(ssh)
        except Exception as exc:
            return RegisterResult(
                ok=True,
                status="degraded",
                message=f"files written but mosquitto reload failed: {exc}",
                details={"user_id": user_id, "ip": ip, "backups": backups},
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
            },
            **cert_kw,
        )
    except Exception as exc:
        return RegisterResult(
            ok=False,
            status="failed",
            message=str(exc),
            details={"user_id": user_id, "ip": ip},
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

        bak = ssh.backup(paths.acl)
        try:
            content = ssh.read_text(paths.acl)
            updated = fileops.update_user_acl(
                content,
                user_id,
                add_rw=add_rw_l,
                add_r=add_r_l,
                delete_rw=del_rw_l,
                delete_r=del_r_l,
            )
            ssh.write_text(paths.acl, updated, mode=0o600)
            _chmod_mosquitto_secrets(ssh, paths)
            mosq_mode = reload_mosquitto(ssh)
            return PlaybookResult(
                ok=True,
                message="ACL updated",
                details={"user_id": user_id, "backup": bak, "mosquitto": mosq_mode},
            )
        except Exception:
            try:
                ssh.restore_backup(paths.acl, bak)
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
) -> PlaybookResult:
    """Remove ACL block + password line.

    ``remove_ip`` is retained for API compatibility; the packaged agent has no
    HAProxy allow-list file, so IP removal is a no-op for remote files.
    """
    paths = _paths(install_root, data_dir)
    bak_acl = bak_pw = None
    mosquitto_reloaded = False

    try:
        user_id = validate_user_id(user_id)
        if ip is not None:
            ip = validate_ip_or_cidr(ip)

        bak_acl = ssh.backup(paths.acl)
        bak_pw = ssh.backup(paths.passwords)

        acl = fileops.remove_user_acl(ssh.read_text(paths.acl), user_id)
        ssh.write_text(paths.acl, acl, mode=0o600)

        pw = fileops.remove_password_user(ssh.read_text(paths.passwords), user_id)
        ssh.write_text(paths.passwords, pw, mode=0o600)

        _chmod_mosquitto_secrets(ssh, paths)
        mosq_mode = reload_mosquitto(ssh)
        mosquitto_reloaded = True

        return PlaybookResult(
            ok=True,
            message="device unregistered",
            details={
                "user_id": user_id,
                "removed_ip": ip if remove_ip else None,
                "mosquitto": mosq_mode,
                "backups": {"acl": bak_acl, "passwords": bak_pw},
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
                )
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
