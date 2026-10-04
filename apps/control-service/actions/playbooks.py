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
from .haproxy import reload_haproxy, restart_mosquitto
from .mosquitto_hash import hash_password_line, zeroize_str
from .paths import DEFAULT_INSTALL_ROOT, GatewayPaths
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


def _paths(install_root: str) -> GatewayPaths:
    return GatewayPaths(install_root=install_root)


def _chmod_mosquitto_secrets(ssh: "SSHClient", paths: GatewayPaths) -> None:
    # Host bind-mount perms; best-effort container ownership like the old workflow.
    ssh.run(
        f"chmod 0600 {_shell_quote(paths.passwords)} {_shell_quote(paths.acl)} || true"
    )
    ssh.run(
        "docker compose"
        f" -f {_shell_quote(paths.compose_file)}"
        " exec -T mosquitto sh -c "
        "'chown mosquitto:mosquitto /mosquitto/config/passwords /mosquitto/config/acl"
        " && chmod 0600 /mosquitto/config/passwords /mosquitto/config/acl' || true"
    )


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def register_device(
    ssh: "SSHClient",
    *,
    user_id: str,
    password: str,
    ip: str,
    topic_rw: str | None = None,
    topic_r: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    ca_passphrase: str,
    cert_days: int = 730,
    reject_default_admin_passphrase: bool = True,
    key_material: ClientKeyMaterial | None = None,
) -> RegisterResult:
    """Register MQTT user: ACL + hashed passwd + allow-list IP + CSR/sign.

    Compensating restores on failure through step 5; mosquitto/haproxy reload
    failures leave files consistent (degraded) per design.
    """
    bak_acl = bak_pw = bak_ips = None
    signed: SignedClientCert | None = None

    try:
        user_id = validate_user_id(user_id)
        ip = validate_ip_or_cidr(ip)
        if topic_rw:
            topic_rw = validate_topic(topic_rw)
        if topic_r:
            topic_r = validate_topic(topic_r)

        paths = _paths(install_root)
        hash_line = hash_password_line(user_id, password)
        zeroize_str(password)

        material = key_material or generate_client_key_and_csr(cn=user_id)

        # 1 Backup
        bak_acl = ssh.backup(paths.acl)
        bak_pw = ssh.backup(paths.passwords)
        bak_ips = ssh.backup(paths.allowed_ips)

        # 2 ACL
        acl = ssh.read_text(paths.acl)
        acl = fileops.append_user_acl(
            acl, user_id, topic_rw=topic_rw, topic_r=topic_r
        )
        try:
            ssh.write_text(paths.acl, acl, mode=0o600)
        except Exception:
            if bak_acl:
                ssh.restore_backup(paths.acl, bak_acl)
            raise

        # 3 Password hash line
        try:
            pw = ssh.read_text(paths.passwords)
            pw = fileops.merge_password_line(pw, hash_line)
            ssh.write_text(paths.passwords, pw, mode=0o600)
        except Exception:
            if bak_pw:
                ssh.restore_backup(paths.passwords, bak_pw)
            if bak_acl:
                ssh.restore_backup(paths.acl, bak_acl)
            raise

        # 4 Allow-list
        try:
            ips = ssh.read_text(paths.allowed_ips)
            ips = fileops.add_allowlist_ips(ips, [ip])
            ssh.write_text(paths.allowed_ips, ips, mode=0o644)
        except Exception:
            if bak_ips:
                ssh.restore_backup(paths.allowed_ips, bak_ips)
            if bak_pw:
                ssh.restore_backup(paths.passwords, bak_pw)
            if bak_acl:
                ssh.restore_backup(paths.acl, bak_acl)
            raise

        # 5 CSR sign
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
            if bak_ips:
                ssh.restore_backup(paths.allowed_ips, bak_ips)
            if bak_pw:
                ssh.restore_backup(paths.passwords, bak_pw)
            if bak_acl:
                ssh.restore_backup(paths.acl, bak_acl)
            raise

        _chmod_mosquitto_secrets(ssh, paths)

        # 6 Restart mosquitto
        try:
            restart_mosquitto(ssh, paths)
        except Exception as exc:
            return RegisterResult(
                ok=False,
                status="degraded",
                message=f"files written but mosquitto restart failed: {exc}",
                details={"user_id": user_id, "ip": ip},
                client_key_pem=material.private_key_pem,
                client_crt_pem=signed.client_crt_pem if signed else None,
                ca_crt_pem=signed.ca_crt_pem if signed else None,
                cert_fingerprint=signed.fingerprint_sha256 if signed else None,
                cert_expires_at=(
                    signed.not_valid_after.isoformat()
                    if signed and signed.not_valid_after
                    else None
                ),
                cert_bundle=(
                    assemble_cert_bundle(
                        ca_crt_pem=signed.ca_crt_pem,
                        client_crt_pem=signed.client_crt_pem,
                        client_key_pem=material.private_key_pem,
                    )
                    if signed
                    else None
                ),
            )

        # 7 HAProxy reload
        haproxy_mode = "unknown"
        try:
            haproxy_mode = reload_haproxy(ssh, paths)
        except Exception as exc:
            return RegisterResult(
                ok=True,
                status="degraded",
                message=(
                    "ACL live, allow-list may be stale until haproxy reload: "
                    f"{exc}"
                ),
                details={
                    "user_id": user_id,
                    "ip": ip,
                    "haproxy": "failed",
                    "backups": {
                        "acl": bak_acl,
                        "passwords": bak_pw,
                        "allowed_ips": bak_ips,
                    },
                },
                client_key_pem=material.private_key_pem,
                client_crt_pem=signed.client_crt_pem,
                ca_crt_pem=signed.ca_crt_pem,
                cert_fingerprint=signed.fingerprint_sha256,
                cert_expires_at=(
                    signed.not_valid_after.isoformat()
                    if signed.not_valid_after
                    else None
                ),
                cert_bundle=assemble_cert_bundle(
                    ca_crt_pem=signed.ca_crt_pem,
                    client_crt_pem=signed.client_crt_pem,
                    client_key_pem=material.private_key_pem,
                ),
            )

        assert signed is not None
        return RegisterResult(
            ok=True,
            status="ok",
            message="device registered",
            details={
                "user_id": user_id,
                "ip": ip,
                "haproxy": haproxy_mode,
                "backups": {
                    "acl": bak_acl,
                    "passwords": bak_pw,
                    "allowed_ips": bak_ips,
                },
            },
            client_key_pem=material.private_key_pem,
            client_crt_pem=signed.client_crt_pem,
            ca_crt_pem=signed.ca_crt_pem,
            cert_fingerprint=signed.fingerprint_sha256,
            cert_expires_at=(
                signed.not_valid_after.isoformat()
                if signed.not_valid_after
                else None
            ),
            cert_bundle=assemble_cert_bundle(
                ca_crt_pem=signed.ca_crt_pem,
                client_crt_pem=signed.client_crt_pem,
                client_key_pem=material.private_key_pem,
            ),
        )
    except Exception as exc:
        return RegisterResult(
            ok=False,
            status="failed",
            message=str(exc),
            details={"user_id": user_id, "ip": ip},
        )


def update_acl(
    ssh: "SSHClient",
    *,
    user_id: str,
    add_rw: list[str] | str | None = None,
    add_r: list[str] | str | None = None,
    delete_rw: list[str] | str | None = None,
    delete_r: list[str] | str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
) -> PlaybookResult:
    """Port of update_acl.yaml."""
    user_id = validate_user_id(user_id)
    paths = _paths(install_root)

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
        restart_mosquitto(ssh, paths)
        return PlaybookResult(
            ok=True,
            message="ACL updated",
            details={"user_id": user_id, "backup": bak},
        )
    except Exception as exc:
        try:
            ssh.restore_backup(paths.acl, bak)
        except Exception:
            pass
        return PlaybookResult(ok=False, status="failed", message=str(exc))


def update_allowlist_ips(
    ssh: "SSHClient",
    *,
    add_ips: list[str] | str | None = None,
    remove_ips: list[str] | str | None = None,
    remove_all: bool = False,
    install_root: str = DEFAULT_INSTALL_ROOT,
) -> PlaybookResult:
    """Port of update_device_ip.yaml — HUP/restart, never down -v."""
    paths = _paths(install_root)

    def _ips(v: list[str] | str | None) -> list[str]:
        if v is None:
            return []
        raw = split_csv(v) if isinstance(v, str) else list(v)
        return [validate_ip_or_cidr(x) for x in raw]

    try:
        add_l, rem_l = _ips(add_ips), _ips(remove_ips)
        if not remove_all and not add_l and not rem_l:
            return PlaybookResult(ok=True, message="no allow-list changes")

        bak = ssh.backup(paths.allowed_ips)
        try:
            content = ssh.read_text(paths.allowed_ips)
            if remove_all:
                content = fileops.clear_allowlist(content)
            else:
                if rem_l:
                    content = fileops.remove_allowlist_ips(content, rem_l)
                if add_l:
                    content = fileops.add_allowlist_ips(content, add_l)
            ssh.write_text(paths.allowed_ips, content, mode=0o644)
            mode = reload_haproxy(ssh, paths)
            return PlaybookResult(
                ok=True,
                message="allow-list updated",
                details={"haproxy": mode, "backup": bak},
            )
        except Exception:
            try:
                ssh.restore_backup(paths.allowed_ips, bak)
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
) -> PlaybookResult:
    """Remove ACL block + password line; optionally remove IP if not shared."""
    user_id = validate_user_id(user_id)
    if ip is not None:
        ip = validate_ip_or_cidr(ip)
    paths = _paths(install_root)

    bak_acl = ssh.backup(paths.acl)
    bak_pw = ssh.backup(paths.passwords)
    bak_ips = ssh.backup(paths.allowed_ips) if remove_ip and ip else None

    try:
        acl = fileops.remove_user_acl(ssh.read_text(paths.acl), user_id)
        ssh.write_text(paths.acl, acl, mode=0o600)

        pw = fileops.remove_password_user(ssh.read_text(paths.passwords), user_id)
        ssh.write_text(paths.passwords, pw, mode=0o600)

        if remove_ip and ip:
            ips = fileops.remove_allowlist_ips(ssh.read_text(paths.allowed_ips), [ip])
            ssh.write_text(paths.allowed_ips, ips, mode=0o644)

        _chmod_mosquitto_secrets(ssh, paths)
        restart_mosquitto(ssh, paths)
        haproxy_mode = None
        if remove_ip and ip:
            haproxy_mode = reload_haproxy(ssh, paths)

        return PlaybookResult(
            ok=True,
            message="device unregistered",
            details={
                "user_id": user_id,
                "removed_ip": ip if remove_ip else None,
                "haproxy": haproxy_mode,
                "backups": {
                    "acl": bak_acl,
                    "passwords": bak_pw,
                    "allowed_ips": bak_ips,
                },
            },
        )
    except Exception as exc:
        try:
            ssh.restore_backup(paths.acl, bak_acl)
            ssh.restore_backup(paths.passwords, bak_pw)
            if bak_ips:
                ssh.restore_backup(paths.allowed_ips, bak_ips)
        except Exception:
            pass
        return PlaybookResult(ok=False, status="failed", message=str(exc))


def clear_logs(
    ssh: "SSHClient",
    *,
    install_root: str = DEFAULT_INSTALL_ROOT,
) -> PlaybookResult:
    """Truncate mosquitto, nodered, haproxy, gateway-state, ids-alerts logs."""
    paths = _paths(install_root)
    truncated: list[str] = []
    errors: list[str] = []
    for path in paths.log_paths():
        # Truncate in place so inodes watched by Promtail stay valid.
        result = ssh.run(f": > {_shell_quote(path)} || truncate -s 0 {_shell_quote(path)}")
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
