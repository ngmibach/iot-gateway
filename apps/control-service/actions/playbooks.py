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


def _paths(install_root: str) -> GatewayPaths:
    return GatewayPaths(install_root=install_root)


def _chmod_mosquitto_secrets(ssh: "SSHClient", paths: GatewayPaths) -> None:
    # Host bind-mount perms; best-effort container ownership like the old workflow.
    ssh.run(
        f"chmod 0600 {shell_quote(paths.passwords)} {shell_quote(paths.acl)} || true"
    )
    ssh.run(
        "docker compose"
        f" -f {shell_quote(paths.compose_file)}"
        " exec -T mosquitto sh -c "
        "'chown mosquitto:mosquitto /mosquitto/config/passwords /mosquitto/config/acl"
        " && chmod 0600 /mosquitto/config/passwords /mosquitto/config/acl' || true"
    )


def _restore_backups(
    ssh: "SSHClient",
    *,
    bak_acl: str | None = None,
    bak_pw: str | None = None,
    bak_ips: str | None = None,
    paths: GatewayPaths,
) -> None:
    if bak_ips:
        ssh.restore_backup(paths.allowed_ips, bak_ips)
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
    ca_passphrase: str,
    cert_days: int = 730,
    reject_default_admin_passphrase: bool = True,
    key_material: ClientKeyMaterial | None = None,
) -> RegisterResult:
    """Register MQTT user: ACL upsert + hashed passwd + allow-list IP + CSR/sign.

    Compensating restores on failure through step 5. After mosquitto restart,
    reload failures return ``ok=True, status="degraded"`` without rolling back
    live ACL/password files.
    """
    bak_acl = bak_pw = bak_ips = None
    signed: SignedClientCert | None = None
    paths = _paths(install_root)

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
        bak_ips = ssh.backup(paths.allowed_ips)

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

        # 4 Allow-list
        try:
            ips = fileops.add_allowlist_ips(ssh.read_text(paths.allowed_ips), [ip])
            ssh.write_text(paths.allowed_ips, ips, mode=0o644)
        except Exception:
            _restore_backups(
                ssh, bak_acl=bak_acl, bak_pw=bak_pw, bak_ips=bak_ips, paths=paths
            )
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
            _restore_backups(
                ssh, bak_acl=bak_acl, bak_pw=bak_pw, bak_ips=bak_ips, paths=paths
            )
            raise

        _chmod_mosquitto_secrets(ssh, paths)
        cert_kw = _cert_fields(material, signed)
        backups = {"acl": bak_acl, "passwords": bak_pw, "allowed_ips": bak_ips}

        # 6 Restart mosquitto — files stay; do not roll back on failure.
        try:
            restart_mosquitto(ssh, paths)
        except Exception as exc:
            return RegisterResult(
                ok=True,
                status="degraded",
                message=f"files written but mosquitto restart failed: {exc}",
                details={"user_id": user_id, "ip": ip, "backups": backups},
                **cert_kw,
            )

        # 7 HAProxy reload — do not roll back mosquitto-live files.
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
                    "backups": backups,
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
                "haproxy": haproxy_mode,
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
    try:
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
        except Exception:
            try:
                ssh.restore_backup(paths.acl, bak)
            except Exception:
                pass
            raise
    except Exception as exc:
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
    """Remove ACL block + password line; optionally remove IP.

    ``remove_ip=True`` is unsafe without a registry/shared-IP check — the
    caller must confirm no other device shares ``ip``. Default is False.
    """
    paths = _paths(install_root)
    bak_acl = bak_pw = bak_ips = None
    mosquitto_restarted = False

    try:
        user_id = validate_user_id(user_id)
        if ip is not None:
            ip = validate_ip_or_cidr(ip)

        bak_acl = ssh.backup(paths.acl)
        bak_pw = ssh.backup(paths.passwords)
        bak_ips = ssh.backup(paths.allowed_ips) if remove_ip and ip else None

        acl = fileops.remove_user_acl(ssh.read_text(paths.acl), user_id)
        ssh.write_text(paths.acl, acl, mode=0o600)

        pw = fileops.remove_password_user(ssh.read_text(paths.passwords), user_id)
        ssh.write_text(paths.passwords, pw, mode=0o600)

        if remove_ip and ip:
            ips = fileops.remove_allowlist_ips(ssh.read_text(paths.allowed_ips), [ip])
            ssh.write_text(paths.allowed_ips, ips, mode=0o644)

        _chmod_mosquitto_secrets(ssh, paths)
        restart_mosquitto(ssh, paths)
        mosquitto_restarted = True

        haproxy_mode = None
        if remove_ip and ip:
            try:
                haproxy_mode = reload_haproxy(ssh, paths)
            except Exception as exc:
                # Mosquitto already dropped the user — do not restore ACL/passwd.
                return PlaybookResult(
                    ok=True,
                    status="degraded",
                    message=(
                        "user removed from mosquitto; allow-list may be stale "
                        f"until haproxy reload: {exc}"
                    ),
                    details={
                        "user_id": user_id,
                        "removed_ip": ip,
                        "haproxy": "failed",
                        "backups": {
                            "acl": bak_acl,
                            "passwords": bak_pw,
                            "allowed_ips": bak_ips,
                        },
                    },
                )

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
        if not mosquitto_restarted:
            try:
                _restore_backups(
                    ssh,
                    bak_acl=bak_acl,
                    bak_pw=bak_pw,
                    bak_ips=bak_ips,
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
) -> PlaybookResult:
    """Truncate mosquitto, nodered, haproxy, gateway-state, ids-alerts logs."""
    paths = _paths(install_root)
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
