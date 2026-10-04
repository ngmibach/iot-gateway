"""Rotate server cert (IP SAN, same CA) vs break-glass CA + reissue devices.

Server SAN follows ``cert-generation.sh`` (``subjectAltName=IP:GATEWAY_IP``),
not the SAN-less ``update_key.yaml`` path (K15). CA passphrase never appears
on remote argv — only ``-passin file:`` / ``-passout file:`` (K7).
"""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Sequence

from actions.csr import (
    ClientKeyMaterial,
    assemble_cert_bundle,
    generate_client_key_and_csr,
    sign_csr_on_gateway,
)
from actions.haproxy import reload_haproxy, restart_mosquitto
from actions.paths import DEFAULT_INSTALL_ROOT, GatewayPaths
from actions.shellutil import shell_quote

if TYPE_CHECKING:
    from actions.ssh import SSHClient
    from registry.registry import Registry


def server_san_extfile(gateway_ip: str) -> str:
    """OpenSSL extfile body matching cert-generation.sh (IP SAN only)."""
    return f"subjectAltName=IP:{gateway_ip}\n"


def _validate_gateway_ip(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("gateway_ip required")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"gateway_ip must be a single IP (not CIDR): {value!r}") from exc
    return value


def _reject_admin(passphrase: str, *, reject: bool) -> None:
    if not passphrase:
        raise ValueError("CA passphrase required")
    if reject and passphrase == "admin":
        raise ValueError("production profile refuses CA passphrase 'admin'")


def _paths(install_root: str) -> GatewayPaths:
    return GatewayPaths(install_root=install_root)


def _backup_if_exists(ssh: "SSHClient", path: str) -> Optional[str]:
    if ssh.exists(path):
        return ssh.backup(path)
    return None


def _install_server_files(
    ssh: "SSHClient",
    paths: GatewayPaths,
    *,
    server_crt_pem: bytes,
    server_key_pem: bytes,
) -> bytes:
    pem = server_crt_pem.rstrip(b"\n") + b"\n" + server_key_pem
    ssh.run(f"mkdir -p {shell_quote(paths.certs_dir)}").check()
    ssh.write_bytes(paths.server_crt, server_crt_pem, mode=0o644)
    ssh.write_bytes(paths.server_key, server_key_pem, mode=0o600)
    ssh.write_bytes(paths.server_pem, pem, mode=0o644)
    ssh.run(
        f"chmod 644 {shell_quote(paths.server_crt)} {shell_quote(paths.server_pem)} "
        f"{shell_quote(paths.ca_crt)} 2>/dev/null || true"
    )
    ssh.run(f"chmod 600 {shell_quote(paths.server_key)} 2>/dev/null || true")
    ssh.run(
        f"chown -R 1883:1883 {shell_quote(paths.certs_dir)} 2>/dev/null || true"
    )
    return pem


def _restart_tls_frontends(ssh: "SSHClient", paths: GatewayPaths) -> dict[str, str]:
    restart_mosquitto(ssh, paths)
    mode = reload_haproxy(ssh, paths)
    return {"mosquitto": "restart", "haproxy": mode}


@dataclass
class RotateServerResult:
    ok: bool
    status: str = "ok"
    message: str = ""
    server_crt_pem: Optional[bytes] = None
    ca_crt_pem: Optional[bytes] = None
    not_valid_after: Optional[datetime] = None
    fingerprint_sha256: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeviceReissue:
    device_id: str
    client_key_pem: bytes
    client_crt_pem: bytes
    ca_crt_pem: bytes
    cert_bundle: bytes
    not_valid_after: Optional[datetime] = None
    fingerprint_sha256: Optional[str] = None


@dataclass
class RotateCAResult:
    ok: bool
    status: str = "ok"
    message: str = ""
    ca_crt_pem: Optional[bytes] = None
    server_crt_pem: Optional[bytes] = None
    devices: list[DeviceReissue] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def rotate_server_cert(
    ssh: "SSHClient",
    *,
    gateway_ip: str,
    ca_passphrase: str,
    install_root: str = DEFAULT_INSTALL_ROOT,
    days: int = 730,
    reject_default_admin_passphrase: bool = True,
    key_material: ClientKeyMaterial | None = None,
) -> RotateServerResult:
    """Re-issue gateway server cert with IP SAN; keep existing CA (K15).

    Operator generates key+CSR (OU=Broker, CN=gateway_ip); gateway signs with
    ``-extfile`` ``subjectAltName=IP:…`` and ``-passin file:``. Writes
    ``server.crt`` / ``server.key`` / ``server.pem``, then restarts mosquitto
    and reloads haproxy.
    """
    bak: dict[str, Optional[str]] = {}
    paths = _paths(install_root)
    try:
        gateway_ip = _validate_gateway_ip(gateway_ip)
        _reject_admin(ca_passphrase, reject=reject_default_admin_passphrase)

        bak = {
            "server_crt": _backup_if_exists(ssh, paths.server_crt),
            "server_key": _backup_if_exists(ssh, paths.server_key),
            "server_pem": _backup_if_exists(ssh, paths.server_pem),
        }

        material = key_material or generate_client_key_and_csr(
            cn=gateway_ip,
            org_unit="Broker",
        )
        signed = sign_csr_on_gateway(
            ssh,
            paths,
            material.csr_pem,
            ca_passphrase,
            days=days,
            reject_default_admin_passphrase=reject_default_admin_passphrase,
            extfile_content=server_san_extfile(gateway_ip),
        )
        _install_server_files(
            ssh,
            paths,
            server_crt_pem=signed.client_crt_pem,
            server_key_pem=material.private_key_pem,
        )
        try:
            services = _restart_tls_frontends(ssh, paths)
        except Exception as exc:
            return RotateServerResult(
                ok=True,
                status="degraded",
                message=f"server cert written but service reload failed: {exc}",
                server_crt_pem=signed.client_crt_pem,
                ca_crt_pem=signed.ca_crt_pem,
                not_valid_after=signed.not_valid_after,
                fingerprint_sha256=signed.fingerprint_sha256,
                details={
                    "gateway_ip": gateway_ip,
                    "san": f"IP:{gateway_ip}",
                    "backups": bak,
                    "services": "failed",
                },
            )
        return RotateServerResult(
            ok=True,
            message="server certificate rotated",
            server_crt_pem=signed.client_crt_pem,
            ca_crt_pem=signed.ca_crt_pem,
            not_valid_after=signed.not_valid_after,
            fingerprint_sha256=signed.fingerprint_sha256,
            details={
                "gateway_ip": gateway_ip,
                "san": f"IP:{gateway_ip}",
                "backups": bak,
                "services": services,
            },
        )
    except Exception as exc:
        for name, bak_path in bak.items():
            if not bak_path:
                continue
            dest = {
                "server_crt": paths.server_crt,
                "server_key": paths.server_key,
                "server_pem": paths.server_pem,
            }[name]
            try:
                ssh.restore_backup(dest, bak_path)
            except Exception:
                pass
        return RotateServerResult(
            ok=False,
            status="failed",
            message=str(exc),
            details={"gateway_ip": gateway_ip, "backups": bak},
        )


def _generate_ca_on_gateway(
    ssh: "SSHClient",
    paths: GatewayPaths,
    ca_passphrase: str,
    *,
    days: int,
    country: str,
    state: str,
    city: str,
    organization: str,
    org_unit: str,
    ca_cn: str,
) -> None:
    """Create new ca.key / ca.crt on gateway via passout/passin file: only."""
    token = secrets.token_hex(8)
    remote_pass = f"/tmp/iotgw-ca-pass-{token}"
    remote_key = f"/tmp/iotgw-ca-{token}.key"
    remote_crt = f"/tmp/iotgw-ca-{token}.crt"
    subj = (
        f"/C={country}/ST={state}/L={city}/O={organization}/OU={org_unit}/CN={ca_cn}"
    )
    try:
        ssh.write_bytes(remote_pass, ca_passphrase.encode("utf-8"), mode=0o600)
        ssh.run(f"mkdir -p {shell_quote(paths.certs_dir)}").check()
        # Never -passout pass: / -passin pass: on argv.
        ssh.run(
            "openssl genrsa -aes256"
            f" -passout file:{remote_pass}"
            f" -out {shell_quote(remote_key)} 2048",
            timeout=300,
        ).check()
        ssh.run(
            "openssl req -new -x509"
            f" -days {int(days)}"
            f" -key {shell_quote(remote_key)}"
            f" -passin file:{remote_pass}"
            f" -out {shell_quote(remote_crt)}"
            f" -subj {shell_quote(subj)}",
            timeout=300,
        ).check()
        ca_key = ssh.read_bytes(remote_key)
        ca_crt = ssh.read_bytes(remote_crt)
        ssh.write_bytes(paths.ca_key, ca_key, mode=0o600)
        ssh.write_bytes(paths.ca_crt, ca_crt, mode=0o644)
        ssh.run(f"chmod 600 {shell_quote(paths.ca_key)} 2>/dev/null || true")
        ssh.run(f"chmod 644 {shell_quote(paths.ca_crt)} 2>/dev/null || true")
    finally:
        for path in (remote_pass, remote_key, remote_crt):
            try:
                ssh.unlink(path)
            except Exception:
                pass


def _reissue_device(
    ssh: "SSHClient",
    paths: GatewayPaths,
    device_id: str,
    ca_passphrase: str,
    *,
    days: int,
    reject_default_admin_passphrase: bool,
    key_material: ClientKeyMaterial | None = None,
) -> DeviceReissue:
    material = key_material or generate_client_key_and_csr(cn=device_id)
    signed = sign_csr_on_gateway(
        ssh,
        paths,
        material.csr_pem,
        ca_passphrase,
        days=days,
        reject_default_admin_passphrase=reject_default_admin_passphrase,
    )
    bundle = assemble_cert_bundle(
        ca_crt_pem=signed.ca_crt_pem,
        client_crt_pem=signed.client_crt_pem,
        client_key_pem=material.private_key_pem,
    )
    return DeviceReissue(
        device_id=device_id,
        client_key_pem=material.private_key_pem,
        client_crt_pem=signed.client_crt_pem,
        ca_crt_pem=signed.ca_crt_pem,
        cert_bundle=bundle,
        not_valid_after=signed.not_valid_after,
        fingerprint_sha256=signed.fingerprint_sha256,
    )


def rotate_ca(
    ssh: "SSHClient",
    *,
    gateway_ip: str,
    ca_passphrase: str,
    confirm_break_glass: bool,
    device_ids: Sequence[str] | None = None,
    registry: "Registry | None" = None,
    gateway_id: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    ca_days: int = 3650,
    server_days: int = 730,
    client_days: int = 730,
    reject_default_admin_passphrase: bool = True,
    country: str = "VN",
    state: str = "Hanoi",
    city: str = "Hanoi",
    organization: str = "My IOT Org",
    org_unit: str = "IOT Devices",
    ca_cn: str = "My IOT CA Root",
    server_key_material: ClientKeyMaterial | None = None,
    device_key_material: dict[str, ClientKeyMaterial] | None = None,
) -> RotateCAResult:
    """Break-glass: new CA + server (IP SAN) + reissue all registry devices.

    Requires ``confirm_break_glass=True``. Client keys use the CSR/sign flow
    (``generate_client_key_and_csr`` + ``sign_csr_on_gateway``). Caller must
    redistribute returned device bundles; registry cert metadata is updated
    when ``registry`` + ``gateway_id`` are provided.
    """
    bak: dict[str, Optional[str]] = {}
    paths = _paths(install_root)
    try:
        if not confirm_break_glass:
            raise ValueError(
                "rotate_ca is break-glass; pass confirm_break_glass=True"
            )
        gateway_ip = _validate_gateway_ip(gateway_ip)
        _reject_admin(ca_passphrase, reject=reject_default_admin_passphrase)

        ids: list[str]
        if device_ids is not None:
            ids = [d for d in device_ids if d]
        elif registry is not None and gateway_id is not None:
            ids = [d["id"] for d in registry.list_devices(gateway_id)]
        else:
            ids = []

        bak = {
            "ca_crt": _backup_if_exists(ssh, paths.ca_crt),
            "ca_key": _backup_if_exists(ssh, paths.ca_key),
            "server_crt": _backup_if_exists(ssh, paths.server_crt),
            "server_key": _backup_if_exists(ssh, paths.server_key),
            "server_pem": _backup_if_exists(ssh, paths.server_pem),
        }

        _generate_ca_on_gateway(
            ssh,
            paths,
            ca_passphrase,
            days=ca_days,
            country=country,
            state=state,
            city=city,
            organization=organization,
            org_unit=org_unit,
            ca_cn=ca_cn,
        )

        server_mat = server_key_material or generate_client_key_and_csr(
            cn=gateway_ip,
            org_unit="Broker",
        )
        server_signed = sign_csr_on_gateway(
            ssh,
            paths,
            server_mat.csr_pem,
            ca_passphrase,
            days=server_days,
            reject_default_admin_passphrase=reject_default_admin_passphrase,
            extfile_content=server_san_extfile(gateway_ip),
        )
        _install_server_files(
            ssh,
            paths,
            server_crt_pem=server_signed.client_crt_pem,
            server_key_pem=server_mat.private_key_pem,
        )

        reissued: list[DeviceReissue] = []
        for device_id in ids:
            mat = (device_key_material or {}).get(device_id)
            item = _reissue_device(
                ssh,
                paths,
                device_id,
                ca_passphrase,
                days=client_days,
                reject_default_admin_passphrase=reject_default_admin_passphrase,
                key_material=mat,
            )
            reissued.append(item)
            if registry is not None and gateway_id is not None:
                expires: Any = None
                if item.not_valid_after is not None:
                    expires = int(item.not_valid_after.timestamp())
                registry.upsert_device(
                    gateway_id,
                    device_id,
                    cert_expires_at=expires,
                    cert_fingerprint=item.fingerprint_sha256,
                )
                registry.audit(
                    "rotate_ca_reissue_device",
                    gateway_id=gateway_id,
                    device_id=device_id,
                    detail={"fingerprint": item.fingerprint_sha256},
                )

        if registry is not None and gateway_id is not None:
            registry.audit(
                "rotate_ca",
                gateway_id=gateway_id,
                detail={
                    "gateway_ip": gateway_ip,
                    "device_count": len(reissued),
                    "san": f"IP:{gateway_ip}",
                },
            )

        ca_crt = ssh.read_bytes(paths.ca_crt)
        try:
            services = _restart_tls_frontends(ssh, paths)
        except Exception as exc:
            return RotateCAResult(
                ok=True,
                status="degraded",
                message=(
                    "CA/server/device certs written but service reload failed: "
                    f"{exc}"
                ),
                ca_crt_pem=ca_crt,
                server_crt_pem=server_signed.client_crt_pem,
                devices=reissued,
                details={
                    "gateway_ip": gateway_ip,
                    "san": f"IP:{gateway_ip}",
                    "device_ids": ids,
                    "backups": bak,
                    "services": "failed",
                },
            )
        return RotateCAResult(
            ok=True,
            message="CA rotated; redistribute device cert bundles",
            ca_crt_pem=ca_crt,
            server_crt_pem=server_signed.client_crt_pem,
            devices=reissued,
            details={
                "gateway_ip": gateway_ip,
                "san": f"IP:{gateway_ip}",
                "device_ids": ids,
                "backups": bak,
                "services": services,
            },
        )
    except Exception as exc:
        for name, bak_path in bak.items():
            if not bak_path:
                continue
            dest = {
                "ca_crt": paths.ca_crt,
                "ca_key": paths.ca_key,
                "server_crt": paths.server_crt,
                "server_key": paths.server_key,
                "server_pem": paths.server_pem,
            }[name]
            try:
                ssh.restore_backup(dest, bak_path)
            except Exception:
                pass
        return RotateCAResult(
            ok=False,
            status="failed",
            message=str(exc),
            details={"gateway_ip": gateway_ip, "backups": bak},
        )
