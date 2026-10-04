"""SSH host-key pin + ed25519 key generate/install (Setup Wizard).

Flow: Fetch fingerprint → user Pin (app known_hosts) → Install ed25519 via
one-time password. Password is never kept after a successful key-auth probe;
``password_auth_disabled`` is set and the keyring secret is deleted.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from . import keyring_store
from .paths import known_hosts_path, load_settings, save_settings, ssh_keys_dir


@dataclass(frozen=True)
class HostKeyInfo:
    host: str
    port: int
    key_type: str
    fingerprint_sha256: str
    base64: str


@dataclass(frozen=True)
class KeyPairPaths:
    private: Path
    public: Path


def key_paths_for(gateway_id: str) -> KeyPairPaths:
    base = ssh_keys_dir() / f"id_ed25519_{gateway_id}"
    return KeyPairPaths(private=base, public=Path(str(base) + ".pub"))


def generate_ed25519(gateway_id: str, *, force: bool = False) -> KeyPairPaths:
    """Create ed25519 keypair with ssh-keygen (no passphrase on key file)."""
    paths = key_paths_for(gateway_id)
    if paths.private.is_file() and not force:
        return paths
    if paths.private.is_file():
        paths.private.unlink()
    if paths.public.is_file():
        paths.public.unlink()
    subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(paths.private),
            "-N",
            "",
            "-C",
            f"iot-gateway-monitor-{gateway_id}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    os.chmod(paths.private, 0o600)
    return paths


def _fingerprint_sha256(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def fetch_host_key(host: str, port: int = 22, timeout: float = 15.0) -> HostKeyInfo:
    """Fetch remote host key via Paramiko (no auth); return pin-able info."""
    import paramiko

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        trans = paramiko.Transport(sock)
        try:
            trans.start_client(timeout=timeout)
            key = trans.get_remote_server_key()
        finally:
            trans.close()
    finally:
        sock.close()
    raw = key.asbytes()
    return HostKeyInfo(
        host=host,
        port=port,
        key_type=key.get_name(),
        fingerprint_sha256=_fingerprint_sha256(raw),
        base64=base64.b64encode(raw).decode("ascii"),
    )


def pin_lookup_key(host: str, port: int = 22) -> Optional[str]:
    """Return pinned host_key_base64 from settings index, if present."""
    settings = load_settings()
    pin = settings.get("ssh_host_pins", {}).get(f"{host}:{port}")
    if not isinstance(pin, dict):
        return None
    b64 = pin.get("base64")
    return str(b64) if b64 else None


def pin_host_key(info: HostKeyInfo) -> None:
    """Write host key to app known_hosts (canonical) + settings fingerprint index."""
    path = known_hosts_path()
    host_field = info.host if info.port == 22 else f"[{info.host}]:{info.port}"
    line = f"{host_field} {info.key_type} {info.base64}\n"
    existing: list[str] = []
    if path.is_file():
        existing = path.read_text(encoding="utf-8").splitlines(True)
    kept = [ln for ln in existing if not ln.startswith(host_field + " ")]
    kept.append(line)
    path.write_text("".join(kept), encoding="utf-8")
    os.chmod(path, 0o600)

    # settings index is for UI/API lookup; known_hosts is what SSHClient loads.
    settings = load_settings()
    pins = settings.setdefault("ssh_host_pins", {})
    pins[f"{info.host}:{info.port}"] = {
        "key_type": info.key_type,
        "fingerprint_sha256": info.fingerprint_sha256,
        "base64": info.base64,
    }
    save_settings(settings)


def resolve_required_pin(
    host: str,
    port: int,
    host_key_base64: Optional[str],
) -> str:
    """Require a wizard pin before password-bearing install.

    ``host_key_base64`` must match the pinned value when both are present.
    """
    pinned = pin_lookup_key(host, port)
    if not pinned:
        raise ValueError(
            "Host key must be pinned in Setup Wizard before installing an SSH key"
        )
    if host_key_base64 and str(host_key_base64) != pinned:
        raise ValueError("host_key_base64 does not match the pinned host key")
    return pinned


def install_pubkey(
    host: str,
    username: str,
    password: str,
    gateway_id: str,
    *,
    port: int = 22,
    host_key_base64: Optional[str] = None,
) -> dict[str, Any]:
    """One-time password SSH: append ed25519 pubkey; then clear password secret."""
    from actions.shellutil import shell_quote  # type: ignore[import-not-found]
    from actions.ssh import SSHClient, SSHTarget  # type: ignore[import-not-found]

    if not gateway_id or any(c in gateway_id for c in " \t\n/\\"):
        raise ValueError("gateway_id must be a non-empty path-safe token")
    pin_b64 = resolve_required_pin(host, port, host_key_base64)

    paths = generate_ed25519(gateway_id)
    pubkey = paths.public.read_text(encoding="utf-8").strip()
    app_known = str(known_hosts_path())
    target = SSHTarget(
        host=host,
        username=username,
        port=port,
        password=password,
        host_key_base64=pin_b64,
        known_hosts_paths=[app_known],
        allow_unknown_host=False,
    )
    client = SSHClient(target)
    try:
        client.connect()
        q = shell_quote(pubkey)
        script = (
            "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
            "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; "
            f"grep -qxF {q} ~/.ssh/authorized_keys || "
            f"echo {q} >> ~/.ssh/authorized_keys"
        )
        result = client.run(script)
        result.check()
    finally:
        client.close()

    # Probe key-only auth; on success drop password from keyring.
    key_target = SSHTarget(
        host=host,
        username=username,
        port=port,
        key_filename=str(paths.private),
        host_key_base64=pin_b64,
        known_hosts_paths=[app_known],
        allow_unknown_host=False,
    )
    key_client = SSHClient(key_target)
    try:
        key_client.connect()
        key_client.run("true").check()
    finally:
        key_client.close()

    settings = load_settings()
    gateways = settings.setdefault("gateways", {})
    gateways[gateway_id] = {
        "host": host,
        "port": port,
        "username": username,
        "ssh_key_path": str(paths.private),
    }
    save_settings(settings)
    mark_password_auth_disabled(gateway_id)

    return {
        "gateway_id": gateway_id,
        "ssh_key_path": str(paths.private),
        "pubkey_installed": True,
        "password_auth_disabled": True,
        "password_retained": False,
    }


def mark_password_auth_disabled(gateway_id: str) -> None:
    """Flag gateway as key-only and delete any leftover keyring password."""
    settings = load_settings()
    gw = settings.get("gateways", {}).get(gateway_id)
    if not gw:
        return
    gw["password_auth_disabled"] = True
    gw.pop("ssh_password_ref", None)
    save_settings(settings)
    keyring_store.delete_secret(gateway_id, kind="ssh")


def host_key_info_dict(info: HostKeyInfo) -> dict[str, Any]:
    return asdict(info)
