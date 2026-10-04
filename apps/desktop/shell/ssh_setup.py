"""SSH host-key pin + ed25519 key generate/install (Setup Wizard).

First connect: show fingerprint, user confirms pin → write app known_hosts.
Generate app ed25519 keypair under data/ssh/; install pubkey via one-time
password auth; store password in keyring only until key auth works, then
prefer key (settings flag password_auth_disabled).
"""

from __future__ import annotations

import base64
import hashlib
import os
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

    sock_timeout = timeout
    trans = paramiko.Transport((host, port))
    try:
        trans.start_client(timeout=sock_timeout)
        key = trans.get_remote_server_key()
    finally:
        trans.close()
    raw = key.asbytes()
    return HostKeyInfo(
        host=host,
        port=port,
        key_type=key.get_name(),
        fingerprint_sha256=_fingerprint_sha256(raw),
        base64=base64.b64encode(raw).decode("ascii"),
    )


def pin_host_key(info: HostKeyInfo) -> None:
    """Append/replace host key in app known_hosts (OpenSSH format)."""
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

    settings = load_settings()
    pins = settings.setdefault("ssh_host_pins", {})
    pins[f"{info.host}:{info.port}"] = {
        "key_type": info.key_type,
        "fingerprint_sha256": info.fingerprint_sha256,
        "base64": info.base64,
    }
    save_settings(settings)


def install_pubkey(
    host: str,
    username: str,
    password: str,
    gateway_id: str,
    *,
    port: int = 22,
    host_key_base64: Optional[str] = None,
) -> dict[str, Any]:
    """One-time password SSH: append ed25519 pubkey to authorized_keys."""
    from actions.shellutil import shell_quote  # type: ignore[import-not-found]
    from actions.ssh import SSHClient, SSHTarget  # type: ignore[import-not-found]

    if not gateway_id or any(c in gateway_id for c in " \t\n/\\"):
        raise ValueError("gateway_id must be a non-empty path-safe token")
    paths = generate_ed25519(gateway_id)
    pubkey = paths.public.read_text(encoding="utf-8").strip()
    target = SSHTarget(
        host=host,
        username=username,
        port=port,
        password=password,
        host_key_base64=host_key_base64,
        allow_unknown_host=host_key_base64 is None,
    )
    client = SSHClient(target)
    try:
        client.connect()
        q = shell_quote(pubkey)
        # Idempotent append
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

    ref = keyring_store.set_secret(gateway_id, password, kind="ssh")
    settings = load_settings()
    gateways = settings.setdefault("gateways", {})
    gateways[gateway_id] = {
        "host": host,
        "port": port,
        "username": username,
        "ssh_key_path": str(paths.private),
        "ssh_password_ref": ref,
        "password_auth_disabled": False,
        "prefer_key": True,
    }
    save_settings(settings)
    return {
        "gateway_id": gateway_id,
        "ssh_key_path": str(paths.private),
        "ssh_password_ref": ref,
        "pubkey_installed": True,
    }


def mark_password_auth_disabled(gateway_id: str) -> None:
    settings = load_settings()
    gw = settings.get("gateways", {}).get(gateway_id)
    if not gw:
        return
    gw["password_auth_disabled"] = True
    save_settings(settings)


def host_key_info_dict(info: HostKeyInfo) -> dict[str, Any]:
    return asdict(info)
