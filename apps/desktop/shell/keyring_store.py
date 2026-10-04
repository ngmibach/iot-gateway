"""OS keyring refs for SSH credentials (K7).

Stores passwords / passphrases under service ``iot-gateway-monitor``.
Private key *paths* live in settings.json; secret material stays in the keyring.
When no OS backend is available (headless CI), falls back to a 0600 file under
the app data dir — never log the contents.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from .paths import ensure_data_dir

logger = logging.getLogger(__name__)

SERVICE = "iot-gateway-monitor"
_FALLBACK_NAME = "keyring-fallback.json"


def _fallback_path() -> Path:
    return ensure_data_dir() / _FALLBACK_NAME


def _fallback_load() -> dict[str, str]:
    path = _fallback_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _fallback_save(data: dict[str, str]) -> None:
    path = _fallback_path()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _keyring_usable() -> bool:
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring
    except ImportError:
        return False
    kr = keyring.get_keyring()
    return not isinstance(kr, FailKeyring)


def cred_username(gateway_id: str, kind: str = "ssh") -> str:
    """Keyring username / account field for a gateway credential."""
    return f"{kind}:{gateway_id}"


def set_secret(gateway_id: str, secret: str, *, kind: str = "ssh") -> str:
    """Persist secret; returns the keyring ref string stored in settings."""
    account = cred_username(gateway_id, kind)
    ref = f"keyring:{SERVICE}:{account}"
    if _keyring_usable():
        import keyring

        keyring.set_password(SERVICE, account, secret)
        return ref
    data = _fallback_load()
    data[account] = secret
    _fallback_save(data)
    logger.warning(
        "OS keyring unavailable; stored %s in 0600 fallback file under app data",
        account,
    )
    return f"file:{account}"


def get_secret(ref_or_gateway_id: str, *, kind: str = "ssh") -> Optional[str]:
    """Resolve a keyring/file ref or bare gateway_id to the secret."""
    account: str
    if ref_or_gateway_id.startswith("keyring:"):
        parts = ref_or_gateway_id.split(":", 2)
        account = parts[2] if len(parts) == 3 else cred_username(ref_or_gateway_id, kind)
    elif ref_or_gateway_id.startswith("file:"):
        account = ref_or_gateway_id[len("file:") :]
    else:
        account = cred_username(ref_or_gateway_id, kind)

    if _keyring_usable():
        import keyring

        val = keyring.get_password(SERVICE, account)
        if val is not None:
            return val
    return _fallback_load().get(account)


def delete_secret(gateway_id: str, *, kind: str = "ssh") -> None:
    account = cred_username(gateway_id, kind)
    if _keyring_usable():
        import keyring

        try:
            keyring.delete_password(SERVICE, account)
        except keyring.errors.PasswordDeleteError:
            pass
    data = _fallback_load()
    if account in data:
        del data[account]
        _fallback_save(data)
