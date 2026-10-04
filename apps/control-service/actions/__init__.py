"""SSH action playbooks — replace Gitea workflow mutations.

Import submodules directly (e.g. ``from actions.playbooks import register_device``)
so pure helpers do not require paramiko at import time.
"""

__all__ = [
    "SSHClient",
    "SSHTarget",
    "clear_logs",
    "hash_password_line",
    "register_device",
    "unregister_device",
    "update_acl",
    "update_allowlist_ips",
    "zeroize_str",
]


def __getattr__(name: str):
    if name in ("SSHClient", "SSHTarget"):
        from . import ssh

        return getattr(ssh, name)
    if name in (
        "clear_logs",
        "register_device",
        "unregister_device",
        "update_acl",
        "update_allowlist_ips",
    ):
        from . import playbooks

        return getattr(playbooks, name)
    if name in ("hash_password_line", "zeroize_str"):
        from . import mosquitto_hash

        return getattr(mosquitto_hash, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
