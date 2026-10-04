"""SSH action playbooks — replace Gitea workflow mutations."""

from .mosquitto_hash import hash_password_line, zeroize_str
from .playbooks import (
    clear_logs,
    register_device,
    unregister_device,
    update_acl,
    update_allowlist_ips,
)
from .ssh import SSHClient, SSHTarget

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
