"""SSH provisioner: install monolithic gateway agent (no Docker)."""

from .provision import (
    DEFAULT_INSTALL_ROOT,
    MIN_FREE_BYTES,
    ProvisionConfig,
    ProvisionError,
    ProvisionResult,
    latest_backup_path,
    list_remote_backups,
    provision,
    repo_root_from_here,
    rollback_install,
)

__all__ = [
    "DEFAULT_INSTALL_ROOT",
    "MIN_FREE_BYTES",
    "ProvisionConfig",
    "ProvisionError",
    "ProvisionResult",
    "latest_backup_path",
    "list_remote_backups",
    "provision",
    "repo_root_from_here",
    "rollback_install",
]
