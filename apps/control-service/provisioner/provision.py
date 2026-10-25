"""Provision a gateway over SSH: disk preflight → monolithic agent install."""

from __future__ import annotations

import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from .agent_install import DEFAULT_AGENT_ROOT
from .ssh import SSHSession

DEFAULT_INSTALL_ROOT = DEFAULT_AGENT_ROOT
# Abort before unpack when free space is below this (df -Pk units are KiB).
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024


class ProvisionError(RuntimeError):
    """Provision failed; message is operator-facing."""


def repo_root_from_here() -> Path:
    """Repo / bundle root that contains ``gateway/``, ``deploy/``."""
    env = os.environ.get("IOTGW_REPO_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    # provisioner/ -> control-service/ -> apps/ -> repo
    return Path(__file__).resolve().parents[3]


@dataclass
class ProvisionConfig:
    gateway_ip: str
    monitoring_ip: str
    install_root: str = DEFAULT_INSTALL_ROOT
    gateway_src: Optional[Path] = None
    repo_root: Optional[Path] = None
    min_free_bytes: int = MIN_FREE_BYTES
    # UI-provided sudo password for apt/systemd on the gateway (never persisted).
    sudo_password: Optional[str] = None


@dataclass
class ProvisionResult:
    install_root: str
    backup_path: Optional[str] = None
    agent_installed: bool = False
    agent_mode: Optional[str] = None
    probes: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    backend: str = "agent"


def provision(ssh: SSHSession, config: ProvisionConfig) -> ProvisionResult:
    """Run the agent provision sequence against an open SSH session."""
    root = config.repo_root or repo_root_from_here()
    gateway_src = Path(config.gateway_src) if config.gateway_src else root / "gateway"
    return _provision_agent(ssh, config, root=root, gateway_src=gateway_src)


def _provision_agent(
    ssh: SSHSession,
    config: ProvisionConfig,
    *,
    root: Path,
    gateway_src: Path,
) -> ProvisionResult:
    """Docker-free path: apt mosquitto + monolithic agent systemd unit."""
    from .agent_install import (
        AgentInstallError,
        provision_monolithic_agent,
    )

    notes: list[str] = []
    install_root = (config.install_root or DEFAULT_INSTALL_ROOT).rstrip("/") or DEFAULT_INSTALL_ROOT
    _preflight_disk(ssh, install_root, config.min_free_bytes)
    agent_src = gateway_src / "agent"
    try:
        notes.extend(
            provision_monolithic_agent(
                ssh,
                monitoring_ip=config.monitoring_ip,
                gateway_ip=config.gateway_ip,
                agent_src=agent_src,
                sudo_password=str(config.sudo_password or ""),
                remote_root=install_root,
            )
        )
    except AgentInstallError as e:
        raise ProvisionError(str(e)) from e

    probes = {
        "agent_health": f"http://{config.gateway_ip}:9139/v1/health",
        "agent_metrics": f"http://{config.gateway_ip}:9139/metrics",
        "mqtt": f"{config.gateway_ip}:1883",
    }
    notes.append("backend=agent (no Docker on gateway)")
    return ProvisionResult(
        install_root=install_root,
        backup_path=None,
        agent_installed=True,
        agent_mode="systemd",
        probes=probes,
        notes=notes,
        backend="agent",
    )


def rollback_install(
    ssh: SSHSession,
    install_root: str,
    backup_path: Optional[str] = None,
) -> str:
    """Restore backup. If backup_path is None, pick newest for root."""
    install_root = install_root.rstrip("/") or DEFAULT_INSTALL_ROOT
    if backup_path is None:
        listed = list_remote_backups(ssh, install_root)
        backup_path = latest_backup_path(listed, install_root)
        if backup_path is None:
            raise ProvisionError(
                f"no backup found for {install_root} (expected {install_root}.bak-<epoch>)"
            )
    _restore_backup(ssh, install_root, backup_path)
    return backup_path


def list_remote_backups(ssh: SSHSession, install_root: str) -> list[str]:
    """List ``INSTALL_ROOT.bak-*`` directories on the remote host."""
    install_root = install_root.rstrip("/")
    parent = _remote_parent(install_root)
    base = install_root.rsplit("/", 1)[-1]
    # Quote path + -name separately so the glob is not literalized by shlex.quote.
    name_pat = f"{base}.bak-*"
    result = ssh.run(
        f"find {shlex.quote(parent)} -maxdepth 1 -type d -name {shlex.quote(name_pat)} "
        f"2>/dev/null || true",
        timeout=15.0,
    )
    paths = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    return [p for p in paths if re.search(r"\.bak-\d+$", p)]


def _preflight_disk(ssh: SSHSession, install_root: str, min_free_bytes: int) -> None:
    parent = _remote_parent(install_root)
    result = ssh.run(f"df -Pk {shlex.quote(parent)} | tail -1", timeout=15.0)
    if not result.ok:
        raise ProvisionError(
            f"disk preflight failed for {parent}: {result.stderr or result.stdout}"
        )
    free_bytes = _parse_df_available_bytes(result.stdout)
    if free_bytes is None:
        raise ProvisionError(f"could not parse df output for {parent}: {result.stdout!r}")
    if free_bytes < min_free_bytes:
        need_gib = min_free_bytes / (1024**3)
        have_gib = free_bytes / (1024**3)
        raise ProvisionError(
            f"insufficient disk on {parent}: {have_gib:.2f} GiB free, "
            f"need at least {need_gib:.2f} GiB before unpacking {install_root}"
        )


def _parse_df_available_bytes(df_line: str) -> Optional[int]:
    """Parse `df -Pk` data line; available column is 1K-blocks."""
    line = df_line.strip().splitlines()[-1] if df_line.strip() else ""
    parts = line.split()
    if len(parts) < 4:
        return None
    try:
        available_k = int(parts[3])
    except ValueError:
        return None
    return available_k * 1024


def _remote_parent(path: str) -> str:
    if path in ("/", ""):
        return "/"
    trimmed = path.rstrip("/")
    idx = trimmed.rfind("/")
    if idx <= 0:
        return "/"
    return trimmed[:idx] or "/"


def _restore_backup(ssh: SSHSession, install_root: str, backup_path: str) -> None:
    ssh.run(f"rm -rf {shlex.quote(install_root)}", timeout=120.0)
    result = ssh.run(
        f"mv {shlex.quote(backup_path)} {shlex.quote(install_root)}",
        timeout=60.0,
    )
    if not result.ok:
        raise ProvisionError(
            f"rollback failed restoring {backup_path} → {install_root}: "
            f"{result.stderr or result.stdout}"
        )


def latest_backup_path(
    candidates: Sequence[str], install_root: str
) -> Optional[str]:
    """Pick newest ``{install_root}.bak-<epoch>`` from candidates."""
    prefix = install_root.rstrip("/") + ".bak-"
    best: Optional[str] = None
    best_ts = -1
    for path in candidates:
        if not path.startswith(prefix):
            continue
        suffix = path[len(prefix) :]
        if not suffix.isdigit():
            continue
        ts = int(suffix)
        if ts >= best_ts:
            best_ts = ts
            best = path
    return best


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
