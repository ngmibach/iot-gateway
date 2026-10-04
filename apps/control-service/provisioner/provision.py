"""Provision a gateway over SSH: preflight → upload → compose up → probes → agent."""

from __future__ import annotations

import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from .bundle import load_render_config, repo_root_from_here, stage_gateway_bundle
from .ssh import SSHSession, shell_quote

DEFAULT_INSTALL_ROOT = "/opt/iot-gateway"
# Abort before unpack when free space is below this (df -Pk units are KiB).
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024
PROBE_RETRIES = 12
PROBE_INTERVAL_S = 5.0


class ProvisionError(RuntimeError):
    """Provision failed; message is operator-facing."""


@dataclass
class ProvisionConfig:
    gateway_ip: str
    monitoring_ip: str
    install_root: str = DEFAULT_INSTALL_ROOT
    gateway_src: Optional[Path] = None
    template_dir: Optional[Path] = None
    repo_root: Optional[Path] = None
    images_tar: Optional[Path] = None
    min_free_bytes: int = MIN_FREE_BYTES
    compose_timeout: float = 600.0
    probe_timeout: float = 5.0
    skip_agent: bool = False
    # Prefer compose overlay; fall back to systemd unit copy when no compose file.
    agent_mode: str = "auto"  # auto | compose | systemd | skip


@dataclass
class ProvisionResult:
    install_root: str
    backup_path: Optional[str] = None
    agent_installed: bool = False
    agent_mode: Optional[str] = None
    probes: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def provision(ssh: SSHSession, config: ProvisionConfig) -> ProvisionResult:
    """Run the full provision sequence against an open SSH session."""
    root = config.repo_root or repo_root_from_here()
    gateway_src = Path(config.gateway_src) if config.gateway_src else root / "gateway"
    install_root = config.install_root.rstrip("/") or DEFAULT_INSTALL_ROOT
    notes: list[str] = []

    _preflight_docker(ssh)
    _preflight_disk(ssh, install_root, config.min_free_bytes)

    if config.images_tar is not None:
        _load_images(ssh, Path(config.images_tar))
        notes.append(f"loaded images from {config.images_tar}")
    else:
        notes.append(
            "no --with-images tarball; compose will pull images (cold pull may take 5–20 min)"
        )

    backup_path = _backup_existing(ssh, install_root)

    staging = Path(tempfile.mkdtemp(prefix="iotgw-stage-"))
    try:
        stage_gateway_bundle(
            gateway_src,
            staging,
            values={
                "GATEWAY_IP": config.gateway_ip,
                "MONITORING_IP": config.monitoring_ip,
            },
            template_dir=config.template_dir,
            repo_root=root,
        )
        ssh.upload_tree(staging, install_root)
    except Exception:
        if backup_path:
            _restore_backup(ssh, install_root, backup_path)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    try:
        _compose_up(ssh, install_root, timeout=config.compose_timeout)
        probes = _run_probes(
            ssh,
            gateway_ip=config.gateway_ip,
            monitoring_ip=config.monitoring_ip,
            timeout=config.probe_timeout,
        )
        agent_installed = False
        agent_mode: Optional[str] = None
        if config.skip_agent or config.agent_mode == "skip":
            notes.append("agent install skipped by config")
        else:
            agent_installed, agent_mode, agent_note = _install_agent(
                ssh,
                install_root,
                gateway_src=gateway_src,
                mode=config.agent_mode,
            )
            if agent_note:
                notes.append(agent_note)
    except Exception:
        if backup_path:
            notes.append(f"provision failed; previous tree kept at {backup_path}")
        raise

    return ProvisionResult(
        install_root=install_root,
        backup_path=backup_path,
        agent_installed=agent_installed,
        agent_mode=agent_mode,
        probes=probes,
        notes=notes,
    )


def rollback_install(ssh: SSHSession, install_root: str, backup_path: str) -> None:
    """Restore a backup directory created during provision."""
    _restore_backup(ssh, install_root.rstrip("/"), backup_path)


# ── preflight ─────────────────────────────────────────────────────────


def _preflight_docker(ssh: SSHSession) -> None:
    result = ssh.run("docker info >/dev/null 2>&1 && echo OK", timeout=30.0)
    if not result.ok or "OK" not in result.stdout:
        raise ProvisionError(
            "Docker engine not available on gateway "
            f"(exit {result.exit_code}): {result.stderr or result.stdout or 'docker info failed'}"
        )


def _preflight_disk(ssh: SSHSession, install_root: str, min_free_bytes: int) -> None:
    parent = _remote_parent(install_root)
    # -Pk: POSIX portable, 1K blocks.
    result = ssh.run(f"df -Pk {shell_quote(parent)} | tail -1", timeout=15.0)
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
    # Filesystem Size Used Available Use% Mounted
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


# ── backup / rollback ─────────────────────────────────────────────────


def _backup_existing(ssh: SSHSession, install_root: str) -> Optional[str]:
    check = ssh.run(
        f"if [ -e {shell_quote(install_root)} ]; then echo EXISTS; fi",
        timeout=15.0,
    )
    if "EXISTS" not in check.stdout:
        return None
    bak = f"{install_root}.bak-{int(time.time())}"
    result = ssh.run(
        f"mv {shell_quote(install_root)} {shell_quote(bak)}",
        timeout=60.0,
    )
    if not result.ok:
        raise ProvisionError(
            f"failed to move existing install to {bak}: {result.stderr or result.stdout}"
        )
    return bak


def _restore_backup(ssh: SSHSession, install_root: str, backup_path: str) -> None:
    ssh.run(f"rm -rf {shell_quote(install_root)}", timeout=120.0)
    result = ssh.run(
        f"mv {shell_quote(backup_path)} {shell_quote(install_root)}",
        timeout=60.0,
    )
    if not result.ok:
        raise ProvisionError(
            f"rollback failed restoring {backup_path} → {install_root}: "
            f"{result.stderr or result.stdout}"
        )


# ── images / compose ──────────────────────────────────────────────────


def _load_images(ssh: SSHSession, images_tar: Path) -> None:
    if not images_tar.is_file():
        raise ProvisionError(f"--with-images file not found: {images_tar}")
    remote = f"/tmp/iotgw-images-{int(time.time())}.tar"
    ssh.upload_bytes(images_tar.read_bytes(), remote, mode=0o600)
    result = ssh.run(
        f"docker load -i {shell_quote(remote)}; ec=$?; rm -f {shell_quote(remote)}; exit $ec",
        timeout=600.0,
    )
    if not result.ok:
        raise ProvisionError(
            f"docker load failed: {result.stderr or result.stdout}"
        )


def _compose_up(ssh: SSHSession, install_root: str, *, timeout: float) -> None:
    compose = f"{install_root}/docker-compose.yaml"
    cmd = (
        f"cd {shell_quote(install_root)} && "
        f"docker compose -f {shell_quote(compose)} up -d --remove-orphans"
    )
    result = ssh.run(cmd, timeout=timeout)
    if not result.ok:
        raise ProvisionError(
            f"docker compose up failed ({result.exit_code}): "
            f"{result.stderr or result.stdout}"
        )


# ── probes ─────────────────────────────────────────────────────────────


def _run_probes(
    ssh: SSHSession,
    *,
    gateway_ip: str,
    monitoring_ip: str,
    timeout: float,
) -> dict[str, str]:
    """Probe node-exporter + cAdvisor from operator; Loki ready via gateway SSH curl."""
    targets = {
        "node_exporter": f"http://{gateway_ip}:9100/metrics",
        "cadvisor": f"http://{gateway_ip}:8080/metrics",
    }
    details: dict[str, str] = {}
    render = load_render_config()

    for name, url in targets.items():
        ok, detail = _wait_http(render.probe_http, url, timeout=timeout)
        details[name] = detail
        if not ok:
            raise ProvisionError(
                f"provision probe failed ({name}): {detail}. "
                "Gateway exporters did not become ready in time."
            )

    loki_url = f"http://{monitoring_ip}:3100/ready"
    ok, detail = _wait_loki_from_gateway(ssh, loki_url, timeout=timeout)
    details["loki_from_gateway"] = detail
    if not ok:
        raise ProvisionError(
            f"Pi cannot reach monitoring Loki — check firewall/portproxy: {detail}"
        )
    return details


def _wait_http(probe_http, url: str, *, timeout: float) -> tuple[bool, str]:
    last = (False, f"{url} -> not attempted")
    for _ in range(PROBE_RETRIES):
        last = probe_http(url, timeout=timeout)
        if last[0]:
            return last
        time.sleep(PROBE_INTERVAL_S)
    return last


def _wait_loki_from_gateway(
    ssh: SSHSession, loki_url: str, *, timeout: float
) -> tuple[bool, str]:
    # Probe from the gateway so NAT/portproxy paths are validated (not operator-local).
    curl = (
        f"curl -fsS --max-time {int(max(1, timeout))} {shell_quote(loki_url)} "
        f"&& echo __LOKI_OK__"
    )
    last_detail = f"{loki_url} -> not attempted"
    for _ in range(PROBE_RETRIES):
        result = ssh.run(curl, timeout=timeout + 10.0)
        if result.ok and "__LOKI_OK__" in result.stdout:
            return True, f"{loki_url} -> ready (via gateway curl)"
        last_detail = (
            f"{loki_url} -> exit {result.exit_code}: "
            f"{(result.stderr or result.stdout).strip()[:200]}"
        )
        time.sleep(PROBE_INTERVAL_S)
    return False, last_detail


# ── agent (last) ───────────────────────────────────────────────────────


def _install_agent(
    ssh: SSHSession,
    install_root: str,
    *,
    gateway_src: Path,
    mode: str,
) -> tuple[bool, Optional[str], str]:
    """Install agent last. Optional — missing agent files is not a hard failure."""
    compose_overlay = Path(gateway_src) / "agent" / "docker-compose.agent.yaml"
    unit_file = Path(gateway_src) / "agent" / "iot-gateway-agent.service"
    remote_overlay = f"{install_root}/agent/docker-compose.agent.yaml"
    remote_compose = f"{install_root}/docker-compose.yaml"

    use_compose = mode in ("auto", "compose") and compose_overlay.is_file()
    use_systemd = mode in ("auto", "systemd") and unit_file.is_file() and not use_compose

    if mode == "compose" and not compose_overlay.is_file():
        return False, None, "agent compose overlay missing; skipped"
    if mode == "systemd" and not unit_file.is_file():
        return False, None, "agent systemd unit missing; skipped"
    if not use_compose and not use_systemd:
        return False, None, "agent files not present; provision succeeded without agent"

    if use_compose:
        # Overlay already uploaded with the bundle when agent/ was in gateway_src.
        check = ssh.run(
            f"test -f {shell_quote(remote_overlay)} && echo OK",
            timeout=15.0,
        )
        if "OK" not in check.stdout:
            return False, None, "agent overlay not on remote; skipped"
        cmd = (
            f"cd {shell_quote(install_root)} && "
            f"docker compose -f {shell_quote(remote_compose)} "
            f"-f {shell_quote(remote_overlay)} up -d agent"
        )
        result = ssh.run(cmd, timeout=300.0)
        if not result.ok:
            raise ProvisionError(
                f"agent compose up failed ({result.exit_code}): "
                f"{result.stderr or result.stdout}"
            )
        return True, "compose", "agent installed via docker compose overlay"

    # systemd path: unit already under install_root/agent/ after upload
    remote_unit_src = f"{install_root}/agent/iot-gateway-agent.service"
    # Rewrite WorkingDirectory/ExecStart paths if INSTALL_ROOT ≠ /opt/iot-gateway
    result = ssh.run(
        f"sed 's|/opt/iot-gateway|{install_root}|g' "
        f"{shell_quote(remote_unit_src)} > /etc/systemd/system/iot-gateway-agent.service "
        f"&& systemctl daemon-reload "
        f"&& systemctl enable --now iot-gateway-agent.service",
        timeout=120.0,
    )
    if not result.ok:
        raise ProvisionError(
            f"agent systemd install failed ({result.exit_code}): "
            f"{result.stderr or result.stdout}"
        )
    return True, "systemd", "agent installed via systemd unit"


def latest_backup_path(candidates: Sequence[str]) -> Optional[str]:
    """Pick the newest ``*.bak-<epoch>`` path from a list."""
    best: Optional[str] = None
    best_ts = -1
    for path in candidates:
        m = re.search(r"\.bak-(\d+)$", path)
        if not m:
            continue
        ts = int(m.group(1))
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
    "provision",
    "rollback_install",
]
