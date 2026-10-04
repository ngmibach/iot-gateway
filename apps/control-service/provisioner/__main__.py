"""CLI: python -m provisioner --host … --gateway-ip … --monitoring-ip …"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .provision import (
    DEFAULT_INSTALL_ROOT,
    ProvisionConfig,
    ProvisionError,
    provision,
)
from .ssh import ParamikoSSHSession, SSHError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Provision gateway over SSH: upload bundle, compose up, probe, "
            "install agent last. Optional --with-images loads a docker image "
            "tarball before compose (field kits); otherwise cold pull."
        )
    )
    p.add_argument("--host", required=True, help="Gateway SSH host / IP")
    p.add_argument("--user", default="ubuntu", help="SSH username")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--password", help="SSH password (prefer key; stored by wizard later)")
    p.add_argument("--key", help="Path to SSH private key")
    p.add_argument("--gateway-ip", required=True)
    p.add_argument("--monitoring-ip", required=True)
    p.add_argument("--install-root", default=DEFAULT_INSTALL_ROOT)
    p.add_argument("--gateway-src", type=Path, help="Local gateway/ tree (default: repo)")
    p.add_argument(
        "--with-images",
        type=Path,
        metavar="TAR",
        help="Optional docker image tarball; docker load on gateway before compose up",
    )
    p.add_argument(
        "--skip-agent",
        action="store_true",
        help="Do not install gateway-agent even if files are present",
    )
    p.add_argument(
        "--agent-mode",
        choices=("auto", "compose", "systemd", "skip"),
        default="auto",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = ProvisionConfig(
        gateway_ip=args.gateway_ip,
        monitoring_ip=args.monitoring_ip,
        install_root=args.install_root,
        gateway_src=args.gateway_src,
        images_tar=args.with_images,
        skip_agent=args.skip_agent,
        agent_mode=args.agent_mode,
    )
    try:
        with ParamikoSSHSession(
            args.host,
            args.user,
            password=args.password,
            key_filename=args.key,
            port=args.port,
        ) as ssh:
            result = provision(ssh, config)
    except (ProvisionError, SSHError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"installed at {result.install_root}")
    if result.backup_path:
        print(f"previous tree backed up to {result.backup_path}")
    for name, detail in result.probes.items():
        print(f"probe {name}: {detail}")
    if result.agent_installed:
        print(f"agent: installed ({result.agent_mode})")
    else:
        print("agent: not installed")
    for note in result.notes:
        print(f"note: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
