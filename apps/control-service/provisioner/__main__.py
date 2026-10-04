"""CLI: python -m provisioner {provision|rollback} …"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .provision import (
    DEFAULT_INSTALL_ROOT,
    DEFAULT_LOKI_PROBE_RETRIES,
    DEFAULT_PROBE_INTERVAL_S,
    DEFAULT_PROBE_RETRIES,
    ProvisionConfig,
    ProvisionError,
    provision,
    rollback_install,
)
from .ssh import ParamikoSSHSession, SSHError


def _add_ssh_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", required=True, help="Gateway SSH host / IP")
    p.add_argument("--user", default="ubuntu", help="SSH username")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--password", help="SSH password (prefer key; stored by wizard later)")
    p.add_argument("--key", help="Path to SSH private key")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Gateway SSH provisioner. Optional --with-images loads a docker image "
            "tarball before compose (field kits); otherwise cold pull."
        )
    )
    sub = p.add_subparsers(dest="command", required=True)

    prov = sub.add_parser(
        "provision",
        help="Upload bundle, compose up, probe, install agent last",
    )
    _add_ssh_args(prov)
    prov.add_argument("--gateway-ip", required=True)
    prov.add_argument("--monitoring-ip", required=True)
    prov.add_argument("--install-root", default=DEFAULT_INSTALL_ROOT)
    prov.add_argument("--gateway-src", type=Path, help="Local gateway/ tree (default: repo)")
    prov.add_argument(
        "--with-images",
        type=Path,
        metavar="TAR",
        help="Optional docker image tarball; SFTP + docker load before compose up",
    )
    prov.add_argument(
        "--agent-mode",
        choices=("auto", "compose", "skip"),
        default="auto",
        help="Compose overlay only in v1 (systemd deferred)",
    )
    prov.add_argument(
        "--keep-failed",
        action="store_true",
        help="Do not auto-rollback to .bak-* after compose/probe failure",
    )
    prov.add_argument("--probe-retries", type=int, default=DEFAULT_PROBE_RETRIES)
    prov.add_argument("--probe-interval", type=float, default=DEFAULT_PROBE_INTERVAL_S)
    prov.add_argument(
        "--loki-probe-retries",
        type=int,
        default=DEFAULT_LOKI_PROBE_RETRIES,
        help="SSH-from-gateway Loki ready retries (default longer than exporter probes)",
    )

    rb = sub.add_parser(
        "rollback",
        help="compose down + restore INSTALL_ROOT.bak-<epoch> (newest if --backup omitted)",
    )
    _add_ssh_args(rb)
    rb.add_argument("--install-root", default=DEFAULT_INSTALL_ROOT)
    rb.add_argument(
        "--backup",
        help="Explicit bak path; default = newest INSTALL_ROOT.bak-<epoch> on remote",
    )
    return p


def _open_ssh(args: argparse.Namespace) -> ParamikoSSHSession:
    return ParamikoSSHSession(
        args.host,
        args.user,
        password=args.password,
        key_filename=args.key,
        port=args.port,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with _open_ssh(args) as ssh:
            if args.command == "rollback":
                restored = rollback_install(ssh, args.install_root, args.backup)
                print(f"restored {args.install_root} from {restored}")
                print("note: run compose up / re-provision if services should be running")
                return 0

            config = ProvisionConfig(
                gateway_ip=args.gateway_ip,
                monitoring_ip=args.monitoring_ip,
                install_root=args.install_root,
                gateway_src=args.gateway_src,
                images_tar=args.with_images,
                agent_mode=args.agent_mode,
                keep_failed=args.keep_failed,
                probe_retries=args.probe_retries,
                probe_interval_s=args.probe_interval,
                loki_probe_retries=args.loki_probe_retries,
            )
            result = provision(ssh, config)
    except (ProvisionError, SSHError, OSError, KeyError, ValueError) as e:
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
