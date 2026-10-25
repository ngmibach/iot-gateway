"""CLI: python -m provisioner {provision|rollback} …"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .provision import (
    DEFAULT_INSTALL_ROOT,
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
            "Gateway SSH provisioner (agent-only). Installs native mosquitto + "
            "the monolithic iot-gateway-agent systemd unit. No Docker on the gateway."
        )
    )
    sub = p.add_subparsers(dest="command", required=True)

    prov = sub.add_parser(
        "provision",
        help="Install mosquitto + monolithic agent over SSH",
    )
    _add_ssh_args(prov)
    prov.add_argument("--gateway-ip", required=True)
    prov.add_argument("--monitoring-ip", required=True)
    prov.add_argument("--install-root", default=DEFAULT_INSTALL_ROOT)
    prov.add_argument(
        "--gateway-src",
        type=Path,
        help="Local gateway/ tree (default: repo); uses gateway/agent/",
    )
    prov.add_argument(
        "--sudo-password",
        help="Gateway sudo password for apt/systemd (prefer wizard UI / keyring)",
    )

    rb = sub.add_parser(
        "rollback",
        help="Restore INSTALL_ROOT.bak-<epoch> (newest if --backup omitted)",
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
                print("note: re-run provision if the agent should be running")
                return 0

            config = ProvisionConfig(
                gateway_ip=args.gateway_ip,
                monitoring_ip=args.monitoring_ip,
                install_root=args.install_root,
                gateway_src=args.gateway_src,
                sudo_password=args.sudo_password,
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
