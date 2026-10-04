"""CLI entry for iot-gateway-agent."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading

from . import AGENT_PORT, __version__
from .health import build_health, build_info
from .mdns import start_mdns, stop_mdns
from .server import create_server

logger = logging.getLogger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="iot-gateway-agent",
        description="Read-only IoT gateway discovery agent (mDNS + /v1/health)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("AGENT_HOST", "0.0.0.0"),
        help="Listen address (default: 0.0.0.0 or AGENT_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("AGENT_PORT", AGENT_PORT)),
        help=f"Listen port (default: {AGENT_PORT} or AGENT_PORT)",
    )
    parser.add_argument(
        "--no-mdns",
        action="store_true",
        help="Disable mDNS even if zeroconf is installed",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Debug logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    mdns_handle = None
    mdns_enabled = False
    if not args.no_mdns:
        mdns_handle, mdns_enabled = start_mdns(args.port)
    else:
        logger.info("mDNS disabled via --no-mdns")

    def health_fn():
        return build_health(mdns_enabled=mdns_enabled, port=args.port)

    def info_fn():
        return build_info(port=args.port)

    server = create_server(args.host, args.port, health_fn, info_fn)

    def _request_shutdown(signum: int, _frame: object) -> None:
        # shutdown() waits for serve_forever to exit — must not run on this thread.
        logger.info("signal %s; shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _request_shutdown)
    # Leave SIGINT as default KeyboardInterrupt so Ctrl+C unwinds serve_forever.

    logger.info(
        "iot-gateway-agent %s listening on %s:%s (mdns=%s)",
        __version__,
        args.host,
        args.port,
        mdns_enabled,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt; shutting down")
    finally:
        server.server_close()
        stop_mdns(mdns_handle)
        logger.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
