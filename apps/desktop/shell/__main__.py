"""python -m shell  → Setup Wizard + optional service launch.

Usage:
  PYTHONPATH=apps/desktop:apps/control-service python -m shell
  PYTHONPATH=... python -m shell --no-browser --port 9138
  PYTHONPATH=... python -m shell --start-services   # API+Streamlit then wizard
"""

from __future__ import annotations

import argparse
import logging
import sys

from . import detect
from .launcher import ProcessManager, wait_http
from .paths import CONTROL_HOST, CONTROL_PORT, STREAMLIT_PORT, WIZARD_PORT
from .wizard_server import run_forever


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IoT Gateway Monitor — Phase-0 shell")
    parser.add_argument("--host", default=CONTROL_HOST)
    parser.add_argument("--port", type=int, default=WIZARD_PORT)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument(
        "--start-services",
        action="store_true",
        help="Start control-service (:9137) and Streamlit (:8501) before wizard",
    )
    parser.add_argument(
        "--detect-only",
        action="store_true",
        help="Print Docker/WSL detection JSON and exit",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.detect_only:
        import json

        print(json.dumps(detect.environment_snapshot(), indent=2))
        return 0

    mgr: ProcessManager | None = None
    if args.start_services:
        mgr = ProcessManager()
        ctrl = mgr.start_control_service()
        if not wait_http(ctrl.url, timeout=45, path="/health"):
            print("control-service failed to become healthy", file=sys.stderr)
            mgr.stop_all()
            return 1
        print(f"control-service ready at {ctrl.url}")
        try:
            st = mgr.start_streamlit()
            if wait_http(st.url, timeout=90):
                print(f"streamlit ready at {st.url}")
            else:
                print("streamlit did not become ready (wizard still usable)", file=sys.stderr)
        except FileNotFoundError as e:
            print(f"streamlit skip: {e}", file=sys.stderr)

    print(
        f"Setup Wizard → http://{args.host}:{args.port}/wizard.html\n"
        f"Actions      → http://{args.host}:{args.port}/actions.html\n"
        f"Control API  → http://{CONTROL_HOST}:{CONTROL_PORT}\n"
        f"Streamlit    → http://{CONTROL_HOST}:{STREAMLIT_PORT} (WebView / browser)\n"
        "Windows: Loki :3100 via guided checklist only; UI ports need localhostForwarding."
    )
    try:
        run_forever(args.host, args.port, open_browser=not args.no_browser)
    finally:
        if mgr is not None:
            mgr.stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
