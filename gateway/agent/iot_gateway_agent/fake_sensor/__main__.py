"""``python -m iot_gateway_agent.fake_sensor --device-id <id>``."""

from __future__ import annotations

import argparse
import os
import sys

from .simulator import run_simulator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IoT Gateway fake sensor simulator")
    parser.add_argument(
        "--device-id",
        required=True,
        help="Device id (WorkingDirectory fake/<id> or IOTGW_AGENT_DATA/fake/<id>)",
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("IOTGW_AGENT_DATA", "/var/lib/iot-gateway-agent"),
        help="Agent data directory (default: IOTGW_AGENT_DATA or /var/lib/iot-gateway-agent)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Publish one message and exit (tests)",
    )
    args = parser.parse_args(argv)
    return run_simulator(
        device_id=args.device_id,
        data_dir=args.data_dir,
        once=args.once,
    )


if __name__ == "__main__":
    sys.exit(main())
