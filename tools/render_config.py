#!/usr/bin/env python3
"""Render deploy/templates with endpoint placeholders; optional HTTP probes."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Mapping

DEFAULTS: dict[str, str] = {
    "CADVISOR_PORT": "8080",
    "AGENT_PORT": "9138",
    "INSTALL_ROOT": "/opt/iot-gateway",
}

PLACEHOLDER_RE = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def load_values(args: argparse.Namespace) -> dict[str, str]:
    values = dict(DEFAULTS)
    if args.values_json:
        raw = json.loads(Path(args.values_json).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise SystemExit(f"--values-json must be a JSON object: {args.values_json}")
        values.update({str(k): str(v) for k, v in raw.items()})
    for key, val in (
        ("GATEWAY_IP", args.gateway_ip),
        ("MONITORING_IP", args.monitoring_ip),
        ("INSTALL_ROOT", args.install_root),
        ("SERVER_CN", args.server_cn),
        ("CADVISOR_PORT", args.cadvisor_port),
        ("AGENT_PORT", args.agent_port),
    ):
        if val is not None:
            values[key] = str(val)
    # SERVER_CN defaults to GATEWAY_IP when unset
    if "SERVER_CN" not in values and "GATEWAY_IP" in values:
        values["SERVER_CN"] = values["GATEWAY_IP"]
    return values


def render_text(template: str, values: Mapping[str, str]) -> str:
    missing: set[str] = set()

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            missing.add(key)
            return match.group(0)
        return values[key]

    out = PLACEHOLDER_RE.sub(repl, template)
    if missing:
        raise KeyError(f"missing template values: {', '.join(sorted(missing))}")
    return out


def render_tree(template_dir: Path, output_dir: Path, values: Mapping[str, str]) -> list[Path]:
    if not template_dir.is_dir():
        raise FileNotFoundError(f"template dir not found: {template_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for src in sorted(template_dir.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(template_dir)
        dest = output_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text(encoding="utf-8")
        dest.write_text(render_text(text, values), encoding="utf-8")
        written.append(dest)
    return written


def probe_http(url: str, timeout: float = 5.0) -> tuple[bool, str]:
    """Check HTTP reachability (provision helper). Returns (ok, detail)."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", resp.getcode())
            body = resp.read(256)
            if 200 <= int(code) < 300:
                return True, f"{url} -> {code} ({len(body)} bytes)"
            return False, f"{url} -> HTTP {code}"
    except urllib.error.HTTPError as e:
        return False, f"{url} -> HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — surface any reachability failure
        return False, f"{url} -> {type(e).__name__}: {e}"


def probe_metrics(host: str, port: int, path: str = "/metrics", timeout: float = 5.0) -> tuple[bool, str]:
    return probe_http(f"http://{host}:{port}{path}", timeout=timeout)


def cmd_render(args: argparse.Namespace) -> int:
    values = load_values(args)
    required = {"GATEWAY_IP", "MONITORING_IP"}
    missing = sorted(k for k in required if k not in values or not values[k])
    if missing:
        print(f"error: required values missing: {', '.join(missing)}", file=sys.stderr)
        return 2
    written = render_tree(Path(args.template_dir), Path(args.output_dir), values)
    for path in written:
        print(path)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    targets = args.url or []
    if args.gateway_ip:
        port = int(args.cadvisor_port or DEFAULTS["CADVISOR_PORT"])
        targets.extend(
            [
                f"http://{args.gateway_ip}:9100/metrics",
                f"http://{args.gateway_ip}:{port}/metrics",
            ]
        )
    if args.monitoring_ip:
        targets.append(f"http://{args.monitoring_ip}:3100/ready")
    if not targets:
        print("error: provide --url and/or --gateway-ip / --monitoring-ip", file=sys.stderr)
        return 2
    failed = 0
    for url in targets:
        ok, detail = probe_http(url, timeout=args.timeout)
        print(("OK  " if ok else "FAIL") + f" {detail}")
        if not ok:
            failed += 1
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("render", help="Render templates into an output directory")
    r.add_argument(
        "--template-dir",
        default="deploy/templates",
        help="Directory of templates with {{VAR}} placeholders",
    )
    r.add_argument(
        "--output-dir",
        required=True,
        help="Destination directory for rendered files",
    )
    r.add_argument("--values-json", help="JSON object of template values")
    r.add_argument("--gateway-ip")
    r.add_argument("--monitoring-ip")
    r.add_argument("--install-root")
    r.add_argument("--server-cn")
    r.add_argument("--cadvisor-port", default=None)
    r.add_argument("--agent-port", default=None)
    r.set_defaults(func=cmd_render)

    pr = sub.add_parser("probe", help="Probe HTTP /metrics or Loki ready endpoints")
    pr.add_argument("--url", action="append", default=[], help="Explicit URL to GET (repeatable)")
    pr.add_argument("--gateway-ip", help="Also probe :9100/metrics and :CADVISOR_PORT/metrics")
    pr.add_argument("--monitoring-ip", help="Also probe :3100/ready")
    pr.add_argument("--cadvisor-port", default=DEFAULTS["CADVISOR_PORT"])
    pr.add_argument("--timeout", type=float, default=5.0)
    pr.set_defaults(func=cmd_probe)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
