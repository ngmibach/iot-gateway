#!/usr/bin/env python3
"""Render deploy/templates with endpoint placeholders; optional HTTP probes."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Mapping

# Placeholders used by deploy/templates today.
KNOWN_KEYS = ("GATEWAY_IP", "MONITORING_IP")


def load_values(args: argparse.Namespace) -> dict[str, str]:
    values: dict[str, str] = {}
    if args.values_json:
        raw = json.loads(Path(args.values_json).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"--values-json must be a JSON object: {args.values_json}")
        for key, val in raw.items():
            if val is None:
                continue
            text = str(val).strip()
            if text == "":
                continue
            values[str(key)] = text
    for key, val in (
        ("GATEWAY_IP", args.gateway_ip),
        ("MONITORING_IP", args.monitoring_ip),
    ):
        if val is not None and str(val).strip() != "":
            values[key] = str(val).strip()
    return values


def _remaining_placeholders(text: str) -> list[str]:
    found: set[str] = set()
    start = 0
    while True:
        i = text.find("{{", start)
        if i < 0:
            break
        j = text.find("}}", i + 2)
        if j < 0:
            break
        found.add(text[i + 2 : j])
        start = j + 2
    return sorted(found)


def render_text(template: str, values: Mapping[str, str]) -> str:
    out = template
    for key, val in values.items():
        out = out.replace("{{" + key + "}}", val)
    leftover = _remaining_placeholders(out)
    if leftover:
        raise KeyError(f"missing template values: {', '.join(leftover)}")
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


def cmd_render(args: argparse.Namespace) -> int:
    values = load_values(args)
    missing = sorted(k for k in KNOWN_KEYS if k not in values)
    if missing:
        print(f"error: required values missing: {', '.join(missing)}", file=sys.stderr)
        return 2
    written = render_tree(Path(args.template_dir), Path(args.output_dir), values)
    for path in written:
        print(path)
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    targets = list(args.url or [])
    if args.gateway_ip:
        targets.extend(
            [
                f"http://{args.gateway_ip}:9100/metrics",
                f"http://{args.gateway_ip}:8080/metrics",
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
    r.set_defaults(func=cmd_render)

    pr = sub.add_parser("probe", help="Probe HTTP /metrics or Loki ready endpoints")
    pr.add_argument("--url", action="append", default=[], help="Explicit URL to GET (repeatable)")
    pr.add_argument("--gateway-ip", help="Also probe :9100/metrics and :8080/metrics")
    pr.add_argument("--monitoring-ip", help="Also probe :3100/ready")
    pr.add_argument("--timeout", type=float, default=5.0)
    pr.set_defaults(func=cmd_probe)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (KeyError, ValueError, OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
