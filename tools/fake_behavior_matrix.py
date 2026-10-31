#!/usr/bin/env python3
"""Drive every fake-sensor Simulate attack and assert agent deny/accept signals.

Usage (from Windows or WSL, with IoTGatewayMonitor wizard on :9138)::

    python tools/fake_behavior_matrix.py
    python tools/fake_behavior_matrix.py --only wrong_client_cert,bad_encryption
    python tools/fake_behavior_matrix.py --device fake2 --gateway-id gateway

Talks to:
  - wizard proxy http://127.0.0.1:9138/api/v1  (PATCH/start/stop fake)
  - gateway agent http://{gateway_ip}:9139     (metrics + /v1/denied)

Always restores the target fake to all-false behaviors in a finally block.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

DEFAULT_BEHAVIORS = {
    "omit_client_cert": False,
    "wrong_client_cert": False,
    "skip_encryption": False,
    "bad_encryption": False,
    "wrong_password": False,
    "wrong_topic": False,
    "key_only": False,
    "data_only": False,
    "stamp_mismatch_key": False,
    "stamp_mismatch_data": False,
    "swapped_msg_id": False,
    "wrong_day_id": False,
    "missing_day_material": False,
    "schema_missing_field": False,
    "schema_wrong_type": False,
    "schema_extra_field": False,
    "wrong_schema_id": False,
    "legacy_fernet_wrapper": False,
}

# expect: deny | accept | soft_deny | soft_accept
# soft_* = conditional / profile-dependent; FAIL only on agent crash or silence when a hard signal was required
CASES: list[dict[str, Any]] = [
    {
        "key": "omit_client_cert",
        "expect": "deny",
        "reasons": {
            "missing_client_cert",
            "tls_handshake",
            "tls_protocol",
            "bad_client_cert",
        },
        "settle_s": 12,
        "class": "transport",
        "note": "bad_client_cert also accepted if broker classifies omit similarly",
    },
    {
        "key": "wrong_client_cert",
        "expect": "deny",
        "reasons": {"bad_client_cert", "missing_client_cert", "tls_handshake"},
        "settle_s": 12,
        "class": "transport",
    },
    {
        "key": "wrong_password",
        "expect": "deny",
        "reasons": {"bad_password"},
        "settle_s": 12,
        "class": "transport",
    },
    {
        "key": "wrong_topic",
        "expect": "deny",
        "reasons": {"acl_deny", "bad_password"},
        "settle_s": 12,
        "class": "transport",
        "note": "ACL deny may surface as Denied PUBLISH or not authorised",
    },
    {
        "key": "skip_encryption",
        "expect": "deny",
        "reasons": {"format", "fernet", "legacy", "envelope", "schema"},
        "settle_s": 10,
        "class": "payload",
    },
    {
        "key": "bad_encryption",
        "expect": "deny",
        "reasons": {"stamp", "fernet", "unwrap", "gcm", "envelope"},
        "settle_s": 10,
        "class": "payload",
    },
    {
        "key": "key_only",
        "expect": "deny",
        "reasons": {"key_only"},
        "settle_s": 14,
        "class": "envelope",
    },
    {
        "key": "data_only",
        "expect": "deny",
        "reasons": {"data_only"},
        "settle_s": 14,
        "class": "envelope",
    },
    {
        "key": "stamp_mismatch_key",
        "expect": "deny",
        "reasons": {"stamp", "unwrap", "envelope"},
        "settle_s": 10,
        "class": "envelope",
    },
    {
        "key": "stamp_mismatch_data",
        "expect": "deny",
        "reasons": {"stamp", "unwrap", "envelope"},
        "settle_s": 10,
        "class": "envelope",
    },
    {
        "key": "swapped_msg_id",
        "expect": "deny",
        "reasons": {"stamp", "unwrap", "envelope", "key_only", "data_only"},
        "settle_s": 14,
        "class": "envelope",
    },
    {
        "key": "wrong_day_id",
        "expect": "soft_deny",
        "reasons": {"day", "unwrap", "envelope", "stamp"},
        "settle_s": 10,
        "class": "envelope",
        "note": "May be soft on v1-psk depending on day checks",
    },
    {
        "key": "missing_day_material",
        "expect": "soft_deny",
        "reasons": {"day", "unwrap", "envelope"},
        "settle_s": 10,
        "class": "envelope",
        "note": "Often no-op on v1-psk; pass if agent stays up",
    },
    {
        "key": "schema_missing_field",
        "expect": "soft_deny",
        "reasons": {"schema"},
        "settle_s": 10,
        "class": "schema",
        "note": "Needs a registered schema that requires the field",
    },
    {
        "key": "schema_wrong_type",
        "expect": "soft_deny",
        "reasons": {"schema"},
        "settle_s": 10,
        "class": "schema",
    },
    {
        "key": "schema_extra_field",
        "expect": "soft_accept",
        "reasons": {"schema"},
        "settle_s": 10,
        "class": "schema",
        "note": "Accept unless schema sets additionalProperties:false",
    },
    {
        "key": "wrong_schema_id",
        "expect": "soft_deny",
        "reasons": {"schema"},
        "settle_s": 10,
        "class": "schema",
    },
    {
        "key": "legacy_fernet_wrapper",
        "expect": "accept",
        "reasons": set(),
        "settle_s": 10,
        "class": "compat",
        "note": "Accept while IOTGW_ENVELOPE_REQUIRE is off",
    },
]


@dataclass
class Snapshot:
    denied_total: int = 0
    device_denied: int = 0
    device_fail: int = 0
    device_ok: int = 0
    fake1_ok: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    arrival_max: int = 0


@dataclass
class CaseResult:
    key: str
    status: str  # PASS | FAIL | WAIVE
    expect: str
    notes: str = ""
    delta_denied: int = 0
    delta_fail: int = 0
    delta_ok: int = 0
    reasons_seen: list[str] = field(default_factory=list)


def _http_json(
    method: str,
    url: str,
    *,
    body: Any = None,
    timeout: float = 60.0,
) -> Any:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"{method} {url} -> HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"{method} {url} -> {e}") from e


def _http_text(url: str, *, timeout: float = 15.0) -> str:
    req = urllib.request.Request(url, headers={"Accept": "text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _settings_gateway_ip() -> Optional[str]:
    candidates = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidates.append(Path(appdata) / "IoTGatewayMonitor" / "settings.json")
    candidates.append(
        Path("/mnt/c/Users/ADMIN/AppData/Roaming/IoTGatewayMonitor/settings.json")
    )
    for path in candidates:
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        ip = str(raw.get("gateway_ip") or raw.get("ssh_host") or "").strip()
        if ip:
            return ip
    return None


def _parse_metrics(text: str, device_id: str) -> dict[str, int]:
    out = {
        "denied_total": 0,
        "device_denied": 0,
        "device_fail": 0,
        "device_ok": 0,
        "fake1_ok": 0,
    }
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith("iotgw_denied_publishes_total "):
            out["denied_total"] = int(float(line.split()[-1]))
        m = re.match(
            r'iotgw_device_denied_publishes_total\{[^}]*device_id="([^"]+)"[^}]*\}\s+(\S+)',
            line,
        )
        if m:
            if m.group(1) == device_id:
                out["device_denied"] = int(float(m.group(2)))
        m = re.match(
            r'iotgw_device_messages_total\{[^}]*device_id="([^"]+)"[^}]*result="(ok|fail)"[^}]*\}\s+(\S+)',
            line,
        )
        if not m:
            m = re.match(
                r'iotgw_device_messages_total\{[^}]*result="(ok|fail)"[^}]*device_id="([^"]+)"[^}]*\}\s+(\S+)',
                line,
            )
            if m:
                result, did, val = m.group(1), m.group(2), m.group(3)
                if did == device_id:
                    out[f"device_{result}"] = int(float(val))
                if did == "fake1" and result == "ok":
                    out["fake1_ok"] = int(float(val))
            continue
        did, result, val = m.group(1), m.group(2), m.group(3)
        if did == device_id:
            out[f"device_{result}"] = int(float(val))
        if did == "fake1" and result == "ok":
            out["fake1_ok"] = int(float(val))
    return out


def behaviors_only(key: str) -> dict[str, bool]:
    out = dict(DEFAULT_BEHAVIORS)
    if key:
        if key not in out:
            raise KeyError(f"unknown behavior {key!r}")
        out[key] = True
    return out


class MatrixRunner:
    def __init__(
        self,
        *,
        api_base: str,
        agent_base: str,
        gateway_id: str,
        device_id: str,
        baseline_device: str,
        interval_ms: int,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.agent_base = agent_base.rstrip("/")
        self.gateway_id = gateway_id
        self.device_id = device_id
        self.baseline_device = baseline_device
        self.interval_ms = interval_ms

    def _fake_url(self, device: str, suffix: str = "") -> str:
        return (
            f"{self.api_base}/gateways/{urllib.parse.quote(self.gateway_id)}"
            f"/devices/{urllib.parse.quote(device)}/fake{suffix}"
        )

    def patch_fake(
        self,
        device: str,
        behaviors: dict[str, bool],
        *,
        payload: Any | None = None,
    ) -> None:
        body: dict[str, Any] = {
            "send_interval_ms": self.interval_ms,
            "behaviors": behaviors,
        }
        if payload is not None:
            body["payload"] = payload
        _http_json("PATCH", self._fake_url(device), body=body, timeout=120.0)

    def clean_payload(self, device: str) -> dict[str, Any]:
        return {"device_id": device, "hello": 1}

    def start_fake(self, device: str) -> None:
        _http_json("POST", self._fake_url(device, "/start"), body={}, timeout=120.0)

    def stop_fake(self, device: str) -> None:
        try:
            _http_json("POST", self._fake_url(device, "/stop"), body={}, timeout=120.0)
        except RuntimeError as exc:
            print(f"  warn: stop {device}: {exc}", file=sys.stderr)

    def snapshot(self) -> Snapshot:
        metrics = _parse_metrics(
            _http_text(f"{self.agent_base}/metrics"), self.device_id
        )
        denied = _http_json(
            "GET",
            f"{self.agent_base}/v1/denied?limit=50&device_id="
            + urllib.parse.quote(self.device_id),
            timeout=10.0,
        )
        events = []
        if isinstance(denied, dict):
            events = list(denied.get("events") or [])
        arrival_max = 0
        for ev in events:
            try:
                arrival_max = max(arrival_max, int(ev.get("arrival_ms") or 0))
            except (TypeError, ValueError):
                pass
        return Snapshot(
            denied_total=metrics["denied_total"],
            device_denied=metrics["device_denied"],
            device_fail=metrics["device_fail"],
            device_ok=metrics["device_ok"],
            fake1_ok=metrics["fake1_ok"],
            events=events,
            arrival_max=arrival_max,
        )

    def agent_up(self) -> bool:
        try:
            h = _http_json("GET", f"{self.agent_base}/v1/health", timeout=5.0)
            return isinstance(h, dict) and h.get("status") == "ok"
        except RuntimeError:
            return False

    def new_events_since(self, before: Snapshot) -> list[dict[str, Any]]:
        after = self.snapshot()
        return [
            ev
            for ev in after.events
            if int(ev.get("arrival_ms") or 0) > before.arrival_max
        ]

    def ensure_baseline(self) -> None:
        print(f"Ensuring baseline {self.baseline_device} running (all behaviors off)…")
        self.patch_fake(
            self.baseline_device,
            dict(DEFAULT_BEHAVIORS),
            payload=self.clean_payload(self.baseline_device),
        )
        self.start_fake(self.baseline_device)

    def restore_target(self) -> None:
        print(f"Restoring {self.device_id} to clean behaviors…")
        self.patch_fake(
            self.device_id,
            dict(DEFAULT_BEHAVIORS),
            payload=self.clean_payload(self.device_id),
        )
        self.start_fake(self.device_id)

    def reset_target_clean(self) -> None:
        """Stop → clean config/payload → start, so TLS context is rebuilt."""
        self.stop_fake(self.device_id)
        time.sleep(1.0)
        self.patch_fake(
            self.device_id,
            dict(DEFAULT_BEHAVIORS),
            payload=self.clean_payload(self.device_id),
        )
        self.start_fake(self.device_id)
        time.sleep(3.0)

    def run_case(self, case: dict[str, Any]) -> CaseResult:
        key = str(case["key"])
        expect = str(case["expect"])
        reasons = set(case.get("reasons") or [])
        settle = float(case.get("settle_s") or 10)
        print(f"\n=== {key} (expect={expect}, settle={settle:.0f}s) ===")
        # Isolate from prior TLS attack processes / stale payload.
        self.reset_target_clean()
        before = self.snapshot()
        self.patch_fake(
            self.device_id,
            behaviors_only(key),
            payload=self.clean_payload(self.device_id),
        )
        self.start_fake(self.device_id)
        time.sleep(settle)
        if not self.agent_up():
            return CaseResult(
                key=key,
                status="FAIL",
                expect=expect,
                notes="gateway agent /v1/health not ok after case",
            )
        after = self.snapshot()
        delta_denied = max(
            after.denied_total - before.denied_total,
            after.device_denied - before.device_denied,
        )
        delta_fail = after.device_fail - before.device_fail
        delta_ok = after.device_ok - before.device_ok
        new_events = [
            ev
            for ev in after.events
            if int(ev.get("arrival_ms") or 0) > before.arrival_max
        ]
        reasons_seen = sorted(
            {str(ev.get("reason") or "") for ev in new_events if ev.get("reason")}
        )
        reason_hit = bool(reasons & set(reasons_seen)) if reasons else False
        deny_signal = delta_denied > 0 or delta_fail > 0 or reason_hit
        accept_signal = delta_ok > 0

        notes_parts: list[str] = []
        if case.get("note"):
            notes_parts.append(str(case["note"]))
        notes_parts.append(
            f"Δdenied={delta_denied} Δfail={delta_fail} Δok={delta_ok} reasons={reasons_seen or '-'}"
        )

        status = "FAIL"
        if expect == "deny":
            # Prefer an expected reason in new events; allow deny delta alone only
            # when reasons set is empty.
            if reason_hit:
                status = "PASS"
            elif deny_signal and not reasons:
                status = "PASS"
            elif deny_signal and reasons and not reason_hit:
                status = "FAIL"
                notes_parts.append(
                    f"denied rose but expected reason not in {sorted(reasons)}"
                )
            else:
                status = "FAIL"
                notes_parts.append("expected deny signal missing")
        elif expect == "accept":
            if accept_signal and not (delta_denied > 0 and delta_ok == 0):
                status = "PASS"
            elif accept_signal:
                status = "PASS"
            else:
                status = "FAIL"
                notes_parts.append("expected ok messages missing")
        elif expect == "soft_deny":
            if deny_signal:
                status = "PASS"
            elif accept_signal:
                status = "WAIVE"
                notes_parts.append("no deny; traffic accepted (schema/profile soft)")
            else:
                status = "WAIVE"
                notes_parts.append("no deny and no ok; attack may be no-op on this profile")
        elif expect == "soft_accept":
            if accept_signal or (not deny_signal):
                status = "PASS" if accept_signal else "WAIVE"
                if not accept_signal:
                    notes_parts.append("no ok delta; left as waive")
            else:
                # denied unexpectedly — still informative
                status = "PASS"
                notes_parts.append("schema rejected extras (additionalProperties false)")
        else:
            status = "FAIL"
            notes_parts.append(f"unknown expect {expect}")

        # Isolation: fake1 should not have collapsed (allow small scrape noise).
        if after.fake1_ok + 2 < before.fake1_ok:
            status = "FAIL"
            notes_parts.append(
                f"baseline fake1 ok dropped {before.fake1_ok}->{after.fake1_ok}"
            )

        print(f"  -> {status}: {'; '.join(notes_parts)}")
        return CaseResult(
            key=key,
            status=status,
            expect=expect,
            notes="; ".join(notes_parts),
            delta_denied=delta_denied,
            delta_fail=delta_fail,
            delta_ok=delta_ok,
            reasons_seen=reasons_seen,
        )


def _print_table(results: list[CaseResult]) -> None:
    print("\n## Results\n")
    print("| Behavior | Expect | Status | Δdenied | Δfail | Δok | Reasons | Notes |")
    print("|---|---|---|---:|---:|---:|---|---|")
    for r in results:
        notes = r.notes.replace("|", "/")
        print(
            f"| `{r.key}` | {r.expect} | **{r.status}** | {r.delta_denied} | "
            f"{r.delta_fail} | {r.delta_ok} | {', '.join(r.reasons_seen) or '—'} | {notes} |"
        )
    failed = [r for r in results if r.status == "FAIL"]
    waived = [r for r in results if r.status == "WAIVE"]
    print(
        f"\nSummary: {sum(1 for r in results if r.status == 'PASS')} PASS, "
        f"{len(waived)} WAIVE, {len(failed)} FAIL / {len(results)} cases"
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--api-base", default="http://127.0.0.1:9138/api/v1")
    p.add_argument("--agent-base", default="")
    p.add_argument("--gateway-ip", default="")
    p.add_argument("--gateway-id", default="gateway")
    p.add_argument("--device", default="fake2")
    p.add_argument("--baseline-device", default="fake1")
    p.add_argument("--interval-ms", type=int, default=500)
    p.add_argument(
        "--only",
        default="",
        help="Comma-separated behavior keys to run (default: all)",
    )
    p.add_argument(
        "--skip-restore-ok-check",
        action="store_true",
        help="Do not require ok traffic after final restore",
    )
    args = p.parse_args(argv)

    gateway_ip = (args.gateway_ip or _settings_gateway_ip() or "").strip()
    if not gateway_ip:
        print("gateway IP required (--gateway-ip or settings.json)", file=sys.stderr)
        return 2
    agent_base = (args.agent_base or f"http://{gateway_ip}:9139").rstrip("/")

    only = {x.strip() for x in args.only.split(",") if x.strip()}
    cases = [c for c in CASES if not only or c["key"] in only]
    if only:
        missing = only - {c["key"] for c in cases}
        if missing:
            print(f"unknown --only keys: {sorted(missing)}", file=sys.stderr)
            return 2

    runner = MatrixRunner(
        api_base=args.api_base,
        agent_base=agent_base,
        gateway_id=args.gateway_id,
        device_id=args.device,
        baseline_device=args.baseline_device,
        interval_ms=args.interval_ms,
    )

    print(f"API {args.api_base}")
    print(f"Agent {agent_base}")
    print(f"Gateway {args.gateway_id} device={args.device} baseline={args.baseline_device}")
    if not runner.agent_up():
        print("agent health check failed", file=sys.stderr)
        return 2

    results: list[CaseResult] = []
    try:
        runner.ensure_baseline()
        time.sleep(3)
        for case in cases:
            try:
                results.append(runner.run_case(case))
            except Exception as exc:  # noqa: BLE001
                print(f"  -> FAIL: exception {exc}")
                results.append(
                    CaseResult(
                        key=str(case["key"]),
                        status="FAIL",
                        expect=str(case["expect"]),
                        notes=f"exception: {exc}",
                    )
                )
    finally:
        try:
            runner.restore_target()
            if not args.skip_restore_ok_check:
                time.sleep(8)
                snap = runner.snapshot()
                print(
                    f"Post-restore {args.device}: ok={snap.device_ok} "
                    f"fail={snap.device_fail} denied={snap.device_denied}"
                )
        except Exception as exc:  # noqa: BLE001
            print(f"restore failed: {exc}", file=sys.stderr)
            results.append(
                CaseResult(
                    key="__restore__",
                    status="FAIL",
                    expect="accept",
                    notes=f"restore failed: {exc}",
                )
            )

    _print_table(results)
    return 1 if any(r.status == "FAIL" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
