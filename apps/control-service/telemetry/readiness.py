"""Readiness probes for Loki and Prometheus."""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    url: str
    detail: str


def _get(url: str, timeout: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        code = int(getattr(resp, "status", resp.getcode()))
        body = resp.read(4096)
        return code, body


def probe_http(url: str, *, timeout: float = 5.0) -> ProbeResult:
    try:
        code, body = _get(url, timeout)
        if 200 <= code < 300:
            return ProbeResult(True, url, f"HTTP {code} ({len(body)} bytes)")
        return ProbeResult(False, url, f"HTTP {code}")
    except urllib.error.HTTPError as e:
        return ProbeResult(False, url, f"HTTP {e.code}")
    except Exception as e:  # noqa: BLE001 — surface any reachability failure
        return ProbeResult(False, url, f"{type(e).__name__}: {e}")


def check_loki(base_url: str, *, timeout: float = 5.0) -> ProbeResult:
    """Loki ready endpoint: ``GET {base}/ready``."""
    base = base_url.rstrip("/")
    return probe_http(f"{base}/ready", timeout=timeout)


def check_prometheus(base_url: str, *, timeout: float = 5.0) -> ProbeResult:
    """Prometheus health: prefer ``/-/healthy``, fall back to ``/api/v1/status/config``."""
    base = base_url.rstrip("/")
    primary = probe_http(f"{base}/-/healthy", timeout=timeout)
    if primary.ok:
        return primary
    fallback = probe_http(f"{base}/api/v1/status/config", timeout=timeout)
    if fallback.ok:
        return fallback
    return ProbeResult(
        False,
        primary.url,
        f"{primary.detail}; fallback {fallback.url}: {fallback.detail}",
    )


def wait_ready(
    *,
    loki_url: str | None = None,
    prometheus_url: str | None = None,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
    probe_timeout: float = 5.0,
) -> dict[str, ProbeResult]:
    """Poll until Loki/Prometheus are ready or ``timeout_s`` elapses."""
    deadline = time.monotonic() + timeout_s
    results: dict[str, ProbeResult] = {}
    while True:
        if loki_url:
            results["loki"] = check_loki(loki_url, timeout=probe_timeout)
        if prometheus_url:
            results["prometheus"] = check_prometheus(
                prometheus_url, timeout=probe_timeout
            )
        pending = [k for k, r in results.items() if not r.ok]
        if not pending:
            return results
        if time.monotonic() >= deadline:
            return results
        time.sleep(interval_s)
