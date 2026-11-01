"""Sliding-window Auto prevent: quarantine sensor IPs via firewall helper."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_POLICY_NAME = "auto_prevent.json"
DEFAULT_STATE_NAME = "auto_prevent_state.json"
DEFAULT_HELPER = "/opt/iot-gateway-agent/bin/iotgw-auto-prevent"
# Reasons that should not re-trigger counting noise after quarantine.
_SKIP_REASONS = frozenset({"auto_prevent"})


def _valid_host_ip(value: str) -> str | None:
    text = (value or "").strip()
    if not text or "/" in text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
        return None
    return str(addr)


class AutoPrevent:
    """Watch deny events and firewall-DROP sensors that exceed the limit."""

    def __init__(
        self,
        *,
        data_dir: Path | str,
        helper_path: str | Path | None = None,
        deny_log: Any = None,
        on_trip: Callable[[str, str, dict[str, Any]], None] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.policy_path = self.data_dir / DEFAULT_POLICY_NAME
        self.state_path = self.data_dir / DEFAULT_STATE_NAME
        self.helper_path = Path(
            helper_path
            or os.environ.get("IOTGW_AUTO_PREVENT_HELPER")
            or DEFAULT_HELPER
        )
        self.deny_log = deny_log
        self.on_trip = on_trip
        self._lock = threading.Lock()
        self._policy_mtime: float = -1.0
        self._policy: dict[str, dict[str, Any]] = {}
        self._windows: dict[str, deque[float]] = defaultdict(deque)
        self._state: dict[str, dict[str, Any]] = {}
        self._load_state()
        self.reload_policy(force=True)

    def _load_state(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._state = {}
            return
        devices = raw.get("devices") if isinstance(raw, dict) else None
        if not isinstance(devices, dict):
            self._state = {}
            return
        out: dict[str, dict[str, Any]] = {}
        for did, rec in devices.items():
            if isinstance(rec, dict):
                out[str(did)] = dict(rec)
        self._state = out

    def _save_state(self) -> None:
        payload = {"devices": self._state}
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            tmp.replace(self.state_path)
        except OSError as exc:
            logger.warning("auto_prevent state write failed: %s", exc)

    def reload_policy(self, *, force: bool = False) -> None:
        path = self.policy_path
        try:
            mtime = path.stat().st_mtime
        except OSError:
            with self._lock:
                self._policy = {}
                self._policy_mtime = -1.0
            return
        if not force and mtime == self._policy_mtime:
            return
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("auto_prevent policy read failed: %s", exc)
            return
        devices = raw.get("devices") if isinstance(raw, dict) else None
        policy: dict[str, dict[str, Any]] = {}
        if isinstance(devices, dict):
            for did, rec in devices.items():
                if not isinstance(rec, dict):
                    continue
                policy[str(did)] = {
                    "enabled": bool(rec.get("enabled")),
                    "limit": max(1, int(rec.get("limit") or 10)),
                    "window_s": max(60, int(rec.get("window_s") or 300)),
                }
        with self._lock:
            self._policy = policy
            self._policy_mtime = mtime

    def status(self) -> dict[str, Any]:
        self.reload_policy()
        with self._lock:
            return {
                "policy_path": str(self.policy_path),
                "helper_path": str(self.helper_path),
                "helper_present": self.helper_path.is_file(),
                "devices": {
                    did: dict(cfg) for did, cfg in self._policy.items()
                },
                "quarantined": {
                    did: dict(rec) for did, rec in self._state.items()
                },
            }

    def is_quarantined(self, device_id: str) -> bool:
        did = (device_id or "").strip()
        with self._lock:
            return did in self._state

    def note_deny(
        self,
        *,
        device_id: str,
        source_ip: str = "",
        reason: str = "",
        arrival_ms: int | None = None,
    ) -> dict[str, Any] | None:
        """Record a deny and quarantine when the sliding window overflows.

        Returns trip info dict when a new quarantine is applied, else None.
        """
        did = (device_id or "").strip()
        if not did or did == "unknown":
            return None
        if (reason or "").strip() in _SKIP_REASONS:
            return None

        self.reload_policy()
        now = (arrival_ms / 1000.0) if arrival_ms else time.time()

        with self._lock:
            if did in self._state:
                return None
            cfg = self._policy.get(did)
            if not cfg or not cfg.get("enabled"):
                return None
            limit = int(cfg["limit"])
            window_s = int(cfg["window_s"])
            q = self._windows[did]
            q.append(now)
            cutoff = now - window_s
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) < limit:
                return None
            # Snapshot IP before releasing lock for helper call.
            ip = _valid_host_ip(source_ip)
            count = len(q)

        if not ip and self.deny_log is not None:
            try:
                ip = _valid_host_ip(self.deny_log.lookup_ip(did))
            except Exception:  # noqa: BLE001
                ip = None
        if not ip:
            logger.warning(
                "auto_prevent trip for %s skipped: no resolvable host IP", did
            )
            return None

        ok, detail = self._drop_ip(ip, did)
        if not ok:
            logger.error("auto_prevent DROP failed for %s (%s): %s", did, ip, detail)
            return None

        tripped_at = int(time.time())
        rec = {
            "ip": ip,
            "tripped_at": tripped_at,
            "limit": limit,
            "window_s": window_s,
            "count": count,
            "reason": (reason or "denied").strip() or "denied",
        }
        with self._lock:
            self._state[did] = rec
            self._windows.pop(did, None)
            self._save_state()

        if self.deny_log is not None:
            try:
                self.deny_log.record(
                    reason="auto_prevent",
                    device_id=did,
                    source_ip=ip,
                    detail=f"quarantined after {count} invalid in {window_s}s",
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("auto_prevent deny_log record failed: %s", exc)

        if self.on_trip is not None:
            try:
                self.on_trip(did, ip, rec)
            except Exception as exc:  # noqa: BLE001
                logger.debug("auto_prevent on_trip failed: %s", exc)

        logger.warning(
            "auto_prevent quarantined device=%s ip=%s count=%s window_s=%s",
            did,
            ip,
            count,
            window_s,
        )
        return {"device_id": did, **rec}

    def lift(self, device_id: str, *, ip: str | None = None) -> bool:
        did = (device_id or "").strip()
        with self._lock:
            rec = self._state.get(did) or {}
            use_ip = _valid_host_ip(ip or "") or _valid_host_ip(
                str(rec.get("ip") or "")
            )
        if use_ip:
            self._lift_ip(use_ip, did)
        with self._lock:
            self._state.pop(did, None)
            self._windows.pop(did, None)
            self._save_state()
        return True

    def _run_helper(self, args: list[str]) -> tuple[bool, str]:
        helper = self.helper_path
        if not helper.is_file():
            return False, f"helper missing: {helper}"
        # Agent unit runs as root by default — call helper directly; else sudo -n.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            candidates = [[str(helper), *args]]
        else:
            candidates = [
                ["sudo", "-n", "--", str(helper), *args],
                [str(helper), *args],
            ]
        last_err = "helper failed"
        for argv in candidates:
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                last_err = str(exc)
                continue
            if proc.returncode == 0:
                return True, (proc.stdout or "").strip()
            last_err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        return False, last_err

    def _drop_ip(self, ip: str, device_id: str) -> tuple[bool, str]:
        return self._run_helper(["drop", ip, device_id])

    def _lift_ip(self, ip: str, device_id: str) -> tuple[bool, str]:
        return self._run_helper(["lift", ip, device_id])
