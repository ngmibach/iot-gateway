"""Background renewer: reissue + feed mTLS certs for fake sensors only."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from actions.fake_sensors import feed_fake_certs
from actions.playbooks import reissue_device_cert
from registry.registry import Registry

from .device_meta import fake_block, is_fake_meta, merge_device_meta, parse_meta

logger = logging.getLogger(__name__)

SECONDS_PER_DAY = 86_400
DEFAULT_CLIENT_CERT_DAYS = 730
# Plan default: min(30d, 10% of client_cert_days)
DEFAULT_RENEW_INTERVAL_S = 600  # 10 minutes
MISSING_CA_BACKOFF_S = 1800  # 30 minutes between "no CA" audits per gateway

Clock = Callable[[], float]
SleepFn = Callable[[float], None]
OpenSSHFactory = Callable[[dict[str, Any]], Any]


def default_renew_window_s(client_cert_days: int = DEFAULT_CLIENT_CERT_DAYS) -> int:
    """Renew when ``now >= cert_expires_at - window``."""
    days = max(1, int(client_cert_days))
    ten_percent = int(days * SECONDS_PER_DAY * 0.10)
    thirty_days = 30 * SECONDS_PER_DAY
    return max(60, min(thirty_days, ten_percent))


def attack_pauses_auto_renew(meta: dict[str, Any] | None) -> bool:
    """True when Simulate TLS attack toggles should block auto-feed."""
    block = fake_block(meta) or {}
    behaviors = block.get("behaviors") if isinstance(block.get("behaviors"), dict) else {}
    return bool(
        behaviors.get("omit_client_cert") or behaviors.get("wrong_client_cert")
    )


@dataclass(frozen=True)
class RenewDecision:
    needed: bool
    reason: str  # near_expiry | feed_lag | skip_attack | skip_no_expiry | ok | skip_disabled


def evaluate_renew(
    row: dict[str, Any],
    *,
    now: int,
    renew_window_s: int,
    require_monitor_enabled: bool = True,
) -> RenewDecision:
    """Decide whether a registry device row needs fake cert renew/feed."""
    meta = parse_meta(row.get("meta_json"))
    if not is_fake_meta(meta):
        return RenewDecision(False, "ok")
    if require_monitor_enabled and not bool(row.get("monitor_enabled", 1)):
        return RenewDecision(False, "skip_disabled")
    if attack_pauses_auto_renew(meta):
        return RenewDecision(False, "skip_attack")

    fingerprint = row.get("cert_fingerprint")
    block = fake_block(meta) or {}
    fed_fp = block.get("cert_feed_fingerprint")
    if fingerprint and fed_fp and str(fingerprint) != str(fed_fp):
        return RenewDecision(True, "feed_lag")
    if fingerprint and not fed_fp:
        return RenewDecision(True, "feed_lag")

    expires = row.get("cert_expires_at")
    if expires is None:
        return RenewDecision(False, "skip_no_expiry")
    try:
        expires_i = int(expires)
    except (TypeError, ValueError):
        return RenewDecision(False, "skip_no_expiry")
    if now >= expires_i - int(renew_window_s):
        return RenewDecision(True, "near_expiry")
    return RenewDecision(False, "ok")


def resolve_ca_passphrase(
    *,
    gateway_id: str,
    settings_ca: str | None,
    data_dir: Path | str | None = None,
    provider: Callable[[str], str | None] | None = None,
) -> str | None:
    """Resolve CA passphrase: settings → provider → OS keyring → file fallback."""
    if settings_ca:
        return settings_ca
    if provider is not None:
        try:
            got = provider(gateway_id)
        except Exception:  # noqa: BLE001
            got = None
        if got:
            return got
    account = f"ca:{gateway_id}"
    try:
        import keyring
        from keyring.backends.fail import Keyring as FailKeyring

        kr = keyring.get_keyring()
        if not isinstance(kr, FailKeyring):
            val = keyring.get_password("iot-gateway-monitor", account)
            if val:
                return val
    except Exception:  # noqa: BLE001
        pass
    if data_dir is not None:
        path = Path(data_dir) / "keyring-fallback.json"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get(account):
                    return str(data[account])
            except (OSError, json.JSONDecodeError):
                pass
    return None


def feed_and_record_certs(
    ssh: Any,
    *,
    registry: Registry,
    gateway_id: str,
    device_id: str,
    ca_pem: bytes | str,
    client_crt_pem: bytes | str,
    client_key_pem: bytes | str,
    fingerprint: str | None,
    install_root: str,
    sudo_password: str | None = None,
    now: int | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Write fake certs, restart unit, update ``cert_fed_*`` meta."""
    fed = feed_fake_certs(
        ssh,
        device_id,
        ca_pem=ca_pem,
        client_crt_pem=client_crt_pem,
        client_key_pem=client_key_pem,
        restart=True,
        sudo_password=sudo_password,
        install_root=install_root,
    )
    row = registry.get_device(gateway_id, device_id)
    prev = parse_meta(row.get("meta_json") if row else None)
    ts = int(now if now is not None else time.time())
    fake_update: dict[str, Any] = {
        "cert_fed_at": ts,
        "cert_feed_fingerprint": fingerprint,
    }
    if fed.ok:
        fake_update["status"] = "running"
        fake_update["last_error"] = None
    else:
        fake_update["status"] = "error"
        fake_update["last_error"] = (fed.message or "feed_fake_certs failed")[:400]
    meta = merge_device_meta(prev, is_fake=True, fake=fake_update)
    device = registry.upsert_device(gateway_id, device_id, meta_json=meta)
    return fed, device


@dataclass
class RenewResult:
    gateway_id: str
    device_id: str
    ok: bool
    reason: str
    message: str = ""
    old_fingerprint: str | None = None
    new_fingerprint: str | None = None


@dataclass
class FakeCertRenewer:
    """Poll registry fakes and renew/feed certs before expiry."""

    registry: Registry
    open_ssh: OpenSSHFactory
    settings_ca: str | None = None
    data_dir: Path | str | None = None
    ca_provider: Callable[[str], str | None] | None = None
    client_cert_days: int = DEFAULT_CLIENT_CERT_DAYS
    renew_window_s: int | None = None
    interval_s: int = DEFAULT_RENEW_INTERVAL_S
    enabled: bool = True
    clock: Clock = time.time
    sleep: SleepFn = time.sleep
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _device_locks: dict[str, threading.Lock] = field(
        default_factory=dict, init=False, repr=False
    )
    _locks_guard: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _ca_skip_until: dict[str, float] = field(default_factory=dict, init=False, repr=False)

    def window_s(self) -> int:
        if self.renew_window_s is not None and self.renew_window_s > 0:
            return int(self.renew_window_s)
        return default_renew_window_s(self.client_cert_days)

    def _lock_for(self, gateway_id: str, device_id: str) -> threading.Lock:
        key = f"{gateway_id}/{device_id}"
        with self._locks_guard:
            lock = self._device_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._device_locks[key] = lock
            return lock

    def _ca_for(self, gateway_id: str) -> str | None:
        return resolve_ca_passphrase(
            gateway_id=gateway_id,
            settings_ca=self.settings_ca,
            data_dir=self.data_dir,
            provider=self.ca_provider,
        )

    def renew_device(
        self,
        gateway: dict[str, Any],
        row: dict[str, Any],
        *,
        reason: str,
        ssh: Any | None = None,
    ) -> RenewResult:
        """Reissue + feed one fake device (holds per-device lock)."""
        gid = str(gateway["id"])
        device_id = str(row["id"])
        old_fp = row.get("cert_fingerprint")
        lock = self._lock_for(gid, device_id)
        if not lock.acquire(blocking=False):
            return RenewResult(
                gateway_id=gid,
                device_id=device_id,
                ok=False,
                reason=reason,
                message="renew already in progress",
                old_fingerprint=old_fp,
            )
        cm: Any = None
        try:
            ca_pass = self._ca_for(gid)
            if not ca_pass:
                return RenewResult(
                    gateway_id=gid,
                    device_id=device_id,
                    ok=False,
                    reason="skip_no_ca",
                    message="CA passphrase unavailable",
                    old_fingerprint=old_fp,
                )
            if ssh is None:
                cm = self.open_ssh(gateway)
                ssh = cm.__enter__()
            result = reissue_device_cert(
                ssh,
                user_id=device_id,
                ca_passphrase=ca_pass,
                install_root=gateway["install_root"],
                cert_days=int(self.client_cert_days),
            )
            if not result.ok:
                return RenewResult(
                    gateway_id=gid,
                    device_id=device_id,
                    ok=False,
                    reason=reason,
                    message=result.message or "reissue failed",
                    old_fingerprint=old_fp,
                )
            expires = None
            if result.cert_expires_at:
                try:
                    from datetime import datetime

                    expires = int(datetime.fromisoformat(result.cert_expires_at).timestamp())
                except ValueError:
                    expires = None
            self.registry.upsert_device(
                gid,
                device_id,
                cert_expires_at=expires,
                cert_fingerprint=result.cert_fingerprint,
            )
            if not (
                result.ca_crt_pem and result.client_crt_pem and result.client_key_pem
            ):
                return RenewResult(
                    gateway_id=gid,
                    device_id=device_id,
                    ok=False,
                    reason=reason,
                    message="reissue missing PEM material",
                    old_fingerprint=old_fp,
                    new_fingerprint=result.cert_fingerprint,
                )
            fed, _device = feed_and_record_certs(
                ssh,
                registry=self.registry,
                gateway_id=gid,
                device_id=device_id,
                ca_pem=result.ca_crt_pem,
                client_crt_pem=result.client_crt_pem,
                client_key_pem=result.client_key_pem,
                fingerprint=result.cert_fingerprint,
                install_root=gateway["install_root"],
                now=int(self.clock()),
            )
            if not fed.ok:
                self.registry.audit(
                    "fake_cert_auto_renew",
                    gateway_id=gid,
                    device_id=device_id,
                    detail={
                        "ok": False,
                        "reason": reason,
                        "message": fed.message,
                        "old_fingerprint": old_fp,
                        "new_fingerprint": result.cert_fingerprint,
                    },
                )
                return RenewResult(
                    gateway_id=gid,
                    device_id=device_id,
                    ok=False,
                    reason=reason,
                    message=fed.message or "feed failed",
                    old_fingerprint=old_fp,
                    new_fingerprint=result.cert_fingerprint,
                )
            self.registry.audit(
                "fake_cert_auto_renew",
                gateway_id=gid,
                device_id=device_id,
                detail={
                    "ok": True,
                    "reason": reason,
                    "old_fingerprint": old_fp,
                    "new_fingerprint": result.cert_fingerprint,
                },
            )
            return RenewResult(
                gateway_id=gid,
                device_id=device_id,
                ok=True,
                reason=reason,
                message="renewed and fed",
                old_fingerprint=old_fp,
                new_fingerprint=result.cert_fingerprint,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "fake cert renew failed gateway=%s device=%s: %s",
                gid,
                device_id,
                exc,
            )
            try:
                prev = parse_meta(
                    (self.registry.get_device(gid, device_id) or {}).get("meta_json")
                )
                meta = merge_device_meta(
                    prev,
                    is_fake=True,
                    fake={"status": "error", "last_error": str(exc)[:400]},
                )
                self.registry.upsert_device(gid, device_id, meta_json=meta)
            except Exception:  # noqa: BLE001
                pass
            self.registry.audit(
                "fake_cert_auto_renew",
                gateway_id=gid,
                device_id=device_id,
                detail={
                    "ok": False,
                    "reason": reason,
                    "message": str(exc)[:400],
                    "old_fingerprint": old_fp,
                },
            )
            return RenewResult(
                gateway_id=gid,
                device_id=device_id,
                ok=False,
                reason=reason,
                message=str(exc)[:400],
                old_fingerprint=old_fp,
            )
        finally:
            if cm is not None:
                try:
                    cm.__exit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass
            lock.release()

    def run_once(self) -> list[RenewResult]:
        """Evaluate all gateways/fakes once; renew those that need it."""
        if not self.enabled:
            return []
        now = int(self.clock())
        window = self.window_s()
        out: list[RenewResult] = []
        for gw in self.registry.list_gateways():
            gid = str(gw["id"])
            ca = self._ca_for(gid)
            if not ca:
                until = self._ca_skip_until.get(gid, 0.0)
                if now >= until:
                    self._ca_skip_until[gid] = float(now + MISSING_CA_BACKOFF_S)
                    self.registry.audit(
                        "fake_cert_auto_renew_skip",
                        gateway_id=gid,
                        detail={"reason": "missing_ca_passphrase"},
                    )
                continue
            self._ca_skip_until.pop(gid, None)

            due: list[tuple[dict[str, Any], RenewDecision]] = []
            for row in self.registry.list_devices(gid):
                decision = evaluate_renew(row, now=now, renew_window_s=window)
                if decision.needed:
                    due.append((row, decision))
            if not due:
                continue
            try:
                with self.open_ssh(gw) as ssh:
                    for row, decision in due:
                        # Re-check under lock path (attack toggle may have flipped).
                        latest = self.registry.get_device(gid, row["id"]) or row
                        again = evaluate_renew(
                            latest, now=int(self.clock()), renew_window_s=window
                        )
                        if not again.needed:
                            continue
                        out.append(
                            self.renew_device(
                                gw, latest, reason=again.reason, ssh=ssh
                            )
                        )
            except Exception as exc:  # noqa: BLE001
                logger.warning("fake cert renew gateway %s SSH failed: %s", gid, exc)
                self.registry.audit(
                    "fake_cert_auto_renew_skip",
                    gateway_id=gid,
                    detail={"reason": "ssh_failed", "message": str(exc)[:300]},
                )
        return out

    def _loop(self) -> None:
        # Immediate pass on startup, then interval.
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                logger.exception("fake cert renewer pass failed")
            self._stop.wait(timeout=max(30, int(self.interval_s)))

    def start(self) -> None:
        if not self.enabled:
            return
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="iotgw-fake-cert-renewer",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "fake cert renewer started (interval=%ss window=%ss)",
            self.interval_s,
            self.window_s(),
        )

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
