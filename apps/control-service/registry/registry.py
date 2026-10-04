"""SQLite-backed registry for gateways, devices, allow-list IPs, and audit."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Iterable, Optional

from .schema import SCHEMA_SQL


def _now() -> int:
    return int(time.time())


def _topics_to_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


class Registry:
    """Local device/gateway registry backed by registry.sqlite."""

    def __init__(self, path: str):
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.path = path
        self._conn = sqlite3.connect(path, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Registry":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ── gateways ──────────────────────────────────────────────────────

    def upsert_gateway(
        self,
        id: str,
        host: str,
        ssh_user: str,
        install_root: str,
        fingerprint: str,
        *,
        agent_url: Optional[str] = None,
        monitoring_ip: Optional[str] = None,
        password_auth_enabled: int = 0,
        created_at: Optional[int] = None,
        last_seen_at: Optional[int] = None,
        status: Optional[str] = None,
    ) -> dict[str, Any]:
        """Insert or update a gateway. Preserves created_at on conflict."""
        ts = created_at if created_at is not None else _now()
        seen = last_seen_at if last_seen_at is not None else ts
        self._conn.execute(
            """
            INSERT INTO gateways (
              id, host, ssh_user, install_root, agent_url, fingerprint,
              monitoring_ip, password_auth_enabled, created_at, last_seen_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              host = excluded.host,
              ssh_user = excluded.ssh_user,
              install_root = excluded.install_root,
              agent_url = excluded.agent_url,
              fingerprint = excluded.fingerprint,
              monitoring_ip = excluded.monitoring_ip,
              password_auth_enabled = excluded.password_auth_enabled,
              last_seen_at = excluded.last_seen_at,
              status = excluded.status
            """,
            (
                id,
                host,
                ssh_user,
                install_root,
                agent_url,
                fingerprint,
                monitoring_ip,
                int(password_auth_enabled),
                ts,
                seen,
                status,
            ),
        )
        self._conn.commit()
        row = self.get_gateway(id)
        assert row is not None
        return row

    def get_gateway(self, gateway_id: str) -> Optional[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM gateways WHERE id = ?", (gateway_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def list_gateways(self) -> list[dict[str, Any]]:
        cur = self._conn.execute("SELECT * FROM gateways ORDER BY id")
        return [dict(r) for r in cur.fetchall()]

    # ── devices ───────────────────────────────────────────────────────

    def upsert_device(
        self,
        gateway_id: str,
        id: str,
        *,
        ip: Optional[str] = None,
        topics_rw: Any = None,
        topics_r: Any = None,
        monitor_enabled: int = 1,
        cert_expires_at: Optional[int] = None,
        cert_fingerprint: Optional[str] = None,
        created_at: Optional[int] = None,
        meta_json: Any = None,
    ) -> dict[str, Any]:
        """Insert or update a device. Preserves created_at on conflict."""
        ts = created_at if created_at is not None else _now()
        meta = meta_json
        if meta is not None and not isinstance(meta, str):
            meta = json.dumps(meta, ensure_ascii=False)
        self._conn.execute(
            """
            INSERT INTO devices (
              gateway_id, id, ip, topics_rw, topics_r, monitor_enabled,
              cert_expires_at, cert_fingerprint, created_at, meta_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(gateway_id, id) DO UPDATE SET
              ip = excluded.ip,
              topics_rw = excluded.topics_rw,
              topics_r = excluded.topics_r,
              monitor_enabled = excluded.monitor_enabled,
              cert_expires_at = excluded.cert_expires_at,
              cert_fingerprint = excluded.cert_fingerprint,
              meta_json = excluded.meta_json
            """,
            (
                gateway_id,
                id,
                ip,
                _topics_to_text(topics_rw),
                _topics_to_text(topics_r),
                int(monitor_enabled),
                cert_expires_at,
                cert_fingerprint,
                ts,
                meta,
            ),
        )
        self._conn.commit()
        row = self.get_device(gateway_id, id)
        assert row is not None
        return row

    def get_device(self, gateway_id: str, device_id: str) -> Optional[dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM devices WHERE gateway_id = ? AND id = ?",
            (gateway_id, device_id),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def list_devices(
        self,
        gateway_id: str,
        monitor_enabled: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        if monitor_enabled is None:
            cur = self._conn.execute(
                "SELECT * FROM devices WHERE gateway_id = ? ORDER BY id",
                (gateway_id,),
            )
        else:
            cur = self._conn.execute(
                """
                SELECT * FROM devices
                WHERE gateway_id = ? AND monitor_enabled = ?
                ORDER BY id
                """,
                (gateway_id, int(monitor_enabled)),
            )
        return [dict(r) for r in cur.fetchall()]

    def delete_device(self, gateway_id: str, device_id: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM devices WHERE gateway_id = ? AND id = ?",
            (gateway_id, device_id),
        )
        # Unlink allow-list rows that pointed at this device
        self._conn.execute(
            """
            UPDATE imported_allowlist_ips
            SET linked_device_id = NULL
            WHERE gateway_id = ? AND linked_device_id = ?
            """,
            (gateway_id, device_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    # ── allow-list import / link ──────────────────────────────────────

    def import_allowlist_ips(
        self,
        gateway_id: str,
        ips: Iterable[str],
    ) -> int:
        """Import allow-list IPs. Idempotent; does not overwrite existing links."""
        inserted = 0
        for ip in ips:
            ip = (ip or "").strip()
            if not ip:
                continue
            cur = self._conn.execute(
                """
                INSERT INTO imported_allowlist_ips (gateway_id, ip, linked_device_id)
                VALUES (?, ?, NULL)
                ON CONFLICT(gateway_id, ip) DO NOTHING
                """,
                (gateway_id, ip),
            )
            inserted += cur.rowcount
        self._conn.commit()
        return inserted

    def link_allowlist_ip(
        self,
        gateway_id: str,
        ip: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Link an imported allow-list IP to a device id (UI step)."""
        self._conn.execute(
            """
            INSERT INTO imported_allowlist_ips (gateway_id, ip, linked_device_id)
            VALUES (?, ?, ?)
            ON CONFLICT(gateway_id, ip) DO UPDATE SET
              linked_device_id = excluded.linked_device_id
            """,
            (gateway_id, ip, device_id),
        )
        self._conn.commit()
        cur = self._conn.execute(
            """
            SELECT * FROM imported_allowlist_ips
            WHERE gateway_id = ? AND ip = ?
            """,
            (gateway_id, ip),
        )
        row = cur.fetchone()
        assert row is not None
        return dict(row)

    def list_allowlist_ips(self, gateway_id: str) -> list[dict[str, Any]]:
        cur = self._conn.execute(
            """
            SELECT * FROM imported_allowlist_ips
            WHERE gateway_id = ?
            ORDER BY ip
            """,
            (gateway_id,),
        )
        return [dict(r) for r in cur.fetchall()]

    def import_acl_usernames(
        self,
        gateway_id: str,
        usernames: Iterable[str],
        *,
        topics_rw: Any = None,
        topics_r: Any = None,
    ) -> int:
        """Import ACL usernames as devices with ip=NULL when missing.

        Existing devices are left unchanged (brownfield: do not invent joins).
        """
        created = 0
        ts = _now()
        rw = _topics_to_text(topics_rw)
        r = _topics_to_text(topics_r)
        for username in usernames:
            username = (username or "").strip()
            if not username:
                continue
            existing = self.get_device(gateway_id, username)
            if existing is not None:
                continue
            self._conn.execute(
                """
                INSERT INTO devices (
                  gateway_id, id, ip, topics_rw, topics_r, monitor_enabled,
                  created_at
                ) VALUES (?, ?, NULL, ?, ?, 1, ?)
                """,
                (gateway_id, username, rw, r, ts),
            )
            created += 1
        self._conn.commit()
        return created

    # ── audit ─────────────────────────────────────────────────────────

    def audit(
        self,
        action: str,
        *,
        gateway_id: Optional[str] = None,
        device_id: Optional[str] = None,
        detail: Any = None,
        actor: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> dict[str, Any]:
        """Append an audit_log row. detail may be str or JSON-serializable."""
        ts = timestamp if timestamp is not None else _now()
        if detail is not None and not isinstance(detail, str):
            detail = json.dumps(detail, ensure_ascii=False)
        cur = self._conn.execute(
            """
            INSERT INTO audit_log (
              timestamp, action, gateway_id, device_id, detail, actor
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ts, action, gateway_id, device_id, detail, actor),
        )
        self._conn.commit()
        row_id = cur.lastrowid
        cur = self._conn.execute(
            "SELECT * FROM audit_log WHERE id = ?", (row_id,)
        )
        row = cur.fetchone()
        assert row is not None
        return dict(row)

    def list_audit(
        self,
        *,
        gateway_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if gateway_id is None:
            cur = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC, id DESC LIMIT ?",
                (int(limit),),
            )
        else:
            cur = self._conn.execute(
                """
                SELECT * FROM audit_log
                WHERE gateway_id = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (gateway_id, int(limit)),
            )
        return [dict(r) for r in cur.fetchall()]
