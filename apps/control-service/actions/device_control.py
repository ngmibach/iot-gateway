"""Control-tab playbooks: block MQTT publish and purge Kafka topic data."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from . import files as fileops
from .kafka_capacity import DEFAULT_TOPIC_RETENTION_BYTES, kafka_topic_name
from .mosquitto_ctl import reload_mosquitto
from .paths import DEFAULT_AGENT_DATA, DEFAULT_INSTALL_ROOT, GatewayPaths
from .playbooks import PlaybookResult, _paths
from .validate import validate_topic, validate_user_id

if TYPE_CHECKING:
    from .ssh import SSHClient


def _read_acl(
    ssh: "SSHClient",
    paths: GatewayPaths,
    *,
    sudo_password: str | None,
) -> str:
    from .playbooks import _read_mosquitto_secret

    return _read_mosquitto_secret(ssh, paths.acl, sudo_password=sudo_password)


def _write_acl(
    ssh: "SSHClient",
    paths: GatewayPaths,
    body: str,
    *,
    sudo_password: str | None,
) -> None:
    from .playbooks import (
        _backup_mosquitto_secret,
        _chmod_mosquitto_secrets,
        _restore_mosquitto_secret,
        _write_mosquitto_secret,
    )

    bak = _backup_mosquitto_secret(ssh, paths.acl, sudo_password=sudo_password)
    try:
        _write_mosquitto_secret(
            ssh, paths.acl, body, sudo_password=sudo_password
        )
        _chmod_mosquitto_secrets(ssh, paths, sudo_password=sudo_password)
    except Exception:
        try:
            _restore_mosquitto_secret(
                ssh, paths.acl, bak, sudo_password=sudo_password
            )
        except Exception:
            pass
        raise


def block_device_publish(
    ssh: "SSHClient",
    *,
    user_id: str,
    topic_rw_hint: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    sudo_password: str | None = None,
) -> PlaybookResult:
    """Remove Mosquitto write ACL for ``user_id`` (keep registration)."""
    try:
        user_id = validate_user_id(user_id)
        paths = _paths(install_root, data_dir)
        fallback = (topic_rw_hint or "").strip() or f"sensors/{user_id}/#"
        try:
            fallback = validate_topic(fallback)
        except ValueError:
            fallback = f"sensors/{user_id}/#"

        content = _read_acl(ssh, paths, sudo_password=sudo_password)
        if not fileops.acl_has_user(content, user_id):
            return PlaybookResult(
                ok=False,
                status="failed",
                message=f"ACL user {user_id!r} not found on gateway",
            )
        if not fileops.user_has_write_acl(content, user_id):
            return PlaybookResult(
                ok=True,
                status="ok",
                message="publish already blocked",
                details={"user_id": user_id, "already_blocked": True},
            )
        updated = fileops.block_user_publish_acl(
            content, user_id, fallback_read_topic=fallback
        )
        _write_acl(ssh, paths, updated, sudo_password=sudo_password)
        mosq = reload_mosquitto(ssh, sudo_password=sudo_password)
        return PlaybookResult(
            ok=True,
            message="publish blocked",
            details={"user_id": user_id, "mosquitto": mosq},
        )
    except Exception as exc:  # noqa: BLE001
        return PlaybookResult(ok=False, status="failed", message=str(exc))


def unblock_device_publish(
    ssh: "SSHClient",
    *,
    user_id: str,
    topic_rw: str | None = None,
    topic_r: str | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    sudo_password: str | None = None,
) -> PlaybookResult:
    """Restore Mosquitto write ACL for ``user_id``."""
    try:
        user_id = validate_user_id(user_id)
        paths = _paths(install_root, data_dir)
        rw = (topic_rw or f"sensors/{user_id}/#").strip()
        rw = validate_topic(rw)
        r = validate_topic(topic_r) if topic_r else None

        content = _read_acl(ssh, paths, sudo_password=sudo_password)
        updated = fileops.upsert_user_acl(
            content, user_id, topic_rw=rw, topic_r=r
        )
        _write_acl(ssh, paths, updated, sudo_password=sudo_password)
        mosq = reload_mosquitto(ssh, sudo_password=sudo_password)
        return PlaybookResult(
            ok=True,
            message="publish allowed",
            details={"user_id": user_id, "topic_rw": rw, "mosquitto": mosq},
        )
    except Exception as exc:  # noqa: BLE001
        return PlaybookResult(ok=False, status="failed", message=str(exc))


def purge_device_kafka(
    ssh: "SSHClient",
    *,
    user_id: str,
    topic: str | None = None,
    retention_bytes: int | None = None,
    install_root: str = DEFAULT_INSTALL_ROOT,
    data_dir: str | None = None,
    sudo_password: str | None = None,
) -> PlaybookResult:
    """Delete and recreate the sensor Kafka topic (messages cleared, slot kept)."""
    del sudo_password  # topic scripts run as login user against local broker
    try:
        user_id = validate_user_id(user_id)
        from provisioner.kafka_install import (
            create_or_update_topic,
            delete_topic,
            kafka_present,
        )

        if not kafka_present(ssh):
            return PlaybookResult(
                ok=False,
                status="failed",
                message="Kafka is not installed on this gateway",
                details={"kafka_missing": True},
            )

        paths = _paths(install_root, data_dir)
        topic_name = (topic or kafka_topic_name(user_id)).strip()
        retention = int(retention_bytes or DEFAULT_TOPIC_RETENTION_BYTES)

        # Prefer catalog retention when present.
        try:
            from .kafka_topics import TopicCatalog

            catalog = TopicCatalog.from_json(
                ssh.read_text(paths.kafka_topics_catalog)
            )
            rec = catalog.get_by_device(user_id)
            if rec is not None:
                topic_name = rec.topic
                retention = int(rec.retention_bytes)
        except FileNotFoundError:
            pass
        except Exception:  # noqa: BLE001
            pass

        delete_topic(ssh, topic=topic_name)
        create_or_update_topic(
            ssh, topic=topic_name, retention_bytes=retention
        )
        return PlaybookResult(
            ok=True,
            message=f"Kafka topic {topic_name} cleared",
            details={
                "user_id": user_id,
                "topic": topic_name,
                "retention_bytes": retention,
            },
        )
    except Exception as exc:  # noqa: BLE001
        return PlaybookResult(ok=False, status="failed", message=str(exc))
