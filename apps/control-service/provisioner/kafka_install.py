"""Install a minimal single-node Apache Kafka (KRaft) on the gateway.

Uses the official JVM Kafka distribution (not Redpanda) with a small heap so
the Pi stays lean. Topics are created from the agent catalog with
``retention.bytes`` as the hard size cap.
"""

from __future__ import annotations

import ipaddress
import json
import shlex
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .agent_install import (
    DEFAULT_AGENT_DATA,
    AgentInstallError,
    sudo_run,
)
from .ssh import SSHSession

DEFAULT_KAFKA_HOME = "/opt/kafka"
DEFAULT_KAFKA_VERSION = "3.7.1"
DEFAULT_SCALA_VERSION = "2.13"
# Agent clients use INTERNAL on loopback; Grafana uses EXTERNAL on LAN :9092.
KAFKA_BOOTSTRAP = "127.0.0.1:9092"
KAFKA_CONTROLLER = "127.0.0.1:9093"
# Official Apache archive size for kafka_2.13-3.7.1.tgz (Content-Length).
# Used when HEAD is unavailable so truncated uploads still fail closed.
_KNOWN_TARBALL_BYTES: dict[str, int] = {
    "3.7.1": 120_235_344,
}


def _kafka_tarball_url(version: str = DEFAULT_KAFKA_VERSION) -> str:
    return (
        f"https://archive.apache.org/dist/kafka/{version}/"
        f"kafka_{DEFAULT_SCALA_VERSION}-{version}.tgz"
    )


def _probe_tarball_size(url: str, *, version: str) -> int | None:
    """Return expected Content-Length, or a known pin, or None."""
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.headers.get("Content-Length")
            if raw and str(raw).isdigit() and int(raw) > 0:
                return int(raw)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        pass
    return _KNOWN_TARBALL_BYTES.get(version)


def _download_tarball_local(url: str, dest: Path, *, expected: int | None) -> None:
    """Download Kafka tarball on the provisioner host (resume-friendly).

    Phone-tether installs often make *remote* curl from the Pi crawl or drop.
    Fetching on the Windows/Linux monitoring host then SFTP-uploading over the
    LAN is much more reliable.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    existing = dest.stat().st_size if dest.is_file() else 0
    if expected and existing == expected:
        return
    if expected and existing > expected:
        dest.unlink(missing_ok=True)
        existing = 0

    headers: dict[str, str] = {}
    mode = "wb"
    if existing > 0:
        headers["Range"] = f"bytes={existing}-"
        mode = "ab"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, dest.open(mode) as out:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                out.write(chunk)
    except urllib.error.HTTPError as exc:
        # 416 = already complete; 200 on Range means server ignored resume.
        if exc.code == 416 and expected and dest.is_file() and dest.stat().st_size == expected:
            return
        if exc.code == 200 and existing > 0:
            # Server ignored Range — restart from scratch.
            dest.unlink(missing_ok=True)
            _download_tarball_local(url, dest, expected=expected)
            return
        raise AgentInstallError(
            f"Kafka host download HTTP {exc.code}: {exc.reason}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AgentInstallError(f"Kafka host download failed: {exc}") from exc

    size = dest.stat().st_size if dest.is_file() else 0
    if expected and size != expected:
        raise AgentInstallError(
            f"Kafka tarball size {size} != expected {expected} after host download"
        )
    if size < 1_000_000:
        raise AgentInstallError(f"Kafka tarball too small after host download: {size} bytes")


def _validate_advertise_host(advertise_host: str | None) -> str:
    """Require a literal IP for EXTERNAL bind/advertise (properties interpolation)."""
    raw = (advertise_host or "").strip() or "127.0.0.1"
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise AgentInstallError(
            f"advertise_host must be an IP address, got {raw!r}"
        ) from exc


def _server_properties(*, data_dir: str, advertise_host: str) -> str:
    """KRaft props with dual INTERNAL/EXTERNAL listeners.

    INTERNAL://127.0.0.1:9092 keeps agent metadata on loopback.
    EXTERNAL binds the LAN IP (not 0.0.0.0) so it can share port 9092 with
    INTERNAL; Grafana connects to {{advertise_host}}:9092.
    TODO: firewall EXTERNAL to monitoring_ip only (follow-up).
    """
    log_dirs = f"{data_dir}/kafka/data"
    adv = _validate_advertise_host(advertise_host)
    if adv in ("127.0.0.1", "::1"):
        # Loopback-only: single INTERNAL listener (EXTERNAL would collide).
        listeners = (
            f"INTERNAL://{KAFKA_BOOTSTRAP},CONTROLLER://{KAFKA_CONTROLLER}"
        )
        advertised = f"INTERNAL://{KAFKA_BOOTSTRAP}"
        proto_map = "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT"
    else:
        # Bind EXTERNAL to the LAN IP — 0.0.0.0:9092 conflicts with INTERNAL.
        listeners = (
            f"INTERNAL://{KAFKA_BOOTSTRAP},"
            f"EXTERNAL://{adv}:9092,"
            f"CONTROLLER://{KAFKA_CONTROLLER}"
        )
        advertised = (
            f"INTERNAL://{KAFKA_BOOTSTRAP},EXTERNAL://{adv}:9092"
        )
        proto_map = "CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT"
    return f"""# Generated by iot-gateway provisioner — KRaft single node (minimal).
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@{KAFKA_CONTROLLER}
listeners={listeners}
advertised.listeners={advertised}
listener.security.protocol.map={proto_map}
controller.listener.names=CONTROLLER
inter.broker.listener.name=INTERNAL
log.dirs={log_dirs}
num.network.threads=2
num.io.threads=2
socket.send.buffer.bytes=102400
socket.receive.buffer.bytes=102400
socket.request.max.bytes=104857600
num.partitions=1
num.recovery.threads.per.data.dir=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
log.retention.check.interval.ms=300000
auto.create.topics.enable=false
# Size-based retention is set per topic; keep a modest default segment size.
log.segment.bytes=67108864
"""


def _systemd_unit(*, kafka_home: str = DEFAULT_KAFKA_HOME) -> str:
    return f"""[Unit]
Description=Apache Kafka (KRaft single-node for IoT Gateway)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=KAFKA_HEAP_OPTS=-Xms128M -Xmx256M
Environment=LOG_DIR={kafka_home}/logs
ExecStart={kafka_home}/bin/kafka-server-start.sh {kafka_home}/config/kraft/iotgw.properties
ExecStop={kafka_home}/bin/kafka-server-stop.sh
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""


def kafka_present(ssh: SSHSession, *, kafka_home: str = DEFAULT_KAFKA_HOME) -> bool:
    check = ssh.run(
        f"test -x {shlex.quote(kafka_home + '/bin/kafka-topics.sh')} && echo OK",
        timeout=15.0,
    )
    return "OK" in (check.stdout or "")


def ensure_kafka_kraft(
    ssh: SSHSession,
    *,
    sudo_password: str,
    data_dir: str = DEFAULT_AGENT_DATA,
    kafka_home: str = DEFAULT_KAFKA_HOME,
    version: str = DEFAULT_KAFKA_VERSION,
    advertise_host: str | None = None,
) -> str:
    """Install OpenJDK + Kafka KRaft single-node and enable systemd unit."""
    notes: list[str] = []
    adv = _validate_advertise_host(advertise_host)

    # JRE via apt (Kafka is JVM). Prefer default-jre-headless (Debian 13+ may
    # not ship openjdk-17-jre-headless under that exact name).
    jre = sudo_run(
        ssh,
        "if java -version >/dev/null 2>&1; then echo JAVA_OK; else "
        "env DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
        "env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "default-jre-headless || "
        "env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "openjdk-21-jre-headless || "
        "env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
        "openjdk-17-jre-headless; fi",
        sudo_password=sudo_password,
        timeout=600.0,
    )
    probe = ssh.run("java -version 2>&1 | head -1", timeout=15.0)
    if probe.exit_code != 0 and "JAVA_OK" not in (jre.stdout or ""):
        raise AgentInstallError(
            "OpenJDK install failed for Kafka: "
            f"{(jre.stderr or jre.stdout or probe.stderr or probe.stdout or '')[:400]}"
        )
    notes.append("openjdk available for Kafka")

    if not kafka_present(ssh, kafka_home=kafka_home):
        url = _kafka_tarball_url(version)
        dest = f"/tmp/kafka-{version}.tgz"
        parent = kafka_home.rsplit("/", 1)[0] or "/opt"
        expected = _probe_tarball_size(url, version=version)
        staged = False
        stage_errors: list[str] = []

        # Preferred path: download on the monitoring host, SFTP to the Pi.
        # Remote curl over phone tether often stalls or truncates.
        local_tgz: Path | None = None
        try:
            tmp_dir = Path(tempfile.gettempdir()) / "iotgw-kafka"
            local_tgz = tmp_dir / f"kafka_{DEFAULT_SCALA_VERSION}-{version}.tgz"
            _download_tarball_local(url, local_tgz, expected=expected)
            # Drop any partial remote file so SFTP put is authoritative.
            ssh.run(f"rm -f {shlex.quote(dest)}", timeout=15.0)
            ssh.upload_file(local_tgz, dest, mode=0o644)
            staged = True
            notes.append("Kafka tarball fetched on host and uploaded via SFTP")
        except (AgentInstallError, OSError) as exc:
            stage_errors.append(f"host/SFTP: {exc}")
            # Fall back to remote curl with resume + size check.
            size_check = ""
            if expected:
                size_check = (
                    f"SIZE=$(stat -c%s {shlex.quote(dest)} 2>/dev/null || echo 0); "
                    f"if [ \"$SIZE\" != {expected} ]; then "
                    f"echo \"Kafka tarball size $SIZE != expected {expected}\" >&2; "
                    f"exit 3; fi && "
                )
            download = sudo_run(
                ssh,
                f"mkdir -p {shlex.quote(parent)} "
                f"{shlex.quote(data_dir + '/kafka/data')} "
                f"{shlex.quote(kafka_home + '/logs')} && "
                f"curl -fL --retry 8 --retry-delay 3 --retry-all-errors -C - "
                f"-o {shlex.quote(dest)} {shlex.quote(url)} && "
                f"{size_check}"
                f"echo DOWNLOAD_OK",
                sudo_password=sudo_password,
                timeout=1200.0,
            )
            if download.ok and "DOWNLOAD_OK" in (download.stdout or ""):
                staged = True
                notes.append("Kafka tarball fetched via remote curl (host path failed)")
            else:
                stage_errors.append(
                    "remote curl: "
                    + ((download.stderr or download.stdout or "")[:300] or "no output")
                )

        if not staged:
            raise AgentInstallError(
                "Kafka download failed: " + " | ".join(stage_errors)[:500]
            )

        extract = sudo_run(
            ssh,
            f"mkdir -p {shlex.quote(parent)} "
            f"{shlex.quote(data_dir + '/kafka/data')} "
            f"{shlex.quote(kafka_home + '/logs')} && "
            f"rm -rf {shlex.quote(kafka_home)} && "
            f"mkdir -p {shlex.quote(kafka_home)} && "
            f"tar -xzf {shlex.quote(dest)} -C {shlex.quote(kafka_home)} "
            f"--strip-components=1 && "
            f"rm -f {shlex.quote(dest)} && "
            f"test -x {shlex.quote(kafka_home + '/bin/kafka-topics.sh')} && "
            f"echo EXTRACT_OK",
            sudo_password=sudo_password,
            timeout=180.0,
        )
        if not extract.ok or not kafka_present(ssh, kafka_home=kafka_home):
            raise AgentInstallError(
                "Kafka extract failed: "
                f"{(extract.stderr or extract.stdout or '')[:500]}"
            )
        notes.append(f"installed Apache Kafka {version} (KRaft) at {kafka_home}")
    else:
        notes.append(f"Kafka already present at {kafka_home}")

    # Write KRaft config + format storage once.
    props = _server_properties(data_dir=data_dir, advertise_host=adv)
    remote_props = "/tmp/iotgw-kafka-iotgw.properties"
    with tempfile.NamedTemporaryFile(
        "w", suffix=".properties", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(props)
        local_props = Path(tmp.name)
    try:
        ssh.upload_file(local_props, remote_props, mode=0o644)
    finally:
        local_props.unlink(missing_ok=True)

    kraft_dir = f"{kafka_home}/config/kraft"
    meta = f"{data_dir}/kafka/kraft-formatted"
    format_cmd = (
        f"mkdir -p {shlex.quote(kraft_dir)} {shlex.quote(data_dir + '/kafka/data')} && "
        f"mv {shlex.quote(remote_props)} {shlex.quote(kraft_dir + '/iotgw.properties')} && "
        f"if [ ! -f {shlex.quote(meta)} ]; then "
        f"CLUSTER_ID=$({shlex.quote(kafka_home + '/bin/kafka-storage.sh')} random-uuid) && "
        f"{shlex.quote(kafka_home + '/bin/kafka-storage.sh')} format "
        f"-t \"$CLUSTER_ID\" -c {shlex.quote(kraft_dir + '/iotgw.properties')} && "
        f"echo \"$CLUSTER_ID\" > {shlex.quote(meta)}; fi"
    )
    formatted = sudo_run(ssh, format_cmd, sudo_password=sudo_password, timeout=120.0)
    if not formatted.ok:
        raise AgentInstallError(
            "Kafka KRaft storage format failed: "
            f"{(formatted.stderr or formatted.stdout or '')[:500]}"
        )

    unit_body = _systemd_unit(kafka_home=kafka_home)
    remote_unit = "/tmp/iotgw-kafka.service"
    with tempfile.NamedTemporaryFile(
        "w", suffix=".service", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(unit_body)
        local_unit = Path(tmp.name)
    try:
        ssh.upload_file(local_unit, remote_unit, mode=0o644)
    finally:
        local_unit.unlink(missing_ok=True)
    enable = sudo_run(
        ssh,
        f"mv {shlex.quote(remote_unit)} /etc/systemd/system/iotgw-kafka.service && "
        "systemctl daemon-reload && "
        "systemctl enable iotgw-kafka && "
        "systemctl restart iotgw-kafka",
        sudo_password=sudo_password,
        timeout=120.0,
    )
    if not enable.ok:
        raise AgentInstallError(
            "failed to enable iotgw-kafka: "
            f"{(enable.stderr or enable.stdout or '')[:400]}"
        )

    # Wait briefly for bootstrap port.
    ready = ssh.run(
        "for i in 1 2 3 4 5 6 7 8 9 10 11 12; do "
        "ss -lnt 2>/dev/null | grep -q ':9092' && echo READY && break; "
        "sleep 2; done",
        timeout=60.0,
    )
    if "READY" not in (ready.stdout or ""):
        notes.append("Kafka unit started but :9092 not yet listening (may still be booting)")
    elif adv in ("127.0.0.1", "::1"):
        notes.append(f"Kafka KRaft INTERNAL listening on {KAFKA_BOOTSTRAP}")
    else:
        notes.append(
            f"Kafka KRaft INTERNAL {KAFKA_BOOTSTRAP} + EXTERNAL {adv}:9092 "
            "(firewall to monitoring_ip TODO)"
        )

    # Sync any catalog topics already reserved.
    sync_notes = sync_catalog_topics(
        ssh, sudo_password=sudo_password, data_dir=data_dir, kafka_home=kafka_home
    )
    notes.extend(sync_notes)
    return "; ".join(notes)


def create_or_update_topic(
    ssh: SSHSession,
    *,
    topic: str,
    retention_bytes: int,
    kafka_home: str = DEFAULT_KAFKA_HOME,
    bootstrap: str = KAFKA_BOOTSTRAP,
) -> str:
    """Create topic if missing; always set retention.bytes."""
    topics_sh = f"{kafka_home}/bin/kafka-topics.sh"
    # Create (ignore exists), then alter config.
    create = ssh.run(
        f"{shlex.quote(topics_sh)} --bootstrap-server {shlex.quote(bootstrap)} "
        f"--create --if-not-exists --topic {shlex.quote(topic)} "
        f"--partitions 1 --replication-factor 1 "
        f"--config retention.bytes={int(retention_bytes)} "
        f"--config retention.ms=-1 "
        f"--config cleanup.policy=delete",
        timeout=60.0,
    )
    alter = ssh.run(
        f"{shlex.quote(topics_sh)} --bootstrap-server {shlex.quote(bootstrap)} "
        f"--alter --topic {shlex.quote(topic)} "
        f"--config retention.bytes={int(retention_bytes)} "
        f"--config retention.ms=-1",
        timeout=60.0,
    )
    if create.exit_code not in (0, None) and "already exists" not in (
        (create.stderr or "") + (create.stdout or "")
    ).lower():
        # kafka-topics returns 0 with --if-not-exists on modern versions
        if not create.ok and "TopicExistsException" not in (create.stderr or ""):
            raise AgentInstallError(
                f"kafka topic create failed for {topic}: "
                f"{(create.stderr or create.stdout or '')[:300]}"
            )
    if not alter.ok and "Cannot alter" not in (alter.stderr or ""):
        # Some versions need --add-config; try configs command.
        cfg = ssh.run(
            f"{shlex.quote(kafka_home + '/bin/kafka-configs.sh')} "
            f"--bootstrap-server {shlex.quote(bootstrap)} "
            f"--entity-type topics --entity-name {shlex.quote(topic)} "
            f"--alter --add-config retention.bytes={int(retention_bytes)},"
            f"retention.ms=-1",
            timeout=60.0,
        )
        if not cfg.ok:
            raise AgentInstallError(
                f"kafka topic retention update failed for {topic}: "
                f"{(cfg.stderr or cfg.stdout or alter.stderr or '')[:300]}"
            )
    return topic


def delete_topic(
    ssh: SSHSession,
    *,
    topic: str,
    kafka_home: str = DEFAULT_KAFKA_HOME,
    bootstrap: str = KAFKA_BOOTSTRAP,
) -> None:
    topics_sh = f"{kafka_home}/bin/kafka-topics.sh"
    ssh.run(
        f"{shlex.quote(topics_sh)} --bootstrap-server {shlex.quote(bootstrap)} "
        f"--delete --topic {shlex.quote(topic)} 2>/dev/null || true",
        timeout=60.0,
    )


def sync_catalog_topics(
    ssh: SSHSession,
    *,
    sudo_password: str | None = None,
    data_dir: str = DEFAULT_AGENT_DATA,
    kafka_home: str = DEFAULT_KAFKA_HOME,
) -> list[str]:
    """Create/update broker topics from topics.json (best-effort)."""
    del sudo_password  # unused; topic scripts run as login user with local broker
    data = read_remote_catalog(ssh, data_dir=data_dir)
    if not kafka_present(ssh, kafka_home=kafka_home):
        return ["kafka binary missing — skip topic sync"]
    topics = data.get("topics") or {}
    if not isinstance(topics, dict) or not topics:
        return ["kafka catalog has no topics yet"]
    created: list[str] = []
    for _key, rec in topics.items():
        if not isinstance(rec, dict):
            continue
        topic = str(rec.get("topic") or "").strip()
        if not topic:
            continue
        retention = int(rec.get("retention_bytes") or 1 * 1024**3)
        try:
            create_or_update_topic(
                ssh, topic=topic, retention_bytes=retention, kafka_home=kafka_home
            )
            created.append(topic)
        except AgentInstallError as exc:
            return [f"topic sync stopped: {exc}"]
    return [f"synced {len(created)} kafka topic(s) from catalog"]


def read_remote_catalog(
    ssh: SSHSession,
    *,
    data_dir: str = DEFAULT_AGENT_DATA,
) -> dict[str, Any]:
    """Return parsed topics.json or empty catalog dict."""
    path = f"{data_dir}/kafka/topics.json"
    empty = {
        "version": 1,
        "retention_bytes_default": 1 * 1024**3,
        "safety_ratio": 0.7,
        "topics": {},
    }
    result = ssh.run(f"cat {shlex.quote(path)} 2>/dev/null || true", timeout=15.0)
    raw = (result.stdout or "").strip()
    if not raw:
        return empty
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return empty
    return data if isinstance(data, dict) else empty
