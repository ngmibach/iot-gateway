"""CLI entry for the monolithic IoT gateway agent (no Docker)."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from . import AGENT_PORT, MQTT_TLS_PORT, __version__
from .broker import MosquittoSupervisor, write_mosquitto_conf
from .day_crypto import ensure_day_material, load_day_cert_pem
from .decrypt_worker import DecryptWorker
from .denied_watcher import DeniedWatcher
from .deny_log import DenyLog
from .envelope_v1 import today_day_id
from .health import build_health, build_info
from .kafka_producer import SensorKafkaProducer
from .mdns import start_mdns, stop_mdns
from .metrics import AgentMetrics
from .server import create_server
from .shipper import LokiShipper

logger = logging.getLogger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="iot-gateway-agent",
        description=(
            "Monolithic IoT gateway agent: MQTT (mosquitto child), decrypt→log, "
            "Loki shipper, /metrics, mDNS — no Docker."
        ),
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("AGENT_HOST", "0.0.0.0"),
        help="HTTP listen address",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("AGENT_PORT", AGENT_PORT)),
        help=f"HTTP listen port (default {AGENT_PORT})",
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("IOTGW_AGENT_DATA", "/var/lib/iot-gateway-agent"),
        help="Config, mosquitto data, sensor_data.log",
    )
    parser.add_argument(
        "--monitoring-ip",
        default=os.environ.get("MONITORING_IP", "127.0.0.1"),
        help="Operator PC IP for Loki push",
    )
    parser.add_argument(
        "--loki-url",
        default=os.environ.get("LOKI_URL", ""),
        help="Override Loki base URL (default http://MONITORING_IP:3100)",
    )
    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=int(os.environ.get("MQTT_PORT", str(MQTT_TLS_PORT))),
        help=f"MQTT(S) broker port (default {MQTT_TLS_PORT})",
    )
    parser.add_argument(
        "--mqtt-ca",
        default=os.environ.get("IOTGW_MQTT_CA"),
        help="CA cert for MQTTS client (default: {data_dir}/certs/ca.crt)",
    )
    parser.add_argument(
        "--mqtt-cert",
        default=os.environ.get("IOTGW_MQTT_CERT"),
        help="Client cert for MQTTS (default: {data_dir}/certs/decrypt.crt)",
    )
    parser.add_argument(
        "--mqtt-key",
        default=os.environ.get("IOTGW_MQTT_KEY"),
        help="Client key for MQTTS (default: {data_dir}/certs/decrypt.key)",
    )
    parser.add_argument(
        "--decrypt-user",
        default=os.environ.get("IOTGW_DECRYPT_USER", "nodered"),
    )
    parser.add_argument(
        "--decrypt-password",
        default=os.environ.get("IOTGW_DECRYPT_PASSWORD", ""),
    )
    parser.add_argument(
        "--no-broker",
        action="store_true",
        help="Do not spawn mosquitto (use an existing broker on localhost)",
    )
    parser.add_argument(
        "--no-decrypt",
        action="store_true",
        help="Disable decrypt worker",
    )
    parser.add_argument(
        "--no-shipper",
        action="store_true",
        help="Disable Loki shipper",
    )
    parser.add_argument(
        "--kafka-bootstrap",
        default=os.environ.get("KAFKA_BOOTSTRAP", "127.0.0.1:9092"),
        help="Local Kafka bootstrap (KRaft single-node)",
    )
    parser.add_argument(
        "--no-kafka",
        action="store_true",
        help="Disable Kafka produce of decrypted sensor payloads",
    )
    parser.add_argument("--no-mdns", action="store_true")
    parser.add_argument(
        "--gateway-id",
        default=os.environ.get("IOTGW_GATEWAY_ID", ""),
        help="Gateway id stamped on denied-message events",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    data = Path(args.data_dir)
    data.mkdir(parents=True, exist_ok=True)
    certs_dir = data / "certs"
    mqtt_ca = Path(args.mqtt_ca) if args.mqtt_ca else certs_dir / "ca.crt"
    mqtt_cert = Path(args.mqtt_cert) if args.mqtt_cert else certs_dir / "decrypt.crt"
    mqtt_key = Path(args.mqtt_key) if args.mqtt_key else certs_dir / "decrypt.key"

    conf_dir = data / "mosquitto"
    passwords = conf_dir / "passwords"
    acl = conf_dir / "acl"
    if not passwords.is_file():
        passwords.parent.mkdir(parents=True, exist_ok=True)
        passwords.write_text("", encoding="utf-8")
    if not acl.is_file():
        acl.write_text(
            "# agent-managed ACL\nuser nodered\ntopic readwrite sensors/#\n",
            encoding="utf-8",
        )

    server_ca = certs_dir / "ca.crt"
    server_cert = certs_dir / "server.crt"
    server_key = certs_dir / "server.key"
    broker_tls: dict = {}
    if server_ca.is_file() and server_cert.is_file() and server_key.is_file():
        broker_tls = {
            "cafile": server_ca,
            "certfile": server_cert,
            "keyfile": server_key,
        }
    elif args.mqtt_port == MQTT_TLS_PORT:
        logger.warning(
            "MQTT broker TLS certs missing under %s (need ca.crt, server.crt, "
            "server.key) — writing plain listener on %s",
            certs_dir,
            args.mqtt_port,
        )

    conf = write_mosquitto_conf(
        conf_dir / "mosquitto.conf",
        data_dir=conf_dir / "data",
        log_dir=conf_dir / "log",
        passwords=passwords,
        acl=acl,
        listen_port=args.mqtt_port,
        **broker_tls,
    )

    broker = MosquittoSupervisor(conf)
    worker: DecryptWorker | None = None
    shipper: LokiShipper | None = None
    kafka: SensorKafkaProducer | None = None
    denied: DeniedWatcher | None = None
    gateway_id = (args.gateway_id or "").strip() or os.environ.get(
        "IOTGW_GATEWAY_ID", ""
    ).strip()
    deny_log = DenyLog(
        path=data / "logs" / "denied_messages.jsonl",
        gateway_id=gateway_id,
    )
    deny_log.set_ip_map_path(data / "fake" / "ip-map.json")
    if not args.no_kafka:
        kafka = SensorKafkaProducer(bootstrap=args.kafka_bootstrap)
    metrics = AgentMetrics(
        broker=broker,
        mqtt_port=args.mqtt_port,
        mqtt_host="127.0.0.1",
        kafka_bootstrap=args.kafka_bootstrap,
        kafka=kafka,
    )

    if args.no_broker:
        # Prefer the distro mosquitto systemd unit (provisioner enables it).
        metrics.refresh_mqtt_up()
        if metrics.mqtt_up:
            logger.info(
                "using existing MQTT broker on %s:%s (--no-broker)",
                metrics.mqtt_host,
                metrics.mqtt_port,
            )
        else:
            logger.warning(
                "no MQTT broker on %s:%s — start system mosquitto or drop --no-broker",
                metrics.mqtt_host,
                metrics.mqtt_port,
            )
    else:
        try:
            broker.start()
            metrics.mqtt_up = broker.running()
        except Exception as e:  # noqa: BLE001
            logger.error("mosquitto start failed: %s", e)
            # Fall back to a system broker already bound to the port.
            metrics.refresh_mqtt_up()
            if metrics.mqtt_up:
                logger.info(
                    "agent child mosquitto failed; using broker already on %s:%s",
                    metrics.mqtt_host,
                    metrics.mqtt_port,
                )

    sensor_log = data / "logs" / "sensor_data.log"
    if not args.no_decrypt:
        # Prefer TLS on :8883; warn if client certs are missing but still attempt TLS.
        tls_kwargs: dict = {}
        certs_present = mqtt_ca.is_file() and mqtt_cert.is_file() and mqtt_key.is_file()
        if args.mqtt_port == MQTT_TLS_PORT or certs_present:
            for label, path in (
                ("CA", mqtt_ca),
                ("client cert", mqtt_cert),
                ("client key", mqtt_key),
            ):
                if not path.is_file():
                    logger.warning(
                        "MQTT TLS %s missing at %s — decrypt worker connect may fail",
                        label,
                        path,
                    )
            tls_kwargs = {
                "tls_ca": mqtt_ca,
                "tls_cert": mqtt_cert,
                "tls_key": mqtt_key,
            }
        try:
            ensure_day_material(
                data,
                ca_cert_path=certs_dir / "ca.crt",
                ca_key_path=certs_dir / "ca.key",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ensure_day_material: %s", exc)
        worker = DecryptWorker(
            host="127.0.0.1",
            port=args.mqtt_port,
            username=args.decrypt_user,
            password=args.decrypt_password,
            log_path=sensor_log,
            kafka=kafka,
            data_dir=data,
            deny_log=deny_log,
            gateway_id=gateway_id,
            **tls_kwargs,
        )
        worker.start()
        metrics.decrypt_worker = worker
        denied = DeniedWatcher(
            worker=worker,
            log_paths=[
                data / "mosquitto" / "log" / "mosquitto.log",
                Path("/var/log/mosquitto/mosquitto.log"),
                Path("/var/log/mosquitto.log"),
            ],
            ids_log_paths=[data / "logs" / "ids_alerts.log"],
            deny_log=deny_log,
        )
        denied.start()
        metrics.denied_watcher = denied

    loki = args.loki_url.strip() or f"http://{args.monitoring_ip}:3100"
    if not args.no_shipper:
        shipper = LokiShipper(sensor_log, loki_url=loki)
        shipper.start()
        metrics.shipper = shipper

    mdns_handle = None
    mdns_enabled = False
    if not args.no_mdns:
        mdns_handle, mdns_enabled = start_mdns(args.port)
    else:
        logger.info("mDNS disabled via --no-mdns")

    def health_fn():
        metrics.refresh_mqtt_up()
        h = build_health(mdns_enabled=mdns_enabled, port=args.port)
        h["mqtt_up"] = metrics.mqtt_up
        h["mode"] = "monolithic"
        h["mqtt_mode"] = "external" if args.no_broker else "child"
        return h

    def info_fn():
        info = build_info(port=args.port)
        info["api"] = [
            "GET /v1/health",
            "GET /v1/info",
            "GET /v1/denied",
            "GET /v1/crypto/day/current",
            "GET /metrics",
            "POST /v1/reload",
        ]
        info["read_only"] = False
        info["mode"] = "monolithic"
        info["data_dir"] = str(data)
        info["mqtt_mode"] = "external" if args.no_broker else "child"
        info["envelope_v1"] = True
        info["gateway_id"] = gateway_id or None
        return info

    def day_crypto_fn():
        did = today_day_id()
        try:
            ensure_day_material(
                data,
                ca_cert_path=certs_dir / "ca.crt",
                ca_key_path=certs_dir / "ca.key",
                day_id=did,
            )
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "day_id": did, "error": str(exc)}
        pem = load_day_cert_pem(data, did)
        return {
            "ok": True,
            "day_id": did,
            "cert_pem": pem.decode("utf-8") if pem else None,
        }

    def denied_fn(params: dict) -> dict:
        try:
            limit = int(params.get("limit") or 100)
        except (TypeError, ValueError):
            limit = 100
        device_id = (params.get("device_id") or "").strip() or None
        events = deny_log.recent(limit=limit, device_id=device_id)
        return {
            "ok": True,
            "gateway_id": gateway_id or None,
            "count": len(events),
            "events": events,
        }

    def reload_fn():
        # Child mode: restart supervised mosquitto. External mode: re-probe port.
        if not args.no_broker:
            broker.stop()
            broker.start()
        try:
            ensure_day_material(
                data,
                ca_cert_path=certs_dir / "ca.crt",
                ca_key_path=certs_dir / "ca.key",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("reload day material: %s", exc)
        metrics.refresh_mqtt_up()
        return {"ok": True, "mqtt_up": metrics.mqtt_up, "day_id": today_day_id()}

    server = create_server(
        args.host,
        args.port,
        health_fn,
        info_fn,
        metrics_fn=metrics.render,
        reload_fn=reload_fn,
        day_crypto_fn=day_crypto_fn,
        denied_fn=denied_fn,
    )

    def _request_shutdown(signum: int, _frame: object) -> None:
        logger.info("signal %s; shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _request_shutdown)

    logger.info(
        "iot-gateway-agent %s monolithic on %s:%s data=%s loki=%s mdns=%s",
        __version__,
        args.host,
        args.port,
        data,
        loki,
        mdns_enabled,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt; shutting down")
    finally:
        server.server_close()
        if denied:
            denied.stop()
        if worker:
            worker.stop()
        if kafka:
            kafka.close()
        if shipper:
            shipper.stop()
        broker.stop()
        stop_mdns(mdns_handle)
        logger.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
