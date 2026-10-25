"""OS-aware Loki/Prometheus lifecycle, NIC selection, and Windows firewall checklist (K18)."""

from .checklist import (
    ChecklistItem,
    format_checklist_for_display,
    generate_windows_native_checklist,
)
from .lifecycle import BackendStatus
from .native import NativeTelemetryManager, NativeTelemetryStatus, default_native_root
from .nic import (
    NicCandidate,
    filter_nic_candidates,
    list_ipv4_candidates,
    pick_default_monitoring_ip,
)
from .readiness import (
    check_loki,
    check_prometheus,
    gateway_loki_ready_curl,
    wait_ready,
)
from .scrape import render_prometheus_scrape

__all__ = [
    "BackendStatus",
    "ChecklistItem",
    "NicCandidate",
    "NativeTelemetryManager",
    "NativeTelemetryStatus",
    "default_native_root",
    "check_loki",
    "check_prometheus",
    "filter_nic_candidates",
    "format_checklist_for_display",
    "gateway_loki_ready_curl",
    "generate_windows_native_checklist",
    "list_ipv4_candidates",
    "pick_default_monitoring_ip",
    "render_prometheus_scrape",
    "wait_ready",
]
