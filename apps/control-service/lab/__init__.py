"""Optional Lab helpers — short-lived fake_sensor demos (not production)."""

from .host_template import (
    HOST_LINE_RE,
    apply_host_to_script,
    stage_fake_sensor_tree,
    template_host_in_tree,
)
from .lifecycle import (
    DEFAULT_DURATION_MINUTES,
    DEFAULT_SENSORS,
    MAX_DURATION_MINUTES,
    STORAGE_OVERFLOW_WARNING,
    FakeSensorStatus,
    LabFakeSensorManager,
)

__all__ = [
    "DEFAULT_DURATION_MINUTES",
    "DEFAULT_SENSORS",
    "HOST_LINE_RE",
    "MAX_DURATION_MINUTES",
    "STORAGE_OVERFLOW_WARNING",
    "FakeSensorStatus",
    "LabFakeSensorManager",
    "apply_host_to_script",
    "stage_fake_sensor_tree",
    "template_host_in_tree",
]
