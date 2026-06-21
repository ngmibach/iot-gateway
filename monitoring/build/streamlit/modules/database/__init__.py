"""
Database helpers for the Streamlit dashboard.

Currently used for persisting "current state" snapshots of gateway panels
(Allowed IPs, Connected Sensors, ACL, etc.) so they can be replayed when
viewing historical time ranges.
"""

from .state import (
    save_state_snapshot,
    get_state_snapshot,
    init_state_db,
    STATE_DB_PATH,
)

__all__ = [
    "save_state_snapshot",
    "get_state_snapshot",
    "init_state_db",
    "STATE_DB_PATH",
]
