# ═══════════════════════════════════════════════════════════════════
# Persistent state snapshots for "current state" gateway panels
# (Allowed IPs, Connected Sensors, ACLs, etc.)
#
# These come from Prometheus textfile collectors (current state only).
# When users select historical date ranges in the sidebar, we replay
# the state from the closest snapshot instead of showing "now".
#
# Snapshots are taken automatically when the dashboard renders live data.
# DB is a simple SQLite file (persist via Docker volume if needed).
# ═══════════════════════════════════════════════════════════════════

import sqlite3
import json
import os
import time as _time  # local name to avoid clobbering

# Default path logic:
# - In Docker (via compose) we override with env + volume mount ./data/streamlit:/data
# - Locally, this tries to put it under the project monitoring/data/ relative to common cwds.
_default_db = "/data/state/streamlit_state.db"
if not os.path.exists("/.dockerenv"):
    # Not in Docker, prefer project data dir
    _default_db = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "data", "streamlit", "state", "streamlit_state.db")
    )

STATE_DB_PATH = os.getenv("STREAMLIT_STATE_DB_PATH", _default_db)
os.makedirs(os.path.dirname(STATE_DB_PATH) or ".", exist_ok=True)


def _get_state_db_conn():
    conn = sqlite3.connect(STATE_DB_PATH, timeout=10)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS state_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            state_type TEXT NOT NULL,
            data_json TEXT NOT NULL
        );
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_state_type_ts 
        ON state_snapshots (state_type, timestamp DESC);
    """)
    return conn


def save_state_snapshot(state_type: str, data):
    """Persist a snapshot of gateway state at the current wall time.

    data must be JSON-serializable (list[dict], dict, etc).
    Safe to call frequently; failures are swallowed.
    """
    if data is None:
        return
    try:
        conn = _get_state_db_conn()
        ts = int(_time.time())
        payload = json.dumps(data, default=str, ensure_ascii=False)
        conn.execute(
            "INSERT INTO state_snapshots (timestamp, state_type, data_json) VALUES (?, ?, ?)",
            (ts, state_type, payload)
        )
        conn.commit()
    except Exception:
        # Never break the dashboard UI because of snapshotting
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_state_snapshot(state_type: str, at_timestamp: int | None = None):
    """Return the most recent snapshot for this state_type at or before at_timestamp.

    If at_timestamp is None → latest snapshot ever.
    Returns the deserialized Python object (usually list of dicts) or None.
    """
    try:
        conn = _get_state_db_conn()
        if at_timestamp is None:
            sql = """
                SELECT data_json FROM state_snapshots 
                WHERE state_type = ? 
                ORDER BY timestamp DESC LIMIT 1
            """
            params = (state_type,)
        else:
            sql = """
                SELECT data_json FROM state_snapshots 
                WHERE state_type = ? AND timestamp <= ? 
                ORDER BY timestamp DESC LIMIT 1
            """
            params = (state_type, at_timestamp)

        row = conn.execute(sql, params).fetchone()
        if row:
            return json.loads(row[0])
        return None
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def init_state_db():
    """Ensure tables/indexes exist. Call early at import time."""
    try:
        _get_state_db_conn().close()
    except Exception:
        pass


# Auto-initialize when the module is imported
init_state_db()
