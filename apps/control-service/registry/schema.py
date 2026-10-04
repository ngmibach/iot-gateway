"""SQLite DDL for registry.sqlite.

Column names follow DESIGN-packaged-app.md (data_json / ts / detail_json).
audit_log also keeps device_id + actor for action attribution.
"""

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS gateways (
  id TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  ssh_user TEXT NOT NULL,
  install_root TEXT NOT NULL,
  agent_url TEXT,
  fingerprint TEXT NOT NULL,
  monitoring_ip TEXT,
  password_auth_enabled INTEGER DEFAULT 0,
  created_at INTEGER,
  last_seen_at INTEGER,
  status TEXT
);

CREATE TABLE IF NOT EXISTS devices (
  gateway_id TEXT NOT NULL REFERENCES gateways(id),
  id TEXT NOT NULL,
  ip TEXT,
  topics_rw TEXT,
  topics_r TEXT,
  monitor_enabled INTEGER DEFAULT 1,
  cert_expires_at INTEGER,
  cert_fingerprint TEXT,
  created_at INTEGER,
  meta_json TEXT,
  PRIMARY KEY (gateway_id, id)
);

CREATE TABLE IF NOT EXISTS imported_allowlist_ips (
  gateway_id TEXT NOT NULL REFERENCES gateways(id),
  ip TEXT NOT NULL,
  linked_device_id TEXT,
  PRIMARY KEY (gateway_id, ip)
);

CREATE TABLE IF NOT EXISTS state_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  state_type TEXT NOT NULL,
  data_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  action TEXT NOT NULL,
  gateway_id TEXT,
  device_id TEXT,
  detail_json TEXT,
  actor TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_monitor
  ON devices (gateway_id, monitor_enabled);

CREATE INDEX IF NOT EXISTS idx_audit_ts
  ON audit_log (ts DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_type_ts
  ON state_snapshots (state_type, timestamp DESC);
"""
