"""
SQLite persistence (Phase 2). WAL mode for concurrent read/write between the
monitor pipeline and the dashboard. Three tables: devices, alerts, connections.

TODO (Phase 2): init_db(path), insert_alert(), upsert_device(), recent_alerts(), etc.
"""

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS devices (
    device_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address  TEXT UNIQUE NOT NULL,
    ip_address   TEXT,
    manufacturer TEXT,
    first_seen   TIMESTAMP,
    last_seen    TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER REFERENCES devices(device_id),
    alert_type   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    description  TEXT,
    timestamp    TIMESTAMP,
    acknowledged BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connections (
    conn_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER REFERENCES devices(device_id),
    dst_ip     TEXT,
    dst_port   INTEGER,
    first_seen TIMESTAMP,
    last_seen  TIMESTAMP
);
"""
