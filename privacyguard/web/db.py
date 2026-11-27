"""
SQLite persistence (Phase 2). WAL mode for concurrent read/write between the
monitor pipeline and the dashboard. Three tables: devices, alerts, connections.

Timestamps are stored as epoch floats. Functions take `now` so behaviour is
deterministic and testable with an in-memory database.
"""

import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address  TEXT UNIQUE NOT NULL,
    ip_address   TEXT,
    manufacturer TEXT,
    first_seen   REAL,
    last_seen    REAL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    INTEGER REFERENCES devices(device_id),
    alert_type   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    description  TEXT,
    timestamp    REAL,
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connections (
    conn_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER REFERENCES devices(device_id),
    dst_ip     TEXT,
    dst_port   INTEGER,
    first_seen REAL,
    last_seen  REAL
);
"""


def connect(path):
    # check_same_thread=False lets the Flask dev server share one connection
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()


def upsert_device(conn, mac, ip=None, manufacturer=None, now=None):
    """Insert a device or update its last_seen (and optional fields). Returns id."""
    if now is None:
        now = time.time()
    cur = conn.execute("SELECT device_id FROM devices WHERE mac_address = ?", (mac,))
    row = cur.fetchone()
    if row is None:
        cur = conn.execute(
            "INSERT INTO devices (mac_address, ip_address, manufacturer, "
            "first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (mac, ip, manufacturer, now, now),
        )
        conn.commit()
        return cur.lastrowid
    device_id = row["device_id"]
    conn.execute(
        "UPDATE devices SET last_seen = ?, "
        "ip_address = COALESCE(?, ip_address), "
        "manufacturer = COALESCE(?, manufacturer) WHERE device_id = ?",
        (now, ip, manufacturer, device_id),
    )
    conn.commit()
    return device_id


def insert_event(conn, event, now=None):
    """Persist a detection event: upsert its device, then insert the alert row."""
    if now is None:
        now = time.time()
    device_id = upsert_device(conn, event["device_mac"], now=now)
    cur = conn.execute(
        "INSERT INTO alerts (device_id, alert_type, severity, description, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        (device_id, event["alert_type"], event["severity"],
         event.get("description"), now),
    )
    conn.commit()
    return cur.lastrowid


def list_devices(conn):
    rows = conn.execute(
        "SELECT * FROM devices ORDER BY last_seen DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def list_alerts(conn, limit=50):
    rows = conn.execute(
        "SELECT a.*, d.mac_address AS device_mac FROM alerts a "
        "JOIN devices d ON a.device_id = d.device_id "
        "ORDER BY a.timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def alerts_since(conn, since):
    """Alerts with timestamp >= since, for Safety Score computation."""
    rows = conn.execute(
        "SELECT severity, acknowledged FROM alerts WHERE timestamp >= ?",
        (since,),
    ).fetchall()
    return [dict(r) for r in rows]


def acknowledge(conn, alert_id):
    conn.execute("UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?", (alert_id,))
    conn.commit()
