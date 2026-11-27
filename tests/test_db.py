"""SQLite persistence tests (Phase 2). Uses an in-memory database, no hardware."""

import pytest
from privacyguard.web import db


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    db.init_db(c)
    yield c
    c.close()


def test_upsert_device_inserts_once_and_updates_in_place(conn):
    id1 = db.upsert_device(conn, "aa:bb:cc:00:00:01", ip="192.168.1.5",
                           manufacturer="Samsung", now=100.0)
    id2 = db.upsert_device(conn, "aa:bb:cc:00:00:01", ip="192.168.1.5",
                           manufacturer="Samsung", now=200.0)
    assert id1 == id2
    devices = db.list_devices(conn)
    assert len(devices) == 1
    assert devices[0]["mac_address"] == "aa:bb:cc:00:00:01"
    assert devices[0]["last_seen"] == 200.0


def test_insert_event_creates_device_and_alert(conn):
    event = {
        "alert_type": "ARP_SPOOF",
        "severity": "HIGH",
        "device_mac": "de:ad:be:ef:00:99",
        "description": "conflicting ARP reply",
    }
    db.insert_event(conn, event, now=500.0)
    alerts = db.list_alerts(conn)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "ARP_SPOOF"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["device_mac"] == "de:ad:be:ef:00:99"
    # the device was auto-created
    assert len(db.list_devices(conn)) == 1


def test_alerts_since_filters_by_timestamp(conn):
    old = {"alert_type": "IOT_ANOMALY", "severity": "LOW",
           "device_mac": "aa:aa:aa:aa:aa:aa", "description": "old"}
    new = {"alert_type": "DEAUTH_FLOOD", "severity": "MEDIUM",
           "device_mac": "bb:bb:bb:bb:bb:bb", "description": "new"}
    db.insert_event(conn, old, now=10.0)
    db.insert_event(conn, new, now=1000.0)
    recent = db.alerts_since(conn, since=500.0)
    assert len(recent) == 1
    assert recent[0]["severity"] == "MEDIUM"


def test_acknowledge_marks_alert(conn):
    event = {"alert_type": "ARP_SPOOF", "severity": "HIGH",
             "device_mac": "de:ad:be:ef:00:99", "description": "x"}
    alert_id = db.insert_event(conn, event, now=1.0)
    db.acknowledge(conn, alert_id)
    alerts = db.list_alerts(conn)
    assert alerts[0]["acknowledged"] == 1
