"""Flask API tests (Phase 2/3). Uses the Flask test client + in-memory DB, no hardware."""

import pytest
from privacyguard.web import db
from privacyguard.web.app import create_app

TOKEN = "test-secret"


@pytest.fixture
def client():
    conn = db.connect(":memory:")
    db.init_db(conn)
    app = create_app(conn=conn, token=TOKEN)
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c
    conn.close()


def _event(severity="HIGH"):
    return {"alert_type": "ARP_SPOOF", "severity": severity,
            "device_mac": "de:ad:be:ef:00:99", "description": "conflicting ARP"}


def test_post_event_without_token_is_unauthorized(client):
    r = client.post("/api/event", json=_event())
    assert r.status_code == 401


def test_post_event_with_wrong_token_is_unauthorized(client):
    r = client.post("/api/event", json=_event(),
                    headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_post_event_with_valid_token_is_stored(client):
    r = client.post("/api/event", json=_event(),
                    headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 201
    alerts = client.get("/api/alerts").get_json()
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "ARP_SPOOF"
    devices = client.get("/api/devices").get_json()
    assert len(devices) == 1


def test_score_reflects_recent_alert(client):
    assert client.get("/api/score").get_json()["score"] == 100
    client.post("/api/event", json=_event("HIGH"),
                headers={"Authorization": f"Bearer {TOKEN}"})
    assert client.get("/api/score").get_json()["score"] == 80


def test_acknowledge_endpoint_marks_alert(client):
    client.post("/api/event", json=_event("CRITICAL"),
                headers={"Authorization": f"Bearer {TOKEN}"})
    alert_id = client.get("/api/alerts").get_json()[0]["alert_id"]
    # critical alert pulls the score down
    assert client.get("/api/score").get_json()["score"] == 60
    r = client.post(f"/api/alerts/{alert_id}/ack")
    assert r.status_code == 200
    # acknowledged alert no longer counts against the score
    assert client.get("/api/score").get_json()["score"] == 100


def test_dashboard_page_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"PrivacyGuard" in r.data
