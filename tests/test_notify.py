"""ntfy push notification tests (Phase 4). HTTP sender is injected, no network."""

from privacyguard.web.notify import should_notify, build_notification, send_ntfy


def ev(severity):
    return {"alert_type": "ARP_SPOOF", "severity": severity,
            "device_mac": "de:ad:be:ef:00:99", "description": "test alert"}


def test_only_high_and_critical_trigger_push():
    assert should_notify(ev("CRITICAL")) is True
    assert should_notify(ev("HIGH")) is True
    assert should_notify(ev("MEDIUM")) is False
    assert should_notify(ev("LOW")) is False


def test_build_notification_maps_severity_to_priority():
    note = build_notification(ev("CRITICAL"))
    assert note["priority"] == "urgent"
    assert "CRITICAL" in note["title"]
    assert "test alert" in note["message"]


def test_send_ntfy_posts_for_high_event():
    calls = []

    def fake_post(url, data=None, headers=None):
        calls.append({"url": url, "data": data, "headers": headers})

    sent = send_ntfy(ev("HIGH"), topic="pg-alerts",
                     base_url="https://ntfy.sh", post=fake_post)
    assert sent is True
    assert len(calls) == 1
    assert calls[0]["url"] == "https://ntfy.sh/pg-alerts"


def test_send_ntfy_skips_low_event():
    calls = []

    def fake_post(url, data=None, headers=None):
        calls.append(url)

    sent = send_ntfy(ev("LOW"), topic="pg-alerts", post=fake_post)
    assert sent is False
    assert calls == []
