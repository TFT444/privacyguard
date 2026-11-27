"""
ntfy push notifications (Phase 4). Only CRITICAL and HIGH events push to the
user's phone. The HTTP sender is injected so the logic is unit-testable without
touching the network; the default sender uses requests.
"""

_PRIORITY = {
    "CRITICAL": "urgent",
    "HIGH": "high",
    "MEDIUM": "default",
    "LOW": "low",
}

_PUSH_SEVERITIES = {"CRITICAL", "HIGH"}


def should_notify(event):
    return event["severity"] in _PUSH_SEVERITIES


def build_notification(event):
    """Build the ntfy title/message/priority/tags for an event."""
    return {
        "title": f"PrivacyGuard: {event['severity']} {event['alert_type']}",
        "message": event.get("description", ""),
        "priority": _PRIORITY.get(event["severity"], "default"),
        "tags": "warning",
    }


def send_ntfy(event, topic, base_url="https://ntfy.sh", post=None):
    """
    Send a push for CRITICAL/HIGH events. Returns True if sent, False if skipped.
    `post` is an injectable callable(url, data, headers); defaults to requests.post.
    """
    if not should_notify(event):
        return False
    if post is None:
        import requests
        post = requests.post
    note = build_notification(event)
    url = f"{base_url.rstrip('/')}/{topic}"
    headers = {
        "Title": note["title"],
        "Priority": note["priority"],
        "Tags": note["tags"],
    }
    post(url, data=note["message"].encode("utf-8"), headers=headers)
    return True
