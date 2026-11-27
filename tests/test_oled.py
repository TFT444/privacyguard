"""OLED render-logic tests (Phase 4). Pure layout logic, no screen needed."""

from privacyguard.display.oled import status_for_score, render_frame


def test_status_thresholds():
    assert status_for_score(92) == "SAFE"
    assert status_for_score(80) == "SAFE"
    assert status_for_score(60) == "WARNING"
    assert status_for_score(50) == "WARNING"
    assert status_for_score(20) == "DANGER"


def test_render_frame_contents():
    frame = render_frame(92)
    assert frame["status"] == "SAFE"
    assert frame["score"] == 92
    assert frame["big"] == "92"
    assert "Safety Score" in frame["title"]
