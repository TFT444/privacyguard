"""
OLED display (Phase 4). Shows status + Safety Score on the front 1.3in I2C screen.

The rendering logic (what to draw for a given score) is pure and unit-tested. The
actual hardware call (push_to_oled) uses luma.oled and only runs on the Pi, so it
is kept separate and import-guarded.
"""


def status_for_score(score):
    """Map a 0-100 Safety Score to a status word."""
    if score >= 80:
        return "SAFE"
    if score >= 50:
        return "WARNING"
    return "DANGER"


def render_frame(score):
    """Return the layout to draw for a given score (pure, testable)."""
    return {
        "title": "Home Safety Score",
        "status": status_for_score(score),
        "score": score,
        "big": str(score),
    }


def push_to_oled(frame, device=None):  # pragma: no cover - hardware only
    """
    Draw a rendered frame on the physical OLED. Runs on the Raspberry Pi only.
    Imported lazily so the rest of the package works on a laptop without luma.oled.
    """
    from luma.core.render import canvas  # noqa: imported here on purpose
    with canvas(device) as draw:
        draw.text((0, 0), frame["title"], fill="white")
        draw.text((0, 20), frame["big"], fill="white")
        draw.text((0, 48), frame["status"], fill="white")
