"""
OLED display driver (Phase 4). Shows status + Safety Score on the front screen.

The rendering logic (what text/layout to draw for a given score) is kept separate
from the hardware calls so it can be unit-tested with a mock, no screen required.

TODO (Phase 4):
  - render_frame(score, status): returns the layout to draw (testable)
  - push_to_oled(frame): luma.oled hardware call (Raspberry Pi only)
"""
