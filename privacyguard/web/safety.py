"""
Home Safety Score (0-100). Higher is safer.

Starts at 100 and subtracts a weighted penalty for each active (non-acknowledged)
alert. The caller is responsible for passing only the alerts inside the rolling
24-hour window; this function is pure so it is trivially testable.
"""

PENALTY = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 3,
}


def compute_safety_score(alerts):
    total = 0
    for a in alerts:
        if a.get("acknowledged"):
            continue
        total += PENALTY.get(a["severity"], 0)
    return max(0, 100 - total)
