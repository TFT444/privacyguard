"""Safety Score tests (Phase 2). Pure function, no hardware."""

from privacyguard.web.safety import compute_safety_score


def alert(severity, acknowledged=False):
    return {"severity": severity, "acknowledged": acknowledged}


def test_no_alerts_is_full_score():
    assert compute_safety_score([]) == 100


def test_single_critical_drops_by_40():
    assert compute_safety_score([alert("CRITICAL")]) == 60


def test_single_high_drops_by_20():
    assert compute_safety_score([alert("HIGH")]) == 80


def test_mixed_alerts_sum_penalties():
    # HIGH (20) + MEDIUM (10) + LOW (3) = 33 -> 67
    score = compute_safety_score([alert("HIGH"), alert("MEDIUM"), alert("LOW")])
    assert score == 67


def test_acknowledged_alerts_are_ignored():
    score = compute_safety_score([alert("CRITICAL", acknowledged=True)])
    assert score == 100


def test_score_never_goes_below_zero():
    many = [alert("CRITICAL") for _ in range(10)]
    assert compute_safety_score(many) == 0
