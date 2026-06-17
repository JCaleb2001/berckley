"""Regression tests for the posture score / grade (scorecard.py)."""
import scorecard as S


def _c(crit=0, high=0, med=0, low=0):
    return {"CRITICAL": crit, "HIGH": high, "MEDIUM": med, "LOW": low}


def test_clean_scan_is_A_100():
    r = S.compute(_c())
    assert r["score"] == 100 and r["grade"] == "A"


def test_formula():
    # 1H + 3M + 5L = 18 + 18 + 7.5 = 43.5 -> 100-43.5 = 56.5 -> round 56 -> F
    r = S.compute(_c(high=1, med=3, low=5))
    assert r["score"] == 56
    assert r["deduction"] == 43.5


def test_floor_at_zero():
    assert S.compute(_c(crit=5))["score"] == 0


def test_grade_bands():
    assert S.compute(_c(low=5))["grade"] == "A"      # 92
    assert S.compute(_c(high=1))["grade"] == "B"      # 82
    assert S.compute(_c(med=5))["grade"] == "C"       # 70


def test_ceiling_never_raises():
    # ceiling only lowers; a clean-ish numeric grade must not be pushed up.
    r = S.compute(_c(low=2))            # 97 -> A, no severe findings
    assert r["grade"] == "A"


def test_shape():
    r = S.compute(_c(high=1, low=2))
    assert {"score", "grade", "numeric_grade", "deduction",
            "ceiling_applied", "color", "counts"} <= set(r)
