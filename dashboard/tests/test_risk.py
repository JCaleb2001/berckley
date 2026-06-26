"""Regression tests for contextual risk scoring (risk.py), incl. the
confidence dampening factor (lower confidence → lower risk, never higher)."""
import risk as R


def test_confidence_lowers_risk_monotonically():
    args = ("HIGH", "Redis Exposed", "db.example.com", "OWNED")
    hi = R.score(*args, confidence="HIGH")
    mid = R.score(*args, confidence="MEDIUM")
    lo = R.score(*args, confidence="LOW")
    assert hi > mid > lo > 0


def test_confidence_default_is_neutral():
    # No confidence arg == HIGH/neutral (1.0) — existing callers unaffected.
    base = R.score("HIGH", "Redis Exposed", "db.example.com", "OWNED")
    neutral = R.score("HIGH", "Redis Exposed", "db.example.com", "OWNED", confidence="HIGH")
    assert base == neutral


def test_confidence_weight_caps_at_one():
    # Unknown / empty band must not amplify risk.
    assert R.confidence_weight("") == 1.0
    assert R.confidence_weight("HIGH") == 1.0
    assert R.confidence_weight("LOW") < 1.0


def test_components_expose_confidence():
    c = R.score_components("HIGH", "Redis Exposed", "x.example.com", "OWNED", "LOW")
    assert c.confidence < 1.0
