"""
scorecard.py — overall security-posture score (0–100) + letter grade.

Single source of truth for the headline "report card" shown on the dashboard
Overview and in the exported reports. Distinct from risk.py: risk.py scores an
*individual* finding's contextual risk (unbounded, higher = worse); this module
turns the whole scan's severity profile into an absolute 0–100 posture score
where **100 = clean** and a familiar A–F letter grade.

Model (severity-weighted deduction, floor at 0):

    score = max(0, 100 − (45·C + 18·H + 6·M + 1.5·L))

with C/H/M/L = number of findings at each severity (use the validated set, so
suppressed false positives don't drag the grade down).

Grade bands: A 90–100 · B 80–89 · C 70–79 · D 60–69 · F <60.

Severity ceiling (safety net so a near-clean number can't hide open severe
issues): ≥1 CRITICAL caps the grade at D; ≥1 HIGH caps it at B. The cap only
ever lowers the letter, never raises it.

Pure function, no I/O, open-coded tables — easy to tune.
"""
from __future__ import annotations

# Deduction applied per finding at each severity.
WEIGHTS: dict[str, float] = {
    "CRITICAL": 45.0,
    "HIGH":     18.0,
    "MEDIUM":    6.0,
    "LOW":       1.5,
}

# Grade bands: (min_score_inclusive, letter). Checked high → low.
BANDS: list[tuple[float, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0,  "F"),
]

# Best → worst, so a higher index means a worse grade.
GRADE_ORDER: list[str] = ["A", "B", "C", "D", "F"]

# Per-grade colors (consistent dark-theme palette; reused by UI + reports).
GRADE_COLORS: dict[str, str] = {
    "A": "#69f0ae",  # green
    "B": "#b2ff59",  # lime
    "C": "#ffd54f",  # amber
    "D": "#ffa726",  # orange
    "F": "#ff5252",  # red
}

# Severity-ceiling rules: if count[sev] >= 1, grade can be no better than letter.
CEILINGS: list[tuple[str, str]] = [
    ("CRITICAL", "D"),
    ("HIGH",     "B"),
]


def _band(score: float) -> str:
    for floor, letter in BANDS:
        if score >= floor:
            return letter
    return "F"


def compute(counts: dict) -> dict:
    """counts: {'CRITICAL': int, 'HIGH': int, 'MEDIUM': int, 'LOW': int}.
    Returns the score, letter grade (post-ceiling), and a transparent
    breakdown for display."""
    c = {s: int(counts.get(s, 0) or 0) for s in WEIGHTS}
    deduction = sum(WEIGHTS[s] * c[s] for s in WEIGHTS)
    score = max(0, round(100 - deduction))

    numeric_grade = _band(score)
    grade = numeric_grade
    ceiling_rule = ""
    for sev, cap in CEILINGS:
        if c[sev] >= 1:
            # apply the cap only if it makes the grade worse
            if GRADE_ORDER.index(grade) < GRADE_ORDER.index(cap):
                grade = cap
                ceiling_rule = sev
            break  # CRITICAL rule dominates HIGH

    return {
        "score": score,
        "grade": grade,
        "numeric_grade": numeric_grade,
        "deduction": round(deduction, 1),
        "ceiling_applied": ceiling_rule,        # "", "CRITICAL", or "HIGH"
        "color": GRADE_COLORS.get(grade, "#90a4ae"),
        "counts": c,
        "weights": dict(WEIGHTS),
    }


def grade_color(grade: str) -> str:
    return GRADE_COLORS.get(grade, "#90a4ae")
