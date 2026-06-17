"""
diff.py — compare two scan runs.

Given pentest_a and pentest_b (typically a=current, b=previous), key findings
by (category, scope) and bucket them:

  new       — present in A, absent in B  (regressions / fresh exposure)
  fixed     — present in B, absent in A  (remediated since last run)
  changed   — same key, different severity
  unchanged — same key, same severity

By default we read each side's validated findings (findings_validated.tsv if
present, else raw findings.tsv) so suppressions/ownership filters are honored
on both sides. The caller can opt into raw with source="raw".
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Row:
    severity: str
    category: str
    scope: str
    description: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.category, self.scope)


def _findings_path(scan_dir: Path, source: str) -> Path:
    val = scan_dir / "report" / "findings_validated.tsv"
    raw = scan_dir / "report" / "findings.tsv"
    if source == "raw":
        return raw
    return val if val.is_file() else raw


def _load(scan_dir: Path, source: str = "validated") -> dict[tuple[str, str], Row]:
    p = _findings_path(scan_dir, source)
    out: dict[tuple[str, str], Row] = {}
    if not p.is_file():
        return out
    with p.open("r", errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            r = Row(parts[0], parts[1], parts[2], parts[3])
            # First-wins on collision (same cat+scope appearing twice would
            # mean the scanner double-counted; rare but defensive).
            out.setdefault(r.key, r)
    return out


def _severity_drift(prev: str, cur: str) -> str:
    if prev == cur:
        return "same"
    pi = _SEV_RANK.get(prev, 99)
    ci = _SEV_RANK.get(cur, 99)
    if ci < pi:
        return "worse"   # CRITICAL has rank 0, so moving toward 0 is worse
    return "better"


def diff_scans(a_dir: Path, b_dir: Path, source: str = "validated") -> dict:
    a = _load(a_dir, source)
    b = _load(b_dir, source)

    a_keys = set(a.keys())
    b_keys = set(b.keys())

    new_keys = a_keys - b_keys
    fixed_keys = b_keys - a_keys
    common_keys = a_keys & b_keys

    new_rows = [_serialize(a[k]) for k in new_keys]
    fixed_rows = [_serialize(b[k]) for k in fixed_keys]
    changed_rows = []
    unchanged_count = 0
    for k in common_keys:
        ra, rb = a[k], b[k]
        if ra.severity == rb.severity:
            unchanged_count += 1
        else:
            drift = _severity_drift(rb.severity, ra.severity)
            changed_rows.append({
                "category": ra.category,
                "scope": ra.scope,
                "description": ra.description,
                "previous_severity": rb.severity,
                "severity": ra.severity,
                "drift": drift,
            })

    new_rows.sort(key=lambda r: (_sev_idx(r["severity"]), r["category"], r["scope"]))
    fixed_rows.sort(key=lambda r: (_sev_idx(r["severity"]), r["category"], r["scope"]))
    changed_rows.sort(key=lambda r: (_sev_idx(r["severity"]), r["category"], r["scope"]))

    return {
        "source": source,
        "a": a_dir.name,
        "b": b_dir.name,
        "totals": {
            "a": len(a),
            "b": len(b),
            "new": len(new_rows),
            "fixed": len(fixed_rows),
            "changed": len(changed_rows),
            "unchanged": unchanged_count,
        },
        "severity_delta": _severity_delta(a, b),
        "new": new_rows,
        "fixed": fixed_rows,
        "changed": changed_rows,
    }


def _sev_idx(s: str) -> int:
    return _SEV_RANK.get(s, 99)


def _serialize(r: Row) -> dict:
    return {
        "severity": r.severity,
        "category": r.category,
        "scope": r.scope,
        "description": r.description,
    }


def _severity_delta(a: dict, b: dict) -> dict:
    ca = Counter(r.severity for r in a.values())
    cb = Counter(r.severity for r in b.values())
    return {
        s: {"a": int(ca.get(s, 0)), "b": int(cb.get(s, 0)),
            "delta": int(ca.get(s, 0)) - int(cb.get(s, 0))}
        for s in SEVERITIES
    }


def pick_previous(scans: Iterable[dict], current: dict) -> Optional[str]:
    """Heuristic: previous scan = most recent scan older than `current` that
    shares at least one input domain (so we don't diff example vs unrelated)."""
    cur_doms = set(current.get("domains") or [])
    candidates = []
    for s in scans:
        if s["name"] == current["name"]:
            continue
        if s.get("mtime", 0) >= current.get("mtime", 0):
            continue
        doms = set(s.get("domains") or [])
        score = len(cur_doms & doms)
        candidates.append((score, s.get("mtime", 0), s["name"]))
    candidates.sort(key=lambda x: (-x[0], -x[1]))
    return candidates[0][2] if candidates else None
