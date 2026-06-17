"""
suppressions.py — persistent allowlist of accepted false positives.

Schema (JSON file at SUPPRESSIONS_FILE, default <PENTEST_ROOT>/suppressions.json):

  [
    {
      "id": "<sha1 hex prefix>",
      "category": "SNMP Community String Accessible",  # exact OR fnmatch
      "scope":    "10.20.12.30",                       # exact OR fnmatch
      "reason":   "lab IP — accepted",
      "created_at": "2026-05-25T10:00:00",
      "created_by": "user",
      "expires_at": null                                # ISO8601 or null
    },
    ...
  ]

The match key is (category, scope). Either field can be a glob (fnmatch syntax
— `*` matches any chars, `?` matches a single char). An entry with expired
`expires_at` is loaded but does not match.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


SUPPRESSIONS_FILE = Path(os.environ.get(
    "SUPPRESSIONS_FILE",
    str(Path(os.environ.get("PENTEST_ROOT", "/workspace")) / "suppressions.json"),
))


@dataclass
class Suppression:
    id: str
    category: str
    scope: str
    reason: str = ""
    created_at: str = ""
    created_by: str = "user"
    expires_at: Optional[str] = None

    @classmethod
    def new(cls, category: str, scope: str, reason: str = "",
            created_by: str = "user", expires_at: Optional[str] = None) -> "Suppression":
        key = f"{category}\x1f{scope}".encode("utf-8")
        sid = hashlib.sha1(key).hexdigest()[:12]
        return cls(
            id=sid,
            category=category.strip(),
            scope=scope.strip(),
            reason=reason.strip(),
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            created_by=created_by,
            expires_at=expires_at,
        )

    def is_active(self, now: Optional[datetime] = None) -> bool:
        if not self.expires_at:
            return True
        try:
            exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return True  # malformed → don't disable
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return (now or datetime.now(timezone.utc)) < exp

    def matches(self, category: str, scope: str) -> bool:
        if not self.is_active():
            return False
        return (
            fnmatch.fnmatchcase(category, self.category) and
            fnmatch.fnmatchcase(scope, self.scope)
        )


# ─── Persistence ──────────────────────────────────────────────────────────────
def load() -> list[Suppression]:
    p = SUPPRESSIONS_FILE
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return []
    out: list[Suppression] = []
    for row in raw or []:
        try:
            out.append(Suppression(**row))
        except TypeError:
            continue
    return out


def save(items: list[Suppression]) -> None:
    p = SUPPRESSIONS_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps([asdict(s) for s in items], indent=2))
    tmp.replace(p)


def add(category: str, scope: str, reason: str = "",
        created_by: str = "user", expires_at: Optional[str] = None) -> Suppression:
    items = load()
    s = Suppression.new(category, scope, reason, created_by, expires_at)
    # Idempotent: if the same (cat, scope) already present, update reason + reset timestamp
    for i, existing in enumerate(items):
        if existing.id == s.id:
            items[i] = s
            save(items)
            return s
    items.append(s)
    save(items)
    return s


def remove(sid: str) -> bool:
    items = load()
    new = [s for s in items if s.id != sid]
    if len(new) == len(items):
        return False
    save(new)
    return True


# ─── Matching ─────────────────────────────────────────────────────────────────
def find_match(category: str, scope: str,
               items: Optional[list[Suppression]] = None) -> Optional[Suppression]:
    items = items if items is not None else load()
    for s in items:
        if s.matches(category, scope):
            return s
    return None
