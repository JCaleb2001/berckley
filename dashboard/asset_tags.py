"""
asset_tags.py — persistent host → owner-tag store.

Keyed by hostname (lowercased). Survives scan re-runs, scan deletion, container
rebuilds. Used by the Triage tab so the analyst can mark a discovered asset as
"belongs to Marketing", "belongs to Acme Corp", etc., and keep that label
across engagements.

File: $PENTEST_ROOT/asset_tags.json (mounted volume in Docker setup).

Schema:
  [
    {
      "host":   "example.com",
      "tag":    "Marketing Team",      # free-form, human-readable owner label
      "notes":  "Contact: jane@…",     # optional analyst notes
      "verified": true,                # last manual verify result
      "verification_status": "alive",  # alive | dead | unknown
      "verification_code": 200,
      "verified_at": "2026-05-28T19:00:00+00:00",
      "updated_at":  "2026-05-28T18:55:00+00:00",
      "created_at":  "2026-05-28T18:55:00+00:00"
    }
  ]
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


TAGS_FILE = Path(os.environ.get(
    "ASSET_TAGS_FILE",
    str(Path(os.environ.get("PENTEST_ROOT", "/workspace")) / "asset_tags.json"),
))


@dataclass
class AssetTag:
    host: str
    tag: str = ""
    notes: str = ""
    verified: bool = False
    verification_status: str = "unknown"   # alive | dead | unknown
    verification_code: int = 0
    verified_at: Optional[str] = None
    updated_at: Optional[str] = None
    created_at: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ─── Persistence ─────────────────────────────────────────────────────────────
def load() -> list[AssetTag]:
    if not TAGS_FILE.is_file():
        return []
    try:
        raw = json.loads(TAGS_FILE.read_text(errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return []
    out: list[AssetTag] = []
    for row in raw or []:
        try:
            out.append(AssetTag(**row))
        except TypeError:
            continue
    return out


def save(items: list[AssetTag]) -> None:
    TAGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = TAGS_FILE.with_suffix(TAGS_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps([t.to_dict() for t in items], indent=2))
    tmp.replace(TAGS_FILE)


def _index() -> dict[str, AssetTag]:
    return {t.host.lower(): t for t in load()}


def get(host: str) -> Optional[AssetTag]:
    return _index().get((host or "").strip().lower())


def set_tag(host: str, tag: str = "", notes: str = "") -> AssetTag:
    items = load()
    key = host.strip().lower()
    now = _now()
    for i, t in enumerate(items):
        if t.host.lower() == key:
            t.tag = tag
            t.notes = notes
            t.updated_at = now
            items[i] = t
            save(items)
            return t
    # new entry
    new = AssetTag(
        host=key,
        tag=tag,
        notes=notes,
        created_at=now,
        updated_at=now,
    )
    items.append(new)
    save(items)
    return new


def remove(host: str) -> bool:
    items = load()
    key = host.strip().lower()
    new = [t for t in items if t.host.lower() != key]
    if len(new) == len(items):
        return False
    save(new)
    return True


def record_verification(host: str, status: str, code: int) -> AssetTag:
    """Update verification metadata for a host (creates entry if missing)."""
    items = load()
    key = host.strip().lower()
    now = _now()
    for i, t in enumerate(items):
        if t.host.lower() == key:
            t.verified = True
            t.verification_status = status
            t.verification_code = int(code or 0)
            t.verified_at = now
            t.updated_at = now
            items[i] = t
            save(items)
            return t
    new = AssetTag(
        host=key,
        verified=True,
        verification_status=status,
        verification_code=int(code or 0),
        verified_at=now,
        created_at=now,
        updated_at=now,
    )
    items.append(new)
    save(items)
    return new


def merge_with_hosts(hosts: list[str]) -> list[dict]:
    """Return one row per supplied host, joined with whatever tag we have."""
    idx = _index()
    rows = []
    for h in hosts:
        h = (h or "").strip()
        if not h:
            continue
        t = idx.get(h.lower())
        if t:
            rows.append({"host": h, **t.to_dict(), "has_tag": bool(t.tag)})
        else:
            rows.append({
                "host": h, "tag": "", "notes": "",
                "verified": False, "verification_status": "unknown",
                "verification_code": 0,
                "verified_at": None, "updated_at": None, "created_at": None,
                "has_tag": False,
            })
    return rows
