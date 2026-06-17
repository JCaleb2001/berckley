"""
screenshots.py — capture chromium-headless PNG of each finding's URL.

For HTTP-based findings (admin panels, exposed paths, web app issues) a
visual screenshot is the difference between "we say it's exposed" and
"here's the login page rendered in a browser". This module captures one PNG
per unique URL into <scan_dir>/screenshots/<hash>.png and a mapping file so
the dashboard + reports can surface them per finding.

Filenames are content-addressable (SHA1 prefix of the URL) so re-capturing
the same URL overwrites the previous PNG rather than accumulating dupes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional


CHROME_CANDIDATES = ("chromium", "chromium-browser", "google-chrome", "chrome")


def _chrome_binary() -> Optional[str]:
    for cand in CHROME_CANDIDATES:
        if shutil.which(cand):
            return cand
    return None


def scope_to_url(scope: str) -> Optional[str]:
    """Extract a probable HTTP URL from a finding scope.
    Returns None for scopes that aren't web-addressable."""
    s = (scope or "").strip()
    if not s:
        return None
    # Many scopes have multiple URLs space-separated (multi-host grouped findings);
    # take the first.
    s = s.split()[0]
    if s.startswith(("http://", "https://")):
        return s
    # host or host:port
    if re.match(r"^[a-z0-9][a-z0-9.-]*(\.[a-z0-9-]+)+(:\d+)?$", s, re.I):
        port = ""
        m = re.search(r":(\d+)$", s)
        if m:
            port_n = m.group(1)
            if port_n == "443":
                return f"https://{s.split(':')[0]}"
            if port_n == "80":
                return f"http://{s.split(':')[0]}"
            return f"http://{s}"
        return f"https://{s}"
    return None


def url_hash(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8", "replace")).hexdigest()[:12]


def _mapping_path(scan_dir: Path) -> Path:
    return scan_dir / "screenshots" / "_mapping.json"


def load_mapping(scan_dir: Path) -> dict:
    p = _mapping_path(scan_dir)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_mapping(scan_dir: Path, mapping: dict) -> None:
    p = _mapping_path(scan_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(mapping, indent=2, sort_keys=True))
    tmp.replace(p)


def capture_url(url: str, out: Path, timeout: int = 30) -> bool:
    """Run chromium headless to capture URL → PNG. Returns True on success."""
    chrome = _chrome_binary()
    if not chrome:
        return False
    out.parent.mkdir(parents=True, exist_ok=True)
    # --virtual-time-budget waits for JS to settle; --window-size standardises
    # the viewport so screenshots compare cleanly across hosts.
    try:
        subprocess.run([
            chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
            "--hide-scrollbars",
            "--window-size=1280,900",
            "--virtual-time-budget=6000",
            "--ignore-certificate-errors",
            f"--screenshot={out}",
            url,
        ], check=False, capture_output=True, timeout=timeout)
        return out.is_file() and out.stat().st_size > 1024  # >1KB to skip blanks
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def capture_for_findings(scan_dir: Path,
                         findings: list[dict],
                         max_workers: int = 4,
                         force: bool = False) -> dict:
    """Capture a screenshot per UNIQUE URL across the supplied findings.
    Returns a stats dict so the API can surface count + file list."""
    shots_dir = scan_dir / "screenshots"
    shots_dir.mkdir(parents=True, exist_ok=True)

    # Dedupe by URL
    url_to_findings: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        url = scope_to_url(f.get("scope", ""))
        if not url:
            continue
        url_to_findings.setdefault(url, []).append(i)

    mapping = load_mapping(scan_dir)
    stats = {"captured": 0, "cached": 0, "failed": 0,
             "skipped_non_http": len(findings) - sum(len(v) for v in url_to_findings.values()),
             "files": {}}

    def _one(url: str) -> tuple[str, str, str]:
        h = url_hash(url)
        out = shots_dir / f"{h}.png"
        if out.is_file() and out.stat().st_size > 1024 and not force:
            return url, h, "cached"
        ok = capture_url(url, out)
        return url, h, "captured" if ok else "failed"

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(_one, u) for u in url_to_findings.keys()]
        for fut in as_completed(futs):
            url, h, status = fut.result()
            if status == "captured":
                stats["captured"] += 1
                stats["files"][url] = f"{h}.png"
                mapping[url] = f"{h}.png"
            elif status == "cached":
                stats["cached"] += 1
                stats["files"][url] = f"{h}.png"
                mapping[url] = f"{h}.png"
            else:
                stats["failed"] += 1

    _save_mapping(scan_dir, mapping)
    return stats


def get_screenshot_filename_for_scope(scan_dir: Path, scope: str) -> Optional[str]:
    """Return the screenshot filename for a finding scope, or None."""
    url = scope_to_url(scope)
    if not url:
        return None
    mapping = load_mapping(scan_dir)
    if url in mapping:
        # Verify the file still exists
        p = scan_dir / "screenshots" / mapping[url]
        if p.is_file():
            return mapping[url]
    # Fallback: maybe the file exists but mapping is stale
    h = url_hash(url)
    p = scan_dir / "screenshots" / f"{h}.png"
    return f"{h}.png" if p.is_file() else None


def stats_for_scan(scan_dir: Path) -> dict:
    """Quick stats for the dashboard sidebar / overview badge."""
    mapping = load_mapping(scan_dir)
    shots_dir = scan_dir / "screenshots"
    existing = sum(1 for fn in mapping.values()
                   if (shots_dir / fn).is_file()) if shots_dir.is_dir() else 0
    return {"total": existing,
            "url_count": len(mapping),
            "available": _chrome_binary() is not None}
