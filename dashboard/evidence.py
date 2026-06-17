"""
evidence.py — capture the HTTP response behind a finding, for verification.

Run as a best-effort pass at validation time: for every finding whose scope is
web-addressable, re-fetch the URL once and persist what came back (final status,
size, a few telling headers, a body snippet, and any "dead deployment" marker).
The analyst — and the report — can then see *why* a finding fired without
re-running the scanner. This is the verification half of the confidence story
(see confidence.py): a captured 200 with real content backs a finding up; a 404
/ parking page / connection refused explains a likely false positive.

Mirrors screenshots.py exactly (same URL keying + JSON mapping) so the dashboard
integrates it the same way it already surfaces screenshots.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

# Reuse the screenshot helpers so evidence + screenshots key URLs identically.
from screenshots import scope_to_url, url_hash

# Markers that explain a likely false positive (subset of validator's list).
_DEAD_MARKERS = (
    "deployment_not_found", "no such app", "there isn't a github pages",
    "page not found", "project not found", "account has been suspended",
    "domain is for sale", "coming soon", "under construction",
    "origin dns error", "error 1016", "error 1020",
)


def _evidence_dir(scan_dir: Path) -> Path:
    return scan_dir / "report" / "evidence"


def _mapping_path(scan_dir: Path) -> Path:
    return _evidence_dir(scan_dir) / "_map.json"


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


def _probe(url: str, timeout: int = 8) -> Optional[str]:
    """Fetch url; return a human-readable evidence blob, or None on hard failure.
    Uses curl (already required by the scanner/validator) — no new deps."""
    import subprocess
    try:
        # -D - dumps response headers to stdout; body goes to a temp file.
        body_file = "/tmp/_evidence_body.txt"
        r = subprocess.run(
            ["curl", "-sk", "-A", "berckley-evidence/1.0", "-L",
             "-o", body_file, "-D", "-",
             "-w", "\n__STATUS__ %{http_code} %{size_download} %{url_effective}",
             "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 4,
        )
    except (subprocess.TimeoutExpired, OSError):
        return f"URL: {url}\nRESULT: no response (timeout / connection refused)\n"

    headers = r.stdout or ""
    status_line = ""
    for ln in headers.splitlines():
        if ln.startswith("__STATUS__"):
            status_line = ln.replace("__STATUS__", "").strip()
    # Keep only a few telling response headers.
    keep = ("HTTP/", "server:", "location:", "content-type:",
            "content-length:", "x-powered-by:", "www-authenticate:",
            "access-control-allow-origin:", "access-control-allow-credentials:")
    hdr_lines = [l.strip() for l in headers.splitlines()
                 if l.lower().startswith(keep)][:14]
    body = ""
    try:
        with open(body_file, "r", errors="ignore") as fh:
            body = fh.read(1200)
    except OSError:
        body = ""
    marker = next((m for m in _DEAD_MARKERS if m in body.lower()), "")

    parts = [f"URL: {url}", f"STATUS: {status_line or 'unknown'}"]
    if marker:
        parts.append(f"DEAD-MARKER: '{marker}' present in body "
                     f"(explains a likely false positive)")
    if hdr_lines:
        parts.append("HEADERS:\n  " + "\n  ".join(hdr_lines))
    snippet = " ".join(body.split())[:600]
    if snippet:
        parts.append(f"BODY (snippet):\n  {snippet}")
    return "\n".join(parts) + "\n"


def capture_for_findings(scan_dir: Path, findings: list, workers: int = 8) -> dict:
    """For each web-addressable finding scope, capture HTTP evidence once per
    unique URL. Returns {captured, urls}. Best-effort: never raises."""
    urls: dict[str, str] = {}  # url -> hash
    for f in findings:
        scope = f.scope if hasattr(f, "scope") else (f.get("scope") if isinstance(f, dict) else "")
        url = scope_to_url(scope or "")
        if url and url not in urls:
            urls[url] = url_hash(url)

    if not urls:
        return {"captured": 0, "urls": 0}

    ev_dir = _evidence_dir(scan_dir)
    ev_dir.mkdir(parents=True, exist_ok=True)
    mapping = load_mapping(scan_dir)
    captured = 0

    def _one(item):
        url, h = item
        blob = _probe(url)
        if not blob:
            return None
        try:
            (ev_dir / f"{h}.txt").write_text(blob)
        except OSError:
            return None
        return h, url

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(_one, urls.items()):
            if res:
                h, url = res
                mapping[h] = f"{h}.txt"
                captured += 1

    _save_mapping(scan_dir, mapping)
    return {"captured": captured, "urls": len(urls)}


def get_evidence_filename_for_scope(scan_dir: Path, scope: str) -> Optional[str]:
    """Return the evidence filename for a finding scope, or None."""
    url = scope_to_url(scope)
    if not url:
        return None
    h = url_hash(url)
    f = _evidence_dir(scan_dir) / f"{h}.txt"
    return f"{h}.txt" if f.is_file() else None
