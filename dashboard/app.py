"""
app.py — Berckley dashboard: FastAPI backend for the external pentest scanner.

Reads runs from PENTEST_ROOT (mounted in Docker, default /workspace),
parses findings.tsv / discovered.log / master.log, and exposes endpoints
the static UI consumes. Can also launch new scans by shelling out to
extpentest.sh and stream the live log via Server-Sent Events.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import signal
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import validator as nw_validator
import ownership as nw_ownership
import suppressions as nw_suppressions
import diff as nw_diff
import report_extras as nw_extras
import intake as nw_intake
import risk as nw_risk
import asset_tags as nw_tags
import screenshots as nw_screenshots
import taxonomy as nw_taxonomy
import scorecard as nw_scorecard
import confidence as nw_confidence
import evidence as nw_evidence

ROOT = Path(os.environ.get("PENTEST_ROOT", "/workspace")).resolve()
SCANNER = Path(os.environ.get("SCANNER_PATH", str(ROOT / "extpentest.sh")))
MGMT_REPORT = Path(os.environ.get("MGMT_REPORT_PATH", str(ROOT / "nw_report_mgmt.sh")))
SOC_REPORT = Path(os.environ.get("SOC_REPORT_PATH", str(ROOT / "nw_report_soc.sh")))
STATIC_DIR = Path(__file__).parent / "static"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SCAN_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

app = FastAPI(title="berckley console", version="0.2.0")


def _findings_path(scan_dir: Path, prefer_validated: bool = True) -> Path:
    """Return the validated TSV if present (and preferred), else the raw one."""
    val = scan_dir / "report" / "findings_validated.tsv"
    raw = scan_dir / "report" / "findings.tsv"
    if prefer_validated and val.is_file():
        return val
    return raw


def _has_validation(scan_dir: Path) -> bool:
    return (scan_dir / "report" / "findings_validated.tsv").is_file()


def _ownership_map(scan_dir: Path) -> dict[str, dict]:
    """Lowercased-host → ownership row dict. Empty if not yet classified."""
    raw = nw_ownership.load(scan_dir)
    return {h.lower(): c.to_dict() for h, c in raw.items()}


def _classify_scope(scope: str, omap: dict[str, dict]) -> Optional[dict]:
    """Look up ownership for a finding/asset scope."""
    if not omap or not scope:
        return None
    key = (scope or "").strip().lower()
    if key in omap:
        return omap[key]
    # Try by host stripped of scheme/port
    from validator import extract_host, extract_ip
    host = extract_host(scope).lower()
    if host and host in omap:
        return omap[host]
    ip = extract_ip(scope) or ""
    if ip and ip in omap:
        return omap[ip]
    return None


def _parse_audit(scan_dir: Path) -> list[dict]:
    p = scan_dir / "report" / "findings_audit.tsv"
    if not p.is_file():
        return []
    rows = []
    with p.open("r", errors="ignore") as f:
        header = f.readline()  # skip header
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 8:
                continue
            rows.append({
                "orig_severity": parts[0],
                "new_severity": parts[1],
                "category": parts[2],
                "scope": parts[3],
                "description": parts[4],
                "verdict": parts[5],
                "rule": parts[6],
                "reason": parts[7],
            })
    return rows


# ─── Process registry ─────────────────────────────────────────────────────────
class RunningScan:
    def __init__(self, name: str, proc: subprocess.Popen, started: float):
        self.name = name
        self.proc = proc
        self.started = started


RUNNING: dict[str, RunningScan] = {}


# ─── Helpers ──────────────────────────────────────────────────────────────────
_SCAN_NAME_PARSER = re.compile(
    r"^pentest(?:_(?P<tag>.+?))?_(?P<date>\d{8})_(?P<time>\d{6})$"
)


def _friendly_name(scan_name: str) -> dict:
    """Parse the timestamp out of a pentest_* directory name and return a
    human-readable display label. Falls back to the raw name if it doesn't
    match the expected scheme."""
    m = _SCAN_NAME_PARSER.match(scan_name or "")
    if not m:
        return {"label": scan_name, "date": "", "time": "", "tag": "",
                "slug": scan_name}
    date_raw = m.group("date")  # YYYYMMDD
    time_raw = m.group("time")  # HHMMSS
    tag = (m.group("tag") or "").strip()
    iso_date = f"{date_raw[:4]}-{date_raw[4:6]}-{date_raw[6:8]}"
    hhmm = f"{time_raw[:2]}:{time_raw[2:4]}"
    label = f"Scan Report · {iso_date} {hhmm}"
    if tag:
        label += f" · {tag}"
    slug = f"Scan_Report_{iso_date}"
    if tag:
        slug += f"_{tag}"
    return {"label": label, "date": iso_date, "time": hhmm,
            "tag": tag, "slug": slug}


def _scan_dir(name: str) -> Path:
    if not SCAN_NAME_RE.match(name):
        raise HTTPException(400, "invalid scan name")
    p = (ROOT / name).resolve()
    if not str(p).startswith(str(ROOT)) or not p.is_dir():
        raise HTTPException(404, "scan not found")
    return p


def _list_scans() -> list[dict]:
    out = []
    if not ROOT.is_dir():
        return out
    for child in sorted(ROOT.iterdir(), reverse=True):
        if not child.is_dir() or not child.name.startswith("pentest"):
            continue
        raw = child / "report" / "findings.tsv"
        assets = child / "assets" / "discovered.log"
        master = child / "report" / "master.log"
        input_doms = child / "recon" / "input_domains.txt"
        input_ips = child / "recon" / "input_targets.txt"
        domains = []
        targets = []
        if input_doms.is_file():
            domains = [l.strip() for l in input_doms.read_text(errors="ignore").splitlines() if l.strip()]
        if input_ips.is_file():
            targets = [l.strip() for l in input_ips.read_text(errors="ignore").splitlines() if l.strip()]
        sev_raw = _severity_counts(raw)
        sev_eff = _severity_counts(_findings_path(child))
        try:
            mtime = child.stat().st_mtime
        except OSError:
            mtime = 0
        running = child.name in RUNNING
        sup = _supplier_meta(child)
        out.append({
            "name": child.name,
            "display": _friendly_name(child.name),
            "mtime": mtime,
            "mtime_iso": datetime.fromtimestamp(mtime).isoformat(timespec="seconds") if mtime else "",
            "domains": domains,
            "targets": targets,
            "severity": sev_eff,
            "severity_raw": sev_raw,
            "total_findings": sum(sev_eff.values()),
            "total_findings_raw": sum(sev_raw.values()),
            "asset_count": _count_lines(assets),
            "has_master_log": master.is_file(),
            "validated": _has_validation(child),
            "running": running,
            "supplier": bool(sup),
            "supplier_name": (sup or {}).get("name", ""),
        })
    return out


def _supplier_meta(scan_dir: Path) -> Optional[dict]:
    """Return the .supplier.json marker for a passive supplier scan, or None."""
    p = scan_dir / "report" / ".supplier.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {"name": ""}


def _severity_counts(tsv: Path) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    if not tsv.is_file():
        return counts
    try:
        with tsv.open("r", errors="ignore") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 1 and parts[0] in counts:
                    counts[parts[0]] += 1
    except OSError:
        pass
    return counts


def _count_lines(p: Path) -> int:
    if not p.is_file():
        return 0
    try:
        return sum(1 for _ in p.open("r", errors="ignore"))
    except OSError:
        return 0


def _parse_findings(tsv: Path) -> list[dict]:
    rows = []
    if not tsv.is_file():
        return rows
    with tsv.open("r", errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            explicit = parts[4] if len(parts) > 4 else ""
            rows.append({
                "severity": parts[0],
                "category": parts[1],
                "scope": parts[2],
                "description": parts[3],
                "domain": nw_taxonomy.classify(parts[1], parts[3]),
                "confidence": nw_confidence.confidence(parts[1], parts[3], explicit),
            })
    return rows


def _parse_assets(log: Path) -> list[dict]:
    rows = []
    if not log.is_file():
        return rows
    with log.open("r", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if "\t" in line:
                t, _, v = line.partition("\t")
            else:
                t, v = "INFO", line
            rows.append({"type": t.strip(), "value": v.strip()})
    return rows


# ─── Routes ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    # Cache-bust the static assets by rewriting the script + link refs with
    # a query param tied to file mtime. Avoids stale JS/CSS in browsers that
    # cached aggressively across rebuilds.
    html = (STATIC_DIR / "index.html").read_text()
    try:
        ver_js  = int((STATIC_DIR / "app.js").stat().st_mtime)
        ver_css = int((STATIC_DIR / "style.css").stat().st_mtime)
    except OSError:
        ver_js = ver_css = 0
    html = html.replace('href="/static/style.css"',
                        f'href="/static/style.css?v={ver_css}"')
    html = html.replace('src="/static/app.js"',
                        f'src="/static/app.js?v={ver_js}"')
    return HTMLResponse(html)


@app.get("/logo.png")
def logo() -> FileResponse:
    """Serve the brand logo from the host repo root (mounted into the
    container at PENTEST_ROOT). 404 if the file isn't present."""
    p = ROOT / "logo.png"
    if not p.is_file():
        raise HTTPException(404, "logo.png not present in PENTEST_ROOT")
    return FileResponse(p, media_type="image/png",
                        headers={"Cache-Control": "public, max-age=3600"})


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "root": str(ROOT),
        "scanner": str(SCANNER),
        "scanner_present": SCANNER.is_file(),
        "running": list(RUNNING.keys()),
    }


@app.get("/api/scans")
def list_scans() -> dict:
    return {"scans": _list_scans()}


@app.get("/api/suppliers")
def list_suppliers() -> dict:
    """Portfolio view of passive supplier scans: each with its posture grade,
    security-domain breakdown and findings count — comparable across suppliers."""
    out = []
    for s in _list_scans():
        if not s.get("supplier"):
            continue
        sd = ROOT / s["name"]
        findings = _parse_findings(_findings_path(sd, prefer_validated=True))
        sev = {k: int(v) for k, v in s["severity"].items()}
        dom = Counter(f["domain"] for f in findings)
        domain_counts = [
            {**d, "count": int(dom[d["slug"]])}
            for d in nw_taxonomy.iter_domains() if dom.get(d["slug"])
        ]
        # Per-domain sub-grade: run the posture formula on each domain's own
        # severity profile, so a supplier shows e.g. Email B / Crypto D / Cloud A.
        dom_sev: dict[str, dict] = {}
        for f in findings:
            d = dom_sev.setdefault(f["domain"], {x: 0 for x in SEVERITIES})
            if f["severity"] in d:
                d[f["severity"]] += 1
        subscores = []
        for d in nw_taxonomy.iter_domains():
            if not dom.get(d["slug"]):
                continue
            sc = nw_scorecard.compute(dom_sev.get(d["slug"], {}))
            subscores.append({
                "slug": d["slug"], "label": d["label"], "icon": d["icon"],
                "count": int(dom[d["slug"]]),
                "grade": sc["grade"], "score": sc["score"], "color": sc["color"],
            })
        out.append({
            "name": s["name"],
            "supplier_name": s["supplier_name"] or s["name"],
            "domains": s["domains"],
            "mtime_iso": s["mtime_iso"],
            "running": s["running"],
            "validated": s["validated"],
            "total_findings": len(findings),
            "severity": sev,
            "scorecard": nw_scorecard.compute(sev),
            "domain_counts": domain_counts,
            "subscores": subscores,
            "reports": {
                "mgmt_html": (sd / "report" / "management_report.html").is_file(),
            },
        })
    return {"suppliers": out}


@app.get("/api/scans/{name}/summary")
def scan_summary(name: str, source: str = "validated") -> dict:
    sd = _scan_dir(name)
    prefer_validated = source != "raw"
    findings = _parse_findings(_findings_path(sd, prefer_validated))
    findings_raw = _parse_findings(sd / "report" / "findings.tsv")
    sev = Counter(f["severity"] for f in findings if f["severity"] in SEVERITIES)
    sev_raw = Counter(f["severity"] for f in findings_raw if f["severity"] in SEVERITIES)
    cat = Counter((f["severity"], f["category"]) for f in findings)
    top_cats = sorted(
        [{"severity": s, "category": c, "count": n} for (s, c), n in cat.items()],
        key=lambda r: (SEVERITIES.index(r["severity"]) if r["severity"] in SEVERITIES else 9, -r["count"]),
    )[:20]
    scope_hits = Counter(f["scope"] for f in findings)
    top_scopes = [{"scope": k, "count": v} for k, v in scope_hits.most_common(15)]

    # Security-domain breakdown — one row per domain that has findings, with a
    # per-severity split, in canonical precedence order (see taxonomy.py).
    dom_total = Counter(f["domain"] for f in findings)
    dom_sev: dict[str, Counter] = {}
    for f in findings:
        dom_sev.setdefault(f["domain"], Counter())[f["severity"]] += 1
    domain_counts = []
    for d in nw_taxonomy.iter_domains():
        slug = d["slug"]
        if not dom_total.get(slug):
            continue
        sv = dom_sev.get(slug, Counter())
        domain_counts.append({
            **d,
            "count": int(dom_total[slug]),
            "severity": {s: int(sv.get(s, 0)) for s in SEVERITIES},
        })

    # Risk-weighted view: each finding scored, summed per host.
    omap = _ownership_map(sd)
    enriched = []
    for f in findings:
        c = _classify_scope(f["scope"], omap)
        owner_class = (c or {}).get("class", "")
        enriched.append({
            **f,
            "owner_class": owner_class,
            "owner_provider": (c or {}).get("provider", ""),
            "risk_score": nw_risk.score(
                f["severity"], f["category"], f["scope"], owner_class
            ),
        })
    top_hosts_by_risk = nw_risk.aggregate_by_host(enriched)[:15]
    total_risk = round(sum(f["risk_score"] for f in enriched), 1)

    # Ownership class breakdown for the donut chart on Overview
    raw_own = nw_ownership.load(sd)
    own_by_class: dict[str, int] = {}
    for h, c in raw_own.items():
        own_by_class[c.owner_class.value] = own_by_class.get(c.owner_class.value, 0) + 1

    return {
        "name": name,
        "source": "validated" if (prefer_validated and _has_validation(sd)) else "raw",
        "validated_available": _has_validation(sd),
        "severity_counts": {s: int(sev.get(s, 0)) for s in SEVERITIES},
        "severity_counts_raw": {s: int(sev_raw.get(s, 0)) for s in SEVERITIES},
        "scorecard": nw_scorecard.compute({s: int(sev.get(s, 0)) for s in SEVERITIES}),
        "total_findings": len(findings),
        "total_findings_raw": len(findings_raw),
        "total_risk": total_risk,
        "top_categories": top_cats,
        "domain_counts": domain_counts,
        "top_scopes": top_scopes,
        "top_hosts_by_risk": top_hosts_by_risk,
        "ownership_by_class": own_by_class,
        "running": name in RUNNING,
        "reports": {
            "mgmt_html": (sd / "report" / "management_report.html").is_file(),
            "soc_html": (sd / "report" / "soc_report.html").is_file(),
        },
    }


@app.get("/api/scans/{name}/findings")
def scan_findings(name: str, severity: Optional[str] = None, q: Optional[str] = None,
                  source: str = "validated", owner_class: Optional[str] = None,
                  domain: Optional[str] = None, confidence: Optional[str] = None,
                  sort: str = "default") -> dict:
    sd = _scan_dir(name)
    prefer_validated = source != "raw"
    rows = _parse_findings(_findings_path(sd, prefer_validated))
    # Domains present in the full (pre-filter) set, in canonical order — drives
    # the domain filter chips on the findings tab.
    present = {r["domain"] for r in rows}
    domains_available = [d for d in nw_taxonomy.iter_domains()
                         if d["slug"] in present]
    present_conf = {r["confidence"]["band"] for r in rows}
    confidences_available = [
        {"band": b, "color": nw_confidence.band_color(b)}
        for b in nw_confidence.BAND_ORDER if b in present_conf
    ]
    omap = _ownership_map(sd)
    tag_index = {t.host.lower(): t for t in nw_tags.load()}
    # Enrich with ownership + contextual risk score + triage tag
    from validator import extract_host as _eh
    for r in rows:
        c = _classify_scope(r["scope"], omap)
        r["owner_class"] = (c or {}).get("class", "")
        r["owner_provider"] = (c or {}).get("provider", "")
        host_key = _eh(r["scope"]).lower()
        tag_rec = tag_index.get(host_key)
        r["owner_tag"] = tag_rec.tag if tag_rec else ""
        # Visual evidence — if we have a screenshot for this scope's URL, surface
        # the URL so the dashboard / report can render it.
        sshot_file = nw_screenshots.get_screenshot_filename_for_scope(sd, r["scope"])
        r["has_screenshot"] = bool(sshot_file)
        r["screenshot_url"] = (
            f"/api/scans/{name}/screenshots/{sshot_file}" if sshot_file else ""
        )
        # HTTP evidence captured at validation time (see evidence.py)
        ev_file = nw_evidence.get_evidence_filename_for_scope(sd, r["scope"])
        r["has_evidence"] = bool(ev_file)
        r["evidence_url"] = (
            f"/api/scans/{name}/evidence/{ev_file}" if ev_file else ""
        )
        comps = nw_risk.score_components(
            r["severity"], r["category"], r["scope"], r["owner_class"],
            r["confidence"]["band"]
        )
        r["risk_score"] = comps.score
        r["risk_breakdown"] = {
            "severity": comps.severity,
            "exploitability": comps.exploitability,
            "ownership": comps.ownership,
            "host_criticality": comps.host_criticality,
            "exploit_label": comps.exploit_label,
            "criticality_label": comps.criticality_label,
        }
    if severity:
        sev_set = {s.strip().upper() for s in severity.split(",") if s.strip()}
        rows = [r for r in rows if r["severity"] in sev_set]
    if owner_class:
        cls_set = {c.strip().upper() for c in owner_class.split(",") if c.strip()}
        rows = [r for r in rows if r["owner_class"] in cls_set]
    if domain:
        dom_set = {d.strip().lower() for d in domain.split(",") if d.strip()}
        rows = [r for r in rows if r["domain"] in dom_set]
    if confidence:
        conf_set = {c.strip().upper() for c in confidence.split(",") if c.strip()}
        rows = [r for r in rows if r["confidence"]["band"] in conf_set]
    if q:
        ql = q.lower()
        rows = [r for r in rows
                if ql in r["category"].lower()
                or ql in r["scope"].lower()
                or ql in r["description"].lower()]
    if sort == "risk":
        rows.sort(key=lambda r: -r.get("risk_score", 0))
    elif sort == "confidence":
        rows.sort(key=lambda r: -r["confidence"]["score"])
    return {
        "name": name,
        "source": "validated" if (prefer_validated and _has_validation(sd)) else "raw",
        "validated_available": _has_validation(sd),
        "ownership_available": bool(omap),
        "domains_available": domains_available,
        "confidences_available": confidences_available,
        "count": len(rows),
        "total_risk": round(sum(r.get("risk_score", 0) for r in rows), 1),
        "findings": rows,
    }


# ─── Screenshots (visual evidence per finding) ───────────────────────────────
class ScreenshotCaptureRequest(BaseModel):
    severity_floor: str = "HIGH"     # capture for findings at this severity or above
    max_findings: int = 100
    force: bool = False              # re-capture even if PNG exists


@app.post("/api/scans/{name}/screenshots/capture")
def screenshots_capture(name: str, req: ScreenshotCaptureRequest) -> dict:
    """Capture chromium-headless PNGs for each HTTP-addressable finding scope
    at or above the severity floor. Returns stats: captured / cached / failed."""
    sd = _scan_dir(name)
    findings = _parse_findings(_findings_path(sd, prefer_validated=True))
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    floor = sev_order.get((req.severity_floor or "").upper(), 1)
    targets = [f for f in findings
               if sev_order.get(f["severity"], 9) <= floor][:req.max_findings]
    if not targets:
        return {"ok": True, "captured": 0, "cached": 0, "failed": 0,
                "message": f"no findings at or above {req.severity_floor}"}
    stats = nw_screenshots.capture_for_findings(sd, targets, force=req.force)
    return {"ok": True, **stats,
            "total_findings_considered": len(targets)}


@app.get("/api/scans/{name}/screenshots/{filename}")
def screenshots_serve(name: str, filename: str) -> FileResponse:
    """Serve a captured PNG. Filename comes from the mapping the dashboard
    populates on the findings endpoint, so it's always sanitised already."""
    sd = _scan_dir(name)
    if "/" in filename or "\\" in filename or not filename.endswith(".png"):
        raise HTTPException(400, "invalid filename")
    p = sd / "screenshots" / filename
    if not p.is_file():
        raise HTTPException(404, "screenshot not found")
    return FileResponse(p, media_type="image/png",
                        headers={"Cache-Control": "public, max-age=3600"})


@app.get("/api/scans/{name}/screenshots")
def screenshots_stats(name: str) -> dict:
    sd = _scan_dir(name)
    return nw_screenshots.stats_for_scan(sd)


@app.get("/api/scans/{name}/evidence/{filename}")
def evidence_serve(name: str, filename: str) -> FileResponse:
    """Serve a captured HTTP-evidence text blob. Filename comes from the
    evidence mapping (sanitised hash + .txt)."""
    sd = _scan_dir(name)
    if "/" in filename or "\\" in filename or not filename.endswith(".txt"):
        raise HTTPException(400, "invalid filename")
    p = sd / "report" / "evidence" / filename
    if not p.is_file():
        raise HTTPException(404, "evidence not found")
    return FileResponse(p, media_type="text/plain; charset=utf-8")


# ─── Triage (asset verification + ownership tagging) ─────────────────────────
_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_FQDN_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")


def _is_subdomain_or_domain(host: str) -> bool:
    """Return True only for clean hostnames the analyst would want to
    triage manually: FQDN, no port, no path, no scheme, not an IP."""
    if not host:
        return False
    h = host.strip().lower()
    # Reject anything with a scheme, path, query, port, or whitespace
    if any(c in h for c in (":", "/", "?", "#", " ", "\t")):
        return False
    # Reject pure IPv4
    if _IPV4_RE.match(h):
        return False
    # Must look like FQDN (has at least one dot, valid chars)
    return bool(_FQDN_RE.match(h))


def _collect_hosts_for_triage(scan_dir: Path) -> list[str]:
    """Build the triage list from sources that yield SUBDOMAINS / DOMAINS:
      - recon/input_domains.txt           (apex domains the analyst supplied)
      - recon/subs_all_<domain>.txt       (per-root passive+brute enum)
      - recon/subs_master.txt             (combined, if present)
      - ownership.tsv hosts that look like FQDNs

    Skips IPs, host:port, URLs-with-paths, and crawl URLs. Sorts so the
    apex domains (input) appear first, then the rest alphabetically."""
    apex: list[str] = []
    subs: set[str] = set()
    recon_dir = scan_dir / "recon"

    # 1) Input apex domains
    p_in = recon_dir / "input_domains.txt"
    if p_in.is_file():
        for line in p_in.read_text(errors="ignore").splitlines():
            s = line.split("#", 1)[0].strip().lower()
            if _is_subdomain_or_domain(s) and s not in apex:
                apex.append(s)

    # 2) Per-domain subdomain enumeration output
    if recon_dir.is_dir():
        for p in (
            *recon_dir.glob("subs_all_*.txt"),
            *recon_dir.glob("subs_master*.txt"),
            *recon_dir.glob("subs_*_*.txt"),
        ):
            try:
                for line in p.read_text(errors="ignore").splitlines():
                    # subdomain files sometimes prefix entries with codes;
                    # take the first whitespace-separated token.
                    s = line.split("#", 1)[0].strip().split()[0].lower() if line.strip() else ""
                    if _is_subdomain_or_domain(s):
                        subs.add(s)
            except OSError:
                pass

    # 3) Ownership-classified hosts (validated) that look like FQDNs
    omap = nw_ownership.load(scan_dir)
    for h in omap.keys():
        h_lc = h.lower()
        if _is_subdomain_or_domain(h_lc):
            subs.add(h_lc)

    # Apex domains never appear under "subs" — they are listed separately
    for a in apex:
        subs.discard(a)

    return apex + sorted(subs)


@app.get("/api/scans/{name}/triage")
def triage_list(name: str,
                status: Optional[str] = None,
                only_with_tag: bool = False,
                q: Optional[str] = None) -> dict:
    """List every identified asset with its persisted tag + verification state."""
    sd = _scan_dir(name)
    hosts = _collect_hosts_for_triage(sd)
    rows = nw_tags.merge_with_hosts(hosts)
    # Mark which hosts are input apex domains (came from input_domains.txt)
    apex_set: set[str] = set()
    p_in = sd / "recon" / "input_domains.txt"
    if p_in.is_file():
        for line in p_in.read_text(errors="ignore").splitlines():
            s = line.split("#", 1)[0].strip().lower()
            if s:
                apex_set.add(s)
    # Also enrich each row with ownership class if known (helps when triaging)
    omap = nw_ownership.load(sd)
    cls_lookup = {h.lower(): c.owner_class.value for h, c in omap.items()}
    prov_lookup = {h.lower(): c.provider for h, c in omap.items()}
    for r in rows:
        r["owner_class"] = cls_lookup.get(r["host"], "")
        r["owner_provider"] = prov_lookup.get(r["host"], "")
        r["is_apex"] = r["host"] in apex_set
    # Filters
    if status:
        wanted = {s.strip().lower() for s in status.split(",") if s.strip()}
        rows = [r for r in rows if r["verification_status"] in wanted]
    if only_with_tag:
        rows = [r for r in rows if r["has_tag"]]
    if q:
        ql = q.lower()
        rows = [r for r in rows
                if ql in r["host"].lower()
                or ql in (r["tag"] or "").lower()
                or ql in (r["notes"] or "").lower()]
    # Status counters for chip badges
    counters = {"alive": 0, "dead": 0, "unknown": 0, "tagged": 0, "total": 0}
    for r in rows:
        counters[r["verification_status"]] = counters.get(r["verification_status"], 0) + 1
        counters["total"] += 1
        if r["has_tag"]:
            counters["tagged"] += 1
    return {"name": name, "count": len(rows), "counters": counters, "rows": rows}


class TriageVerifyRequest(BaseModel):
    hosts: list[str]


@app.post("/api/scans/{name}/triage/verify")
def triage_verify(name: str, req: TriageVerifyRequest) -> dict:
    """Probe each host with a HEAD on http/https. Persist the result via
    asset_tags.record_verification so it carries across scan re-runs."""
    sd = _scan_dir(name)  # validates the scan name even if we don't read it
    out = []
    for raw in req.hosts:
        host = (raw or "").strip().lower()
        if not host:
            continue
        # Try https first, fall back to http
        status = "unknown"
        code = 0
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                proc = subprocess.run(
                    ["curl", "-sk", "-A", "berckley-triage/1.0",
                     "-o", "/dev/null",
                     "-w", "%{http_code}",
                     "--max-time", "6",
                     "--connect-timeout", "4",
                     url],
                    capture_output=True, text=True, timeout=10,
                )
                code_str = (proc.stdout or "").strip()
                code = int(code_str) if code_str.isdigit() else 0
            except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                code = 0
            if code and code != 0:
                break
        if code == 0:
            status = "dead"
        else:
            status = "alive"
        rec = nw_tags.record_verification(host, status, code)
        out.append({"host": host, "status": status, "code": code,
                    "verified_at": rec.verified_at})
    return {"ok": True, "verified": len(out), "results": out}


class TriageTagRequest(BaseModel):
    host: str
    tag: str = ""
    notes: str = ""


@app.post("/api/asset_tags")
def triage_set_tag(req: TriageTagRequest) -> dict:
    if not req.host.strip():
        raise HTTPException(400, "host required")
    rec = nw_tags.set_tag(req.host, req.tag, req.notes)
    return {"ok": True, "tag": rec.to_dict()}


@app.delete("/api/asset_tags/{host}")
def triage_delete_tag(host: str) -> dict:
    ok = nw_tags.remove(host)
    if not ok:
        raise HTTPException(404, "no tag for that host")
    return {"ok": True, "removed": host}


@app.get("/api/scans/{name}/extract")
def extract_assets(
    name: str,
    format: str = "json",
    owner_class: Optional[str] = None,
    only_with_findings: bool = False,
    download: bool = False,
) -> object:
    """Export the identified asset inventory.

    Sources merged into a single row-per-host view:
      - ownership.tsv  (host + class + provider + IP + ASN)
      - findings.tsv   (scopes that surfaced an issue → count + max severity)
      - recon/subs_all_<root>.txt  (subdomain enum lists, supplementary)

    Filters:
      owner_class           comma-separated subset of OWNED|SAAS|CDN|CLOUD_SHARED|INTERNAL|EXTERNAL|UNKNOWN
      only_with_findings    drop hosts that produced zero findings

    Formats:
      txt   one host per line (drop-in for nmap/nuclei/ffuf input)
      csv   host,owner_class,provider,ip,asn,findings,max_severity
      json  structured array (default)
    """
    sd = _scan_dir(name)
    omap = nw_ownership.load(sd)
    findings = _parse_findings(_findings_path(sd, prefer_validated=True))
    # Count findings + track max severity per host
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    per_host: dict[str, dict] = {}
    from validator import extract_host as _eh, extract_ip as _ei
    for f in findings:
        host = _eh(f["scope"]).lower() or (_ei(f["scope"]) or "").lower()
        if not host:
            continue
        bucket = per_host.setdefault(host, {"n": 0, "max_sev": "LOW", "max_rank": 9})
        bucket["n"] += 1
        r = sev_rank.get(f["severity"], 9)
        if r < bucket["max_rank"]:
            bucket["max_rank"] = r
            bucket["max_sev"] = f["severity"]

    # Pull in subdomain enum files for hosts ownership/findings missed
    enum_hosts: set[str] = set()
    recon_dir = sd / "recon"
    if recon_dir.is_dir():
        for p in recon_dir.glob("subs_all_*.txt"):
            try:
                for line in p.read_text(errors="ignore").splitlines():
                    s = line.strip().lower()
                    if s and "." in s and not s.startswith("#"):
                        enum_hosts.add(s)
            except OSError:
                pass

    # Union the universe
    all_hosts: set[str] = set()
    all_hosts.update(h.lower() for h in omap.keys())
    all_hosts.update(per_host.keys())
    all_hosts.update(enum_hosts)

    rows = []
    for h in sorted(all_hosts):
        c = omap.get(h) or omap.get(h.lower())
        cls = c.owner_class.value if c else ""
        prov = c.provider if c else ""
        ip = c.ip if c else ""
        asn = c.asn if c else ""
        fh = per_host.get(h, {"n": 0, "max_sev": ""})
        rows.append({
            "host":         h,
            "owner_class":  cls,
            "provider":     prov,
            "ip":           ip,
            "asn":          asn,
            "findings":     fh["n"],
            "max_severity": fh["max_sev"] if fh["n"] else "",
        })

    if owner_class:
        cls_set = {c.strip().upper() for c in owner_class.split(",") if c.strip()}
        rows = [r for r in rows if r["owner_class"] in cls_set]
    if only_with_findings:
        rows = [r for r in rows if r["findings"] > 0]

    fmt = (format or "json").lower()
    if fmt == "txt":
        body = "\n".join(r["host"] for r in rows) + ("\n" if rows else "")
        headers = {}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="{name}_assets.txt"'
        return PlainTextResponse(body, headers=headers)
    if fmt == "csv":
        import io, csv
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["host", "owner_class", "provider", "ip", "asn",
                    "findings", "max_severity"])
        for r in rows:
            w.writerow([r["host"], r["owner_class"], r["provider"], r["ip"],
                        r["asn"], r["findings"], r["max_severity"]])
        headers = {}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="{name}_assets.csv"'
        return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers=headers)
    # json (default)
    return JSONResponse({
        "name": name,
        "count": len(rows),
        "sources": {
            "ownership":  len(omap),
            "findings":   sum(1 for h in per_host),
            "enum_files": len(enum_hosts),
        },
        "filters": {
            "owner_class": owner_class,
            "only_with_findings": only_with_findings,
        },
        "rows": rows,
    })


@app.get("/api/scans/{name}/ownership")
def scan_ownership(name: str, owner_class: Optional[str] = None) -> dict:
    sd = _scan_dir(name)
    raw = nw_ownership.load(sd)
    rows = [
        {"host": h, **c.to_dict()}
        for h, c in sorted(raw.items())
    ]
    if owner_class:
        cls_set = {c.strip().upper() for c in owner_class.split(",") if c.strip()}
        rows = [r for r in rows if r["class"] in cls_set]
    by_class: dict[str, int] = {}
    for h, c in raw.items():
        by_class[c.owner_class.value] = by_class.get(c.owner_class.value, 0) + 1
    return {
        "name": name,
        "count": len(rows),
        "total": len(raw),
        "by_class": [{"class": k, "count": v}
                     for k, v in sorted(by_class.items(), key=lambda x: -x[1])],
        "hosts": rows,
    }


@app.get("/api/scans/{name}/audit")
def scan_audit(name: str, verdict: Optional[str] = None) -> dict:
    sd = _scan_dir(name)
    rows = _parse_audit(sd)
    if verdict:
        verdicts = {v.strip().upper() for v in verdict.split(",") if v.strip()}
        rows = [r for r in rows if r["verdict"] in verdicts]
    return {"name": name, "count": len(rows), "audit": rows}


@app.post("/api/scans/{name}/validate")
def validate_scan(name: str) -> dict:
    sd = _scan_dir(name)
    try:
        stats = nw_validator.run_validation(sd)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"validation failed: {e}")
    return stats


# ─── Suppressions ─────────────────────────────────────────────────────────────
class SuppressionIn(BaseModel):
    category: str
    scope: str
    reason: str = ""
    expires_at: Optional[str] = None


@app.get("/api/suppressions")
def list_suppressions() -> dict:
    items = nw_suppressions.load()
    return {
        "count": len(items),
        "active": sum(1 for s in items if s.is_active()),
        "file": str(nw_suppressions.SUPPRESSIONS_FILE),
        "suppressions": [s.__dict__ | {"active": s.is_active()} for s in items],
    }


@app.post("/api/suppressions")
def add_suppression(req: SuppressionIn) -> dict:
    if not req.category.strip() or not req.scope.strip():
        raise HTTPException(400, "category and scope are required")
    s = nw_suppressions.add(req.category, req.scope, req.reason,
                            expires_at=req.expires_at or None)
    return {"ok": True, "id": s.id, "suppression": s.__dict__}


@app.delete("/api/suppressions/{sid}")
def delete_suppression(sid: str) -> dict:
    ok = nw_suppressions.remove(sid)
    if not ok:
        raise HTTPException(404, "not found")
    return {"ok": True, "removed": sid}


# ─── Diff ─────────────────────────────────────────────────────────────────────
@app.get("/api/scans/{name}/diff")
def diff_scan(name: str, against: Optional[str] = None,
              source: str = "validated") -> dict:
    sd = _scan_dir(name)
    # Auto-pick a comparable previous scan if `against` is omitted.
    if not against:
        scans = _list_scans()
        current = next((s for s in scans if s["name"] == name), None)
        if not current:
            raise HTTPException(404, "scan not found")
        prev = nw_diff.pick_previous(scans, current)
        if not prev:
            return {
                "auto": True,
                "a": name,
                "b": None,
                "message": "no previous scan with overlapping domains",
                "available": [{"name": s["name"], "mtime_iso": s["mtime_iso"],
                               "domains": s["domains"]}
                              for s in scans if s["name"] != name],
            }
        against = prev
    other = _scan_dir(against)
    return nw_diff.diff_scans(sd, other, source=source)


@app.get("/api/scans/{name}/assets")
def scan_assets(name: str, type: Optional[str] = None) -> dict:
    sd = _scan_dir(name)
    rows = _parse_assets(sd / "assets" / "discovered.log")
    by_type: dict[str, int] = defaultdict(int)
    for r in rows:
        by_type[r["type"]] += 1
    if type:
        rows = [r for r in rows if r["type"].upper() == type.upper()]
    return {
        "name": name,
        "count": len(rows),
        "types": [{"type": k, "count": v} for k, v in sorted(by_type.items(), key=lambda x: -x[1])],
        "assets": rows[:5000],
    }


@app.get("/api/scans/{name}/log", response_class=PlainTextResponse)
def scan_log(name: str, tail: int = 500) -> PlainTextResponse:
    sd = _scan_dir(name)
    p = sd / "report" / "master.log"
    if not p.is_file():
        return PlainTextResponse("(no master.log yet)")
    try:
        with p.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, max(tail * 200, 16384))
            f.seek(max(0, size - chunk))
            data = f.read().decode(errors="replace")
    except OSError as e:
        return PlainTextResponse(f"(error reading log: {e})")
    lines = data.splitlines()[-tail:]
    return PlainTextResponse("\n".join(lines))


@app.get("/api/scans/{name}/log/stream")
async def scan_log_stream(name: str, request: Request) -> StreamingResponse:
    sd = _scan_dir(name)
    log_path = sd / "report" / "master.log"

    async def gen():
        last_size = 0
        # Send any existing content first
        while True:
            if await request.is_disconnected():
                break
            try:
                if log_path.is_file():
                    size = log_path.stat().st_size
                    if size > last_size:
                        with log_path.open("rb") as f:
                            f.seek(last_size)
                            chunk = f.read(size - last_size).decode(errors="replace")
                        last_size = size
                        for line in chunk.splitlines():
                            yield f"data: {json.dumps({'line': line})}\n\n"
                    elif size < last_size:
                        # log rotated/truncated
                        last_size = 0
            except OSError:
                pass
            # Stop streaming if scan is finished AND no new bytes came in
            if name not in RUNNING and log_path.is_file() and log_path.stat().st_size == last_size:
                yield f"data: {json.dumps({'event': 'eof'})}\n\n"
                await asyncio.sleep(2)
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ─── Launching scans ──────────────────────────────────────────────────────────
class LaunchRequest(BaseModel):
    domains: str = ""           # comma-separated (used when no scope_hosts)
    targets: str = ""           # IP[:port] comma-separated
    phase: str = "all"
    threads: int = 20
    rate: int = 50
    name_suffix: str = ""
    # If provided, overrides `domains`: an explicit, user-curated list of hosts
    # to put into recon/input_domains.txt for the scan.
    scope_hosts: Optional[list[str]] = None
    # Supplier / passive mode — outside-in only (no aggressive scanning).
    passive: bool = False
    supplier_name: str = ""


class IntakeRequest(BaseModel):
    domains: list[str]


@app.post("/api/intake")
def run_intake(req: IntakeRequest) -> dict:
    if not req.domains:
        raise HTTPException(400, "domains required")
    # Cap to keep per-request work bounded — analyst can run multiple times.
    domains = [d.strip().lower() for d in req.domains if d and d.strip()][:10]
    result = nw_intake.run_intake(domains)
    return nw_intake.to_payload(result)


@app.post("/api/scans")
async def launch_scan(req: LaunchRequest) -> dict:
    if not SCANNER.is_file():
        raise HTTPException(500, f"scanner not found at {SCANNER}")

    # Prefer the explicit curated scope from intake, fall back to free-form
    # comma-separated domains for quick launches.
    if req.scope_hosts:
        scope_hosts = [h.strip().lower() for h in req.scope_hosts
                       if h and h.strip()]
        scope_hosts = sorted(set(scope_hosts))
    else:
        scope_hosts = []

    if not scope_hosts and not req.domains.strip() and not req.targets.strip():
        raise HTTPException(400, "need at least one domain or target")
    if req.phase not in ("all", "1", "2", "3", "4", "5", "6", "7", "8", "9"):
        raise HTTPException(400, "invalid phase")
    if not (1 <= int(req.threads) <= 200):
        raise HTTPException(400, "threads out of range")
    if not (1 <= int(req.rate) <= 1000):
        raise HTTPException(400, "rate out of range")

    suffix = "".join(c for c in req.name_suffix if c.isalnum() or c in "._-")[:32]
    # Supplier scans get a recognizable dir prefix + a supplier_name-derived slug.
    if req.passive:
        sup_slug = "".join(c for c in req.supplier_name if c.isalnum() or c in "._-")[:32]
        suffix = f"supplier_{sup_slug}" if sup_slug else (suffix or "supplier")
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    name = f"pentest_{suffix + '_' if suffix else ''}{ts}"
    out_dir = ROOT / name

    cmd = ["bash", str(SCANNER), "-o", str(out_dir), "-p", req.phase,
           "-t", str(req.threads), "-r", str(req.rate)]
    if req.passive:
        cmd.append("-P")   # outside-in only — no aggressive scanning
    if scope_hosts:
        # Materialize the curated scope as a file the scanner reads with `-d`.
        out_dir.mkdir(parents=True, exist_ok=True)
        scope_file = out_dir / "scope.txt"
        scope_file.write_text("\n".join(scope_hosts) + "\n")
        cmd += ["-d", str(scope_file)]
    elif req.domains.strip():
        cmd += ["-d", req.domains.strip()]
    if req.targets.strip():
        cmd += ["-i", req.targets.strip()]

    out_dir.mkdir(parents=True, exist_ok=True)
    # Pre-create master.log so the stream can attach immediately
    (out_dir / "report").mkdir(parents=True, exist_ok=True)
    (out_dir / "report" / "master.log").touch()
    # Tag supplier (passive) scans so the Suppliers tab can find + label them.
    if req.passive:
        marker = {
            "name": req.supplier_name.strip() or (req.domains.strip() or "supplier"),
            "domains": req.domains.strip(),
            "passive": True,
            "created": ts,
        }
        (out_dir / "report" / ".supplier.json").write_text(json.dumps(marker, indent=2))

    proc = subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    RUNNING[name] = RunningScan(name, proc, time.time())

    # Schedule the reaper on the running event loop. We're now in an async
    # endpoint, so create_task() targets the live loop (no get_event_loop()
    # which uvloop refuses to call from non-loop threads).
    asyncio.create_task(_reap(name))
    return {"ok": True, "name": name, "cmd": " ".join(shlex.quote(c) for c in cmd)}


async def _reap(name: str) -> None:
    rs = RUNNING.get(name)
    if not rs:
        return
    while True:
        rc = rs.proc.poll()
        if rc is not None:
            RUNNING.pop(name, None)
            return
        await asyncio.sleep(2)


@app.delete("/api/scans/{name}")
def delete_scan(name: str) -> dict:
    """Remove a scan directory and all its files. Refuses to delete a scan
    that is currently running -- the caller must stop it first."""
    sd = _scan_dir(name)
    if name in RUNNING:
        raise HTTPException(409, "scan is currently running -- stop it first")
    import shutil
    try:
        shutil.rmtree(sd)
    except OSError as e:
        raise HTTPException(500, f"delete failed: {e}")
    return {"ok": True, "deleted": name}


@app.post("/api/scans/{name}/stop")
def stop_scan(name: str) -> dict:
    rs = RUNNING.get(name)
    if not rs:
        raise HTTPException(404, "not running")
    try:
        os.killpg(os.getpgid(rs.proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    return {"ok": True, "stopping": name}


# ─── Reports ──────────────────────────────────────────────────────────────────
@app.post("/api/scans/{name}/reports/{kind}")
def generate_report(name: str, kind: str) -> dict:
    sd = _scan_dir(name)
    if kind == "mgmt":
        script = MGMT_REPORT
        out = sd / "report" / "management_report.html"
        theme = "mgmt"
    elif kind == "soc":
        script = SOC_REPORT
        out = sd / "report" / "soc_report.html"
        theme = "soc"
    else:
        raise HTTPException(400, "kind must be mgmt|soc")
    if not script.is_file():
        raise HTTPException(500, f"report script missing: {script}")
    try:
        subprocess.run(["bash", str(script), str(sd), str(out)],
                       check=True, capture_output=True, timeout=300)
    except subprocess.CalledProcessError as e:
        raise HTTPException(500, f"report failed: {e.stderr.decode(errors='replace')[:500]}")

    # Inject validation / ownership / diff sections into the generated HTML.
    # Each section silently no-ops if its underlying data isn't present yet
    # (e.g. validation hasn't been run, or there's no comparable prior scan).
    extras_injected = False
    extras_error = ""
    try:
        if out.is_file():
            html_str = out.read_text(errors="ignore")
            extras = nw_extras.build_all(sd, theme=theme)
            if extras.strip():
                out.write_text(nw_extras.inject(html_str, extras))
                extras_injected = True
    except Exception as e:
        extras_error = str(e)

    return {
        "ok": True,
        "path": str(out),
        "url": f"/api/scans/{name}/reports/{kind}",
        "extras_injected": extras_injected,
        "extras_error": extras_error,
    }


@app.get("/api/scans/{name}/reports/{kind}/pdf")
def export_report_pdf(name: str, kind: str) -> FileResponse:
    """Render the HTML report to PDF using headless Chromium. The PDF is
    cached next to the HTML so repeated downloads are instant."""
    sd = _scan_dir(name)
    fname = "management_report.html" if kind == "mgmt" else "soc_report.html" if kind == "soc" else None
    if not fname:
        raise HTTPException(400, "kind must be mgmt|soc")
    html_path = sd / "report" / fname
    if not html_path.is_file():
        raise HTTPException(404, "report HTML not yet generated -- run Generate first")

    pdf_name = fname.replace(".html", ".pdf")
    pdf_path = sd / "report" / pdf_name

    # Regenerate if PDF is stale or missing
    needs_render = (
        not pdf_path.is_file()
        or pdf_path.stat().st_mtime < html_path.stat().st_mtime
    )
    if needs_render:
        chrome = None
        for cand in ("chromium", "chromium-browser", "google-chrome", "chrome"):
            if subprocess.run(["which", cand], capture_output=True).returncode == 0:
                chrome = cand
                break
        if not chrome:
            raise HTTPException(500, "chromium not installed in container")
        try:
            subprocess.run([
                chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
                "--hide-scrollbars", "--no-pdf-header-footer",
                "--virtual-time-budget=8000",
                f"--print-to-pdf={pdf_path}",
                f"file://{html_path}",
            ], check=True, capture_output=True, timeout=120)
        except subprocess.CalledProcessError as e:
            err = (e.stderr.decode(errors="replace") or "")[:400]
            raise HTTPException(500, f"chromium pdf render failed: {err}")
        except subprocess.TimeoutExpired:
            raise HTTPException(500, "chromium pdf render timed out (>120s)")

    friendly = _friendly_name(name)
    suffix = "management" if kind == "mgmt" else "soc"
    dl_name = f"{friendly['slug']}_{suffix}.pdf"
    return FileResponse(pdf_path, media_type="application/pdf",
                        filename=dl_name)


@app.get("/api/scans/{name}/reports/{kind}")
def view_report(name: str, kind: str, download: bool = False) -> FileResponse:
    sd = _scan_dir(name)
    fname = "management_report.html" if kind == "mgmt" else "soc_report.html" if kind == "soc" else None
    if not fname:
        raise HTTPException(400, "kind must be mgmt|soc")
    p = sd / "report" / fname
    if not p.is_file():
        raise HTTPException(404, f"{fname} not yet generated")
    headers = {}
    # Always advertise a friendly filename so save-as / browser title is nice.
    friendly = _friendly_name(name)
    suffix = "management" if kind == "mgmt" else "soc"
    dl_name = f"{friendly['slug']}_{suffix}.html"
    disp = "attachment" if download else "inline"
    headers["Content-Disposition"] = f'{disp}; filename="{dl_name}"'
    return FileResponse(p, media_type="text/html", headers=headers)


# Static UI (after API routes so /api wins)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
