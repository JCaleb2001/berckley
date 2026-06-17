"""
report_extras.py — extra HTML sections injected into the bash-generated reports.

Each generator takes a pentest_dir + a theme ('mgmt' or 'soc') and returns an
HTML fragment styled to fit that report's existing palette. We do NOT depend on
the bash scripts' CSS — every fragment carries its own scoped <style> so it
looks consistent even if the upstream layout shifts.

Three sections:
  validation_summary_html — what the validation layer suppressed/downgraded
  ownership_html          — asset ownership breakdown
  diff_html               — change since the most recent comparable prior run
"""
from __future__ import annotations

import html
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

import diff as nw_diff
import ownership as nw_ownership
import suppressions as nw_suppressions
import risk as nw_risk
import screenshots as nw_screenshots
import taxonomy as nw_taxonomy
import scorecard as nw_scorecard

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ─── Themes ───────────────────────────────────────────────────────────────────
# Each theme is a self-contained CSS string scoped under a wrapper class so it
# can't bleed into the host report's own styles.
THEMES = {
    "mgmt": {
        "wrap_class": "nw-ext-mgmt",
        "css": """
        .nw-ext-mgmt { font-family: Georgia, "Times New Roman", serif; color:#1a1a1a;
            margin: 36px auto; max-width: 1100px; padding: 0 24px; }
        .nw-ext-mgmt h2 { font-family: Georgia, serif; color:#1e3a5f;
            border-bottom: 2px solid #1e3a5f; padding-bottom:6px; margin-top:48px;
            font-weight: 600; letter-spacing: .02em; }
        .nw-ext-mgmt h3 { color:#1e3a5f; font-family: Georgia, serif; margin: 24px 0 8px; }
        .nw-ext-mgmt p  { color:#333; line-height: 1.55; }
        .nw-ext-mgmt table { width:100%; border-collapse: collapse; margin: 12px 0;
            font-family: Helvetica, Arial, sans-serif; font-size: 13px; }
        .nw-ext-mgmt th { background:#1e3a5f; color:#fff; text-align:left;
            padding:6px 10px; font-weight: 600; letter-spacing: .04em; font-size: 11px; }
        .nw-ext-mgmt td { padding:6px 10px; border-bottom: 1px solid #e6e6e6; vertical-align: top; }
        .nw-ext-mgmt tr:nth-child(even) td { background:#f9f9f9; }
        .nw-ext-mgmt .grid { display:grid; grid-template-columns: repeat(4, 1fr);
            gap: 12px; margin: 16px 0; }
        .nw-ext-mgmt .stat { border: 1px solid #d6d6d6; padding: 14px;
            background:#fafafa; }
        .nw-ext-mgmt .stat .lbl { font-size: 11px; color:#666;
            letter-spacing: .14em; text-transform: uppercase; }
        .nw-ext-mgmt .stat .val { font-size: 28px; color:#1e3a5f;
            font-weight: 700; margin-top: 2px; }
        .nw-ext-mgmt .stat .delta { font-size: 11px; color:#666; margin-top: 2px; }
        .nw-ext-mgmt .pill { display:inline-block; padding:1px 8px; font-size:11px;
            border-radius: 2px; border:1px solid; }
        .nw-ext-mgmt .pill.crit { color:#9c1b2c; border-color:#9c1b2c; }
        .nw-ext-mgmt .pill.high { color:#b65a00; border-color:#b65a00; }
        .nw-ext-mgmt .pill.med  { color:#7a6200; border-color:#7a6200; }
        .nw-ext-mgmt .pill.low  { color:#1e3a5f; border-color:#1e3a5f; }
        .nw-ext-mgmt .pill.owned { color:#2e7d32; border-color:#2e7d32; }
        .nw-ext-mgmt .pill.saas  { color:#5e35b1; border-color:#5e35b1; }
        .nw-ext-mgmt .pill.cdn   { color:#c2185b; border-color:#c2185b; }
        .nw-ext-mgmt .pill.cloud { color:#b65a00; border-color:#b65a00; }
        .nw-ext-mgmt .pill.internal,.nw-ext-mgmt .pill.unknown,.nw-ext-mgmt .pill.external
            { color:#666; border-color:#999; }
        .nw-ext-mgmt .dim { color:#777; }
        .nw-ext-mgmt .drift-worse  { color:#9c1b2c; font-weight: bold; }
        .nw-ext-mgmt .drift-better { color:#2e7d32; font-weight: bold; }
        """,
    },
    "soc": {
        "wrap_class": "nw-ext-soc",
        "css": """
        .nw-ext-soc { font-family: "JetBrains Mono", "Fira Code", ui-monospace, monospace;
            color:#c3e8c8; background:#06090a; padding: 32px; margin: 30px 0;
            border-top: 2px solid #173238; border-bottom: 2px solid #173238; }
        .nw-ext-soc h2 { color:#00d8ff; letter-spacing: .14em; text-transform: uppercase;
            font-size: 14px; margin-top: 32px; border-bottom:1px solid #173238;
            padding-bottom: 6px; }
        .nw-ext-soc h3 { color:#00d8ff; font-size: 12px; letter-spacing: .14em;
            text-transform: uppercase; margin: 18px 0 6px; }
        .nw-ext-soc p { color:#8b96a3; line-height: 1.45; font-size: 12px; }
        .nw-ext-soc table { width:100%; border-collapse: collapse; margin: 8px 0;
            font-size: 11px; }
        .nw-ext-soc th { background:#06090c; color:#8b96a3; text-align:left;
            padding:5px 8px; font-weight: 500; letter-spacing: .14em;
            font-size: 10px; text-transform: uppercase; border-bottom:1px solid #173238; }
        .nw-ext-soc td { padding:5px 8px; border-bottom: 1px solid #11171b;
            vertical-align: top; color:#c3e8c8; }
        .nw-ext-soc td.scope { color:#4fc3ff; word-break: break-all; }
        .nw-ext-soc td.dim { color:#4a5662; }
        .nw-ext-soc .grid { display:grid; grid-template-columns: repeat(4, 1fr);
            gap: 10px; margin: 12px 0; }
        .nw-ext-soc .stat { border:1px solid #173238; padding:10px; background:#0a1015; }
        .nw-ext-soc .stat .lbl { color:#8b96a3; font-size:10px;
            letter-spacing:.18em; text-transform: uppercase; }
        .nw-ext-soc .stat .val { color:#00d8ff; font-size:26px; font-weight:700;
            margin-top: 2px; font-family: "Share Tech Mono", monospace; }
        .nw-ext-soc .stat .delta { color:#8b96a3; font-size: 10px; }
        .nw-ext-soc .pill { display:inline-block; padding:1px 6px; font-size:10px;
            letter-spacing:.06em; border:1px solid; }
        .nw-ext-soc .pill.crit { color:#ff3b5c; }
        .nw-ext-soc .pill.high { color:#ff8c1a; }
        .nw-ext-soc .pill.med  { color:#ffd400; }
        .nw-ext-soc .pill.low  { color:#6ec1ff; }
        .nw-ext-soc .pill.owned { color:#00d8ff; }
        .nw-ext-soc .pill.saas  { color:#b47bff; }
        .nw-ext-soc .pill.cdn   { color:#ff8cce; }
        .nw-ext-soc .pill.cloud { color:#ffb86c; }
        .nw-ext-soc .pill.internal,.nw-ext-soc .pill.unknown,.nw-ext-soc .pill.external
            { color:#8b96a3; }
        .nw-ext-soc .drift-worse  { color:#ff3b5c; }
        .nw-ext-soc .drift-better { color:#00d8ff; }
        """,
    },
}

SEV_PILL = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
OWN_PILL = {"OWNED": "owned", "SAAS": "saas", "CDN": "cdn",
            "CLOUD_SHARED": "cloud", "INTERNAL": "internal",
            "UNKNOWN": "unknown", "EXTERNAL": "external"}

SEV_COLORS = {"CRITICAL": "#ff3b5c", "HIGH": "#ff8c1a",
              "MEDIUM": "#ffd400",   "LOW": "#6ec1ff"}
OWN_COLORS = {"OWNED": "#00d8ff", "SAAS": "#b47bff",
              "CLOUD_SHARED": "#ffb86c", "CDN": "#ff8cce",
              "INTERNAL": "#8694a3", "EXTERNAL": "#ff6b6b",
              "UNKNOWN": "#4d5965"}


# ─── SVG chart primitives ─────────────────────────────────────────────────────
# Pure SVG — no JS, no CDN — so the chart renders identically inside a
# downloaded report HTML or an offline email attachment.
def _svg_donut(data: list[tuple[str, int, str]], sublabel: str,
               size: int = 200, theme: str = "mgmt") -> str:
    """data: list of (label, value, color)."""
    import math
    total = sum(v for _, v, _ in data)
    cx = cy = size // 2
    r = int(size * 0.40)
    sw = int(size * 0.13)
    circ = 2 * math.pi * r
    segments = []
    offset = 0.0
    if total == 0:
        track_color = "#dcdee0" if theme == "mgmt" else "#1c232c"
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{track_color}" stroke-width="{sw}"/>')
    else:
        for label, value, color in data:
            if value <= 0:
                continue
            length = (value / total) * circ
            segments.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="{color}" stroke-width="{sw}" '
                f'stroke-dasharray="{length:.2f} {circ - length:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 {cx} {cy})"/>')
            offset += length

    text_color = "#1a1a1a" if theme == "mgmt" else "#f3f7fb"
    sub_color = "#666" if theme == "mgmt" else "#8694a3"
    title_font = "Georgia, serif" if theme == "mgmt" else "'Space Grotesk', sans-serif"
    legend_rows = []
    for label, value, color in data:
        if value <= 0:
            continue
        pct = round(100 * value / total) if total else 0
        legend_rows.append(
            f'<div class="lg-row">'
            f'<span class="lg-dot" style="background:{color}"></span>'
            f'<span class="lg-lbl">{_h(label)}</span>'
            f'<span class="lg-val">{value}</span>'
            f'<span class="lg-pct">{pct}%</span>'
            f'</div>')
    legend_html = "".join(legend_rows) or '<div class="lg-row dim">no data</div>'

    return f'''
    <div class="svg-chart svg-donut">
      <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
        {''.join(segments)}
        <text x="{cx}" y="{cy - 2}" text-anchor="middle"
          fill="{text_color}" font-family="{title_font}"
          font-size="28" font-weight="700">{total}</text>
        <text x="{cx}" y="{cy + 18}" text-anchor="middle"
          fill="{sub_color}" font-family="Inter, sans-serif"
          font-size="10" font-weight="600"
          letter-spacing="1.5">{sublabel.upper()}</text>
      </svg>
      <div class="svg-legend">{legend_html}</div>
    </div>
    '''


def _svg_hbar(rows: list[tuple[str, float, str, str]], theme: str = "mgmt") -> str:
    """rows: (label, value, color, optional sub-text)."""
    if not rows:
        return '<div class="svg-chart svg-empty">no data</div>'
    max_v = max(v for _, v, _, _ in rows) or 1
    out = ['<div class="svg-chart svg-hbar">']
    for label, value, color, sub in rows:
        pct = max(2, min(100, (value / max_v) * 100))
        out.append(
            f'<div class="hb-row" title="{_h(sub)}">'
            f'<span class="hb-label" title="{_h(label)}">{_h(label)}</span>'
            f'<span class="hb-track"><span class="hb-bar" '
            f'style="width:{pct:.1f}%;background:{color}"></span></span>'
            f'<span class="hb-val">{value:.1f}</span>'
            f'</div>')
    out.append('</div>')
    return "".join(out)


_CHART_CSS_COMMON = """
.svg-chart { font-family: 'Inter', sans-serif; }
.svg-donut { display: grid; grid-template-columns: auto 1fr; gap: 16px; align-items: center; }
.svg-donut svg { display: block; }
.svg-legend { display: flex; flex-direction: column; gap: 4px; }
.lg-row { display: grid; grid-template-columns: 10px 1fr auto auto; gap: 8px; align-items: center;
          font-family: 'JetBrains Mono', monospace; font-size: 11.5px; }
.lg-dot { width: 10px; height: 10px; border-radius: 2px; }
.lg-val { font-weight: 600; }
.lg-pct { font-size: 10.5px; opacity: .75; }
.svg-hbar { display: flex; flex-direction: column; gap: 7px; }
.hb-row { display: grid; grid-template-columns: minmax(140px, 280px) 1fr 56px;
          gap: 12px; align-items: center; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; }
.hb-label { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hb-track { display: block; height: 14px; border-radius: 3px; overflow: hidden; }
.hb-bar { display: block; height: 100%; border-radius: 3px; }
.hb-val { text-align: right; font-weight: 700; font-variant-numeric: tabular-nums; }
.charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 16px 0; }
.charts-row .chart-card { padding: 16px 18px; border-radius: 8px; }
.charts-row .chart-card h4 { margin: 0 0 10px 0; font-family: 'Space Grotesk', sans-serif;
                              font-size: 13px; font-weight: 600; letter-spacing: -.005em; }
"""


def charts_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    """Build a Charts section: severity donut + ownership donut + top-risk bar.
    Reads the same TSVs the dashboard summary endpoint uses, so the charts
    always reflect the report's underlying data."""
    findings = _load_findings(pentest_dir)
    if not findings:
        return ""

    # Severity counts
    sev_counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f["severity"] in sev_counts:
            sev_counts[f["severity"]] += 1
    sev_data = [(s.capitalize(), sev_counts[s], SEV_COLORS[s]) for s in SEVERITIES]

    # Ownership counts
    raw_own = nw_ownership.load(pentest_dir)
    own_counts: dict[str, int] = {}
    for h, c in raw_own.items():
        own_counts[c.owner_class.value] = own_counts.get(c.owner_class.value, 0) + 1
    own_order = ["OWNED", "SAAS", "CLOUD_SHARED", "CDN", "INTERNAL", "EXTERNAL", "UNKNOWN"]
    own_data = [(c, own_counts.get(c, 0), OWN_COLORS[c])
                for c in own_order if own_counts.get(c, 0) > 0]

    # Top risks
    omap = {h.lower(): c.to_dict() for h, c in raw_own.items()}
    def _lookup(scope):
        from validator import extract_host, extract_ip
        k = (scope or "").strip().lower()
        if k in omap: return omap[k]["class"]
        h = extract_host(scope).lower()
        if h in omap: return omap[h]["class"]
        ip = extract_ip(scope) or ""
        if ip in omap: return omap[ip]["class"]
        return ""
    enriched = []
    for f in findings:
        oc = _lookup(f["scope"])
        enriched.append({
            **f, "owner_class": oc,
            "risk_score": nw_risk.score(f["severity"], f["category"], f["scope"], oc),
        })
    hosts = nw_risk.aggregate_by_host(enriched)[:10]
    bar_rows = [(h["scope"], h["total_risk"],
                 SEV_COLORS.get(h["max_severity"], SEV_COLORS["LOW"]),
                 f"{h['n']} findings · max {h['max_severity']}")
                for h in hosts]

    wrap = THEMES[theme]["wrap_class"]
    base_css = THEMES[theme]["css"]

    own_html = (
        _svg_donut(own_data, "Hosts", theme=theme)
        if own_data else
        '<div class="dim" style="padding:30px;text-align:center;font-style:italic">'
        'No ownership data — validation has not been run on this scan.</div>'
    )
    bar_html = (
        _svg_hbar(bar_rows, theme=theme)
        if bar_rows else
        '<div class="dim" style="padding:30px;text-align:center;font-style:italic">'
        'No risk data available.</div>'
    )

    return f"""
    <style>{base_css}{_CHART_CSS_COMMON}</style>
    <div class="{wrap}">
      <h2>Visual Summary</h2>
      <p>Severity distribution, asset ownership breakdown, and the ten
      highest-risk hosts at a glance. Same data as the tables below, charted.</p>

      <div class="charts-row">
        <div class="chart-card">
          <h4>Severity Distribution</h4>
          {_svg_donut(sev_data, "Total", theme=theme)}
        </div>
        <div class="chart-card">
          <h4>Asset Ownership</h4>
          {own_html}
        </div>
      </div>

      <h3>Top 10 Hosts by Risk</h3>
      {bar_html}
    </div>
    """


def _h(s) -> str:
    return html.escape("" if s is None else str(s), quote=False)


# ─── Audit (validation summary) ───────────────────────────────────────────────
def _load_audit(pentest_dir: Path) -> list[dict]:
    p = pentest_dir / "report" / "findings_audit.tsv"
    if not p.is_file():
        return []
    rows = []
    with p.open("r", errors="ignore") as f:
        next(f, None)  # header
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 8:
                continue
            rows.append({
                "orig_severity": parts[0],
                "new_severity":  parts[1],
                "category":      parts[2],
                "scope":         parts[3],
                "description":   parts[4],
                "verdict":       parts[5],
                "rule":          parts[6],
                "reason":        parts[7],
            })
    return rows


def validation_summary_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    audit = _load_audit(pentest_dir)
    if not audit:
        return ""
    sup = [r for r in audit if r["verdict"] == "SUPPRESS"]
    dgr = [r for r in audit if r["verdict"] == "DOWNGRADE"]
    kept = [r for r in audit if r["verdict"] == "KEEP"]
    total = len(audit)
    by_rule = Counter(r["rule"] for r in (sup + dgr) if r["rule"])

    sup_list = nw_suppressions.load()
    active_sup = [s for s in sup_list if s.is_active()]

    wrap = THEMES[theme]["wrap_class"]
    css = THEMES[theme]["css"]

    rule_rows = "".join(
        f"<tr><td>{_h(rule)}</td><td>{n}</td></tr>"
        for rule, n in by_rule.most_common()
    ) or '<tr><td colspan="2" class="dim">no automatic adjustments</td></tr>'

    user_sup_rows = "".join(
        f"<tr><td>{_h(s.category)}</td><td>{_h(s.scope)}</td><td>{_h(s.reason)}</td>"
        f"<td class=\"dim\">{_h(s.created_at)}</td></tr>"
        for s in active_sup
    ) or '<tr><td colspan="4" class="dim">no user-accepted suppressions</td></tr>'

    return f"""
    <style>{css}</style>
    <div class="{wrap}">
      <h2>Validation summary</h2>
      <p>The findings shown in the body of this report have already been processed
      by the validation layer: false positives caught by re-probing have been
      removed, and findings on infrastructure the organisation does not control
      (third-party SaaS, CDN edge, internal-only IPs) have been re-weighted.
      The original scanner output is preserved on disk for audit.</p>

      <div class="grid">
        <div class="stat"><div class="lbl">Total findings</div><div class="val">{total}</div></div>
        <div class="stat"><div class="lbl">Kept as-is</div><div class="val">{len(kept)}</div></div>
        <div class="stat"><div class="lbl">Downgraded</div><div class="val">{len(dgr)}</div></div>
        <div class="stat"><div class="lbl">Suppressed</div><div class="val">{len(sup)}</div></div>
      </div>

      <h3>Adjustments by rule</h3>
      <table>
        <thead><tr><th>Rule</th><th>Findings adjusted</th></tr></thead>
        <tbody>{rule_rows}</tbody>
      </table>

      <h3>Persistent suppression list (user-accepted)</h3>
      <p>{len(active_sup)} active entries.</p>
      <table>
        <thead><tr><th>Category</th><th>Scope</th><th>Reason</th><th>Added</th></tr></thead>
        <tbody>{user_sup_rows}</tbody>
      </table>
    </div>
    """


# ─── Ownership breakdown ──────────────────────────────────────────────────────
def _load_ownership(pentest_dir: Path) -> list[dict]:
    p = pentest_dir / "report" / "ownership.tsv"
    if not p.is_file():
        return []
    rows = []
    with p.open("r", errors="ignore") as f:
        next(f, None)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            rows.append({
                "host": parts[0], "class": parts[1], "provider": parts[2],
                "ip": parts[3], "asn": parts[4], "evidence": parts[5],
            })
    return rows


def ownership_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    own = _load_ownership(pentest_dir)
    if not own:
        return ""
    by_class = Counter(r["class"] for r in own)
    providers_by_class: dict[str, Counter] = defaultdict(Counter)
    for r in own:
        if r["provider"]:
            providers_by_class[r["class"]][r["provider"]] += 1

    wrap = THEMES[theme]["wrap_class"]
    css = THEMES[theme]["css"]

    # Class table
    class_rows = ""
    for cls in ("OWNED", "SAAS", "CLOUD_SHARED", "CDN", "INTERNAL", "EXTERNAL", "UNKNOWN"):
        n = by_class.get(cls, 0)
        if n == 0 and cls not in ("OWNED",):
            continue
        provs = providers_by_class.get(cls, Counter())
        top_provs = ", ".join(f"{p} ({c})" for p, c in provs.most_common(3)) or "—"
        class_rows += (
            f"<tr><td><span class=\"pill {OWN_PILL.get(cls, '')}\">{cls}</span></td>"
            f"<td>{n}</td><td>{_h(top_provs)}</td></tr>"
        )

    # Stat grid: highlight the four most-actionable classes
    owned = by_class.get("OWNED", 0)
    saas = by_class.get("SAAS", 0)
    cloud = by_class.get("CLOUD_SHARED", 0)
    third = saas + cloud + by_class.get("CDN", 0)
    pct_owned = (100 * owned // max(len(own), 1))

    return f"""
    <style>{css}</style>
    <div class="{wrap}">
      <h2>Asset ownership breakdown</h2>
      <p>Of {len(own)} unique hosts surfaced by the scan,
      <strong>{owned}</strong> ({pct_owned}%) sit on infrastructure the
      organisation directly controls. The remaining {len(own) - owned} are
      hosted on third-party platforms (SaaS, shared cloud, CDN edges) — issues
      on those scopes generally require switching provider or product
      configuration rather than direct remediation.</p>

      <div class="grid">
        <div class="stat"><div class="lbl">Owned</div><div class="val">{owned}</div></div>
        <div class="stat"><div class="lbl">SaaS</div><div class="val">{saas}</div></div>
        <div class="stat"><div class="lbl">Shared cloud</div><div class="val">{cloud}</div></div>
        <div class="stat"><div class="lbl">Third-party total</div><div class="val">{third}</div></div>
      </div>

      <h3>Classification detail</h3>
      <table>
        <thead><tr><th>Class</th><th>Hosts</th><th>Top providers</th></tr></thead>
        <tbody>{class_rows}</tbody>
      </table>
    </div>
    """


# ─── Top risks (risk-weighted hosts) ─────────────────────────────────────────
def _load_findings(pentest_dir: Path) -> list[dict]:
    """Prefer validated; fall back to raw."""
    val = pentest_dir / "report" / "findings_validated.tsv"
    raw = pentest_dir / "report" / "findings.tsv"
    p = val if val.is_file() else raw
    if not p.is_file():
        return []
    rows = []
    with p.open("r", errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            rows.append({
                "severity": parts[0], "category": parts[1],
                "scope": parts[2], "description": parts[3],
            })
    return rows


def top_risks_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    findings = _load_findings(pentest_dir)
    if not findings:
        return ""
    omap = {h.lower(): c.to_dict() for h, c in nw_ownership.load(pentest_dir).items()}

    def _lookup(scope: str) -> str:
        key = (scope or "").strip().lower()
        if key in omap:
            return omap[key]["class"]
        from validator import extract_host, extract_ip
        h = extract_host(scope).lower()
        if h in omap:
            return omap[h]["class"]
        ip = extract_ip(scope) or ""
        if ip in omap:
            return omap[ip]["class"]
        return ""

    enriched = []
    for f in findings:
        oc = _lookup(f["scope"])
        enriched.append({
            **f,
            "owner_class": oc,
            "risk_score": nw_risk.score(f["severity"], f["category"], f["scope"], oc),
        })
    hosts = nw_risk.aggregate_by_host(enriched)[:15]
    if not hosts:
        return ""

    wrap = THEMES[theme]["wrap_class"]
    css = THEMES[theme]["css"]
    total_risk = round(sum(h["total_risk"] for h in hosts), 1)

    rows_html = ""
    for h in hosts:
        own_cls = (h.get("owner_class") or "").lower() or "unknown"
        own_pill_cls = OWN_PILL.get(h.get("owner_class") or "UNKNOWN", "unknown")
        rows_html += (
            f"<tr>"
            f"<td><strong>{h['total_risk']:.1f}</strong></td>"
            f"<td>{h['n']}</td>"
            f"<td><span class=\"pill {SEV_PILL.get(h['max_severity'], '')}\">{h['max_severity']}</span></td>"
            f"<td><span class=\"pill {own_pill_cls}\">{h['owner_class'] or 'UNKNOWN'}</span></td>"
            f"<td>{_h(h.get('criticality_label') or '—')}</td>"
            f"<td class=\"scope\">{_h(h['scope'])}</td>"
            f"</tr>"
        )

    # Quick wins: highest-risk findings on OWNED infrastructure where the
    # exploit factor is high enough to actually move the needle (≥1.5).
    quick_wins = sorted(
        [
            f for f in enriched
            if f.get("owner_class") in ("OWNED", "")
            and f["risk_score"] >= 30
        ],
        key=lambda r: -r["risk_score"],
    )[:10]
    qw_rows = ""
    for f in quick_wins:
        qw_rows += (
            f"<tr><td><strong>{f['risk_score']:.1f}</strong></td>"
            f"<td><span class=\"pill {SEV_PILL.get(f['severity'], '')}\">{f['severity']}</span></td>"
            f"<td>{_h(f['category'])}</td>"
            f"<td class=\"scope\">{_h(f['scope'])}</td></tr>"
        )
    qw_rows = qw_rows or '<tr><td colspan="4" class="dim">no high-risk OWNED findings — well done</td></tr>'

    return f"""
    <style>{css}</style>
    <div class="{wrap}">
      <h2>Risk-weighted view</h2>
      <p>Each finding is scored as
      <code>severity × exploitability × ownership × host_criticality</code>.
      The same finding category therefore registers differently on a
      marketing static site than on an authentication endpoint.
      Aggregate risk across the top-listed hosts is <strong>{total_risk}</strong>.</p>

      <h3>Top {len(hosts)} hosts by risk</h3>
      <table>
        <thead><tr><th>Risk</th><th>Findings</th><th>Max sev</th><th>Ownership</th><th>Criticality</th><th>Host</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>

      <h3>Quick wins — highest-risk findings on owned infrastructure</h3>
      <table>
        <thead><tr><th>Risk</th><th>Sev</th><th>Category</th><th>Scope</th></tr></thead>
        <tbody>{qw_rows}</tbody>
      </table>
    </div>
    """


# ─── Evidence gallery (screenshot per finding) ──────────────────────────────
def _png_to_data_uri(p: Path) -> str:
    """Embed a PNG as a base64 data URI so the report is self-contained
    (analyst can save / email the HTML file without losing the images)."""
    import base64
    try:
        b64 = base64.b64encode(p.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{b64}"
    except OSError:
        return ""


def evidence_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    """Gallery of captured screenshots, grouped by finding. Only shows up
    if at least one screenshot exists (the analyst ran 'Capture' first)."""
    findings = _load_findings(pentest_dir)
    if not findings:
        return ""
    shots_dir = pentest_dir / "screenshots"
    if not shots_dir.is_dir():
        return ""
    mapping = nw_screenshots.load_mapping(pentest_dir)
    if not mapping:
        return ""

    # Group findings by URL so each screenshot appears once, listing all
    # findings that produced it.
    url_to_meta: dict[str, dict] = {}
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in findings:
        url = nw_screenshots.scope_to_url(f["scope"])
        if not url or url not in mapping:
            continue
        fn = mapping[url]
        p = shots_dir / fn
        if not p.is_file():
            continue
        entry = url_to_meta.setdefault(url, {
            "filename": fn, "path": p, "findings": [],
            "max_sev": "LOW", "max_rank": 9,
        })
        entry["findings"].append(f)
        rank = sev_rank.get(f["severity"], 9)
        if rank < entry["max_rank"]:
            entry["max_rank"] = rank
            entry["max_sev"] = f["severity"]

    if not url_to_meta:
        return ""

    # Sort: most severe first, then alphabetic
    entries = sorted(url_to_meta.values(),
                     key=lambda e: (e["max_rank"], e["findings"][0]["scope"]))

    wrap = THEMES[theme]["wrap_class"]
    base_css = THEMES[theme]["css"]

    cards = []
    for e in entries:
        data_uri = _png_to_data_uri(e["path"])
        if not data_uri:
            continue
        sev_class = SEV_PILL.get(e["max_sev"], "")
        url = next(iter(u for u, m in url_to_meta.items() if m is e))
        finding_pills = "".join(
            f'<span class="pill {SEV_PILL.get(fnd["severity"], "")}">{fnd["severity"]}</span> '
            f'<span class="dim">{_h(fnd["category"])}</span><br>'
            for fnd in e["findings"][:6]
        )
        if len(e["findings"]) > 6:
            finding_pills += f'<span class="dim">+{len(e["findings"]) - 6} more</span>'
        cards.append(f"""
        <div class="ev-card">
          <div class="ev-img-wrap">
            <img src="{data_uri}" alt="{_h(url)}">
          </div>
          <div class="ev-meta">
            <div class="ev-url">{_h(url)}</div>
            <div class="ev-findings">{finding_pills}</div>
          </div>
        </div>
        """)

    if not cards:
        return ""

    extra_css = """
    .ev-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin: 16px 0; }
    .ev-card { border: 1px solid #1c232c; border-radius: 8px; overflow: hidden;
               background: linear-gradient(180deg, #0e1217, #0a0d11); }
    .ev-img-wrap { background: #fff; border-bottom: 1px solid #1c232c; }
    .ev-img-wrap img { display: block; width: 100%; height: auto; max-height: 360px; object-fit: cover; object-position: top; }
    .ev-meta { padding: 12px 14px; font-size: 12px; }
    .ev-url { font-family: 'JetBrains Mono', monospace; color: #66e3ff;
              word-break: break-all; margin-bottom: 8px; font-size: 11.5px; }
    .ev-findings { line-height: 1.7; }
    .ev-findings .pill { font-family: 'Inter', sans-serif; }
    @media (max-width: 900px) { .ev-grid { grid-template-columns: 1fr; } }
    """
    # For mgmt theme, override the dark card colors for the white-paper look
    if theme == "mgmt":
        extra_css += """
        .nw-ext-mgmt .ev-card { border-color: #d6d6d6;
            background: #fafafa; }
        .nw-ext-mgmt .ev-img-wrap { border-color: #d6d6d6; }
        .nw-ext-mgmt .ev-url { color: #1e3a5f; }
        """

    return f"""
    <style>{base_css}{extra_css}</style>
    <div class="{wrap}">
      <h2>Visual Evidence</h2>
      <p>Browser-rendered screenshots of the affected scopes, captured by
      headless Chromium at validation time. {len(cards)} unique surface(s)
      with at least one HIGH-or-CRITICAL finding.</p>
      <div class="ev-grid">{''.join(cards)}</div>
    </div>
    """


# ─── Diff (change since previous run) ─────────────────────────────────────────
def _list_comparable_scans(pentest_dir: Path) -> list[Path]:
    parent = pentest_dir.parent
    out = []
    for child in sorted(parent.iterdir(), reverse=True):
        if not child.is_dir() or not child.name.startswith("pentest"):
            continue
        if child.resolve() == pentest_dir.resolve():
            continue
        if (child / "report" / "findings.tsv").is_file():
            out.append(child)
    return out


def _read_input_domains(pentest_dir: Path) -> set[str]:
    p = pentest_dir / "recon" / "input_domains.txt"
    if not p.is_file():
        return set()
    return {l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()}


def diff_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    """Pick the most recent prior scan that shares at least one input domain,
    diff against it, and render. Renders nothing if no prior run found."""
    cur_doms = _read_input_domains(pentest_dir)
    candidates = []
    for c in _list_comparable_scans(pentest_dir):
        try:
            mt = c.stat().st_mtime
        except OSError:
            mt = 0
        if mt >= pentest_dir.stat().st_mtime:
            continue  # only look backward
        score = len(cur_doms & _read_input_domains(c))
        candidates.append((score, mt, c))
    if not candidates:
        return ""
    candidates.sort(key=lambda x: (-x[0], -x[1]))
    prev = candidates[0][2]
    if candidates[0][0] == 0:
        # No overlapping input domains — skip rather than diff apples vs oranges.
        return ""

    d = nw_diff.diff_scans(pentest_dir, prev, source="validated")
    wrap = THEMES[theme]["wrap_class"]
    css = THEMES[theme]["css"]

    def _rows(rows, kind):
        if not rows:
            return '<tr><td colspan="3" class="dim">none</td></tr>'
        out = []
        for r in rows[:50]:
            out.append(
                f"<tr><td><span class=\"pill {SEV_PILL.get(r['severity'], '')}\">"
                f"{r['severity']}</span></td>"
                f"<td>{_h(r['category'])}</td>"
                f"<td class=\"scope\">{_h(r['scope'])}</td></tr>"
            )
        if len(rows) > 50:
            out.append(f'<tr><td colspan="3" class="dim">… {len(rows) - 50} more</td></tr>')
        return "".join(out)

    def _changed_rows(rows):
        if not rows:
            return '<tr><td colspan="4" class="dim">none</td></tr>'
        out = []
        for r in rows[:50]:
            arrow = "↑" if r["drift"] == "worse" else ("↓" if r["drift"] == "better" else "·")
            out.append(
                f"<tr><td><span class=\"pill {SEV_PILL.get(r['previous_severity'], '')}\">"
                f"{r['previous_severity']}</span> "
                f"<span class=\"drift-{r['drift']}\">{arrow}</span> "
                f"<span class=\"pill {SEV_PILL.get(r['severity'], '')}\">"
                f"{r['severity']}</span></td>"
                f"<td>{_h(r['category'])}</td>"
                f"<td class=\"scope\">{_h(r['scope'])}</td>"
                f"<td class=\"dim\">{r['drift']}</td></tr>"
            )
        if len(rows) > 50:
            out.append(f'<tr><td colspan="4" class="dim">… {len(rows) - 50} more</td></tr>')
        return "".join(out)

    delta = d["severity_delta"]

    def _d(sev):
        v = delta[sev]["delta"]
        if v == 0:
            return f'<span class="dim">±0</span>'
        sign = "+" if v > 0 else ""
        cls = "drift-worse" if v > 0 else "drift-better"
        return f'<span class="{cls}">{sign}{v}</span>'

    return f"""
    <style>{css}</style>
    <div class="{wrap}">
      <h2>Change since previous engagement</h2>
      <p>Compared against <code>{_h(d["b"])}</code> (validated findings on both sides).
      <strong>{d['totals']['new']}</strong> new finding(s),
      <strong>{d['totals']['fixed']}</strong> fixed,
      <strong>{d['totals']['changed']}</strong> changed severity,
      {d['totals']['unchanged']} unchanged.</p>

      <div class="grid">
        <div class="stat"><div class="lbl">CRITICAL</div><div class="val">{delta['CRITICAL']['a']}</div><div class="delta">{_d('CRITICAL')}</div></div>
        <div class="stat"><div class="lbl">HIGH</div><div class="val">{delta['HIGH']['a']}</div><div class="delta">{_d('HIGH')}</div></div>
        <div class="stat"><div class="lbl">MEDIUM</div><div class="val">{delta['MEDIUM']['a']}</div><div class="delta">{_d('MEDIUM')}</div></div>
        <div class="stat"><div class="lbl">LOW</div><div class="val">{delta['LOW']['a']}</div><div class="delta">{_d('LOW')}</div></div>
      </div>

      <h3>New findings ({d['totals']['new']})</h3>
      <table><thead><tr><th>Sev</th><th>Category</th><th>Scope</th></tr></thead>
        <tbody>{_rows(d['new'], 'new')}</tbody></table>

      <h3>Fixed since last run ({d['totals']['fixed']})</h3>
      <table><thead><tr><th>Sev</th><th>Category</th><th>Scope</th></tr></thead>
        <tbody>{_rows(d['fixed'], 'fixed')}</tbody></table>

      <h3>Severity changed ({d['totals']['changed']})</h3>
      <table><thead><tr><th>Sev (prev → now)</th><th>Category</th><th>Scope</th><th>Drift</th></tr></thead>
        <tbody>{_changed_rows(d['changed'])}</tbody></table>
    </div>
    """


def scorecard_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    """Headline security-posture grade (0–100 + letter) for the whole scan,
    computed from the validated severity profile. Same model as the dashboard
    (scorecard.py). Self-contained inline styles so it renders in either theme
    and survives PDF export."""
    findings = _load_findings(pentest_dir)
    if not findings:
        return ""
    counts = Counter(f["severity"] for f in findings if f["severity"] in SEVERITIES)
    sc = nw_scorecard.compute({s: counts.get(s, 0) for s in SEVERITIES})

    wrap = THEMES[theme]["wrap_class"]
    css = THEMES[theme]["css"]
    col = sc["color"]
    c = sc["counts"]
    ink = "#1a1a1a" if theme == "mgmt" else "#c3e8c8"
    panel = "#fafafa" if theme == "mgmt" else "#0a1015"
    edge = "#d6d6d6" if theme == "mgmt" else "#173238"
    soft = "#666" if theme == "mgmt" else "#8b96a3"

    ceiling = ""
    if sc["ceiling_applied"]:
        ceiling = (f'<div style="font-size:12px;color:{col};margin-top:4px">'
                   f'Grade capped at {sc["grade"]} — open {sc["ceiling_applied"]} '
                   f'finding(s) present.</div>')

    return f"""
    <style>{css}</style>
    <div class="{wrap}">
      <h2>Security Posture Score</h2>
      <p>Overall posture graded from the validated findings:
      <code>100 − (45·C + 18·H + 6·M + 1.5·L)</code>, floored at 0
      (100 = clean). A 90+ · B 80+ · C 70+ · D 60+ · F &lt;60.</p>
      <div style="display:flex;align-items:stretch;gap:20px;border:1px solid {edge};
          border-left:6px solid {col};background:{panel};border-radius:6px;
          padding:18px 22px;margin:14px 0;max-width:680px">
        <div style="display:flex;align-items:center;justify-content:center;
            min-width:110px;font-size:64px;font-weight:800;line-height:1;
            color:{col};border-right:1px solid {edge};padding-right:18px">{sc['grade']}</div>
        <div style="flex:1">
          <div style="font-size:30px;font-weight:700;color:{ink}">
            {sc['score']}<span style="font-size:15px;color:{soft};font-weight:400">/100</span>
          </div>
          <div style="font-size:11px;letter-spacing:.16em;text-transform:uppercase;
              color:{soft};margin:2px 0 10px">Security Posture</div>
          <div style="height:8px;background:rgba(127,127,127,.18);border-radius:999px;overflow:hidden">
            <div style="height:100%;width:{sc['score']}%;background:{col}"></div>
          </div>
          <div style="font-size:12px;color:{soft};margin-top:8px">
            −{sc['deduction']} pts from
            {c['CRITICAL']} Critical · {c['HIGH']} High ·
            {c['MEDIUM']} Medium · {c['LOW']} Low
          </div>
          {ceiling}
        </div>
      </div>
    </div>
    """


def domains_html(pentest_dir: Path, theme: str = "mgmt") -> str:
    """Group every finding into one main security domain (see taxonomy.py) and
    render a summary table + a per-domain breakdown. Same classifier the live
    dashboard uses, so the report matches the UI exactly."""
    findings = _load_findings(pentest_dir)
    if not findings:
        return ""

    # Bucket findings by domain, preserving canonical precedence order.
    buckets: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        buckets[nw_taxonomy.classify(f["category"], f["description"])].append(f)
    ordered = [d for d in nw_taxonomy.iter_domains() if buckets.get(d["slug"])]
    if not ordered:
        return ""

    wrap = THEMES[theme]["wrap_class"]
    css = THEMES[theme]["css"]

    # Summary table: one row per domain with a per-severity split.
    sum_rows = ""
    for d in ordered:
        rows = buckets[d["slug"]]
        sev = Counter(r["severity"] for r in rows)
        swatch = (f'<span style="display:inline-block;width:10px;height:10px;'
                  f'border-radius:2px;background:{d["color"]};margin-right:6px;'
                  f'vertical-align:middle"></span>')
        cells = "".join(
            f'<td>{sev.get(s, 0) or "—"}</td>' for s in SEVERITIES
        )
        sum_rows += (
            f"<tr><td>{swatch}<strong>{_h(d['label'])}</strong></td>"
            f"<td>{len(rows)}</td>{cells}</tr>"
        )

    # Per-domain detail tables.
    detail = ""
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    for d in ordered:
        rows = sorted(
            buckets[d["slug"]],
            key=lambda r: (sev_rank.get(r["severity"], 9), r["category"]),
        )
        body = "".join(
            f"<tr><td><span class=\"pill {SEV_PILL.get(r['severity'], '')}\">"
            f"{r['severity']}</span></td>"
            f"<td>{_h(r['category'])}</td>"
            f"<td class=\"scope\">{_h(r['scope'])}</td>"
            f"<td>{_h(r['description'])}</td></tr>"
            for r in rows
        )
        detail += (
            f'<h3><span style="display:inline-block;width:11px;height:11px;'
            f'border-radius:2px;background:{d["color"]};margin-right:8px;'
            f'vertical-align:middle"></span>{_h(d["label"])} '
            f'<span style="font-weight:400">({len(rows)})</span></h3>'
            f"<table><thead><tr><th>Sev</th><th>Category</th><th>Scope</th>"
            f"<th>Description</th></tr></thead><tbody>{body}</tbody></table>"
        )

    return f"""
    <style>{css}</style>
    <div class="{wrap}">
      <h2>Findings by Security Domain</h2>
      <p>Every finding is classified into exactly one main security domain, so
      remediation can be routed to the right team (network, crypto/TLS, web
      application, email/DNS, cloud, secrets, access control).</p>
      <table>
        <thead><tr><th>Domain</th><th>Total</th><th>Critical</th><th>High</th>
        <th>Medium</th><th>Low</th></tr></thead>
        <tbody>{sum_rows}</tbody>
      </table>
      {detail}
    </div>
    """


# ─── Driver ───────────────────────────────────────────────────────────────────
def build_all(pentest_dir: Path, theme: str = "mgmt") -> str:
    """Concatenate the sections in a sensible order."""
    chunks = []
    for fn in (scorecard_html, charts_html, validation_summary_html, ownership_html,
               top_risks_html, domains_html, evidence_html, diff_html):
        try:
            chunks.append(fn(pentest_dir, theme))
        except Exception as e:
            chunks.append(
                f"<!-- nw extras section {fn.__name__} failed: {_h(str(e))} -->"
            )
    return "\n".join(c for c in chunks if c.strip())


def inject(html_str: str, extras: str) -> str:
    """Insert extras immediately before </body> (case-insensitive). If no
    body close found, append at the end."""
    if not extras:
        return html_str
    needle = "</body>"
    idx = html_str.lower().rfind(needle)
    if idx == -1:
        return html_str + "\n" + extras
    return html_str[:idx] + extras + html_str[idx:]
