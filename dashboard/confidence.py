"""
confidence.py — how sure we are a finding is real (single source of truth).

Orthogonal to severity (how bad) and risk (severity × context). Confidence
answers: "did the scanner actually *prove* this, or is it a tentative signal?"
A Redis instance that answered a RESP probe is HIGH; a service identified only by
a banner fingerprint, a wayback/historical hit, or a single-GET missing header is
lower — those are where false positives live.

Derivation (no scanner churn — works on existing 4-column findings.tsv):
  1. explicit  — if the optional 5th TSV column carries a band, it wins.
  2. markers   — confidence words in the DESCRIPTION (active-probe vs tentative).
  3. category  — defaults for categories that are inherently confirmed (DNS/TLS
                 record checks, services that answered a protocol probe) vs
                 inherently tentative (fingerprint detection, takeover, nuclei).
  4. else MEDIUM.

A strong false-positive marker ("may cause false positives", "verify if…") always
wins, even over an active-probe marker — better to under-claim confidence than to
hide that a result is shaky. Pure function, open-coded tables, no I/O.
"""
from __future__ import annotations

import re

# Band → representative numeric score (for sorting/filtering) + display color.
BANDS: dict[str, tuple[int, str]] = {
    "HIGH":   (90, "#4caf50"),   # green — actively proven
    "MEDIUM": (60, "#ffb300"),   # amber — plausible, single observation
    "LOW":    (30, "#9e9e9e"),   # grey  — tentative / fingerprint / historical
}
BAND_ORDER = ["HIGH", "MEDIUM", "LOW"]

# Tentative markers in the description → LOW. Checked first (conservative).
_LOW_MARKERS = re.compile(
    r"may cause false|verify if|deserves review|\bpotential\b|\bindicator\b|"
    r"\bfingerprint|\bwayback\b|\bhistorical(ly)?\b|\bappears?\b|\blikely\b|"
    r"\bpossible\b|\bseems\b|\bmight\b|unconfirmed|"
    r"may be|suspected|candidate|heuristic|inferred|not confirmed|review manually",
    re.IGNORECASE,
)

# Active-proof markers in the description → HIGH.
_HIGH_MARKERS = re.compile(
    r"\bconfirmed\b|answered RESP|answers .*(wire-protocol|protocol) probe|"
    r"\baccepted\b|\benabled\b|\bverified\b|negotiat|responded|"
    r"grant(s)? (full|admin)|credentials (accepted|work)|world-readable|"
    r"anonymous (bind|login|listable|readable) (allowed|succeed|confirmed)?",
    re.IGNORECASE,
)

# Category defaults (substring match, case-insensitive). First hit wins.
# Inherently confirmed: deterministic record checks + active protocol probes.
_HIGH_CATEGORIES = (
    "No SPF", "SPF", "DMARC", "DKIM", "DNSSEC", "CAA", "Zone Transfer",
    "TLS", "SSL", "Cipher", "Certificate", "Cert ", "Heartbleed", "POODLE",
    "Self-Signed", "Expired", "Weak DH", "Weak RSA", "Weak EC", "OCSP",
    "Default Credentials", "Redis", "MongoDB", "Elasticsearch", "Memcached",
    "PostgreSQL", "MySQL", "Telnet", "FTP Anonymous", "SMB Null", "NFS Export",
    "LDAP Anonymous", "Open SMTP Relay", "Zone Walk",
)
# Inherently tentative: fingerprint / heuristic / one-shot indicators.
_LOW_CATEGORIES = (
    "Subdomain Takeover", "Dangling DNS", "Indicator", "Deserves Review",
    "Lookalike", "Typosquat", "Historical", "Paste Sites", "Detected",
    "Reference in Page Source", "Wildcard DNS", "Technology Disclosure",
    "Deprecated", "Outdated", "End-of-Life", "EoL", "Version Detected",
    "Reflected", "Potential", "Nuclei",
)


def _band(category: str, description: str) -> str:
    desc = description or ""
    cat = category or ""
    # 2. description markers — LOW wins over HIGH (conservative)
    if _LOW_MARKERS.search(desc):
        return "LOW"
    if _HIGH_MARKERS.search(desc):
        return "HIGH"
    # 3. category defaults
    low = cat.lower()
    for needle in _LOW_CATEGORIES:
        if needle.lower() in low:
            return "LOW"
    for needle in _HIGH_CATEGORIES:
        if needle.lower() in low:
            return "HIGH"
    return "MEDIUM"


def confidence(category: str, description: str = "", explicit: str = "") -> dict:
    """Return {'band','score','color'} for a finding. An explicit band from the
    scanner (5th TSV column) overrides derivation."""
    band = (explicit or "").strip().upper()
    if band not in BANDS:
        band = _band(category, description)
    score, color = BANDS[band]
    return {"band": band, "score": score, "color": color}


def band_color(band: str) -> str:
    return BANDS.get((band or "").upper(), BANDS["MEDIUM"])[1]
