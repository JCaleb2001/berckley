"""
taxonomy.py — single source of truth for the security-domain of a finding.

`extpentest.sh` writes each finding to findings.tsv as
    SEVERITY <TAB> TITLE <TAB> SCOPE <TAB> DESCRIPTION
with no notion of a top-level security domain. This module maps every finding
(by its TITLE, with the DESCRIPTION as a fallback) into exactly one of seven
"main" domains, so the live dashboard and the exported report can both group
and filter findings the same way.

Design:
  * Single membership — each finding lands in exactly one domain.
  * Deterministic precedence — DOMAINS is evaluated top to bottom and the first
    domain whose pattern matches wins. Order the most specific domains first.
  * `network` is the catch-all default for exposed services / ports / EoL
    software / CVEs; `other` only ever shows up if a title matches nothing,
    which (see taxonomy self-check) should not happen for scanner output.

The classifier is pure (same input → same output, no I/O) and the rule table is
open-coded so any finding can be re-routed by editing one regex.
"""
from __future__ import annotations

import re

# ─── Domains, in precedence order (first match wins) ──────────────────────────
# Each entry: (slug, label, icon, color, pattern). `pattern` is matched
# case-insensitively against "<title>\n<description>".
DOMAINS: list[tuple[str, str, str, str, re.Pattern]] = []


def _d(slug: str, label: str, icon: str, color: str, *keywords: str) -> None:
    pat = re.compile("|".join(keywords), re.IGNORECASE)
    DOMAINS.append((slug, label, icon, color, pat))


# 1 ── Email & DNS Security ----------------------------------------------------
_d("email_dns", "Email & DNS Security", "✉", "#c792ea",
   r"\bspf\b", r"\bdmarc\b", r"\bdkim\b", r"\bbimi\b", r"dnssec",
   r"\bcaa\b", r"\bdns\b", r"\bmx\b", r"zone transfer", r"wildcard dns",
   r"open .*resolver", r"subdomain takeover", r"dangling dns",
   r"typosquat", r"lookalike", r"nsec zone walk")

# 2 ── Cloud & Storage Exposure ------------------------------------------------
_d("cloud", "Cloud & Storage Exposure", "☁", "#4fc3f7",
   r"\bs3\b", r"\bgcs\b", r"gcp storage", r"google cloud storage",
   r"azure (blob|storage|sas|ad)", r"firebase", r"digitalocean space",
   r"cloud storage reference", r"ssrf to cloud metadata", r"cloud metadata",
   r"\bbucket\b", r"\bsas token\b")

# 3 ── Secrets & Information Disclosure ----------------------------------------
_d("secrets", "Secrets & Info Disclosure", "🔑", "#ffb74d",
   r"leaked", r"in javascript", r"api key", r"access key", r"\bsecret",
   r"\btoken\b", r"breach", r"\bhibp\b", r"paste site", r"github .*(repo|token|pat)",
   r"source map", r"verbose error", r"stack trace", r"technology disclosure",
   r"sensitive (file|config|path)", r"database/backup file", r"backup file",
   r"dependency (manifest|confusion)", r"infrastructure file",
   r"api documentation exposed", r"robots\.txt", r"directory listing",
   r"analytics tracking", r"ipv6 address exposed", r"historical sensitive",
   r"\.trace\.axd", r"phpinfo|php info|adminer", r"javascript source map",
   r"debug/oidc")

# 4 ── Cryptography & TLS ------------------------------------------------------
_d("crypto", "Cryptography & TLS", "🔒", "#69f0ae",
   # `\bssl\b` but not "SSL VPN" / "SSL-VPN" (those are network appliances)
   r"\btls\b", r"\bssl\b(?![- ]?vpn)", r"sslv2|sslv3", r"cipher",
   r"certificate", r"\bcert\b",
   r"\bdh parameters\b", r"diffie-hellman", r"rsa key", r"ec key", r"key size",
   r"heartbleed", r"poodle", r"\bcrime\b", r"\bbeast\b", r"sweet32", r"\brc4\b",
   r"3des|single-des|\bdes\b", r"\bmd5\b", r"null cipher", r"export-grade",
   r"\bocsp\b", r"revocation", r"self-signed", r"untrusted certificate",
   r"\bjwt\b.*(algorithm|signature|symmetric|none)", r"jwt no signature",
   r"\bssh\b.*(cipher|mac|key exchange|host key|configuration)", r"ssh-audit",
   r"ssh protocol v1", r"weak certificate", r"signature algorithm",
   r"cabforum|certificate lifetime", r"fallback scsv", r"tls compression",
   r"must-staple", r"legacy tls", r"hostname mismatch", r"expiring soon|expired tls")

# 5 ── Access Control & Authentication -----------------------------------------
# Explicit auth-failure markers win over generic "service exposed" (network).
_d("access", "Access Control & Auth", "🛡", "#ff5fa2",
   r"default credential", r"no auth", r"\(no auth\)", r"noauth", r"unauthenticated",
   r"anonymous", r"anonymously", r"null session", r"user enumeration",
   r"account enumeration", r"user enum", r"no rate limiting", r"rate limit",
   r"admin panel", r"login exposed", r"403 .*(bypass|access control)",
   r"uninitialized", r"vrfy|expn", r"snmp community", r"open smtp relay",
   r"smtp relay")

# 6 ── Web Application Security -------------------------------------------------
_d("webapp", "Web Application Security", "🌐", "#5c9dff",
   r"\bxss\b", r"cross-site scripting", r"sql injection", r"\bssti\b",
   r"template injection", r"\bssrf\b", r"\bcors\b", r"\bcsp\b",
   r"content-security-policy", r"x-frame-options", r"x-content-type-options",
   r"referrer-policy", r"permissions-policy", r"cross-origin-opener",
   r"\bhsts\b", r"strict transport", r"subresource integrity", r"\bsri\b",
   r"cookie", r"open redirect", r"path traversal", r"directory traversal",
   r"prototype pollution", r"cache poisoning|cacheable", r"host header",
   r"http (put|delete|trace)", r"\btrace\b enabled", r"graphql", r"websocket",
   r"mixed content", r"http to https|https redirect", r"security\.txt",
   r"cross-domain policy", r"\bwaf\b", r"header injection", r"xml-consuming",
   r"virtual hosts", r"reflected", r"web cache")

# 7 ── Network & Infrastructure (catch-all default) ----------------------------
_d("network", "Network & Infrastructure", "🖧", "#b0bec5",
   r".")  # matches everything not caught above

# `other` is a defensive bucket; classify() never returns it unless a finding
# somehow matches nothing (it cannot, because `network` matches ".").
_OTHER = ("other", "Other", "•", "#607d8b")

DOMAIN_ORDER: list[str] = [d[0] for d in DOMAINS] + [_OTHER[0]]
_LABELS: dict[str, str] = {d[0]: d[1] for d in DOMAINS} | {_OTHER[0]: _OTHER[1]}
_META: dict[str, dict] = {
    d[0]: {"slug": d[0], "label": d[1], "icon": d[2], "color": d[3]}
    for d in DOMAINS
}
_META[_OTHER[0]] = {"slug": _OTHER[0], "label": _OTHER[1],
                    "icon": _OTHER[2], "color": _OTHER[3]}


def classify(title: str, description: str = "") -> str:
    """Return the domain slug for a finding. First matching rule wins."""
    hay = f"{title or ''}\n{description or ''}"
    for slug, _label, _icon, _color, pat in DOMAINS:
        if pat.search(hay):
            return slug
    return _OTHER[0]


def label(slug: str) -> str:
    return _LABELS.get(slug, slug)


def meta(slug: str) -> dict:
    return _META.get(slug, {"slug": slug, "label": slug, "icon": "•",
                            "color": "#607d8b"})


def iter_domains() -> list[dict]:
    """Domains in display/precedence order, as metadata dicts (incl. Other)."""
    return [_META[s] for s in DOMAIN_ORDER]
