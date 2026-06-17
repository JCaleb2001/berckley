"""
risk.py — contextual risk scoring for findings.

The validator labels each finding with a base severity. That severity is
context-free: a missing HSTS header on `marketing-blog` is not equivalent to
the same finding on `auth.company.com`. This module multiplies the base
severity by three modifiers that capture context:

    risk = severity × exploitability × ownership × host_criticality

  severity        — base scanner-assigned weight (CRITICAL .. LOW)
  exploitability  — category-specific factor (SNMP / default creds: high;
                    missing security header: low)
  ownership       — full risk for OWNED assets, discounted for third-party
                    infra the customer cannot remediate
  host_criticality— hostname-pattern heuristic (auth/admin/api/db = high
                    impact targets; marketing/static = low)

All four are open-coded tables — easy to tune, no external dependencies. The
function is pure: same inputs always produce the same score, no I/O.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ─── Severity (base scanner weight) ──────────────────────────────────────────
SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 100.0,
    "HIGH":     40.0,
    "MEDIUM":   10.0,
    "LOW":       2.0,
}

# ─── Ownership weights ──────────────────────────────────────────────────────
# Findings on infra the customer cannot remediate are partially discounted.
# CDN / INTERNAL / EXTERNAL essentially zero — those should have been
# suppressed by the validator's ownership rule already, but this keeps the
# scoring honest if anything slips through.
OWNERSHIP_WEIGHTS: dict[str, float] = {
    "OWNED":        1.00,
    "SAAS":         0.45,   # customer chose the SaaS but can't fix infra
    "CLOUD_SHARED": 0.45,
    "CDN":          0.15,
    "INTERNAL":     0.00,
    "EXTERNAL":     0.00,
    "UNKNOWN":      0.80,   # default to mostly-counted; UI lets analyst tag
    "":             1.00,   # ownership not classified yet → full weight
}

# ─── Exploitability (category-driven) ───────────────────────────────────────
# Substring match against the finding category. First hit wins, so order from
# strongest signal → weakest. Default is 1.0.
EXPLOIT_PATTERNS: list[tuple[str, float, str]] = [
    # Authentication / authorization bypasses
    ("Default Credentials",           2.50, "default creds"),
    ("Default Password",              2.50, "default password"),
    ("Anonymous",                     2.20, "anonymous access"),
    ("Unauthenticated",               2.20, "unauthenticated"),
    ("No Auth",                       2.20, "no-auth"),
    ("RCE",                           2.50, "remote code exec"),
    ("Remote Code",                   2.50, "remote code exec"),
    ("Command Injection",             2.50, "command injection"),
    ("SQL Injection",                 2.30, "SQLi"),
    ("Path Traversal",                2.00, "path traversal"),
    ("LFI",                           2.00, "local file include"),
    ("SSRF",                          2.00, "SSRF"),
    # Direct-access surfaces
    ("SNMP",                          2.00, "SNMP exposed"),
    ("Admin Panel",                   1.80, "admin panel"),
    ("Database Exposed",              2.20, "db exposed"),
    ("Backup File",                   1.80, "backup leak"),
    ("Open Redirect",                 1.30, "open redirect"),
    ("Subdomain Takeover",            2.20, "subdomain takeover"),
    # SMTP / email
    ("SMTP Open Relay",               2.00, "open SMTP relay"),
    ("VRFY",                          1.40, "user enum"),
    # TLS / cert (real impact = MITM-ability)
    ("Certificate Expired",           1.60, "expired cert"),
    ("Hostname Mismatch",             0.80, "cert mismatch"),
    ("Self-Signed",                   1.20, "self-signed"),
    ("Weak Cipher",                   0.90, "weak cipher"),
    ("Old TLS",                       1.10, "outdated TLS"),
    # Headers / hygiene (real impact is contextual on auth surface)
    ("HSTS",                          0.70, "missing HSTS"),
    ("CSP",                           0.70, "missing CSP"),
    ("X-Frame",                       0.50, "missing X-Frame"),
    ("X-Content-Type",                0.40, "missing X-Content-Type"),
    ("Referrer-Policy",               0.30, "missing referrer policy"),
    ("Permissions-Policy",            0.30, "missing permissions policy"),
    # DNS / email auth
    ("No SPF",                        0.80, "no SPF"),
    ("No DMARC",                      0.90, "no DMARC"),
    ("DMARC Policy Not Enforced",     0.70, "DMARC p=none"),
    ("DNSSEC",                        0.40, "no DNSSEC"),
    # Fingerprint / disclosure
    ("Powered-By",                    0.40, "tech fingerprint"),
    ("Server Banner",                 0.40, "server banner"),
    ("Legacy",                        1.40, "legacy / EOL software"),
    ("End-of-Life",                   1.50, "EOL software"),
    # Defaults / typosquatting
    ("Lookalike",                     1.30, "typosquat / lookalike"),
    ("Default Page",                  0.60, "default page"),
    ("Wildcard DNS",                  0.40, "wildcard DNS"),
]

# ─── Host criticality (hostname pattern) ────────────────────────────────────
# Higher = more business-critical surface. Pattern order matters: first match
# wins, so put high-impact tokens first.
CRITICALITY_PATTERNS: list[tuple[re.Pattern, float, str]] = [
    (re.compile(r'(?<![a-z0-9])(?:auth|sso|login|signin|oauth|idp|sts|oidc|adfs|saml|identity)(?![a-z0-9])'),
        2.00, "auth"),
    (re.compile(r'(?<![a-z0-9])(?:admin|adm|mgmt|manage|panel|control|console|root)(?![a-z0-9])'),
        1.80, "admin"),
    (re.compile(r'(?<![a-z0-9])(?:vault|secret|secure|hsm|kms)(?![a-z0-9])'),
        1.80, "secrets"),
    (re.compile(r'(?<![a-z0-9])(?:db|database|mysql|postgres|mssql|oracle|mongo|redis|elastic|cassandra)(?![a-z0-9])'),
        1.90, "db"),
    (re.compile(r'(?<![a-z0-9])(?:vpn|ipsec|wireguard|openvpn|anyconnect|pulse)(?![a-z0-9])'),
        1.70, "vpn"),
    (re.compile(r'(?<![a-z0-9])(?:pay|payment|checkout|billing|invoice)(?![a-z0-9])'),
        1.70, "payment"),
    (re.compile(r'(?<![a-z0-9])(?:api|graphql|rest|services|svc|gateway|gw)(?![a-z0-9])'),
        1.50, "api"),
    (re.compile(r'(?<![a-z0-9])(?:erp|crm|hr|workday|sap|navision|dynamics|bc|salesforce|sf)(?![a-z0-9])'),
        1.50, "business app"),
    (re.compile(r'(?<![a-z0-9])(?:internal|intranet|private|corp|corporate|enterprise|finance|legal|hr)(?![a-z0-9])'),
        1.40, "internal"),
    (re.compile(r'(?<![a-z0-9])(?:backup|backups|archive|repo|repository|git|svn|gitlab|gitea|bitbucket|jenkins|ci|cd|build|artifact)(?![a-z0-9])'),
        1.40, "build / source"),
    (re.compile(r'(?<![a-z0-9])(?:ssh|sftp|ftp|rsync|scp)(?![a-z0-9])'),
        1.40, "file transfer"),
    (re.compile(r'(?<![a-z0-9])(?:mail|email|smtp|exchange|outlook|owa|webmail|imap|pop)(?![a-z0-9])'),
        1.30, "mail"),
    (re.compile(r'(?<![a-z0-9])(?:portal|dashboard|app|apps|workspace|tenant)(?![a-z0-9])'),
        1.20, "portal"),
    (re.compile(r'(?<![a-z0-9])(?:helpdesk|support|ticket|servicedesk|jira)(?![a-z0-9])'),
        1.20, "support"),
    (re.compile(r'(?<![a-z0-9])(?:dev|develop|staging|stage|stg|test|qa|preprod|uat|sandbox)(?![a-z0-9])'),
        0.85, "non-prod"),
    (re.compile(r'(?<![a-z0-9])(?:blog|news|press|marketing|landing|content|academy|learn|training|kb|docs|wiki)(?![a-z0-9])'),
        0.60, "marketing / content"),
    (re.compile(r'(?<![a-z0-9])(?:static|cdn|assets|media|img|images|video|fonts|files|download|downloads)(?![a-z0-9])'),
        0.50, "static / cdn"),
]

DEFAULT_CRITICALITY = 1.0
DEFAULT_EXPLOIT = 1.0


# ─── API ─────────────────────────────────────────────────────────────────────
@dataclass
class Components:
    severity: float
    exploitability: float
    ownership: float
    host_criticality: float
    exploit_label: str = ""
    criticality_label: str = ""

    @property
    def score(self) -> float:
        return round(
            self.severity * self.exploitability * self.ownership * self.host_criticality,
            1,
        )


def severity_weight(severity: str) -> float:
    return SEVERITY_WEIGHTS.get((severity or "").upper(), 1.0)


def ownership_weight(owner_class: str) -> float:
    return OWNERSHIP_WEIGHTS.get((owner_class or "").upper(), 1.0)


def category_exploitability(category: str) -> tuple[float, str]:
    c = category or ""
    for needle, w, label in EXPLOIT_PATTERNS:
        if needle in c:
            return w, label
    return DEFAULT_EXPLOIT, ""


def host_criticality(scope: str) -> tuple[float, str]:
    """Match against the host portion of the scope. The check is over the
    *leftmost label sequence* — patterns like `auth` look at subdomain names,
    not the apex (so `auth.example.com` hits, but `example.com/authpage` does
    not — that would need its own URL-aware rule)."""
    if not scope:
        return DEFAULT_CRITICALITY, ""
    s = scope.lower().split()[0]
    # strip scheme/path/port to bare host
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = re.sub(r":\d+$", "", s)
    # match patterns on the host string (uses word boundaries internally)
    for pat, w, label in CRITICALITY_PATTERNS:
        if pat.search(s):
            return w, label
    return DEFAULT_CRITICALITY, ""


def score_components(severity: str, category: str, scope: str,
                     owner_class: str) -> Components:
    exploit, e_label = category_exploitability(category)
    crit, c_label = host_criticality(scope)
    return Components(
        severity=severity_weight(severity),
        exploitability=exploit,
        ownership=ownership_weight(owner_class),
        host_criticality=crit,
        exploit_label=e_label,
        criticality_label=c_label,
    )


def score(severity: str, category: str, scope: str, owner_class: str = "") -> float:
    return score_components(severity, category, scope, owner_class).score


def aggregate_by_host(findings: list[dict]) -> list[dict]:
    """Sum per-host risk and return sorted by descending risk."""
    from collections import defaultdict
    bucket: dict[str, dict] = defaultdict(lambda: {
        "scope": "", "total_risk": 0.0, "n": 0,
        "owner_class": "", "owner_provider": "",
        "max_severity": "LOW", "max_severity_rank": 4,
        "criticality_label": "",
    })
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in findings:
        if not f.get("risk_score"):
            continue
        scope = f.get("scope") or "—"
        b = bucket[scope]
        b["scope"] = scope
        b["total_risk"] += float(f["risk_score"])
        b["n"] += 1
        b["owner_class"] = f.get("owner_class", "") or b["owner_class"]
        b["owner_provider"] = f.get("owner_provider", "") or b["owner_provider"]
        r = sev_rank.get(f["severity"], 9)
        if r < b["max_severity_rank"]:
            b["max_severity_rank"] = r
            b["max_severity"] = f["severity"]
        if not b["criticality_label"]:
            _, lbl = host_criticality(scope)
            b["criticality_label"] = lbl
    rows = sorted(bucket.values(), key=lambda x: -x["total_risk"])
    for r in rows:
        r["total_risk"] = round(r["total_risk"], 1)
    return rows
