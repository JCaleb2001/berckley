"""
ownership.py — classify each scope so findings on infra the customer does not
actually control can be filtered or downgraded.

A scope falls into one of:
  OWNED          — customer's own infrastructure (own/rented hosting, on-prem)
  SAAS           — third-party SaaS app where customer has tenancy
                   (M365 SharePoint, Azure App Service, Heroku, Atlassian, ...)
  CDN            — content-delivery edge (Cloudflare, Akamai, Fastly, CloudFront)
  CLOUD_SHARED   — generic shared cloud IP (Azure VM range, AWS shared) — usually
                   means SaaS but we couldn't pin down a product
  INTERNAL       — RFC1918 / link-local / loopback (should not be in external scope)
  EXTERNAL       — clearly someone else's domain (lookalikes that landed on third-party IP)
  UNKNOWN        — couldn't decide; treat as OWNED by default in remediation flows

Classification signals (cheap → expensive):
  1. Direct domain match against known SaaS/CDN apex (e.g., .sharepoint.com → SAAS)
  2. CNAME chain — first hop ending in a known suffix
  3. RFC1918 IP                        → INTERNAL
  4. WHOIS on the IP → AS number / org → CDN / SAAS lookup table
  5. Subdomain of one of the customer's input root domains → OWNED
  6. Else                              → UNKNOWN

Persists to <pentest_dir>/report/ownership.tsv (HOST<TAB>CLASS<TAB>PROVIDER<TAB>IP<TAB>ASN<TAB>EVIDENCE).
"""
from __future__ import annotations

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

# Reuse cached primitives from the validator module. validator does NOT import
# ownership at module top, so this direction stays acyclic.
from validator import (
    dns_lookup,
    extract_host,
    extract_ip,
    have,
    is_private,
    resolve_cname,
    run,
)


class OwnerClass(str, Enum):
    OWNED        = "OWNED"
    SAAS         = "SAAS"
    CDN          = "CDN"
    CLOUD_SHARED = "CLOUD_SHARED"
    INTERNAL     = "INTERNAL"
    EXTERNAL     = "EXTERNAL"
    UNKNOWN      = "UNKNOWN"


@dataclass
class Classification:
    owner_class: OwnerClass = OwnerClass.UNKNOWN
    provider: str = ""
    ip: str = ""
    asn: str = ""
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "class": self.owner_class.value,
            "provider": self.provider,
            "ip": self.ip,
            "asn": self.asn,
            "evidence": self.evidence,
        }


# ─── Suffix tables ────────────────────────────────────────────────────────────
# CNAME suffix → (class, provider name). Order matters: longest suffix wins,
# so we sort at lookup time.
SUFFIX_TABLE: dict[str, tuple[OwnerClass, str]] = {
    # CDN
    ".cloudfront.net":          (OwnerClass.CDN, "Amazon CloudFront"),
    ".azureedge.net":           (OwnerClass.CDN, "Azure CDN"),
    ".akamaiedge.net":          (OwnerClass.CDN, "Akamai"),
    ".akamai.net":              (OwnerClass.CDN, "Akamai"),
    ".akamaihd.net":            (OwnerClass.CDN, "Akamai"),
    ".akamaized.net":           (OwnerClass.CDN, "Akamai"),
    ".fastly.net":              (OwnerClass.CDN, "Fastly"),
    ".fastlylb.net":            (OwnerClass.CDN, "Fastly"),
    ".cdn.cloudflare.net":      (OwnerClass.CDN, "Cloudflare"),
    ".cloudflare.net":          (OwnerClass.CDN, "Cloudflare"),
    ".cdn77.org":               (OwnerClass.CDN, "CDN77"),
    ".bunnycdn.com":            (OwnerClass.CDN, "Bunny CDN"),
    ".keycdn.com":              (OwnerClass.CDN, "KeyCDN"),

    # Shared cloud
    ".cloudapp.net":            (OwnerClass.CLOUD_SHARED, "Azure Cloud Service"),
    ".cloudapp.azure.com":      (OwnerClass.CLOUD_SHARED, "Azure VM"),
    ".trafficmanager.net":      (OwnerClass.CLOUD_SHARED, "Azure Traffic Manager"),
    ".elb.amazonaws.com":       (OwnerClass.CLOUD_SHARED, "AWS ELB"),
    ".compute.amazonaws.com":   (OwnerClass.CLOUD_SHARED, "AWS EC2"),
    ".s3.amazonaws.com":        (OwnerClass.CLOUD_SHARED, "AWS S3"),
    ".windows.net":             (OwnerClass.CLOUD_SHARED, "Microsoft Azure"),

    # SaaS — application platforms
    ".azurewebsites.net":       (OwnerClass.SAAS, "Azure App Service"),
    ".scm.azurewebsites.net":   (OwnerClass.SAAS, "Azure App Service (Kudu)"),
    ".azurestaticapps.net":     (OwnerClass.SAAS, "Azure Static Web Apps"),
    ".herokuapp.com":           (OwnerClass.SAAS, "Heroku"),
    ".github.io":               (OwnerClass.SAAS, "GitHub Pages"),
    ".githubusercontent.com":   (OwnerClass.SAAS, "GitHub"),
    ".pages.dev":               (OwnerClass.SAAS, "Cloudflare Pages"),
    ".workers.dev":             (OwnerClass.SAAS, "Cloudflare Workers"),
    ".vercel.app":              (OwnerClass.SAAS, "Vercel"),
    ".netlify.app":             (OwnerClass.SAAS, "Netlify"),
    ".firebaseapp.com":         (OwnerClass.SAAS, "Firebase"),
    ".web.app":                 (OwnerClass.SAAS, "Firebase Hosting"),
    ".appspot.com":             (OwnerClass.SAAS, "Google App Engine"),
    ".readthedocs.io":          (OwnerClass.SAAS, "Read the Docs"),
    ".360learning.com":         (OwnerClass.SAAS, "360Learning"),
    ".thinkific.com":           (OwnerClass.SAAS, "Thinkific"),
    ".litmos.com":              (OwnerClass.SAAS, "Litmos LMS"),
    ".docebosaas.com":          (OwnerClass.SAAS, "Docebo"),
    ".jiveon.com":              (OwnerClass.SAAS, "Jive"),
    ".mailgun.org":             (OwnerClass.SAAS, "Mailgun"),
    ".sendgrid.net":            (OwnerClass.SAAS, "SendGrid"),
    ".mandrillapp.com":         (OwnerClass.SAAS, "Mandrill"),
    ".helpscout.net":           (OwnerClass.SAAS, "Help Scout"),
    ".freshcaller.com":         (OwnerClass.SAAS, "Freshcaller"),
    ".kustomerapp.com":         (OwnerClass.SAAS, "Kustomer"),
    ".gitbook.io":              (OwnerClass.SAAS, "GitBook"),
    ".wpengine.com":            (OwnerClass.SAAS, "WP Engine"),
    ".kinsta.cloud":            (OwnerClass.SAAS, "Kinsta"),
    ".pantheonsite.io":         (OwnerClass.SAAS, "Pantheon"),
    ".myshopify.com":           (OwnerClass.SAAS, "Shopify"),
    ".webflow.io":              (OwnerClass.SAAS, "Webflow"),
    ".squarespace.com":         (OwnerClass.SAAS, "Squarespace"),
    ".wix.com":                 (OwnerClass.SAAS, "Wix"),

    # SaaS — collaboration / business apps
    ".sharepoint.com":          (OwnerClass.SAAS, "Microsoft 365 SharePoint"),
    ".onmicrosoft.com":         (OwnerClass.SAAS, "Microsoft 365"),
    ".dynamics.com":            (OwnerClass.SAAS, "Microsoft Dynamics 365"),
    ".outlook.com":             (OwnerClass.SAAS, "Microsoft 365 Outlook"),
    ".office.com":              (OwnerClass.SAAS, "Microsoft 365"),
    ".lync.com":                (OwnerClass.SAAS, "Microsoft Teams"),
    ".atlassian.net":           (OwnerClass.SAAS, "Atlassian Cloud"),
    ".zendesk.com":             (OwnerClass.SAAS, "Zendesk"),
    ".freshdesk.com":           (OwnerClass.SAAS, "Freshdesk"),
    ".freshservice.com":        (OwnerClass.SAAS, "Freshservice"),
    ".hubspot.com":             (OwnerClass.SAAS, "HubSpot"),
    ".hubspotusercontent.com":  (OwnerClass.SAAS, "HubSpot"),
    ".sites.hubspot.net":       (OwnerClass.SAAS, "HubSpot"),
    ".intercom.io":             (OwnerClass.SAAS, "Intercom"),
    ".helpscoutdocs.com":       (OwnerClass.SAAS, "Help Scout"),
    ".typeform.com":            (OwnerClass.SAAS, "Typeform"),
    ".surveymonkey.com":        (OwnerClass.SAAS, "SurveyMonkey"),
    ".mailchimp.com":           (OwnerClass.SAAS, "Mailchimp"),
    ".pardot.com":              (OwnerClass.SAAS, "Pardot"),
    ".salesforce.com":          (OwnerClass.SAAS, "Salesforce"),
    ".force.com":               (OwnerClass.SAAS, "Salesforce"),
    ".my.salesforce.com":       (OwnerClass.SAAS, "Salesforce"),
    ".workday.com":             (OwnerClass.SAAS, "Workday"),
    ".servicenow.com":          (OwnerClass.SAAS, "ServiceNow"),
}

# WHOIS AS number → (class, provider). Populated from public ASN registries.
ASN_TABLE: dict[str, tuple[OwnerClass, str]] = {
    # CDN
    "AS13335": (OwnerClass.CDN, "Cloudflare"),
    "AS20940": (OwnerClass.CDN, "Akamai"),
    "AS16625": (OwnerClass.CDN, "Akamai"),
    "AS21342": (OwnerClass.CDN, "Akamai"),
    "AS54113": (OwnerClass.CDN, "Fastly"),
    "AS60068": (OwnerClass.CDN, "CDN77"),

    # Cloud — Microsoft (M365/Azure ASNs are large and overlap; mark shared)
    "AS8075":  (OwnerClass.SAAS,         "Microsoft"),
    "AS8068":  (OwnerClass.SAAS,         "Microsoft"),
    "AS6584":  (OwnerClass.SAAS,         "Microsoft"),
    "AS3598":  (OwnerClass.SAAS,         "Microsoft"),

    # Cloud — AWS
    "AS16509": (OwnerClass.CLOUD_SHARED, "Amazon AWS"),
    "AS14618": (OwnerClass.CLOUD_SHARED, "Amazon AWS"),
    "AS39111": (OwnerClass.CLOUD_SHARED, "Amazon AWS"),

    # Cloud — Google
    "AS15169": (OwnerClass.CLOUD_SHARED, "Google"),
    "AS396982":(OwnerClass.CLOUD_SHARED, "Google Cloud"),

    # Cloud — Other
    "AS14061": (OwnerClass.CLOUD_SHARED, "DigitalOcean"),
    "AS63949": (OwnerClass.CLOUD_SHARED, "Linode/Akamai Cloud"),
    "AS20473": (OwnerClass.CLOUD_SHARED, "Vultr/Choopa"),
    "AS24940": (OwnerClass.CLOUD_SHARED, "Hetzner"),
    "AS16276": (OwnerClass.CLOUD_SHARED, "OVH"),
    "AS9009":  (OwnerClass.CLOUD_SHARED, "M247"),
}

# Substring match on the WHOIS Org field — catches ASNs we don't have an entry
# for (long tail) but where the org name is unmistakable.
ORG_SUBSTR_TABLE: tuple[tuple[str, OwnerClass, str], ...] = (
    ("cloudflare",  OwnerClass.CDN, "Cloudflare"),
    ("akamai",      OwnerClass.CDN, "Akamai"),
    ("fastly",      OwnerClass.CDN, "Fastly"),
    ("cdn77",       OwnerClass.CDN, "CDN77"),
    ("microsoft",   OwnerClass.SAAS, "Microsoft"),
    ("msft",        OwnerClass.SAAS, "Microsoft"),
    ("amazon",      OwnerClass.CLOUD_SHARED, "Amazon AWS"),
    ("amzn",        OwnerClass.CLOUD_SHARED, "Amazon AWS"),
    ("at-88-z",     OwnerClass.CLOUD_SHARED, "Amazon AWS"),
    ("google",      OwnerClass.CLOUD_SHARED, "Google"),
    ("digitalocean",OwnerClass.CLOUD_SHARED, "DigitalOcean"),
    ("hetzner",     OwnerClass.CLOUD_SHARED, "Hetzner"),
    ("ovh",         OwnerClass.CLOUD_SHARED, "OVH"),
    ("linode",      OwnerClass.CLOUD_SHARED, "Linode"),
    ("vultr",       OwnerClass.CLOUD_SHARED, "Vultr"),
    ("oracle",      OwnerClass.CLOUD_SHARED, "Oracle Cloud"),
)


# ─── Lookup helpers ───────────────────────────────────────────────────────────
_whois_cache: dict[str, tuple[str, str]] = {}  # ip -> (asn, org)

_ASN_RE = re.compile(r"\bAS(\d{2,7})\b", re.I)


def whois_asn(ip: str, timeout: float = 6.0) -> tuple[str, str]:
    """Return (ASN, Org) for an IP — both may be ''. Cached.

    Two-pass parse:
      - First we look for an *expressive* Org line (OrgName, organization, owner,
        descr, role) and ASN line.
      - NetName / CustName are cryptic codes ("MSFT", "AT-88-Z"); keep them as a
        fallback only if no expressive Org line shows up.
    """
    if ip in _whois_cache:
        return _whois_cache[ip]
    if not have("whois"):
        _whois_cache[ip] = ("", "")
        return ("", "")
    rc, out = run(["whois", ip], timeout=timeout)
    asn = ""
    org = ""
    fallback_org = ""
    last_asn_anywhere = ""
    EXPRESSIVE = ("orgname:", "org-name:", "organization:", "owner:",
                  "descr:", "org:", "role:")
    CRYPTIC = ("netname:", "custname:", "cust-name:")
    for line in out.splitlines():
        s = line.strip()
        low = s.lower()
        # ASN — explicit fields first
        if not asn and ("origin:" in low or "originas:" in low or "origin_as:" in low):
            m = _ASN_RE.search(s)
            if m:
                asn = f"AS{m.group(1)}"
        if not asn and low.startswith("aut-num:"):
            m = _ASN_RE.search(s)
            if m:
                asn = f"AS{m.group(1)}"
        # remember any AS number we saw — used as a last-ditch fallback
        if not last_asn_anywhere:
            m = _ASN_RE.search(s)
            if m:
                last_asn_anywhere = f"AS{m.group(1)}"
        # Expressive org wins
        if not org and any(low.startswith(k) for k in EXPRESSIVE):
            v = s.split(":", 1)[1].strip()
            if v:
                org = v
        if not fallback_org and any(low.startswith(k) for k in CRYPTIC):
            v = s.split(":", 1)[1].strip()
            if v:
                fallback_org = v
    if not org:
        org = fallback_org
    if not asn:
        asn = last_asn_anywhere
    _whois_cache[ip] = (asn, org)
    return _whois_cache[ip]


def _suffix_match(name: str) -> Optional[tuple[OwnerClass, str, str]]:
    """Return (class, provider, matched suffix) or None."""
    n = name.lower().rstrip(".")
    # longest suffix first so .scm.azurewebsites.net beats .azurewebsites.net
    for suffix in sorted(SUFFIX_TABLE.keys(), key=len, reverse=True):
        if n.endswith(suffix):
            cls, prov = SUFFIX_TABLE[suffix]
            return cls, prov, suffix
    return None


def _asn_match(asn: str, org: str) -> Optional[tuple[OwnerClass, str]]:
    if asn and asn in ASN_TABLE:
        return ASN_TABLE[asn]
    if org:
        ol = org.lower()
        for needle, cls, prov in ORG_SUBSTR_TABLE:
            if needle in ol:
                return cls, prov
    return None


def _is_subdomain_of(host: str, roots: list[str]) -> bool:
    h = host.lower().rstrip(".")
    for r in roots:
        r = r.lower().rstrip(".")
        if h == r or h.endswith("." + r):
            return True
    return False


# ─── Core classification ──────────────────────────────────────────────────────
def classify(scope_or_host: str, root_domains: list[str]) -> Classification:
    """Classify a single scope. Safe to call concurrently."""
    raw = (scope_or_host or "").strip()
    if not raw:
        return Classification(OwnerClass.UNKNOWN, evidence="empty scope")

    # 1) If scope is/contains an IP, classify from the IP directly
    ip_in_scope = extract_ip(raw)
    if ip_in_scope:
        if is_private(ip_in_scope):
            return Classification(OwnerClass.INTERNAL, ip=ip_in_scope,
                                  evidence="RFC1918 / link-local / loopback")
        asn, org = whois_asn(ip_in_scope)
        m = _asn_match(asn, org)
        if m:
            cls, prov = m
            return Classification(cls, provider=prov, ip=ip_in_scope, asn=asn,
                                  evidence=f"WHOIS {asn or org}".strip())
        # Unknown ASN — if this IP shows up only because the user named it as a
        # target, consider it OWNED. We can't tell apart here, mark UNKNOWN.
        return Classification(OwnerClass.UNKNOWN, ip=ip_in_scope, asn=asn,
                              evidence=f"WHOIS {asn} / {org}".strip(" /"))

    host = extract_host(raw)
    if not host:
        return Classification(OwnerClass.UNKNOWN, evidence="no host parsed")

    # 2) Direct suffix match on the host itself (handles cases where the
    #    customer aliased to a SaaS subdomain rather than CNAMEing).
    m = _suffix_match(host)
    if m:
        cls, prov, suf = m
        return Classification(cls, provider=prov,
                              evidence=f"host suffix {suf}")

    # 3) CNAME chain — first hop only is usually sufficient
    cname = resolve_cname(host)
    if cname:
        m = _suffix_match(cname)
        if m:
            cls, prov, suf = m
            return Classification(cls, provider=prov,
                                  evidence=f"CNAME → {cname} ({suf})")

    # 4) Resolve to IP, look up ASN
    ips = dns_lookup(host, "A")
    if ips:
        ip = ips[0]
        if is_private(ip):
            return Classification(OwnerClass.INTERNAL, ip=ip,
                                  evidence=f"{host} → {ip} (private)")
        asn, org = whois_asn(ip)
        m = _asn_match(asn, org)
        if m:
            cls, prov = m
            return Classification(cls, provider=prov, ip=ip, asn=asn,
                                  evidence=f"{host} → {ip} (WHOIS {asn or org})")
        # 5) No SaaS/CDN signals → check root match
        if _is_subdomain_of(host, root_domains):
            return Classification(OwnerClass.OWNED, ip=ip, asn=asn,
                                  evidence=f"subdomain of input root ({_matched_root(host, root_domains)})")
        return Classification(OwnerClass.EXTERNAL, ip=ip, asn=asn,
                              evidence=f"not in input roots; ASN {asn or org}".strip())

    # No IP resolution and no SaaS suffix
    if _is_subdomain_of(host, root_domains):
        return Classification(OwnerClass.OWNED,
                              evidence=f"subdomain of input root ({_matched_root(host, root_domains)}); no A record")
    return Classification(OwnerClass.UNKNOWN, evidence="no resolution, no root match")


def _matched_root(host: str, roots: list[str]) -> str:
    h = host.lower().rstrip(".")
    best = ""
    for r in roots:
        r_ = r.lower().rstrip(".")
        if h == r_ or h.endswith("." + r_):
            if len(r_) > len(best):
                best = r_
    return best


# ─── Driver ───────────────────────────────────────────────────────────────────
def read_root_domains(pentest_dir: Path) -> list[str]:
    p = pentest_dir / "recon" / "input_domains.txt"
    if not p.is_file():
        return []
    out = []
    for line in p.read_text(errors="ignore").splitlines():
        s = line.split("#", 1)[0].strip()
        if s:
            out.append(s)
    return out


def collect_scopes_from_findings(tsv: Path) -> list[str]:
    if not tsv.is_file():
        return []
    seen: dict[str, None] = {}
    with tsv.open("r", errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            scope = parts[2].strip()
            if not scope:
                continue
            key = extract_host(scope) or extract_ip(scope) or scope
            if key not in seen:
                seen[key] = None
    return list(seen.keys())


def collect_resolved_subdomains(pentest_dir: Path) -> list[str]:
    """Every resolved subdomain from recon/subs_all_*.txt (post-DNS-resolution,
    so live hosts, not historical candidates). Folding these into the ownership
    pass means the asset export carries IP/ASN/owner-class for EVERY real asset
    — not just the ones that produced a finding — which the owner-assignment
    workflow needs."""
    recon = pentest_dir / "recon"
    out: dict[str, None] = {}
    if not recon.is_dir():
        return []
    import re as _re
    _fqdn = _re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
    for p in list(recon.glob("subs_all_*.txt")) + [recon / "subs_master.txt"]:
        if not p.is_file():
            continue
        try:
            for line in p.read_text(errors="ignore").splitlines():
                s = line.strip().lower()
                # strip wildcard/leading dots + trailing dot; drop malformed names
                s = _re.sub(r"^\*\.", "", s)
                s = s.strip(".")
                if s and not s.startswith("#") and _fqdn.match(s):
                    out[s] = None
        except OSError:
            pass
    return list(out.keys())


def build_map(pentest_dir: Path, workers: int = 16,
              progress=None) -> dict[str, Classification]:
    roots = read_root_domains(pentest_dir)
    findings = pentest_dir / "report" / "findings.tsv"
    # Universe = finding-scopes UNION every resolved subdomain, so ownership
    # (IP/ASN/provider/class) is computed for the full realistic asset inventory
    # the team will assign owners to — not only hosts that raised an issue.
    # (discovered.log SUBDOMAINS rows are summary counts, not hosts — excluded.)
    scope_set: dict[str, None] = {}
    for s in collect_scopes_from_findings(findings):
        scope_set[s] = None
    for h in collect_resolved_subdomains(pentest_dir):
        scope_set[h] = None
    scopes = list(scope_set.keys())

    result: dict[str, Classification] = {}
    total = len(scopes)
    done = 0

    def _one(s: str) -> tuple[str, Classification]:
        try:
            return s, classify(s, roots)
        except Exception as e:
            return s, Classification(OwnerClass.UNKNOWN, evidence=f"error: {e}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, cls in pool.map(_one, scopes):
            result[host] = cls
            done += 1
            if progress:
                progress(done, total)

    persist(pentest_dir, result)
    return result


def persist(pentest_dir: Path, m: dict[str, Classification]) -> Path:
    p = pentest_dir / "report" / "ownership.tsv"
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        f.write("HOST\tCLASS\tPROVIDER\tIP\tASN\tEVIDENCE\n")
        for host, c in sorted(m.items()):
            f.write(f"{host}\t{c.owner_class.value}\t{c.provider}\t{c.ip}\t{c.asn}\t{c.evidence}\n")
    return p


def load(pentest_dir: Path) -> dict[str, Classification]:
    p = pentest_dir / "report" / "ownership.tsv"
    out: dict[str, Classification] = {}
    if not p.is_file():
        return out
    with p.open("r", errors="ignore") as f:
        next(f, None)  # header
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            host, cls, prov, ip, asn, ev = parts[:6]
            try:
                oc = OwnerClass(cls)
            except ValueError:
                oc = OwnerClass.UNKNOWN
            out[host] = Classification(owner_class=oc, provider=prov, ip=ip, asn=asn, evidence=ev)
    return out


# ─── CLI ──────────────────────────────────────────────────────────────────────
def _main() -> int:
    import argparse, json, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("pentest_dir", type=Path)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    def prog(d, t):
        if not args.json:
            print(f"\r[ownership] {d}/{t}", end="", file=sys.stderr, flush=True)

    m = build_map(args.pentest_dir, workers=args.workers, progress=prog)
    if not args.json:
        print(file=sys.stderr)
        from collections import Counter
        counts = Counter(c.owner_class.value for c in m.values())
        print(f"[ownership] {len(m)} hosts classified")
        for cls, n in counts.most_common():
            print(f"  {cls:14s} {n}")
        print(f"[ownership] wrote: {args.pentest_dir}/report/ownership.tsv")
    else:
        print(json.dumps({h: c.to_dict() for h, c in m.items()}, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
