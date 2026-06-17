"""
validator.py — Berckley validation layer: re-probes findings to filter false positives.

Reads  : <pentest_dir>/report/findings.tsv     (raw)
Writes : <pentest_dir>/report/findings_validated.tsv  (post-validation, same 4-col schema)
         <pentest_dir>/report/findings_audit.tsv      (verdict + rule + reason per finding)

Design:
  Each Rule is a small class. `applies()` decides if the rule even looks at a
  finding; `validate()` returns a Verdict (KEEP / SUPPRESS / DOWNGRADE).
  Rules run in registration order; first non-KEEP verdict wins (so cheap
  filters can short-circuit before we make network calls).

CLI:
  python validator.py <pentest_dir>
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# ─── Data ─────────────────────────────────────────────────────────────────────
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


@dataclass
class Finding:
    severity: str
    category: str
    scope: str
    description: str
    line_no: int = 0  # original index, useful for stable audit output

    def to_tsv(self) -> str:
        return f"{self.severity}\t{self.category}\t{self.scope}\t{self.description}"


@dataclass
class Verdict:
    action: str               # KEEP | SUPPRESS | DOWNGRADE
    rule: str = ""
    reason: str = ""
    new_severity: str = ""    # only set when action == DOWNGRADE

    @classmethod
    def keep(cls) -> "Verdict":
        return cls(action="KEEP")

    @classmethod
    def suppress(cls, rule: str, reason: str) -> "Verdict":
        return cls(action="SUPPRESS", rule=rule, reason=reason)

    @classmethod
    def downgrade(cls, rule: str, new_sev: str, reason: str) -> "Verdict":
        return cls(action="DOWNGRADE", rule=rule, new_severity=new_sev, reason=reason)


# ─── Helpers ──────────────────────────────────────────────────────────────────
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_PORT_RE = re.compile(r":(\d+)$")


def extract_ip(scope: str) -> Optional[str]:
    """Pull an IPv4 out of a scope string (which may also be a hostname)."""
    if not scope:
        return None
    m = _IP_RE.search(scope)
    if m:
        try:
            ipaddress.ip_address(m.group(1))
            return m.group(1)
        except ValueError:
            return None
    return None


def extract_host(scope: str) -> str:
    """Strip URL scheme, path, and trailing :port — return bare host.
    Some scopes are space-separated lists of URLs (when one finding clusters
    many hosts); take only the first token to avoid producing garbage hosts."""
    s = scope.strip()
    if not s:
        return ""
    s = s.split()[0]
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    s = _PORT_RE.sub("", s)
    return s


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local or a.is_loopback or a.is_reserved
    except ValueError:
        return False


def run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, ""
    except FileNotFoundError:
        return 127, ""


_have_cache: dict[str, bool] = {}


def have(tool: str) -> bool:
    if tool not in _have_cache:
        _have_cache[tool] = shutil.which(tool) is not None
    return _have_cache[tool]


# ─── DNS / probe primitives ───────────────────────────────────────────────────
_dns_cache: dict[tuple[str, str], list[str]] = {}

# Public resolvers — pinning avoids being fooled by broken/corporate
# local DNS (which can silently return NXDOMAIN for valid public zones).
DNS_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


def dns_lookup(host: str, rrtype: str) -> list[str]:
    key = (host.lower(), rrtype.upper())
    if key in _dns_cache:
        return _dns_cache[key]
    if not have("dig"):
        _dns_cache[key] = []
        return []
    rows: list[str] = []
    for resolver in DNS_RESOLVERS:
        rc, out = run(
            ["dig", f"@{resolver}", "+short", "+time=3", "+tries=1", host, rrtype],
            timeout=6,
        )
        rows = [l.strip().rstrip(".") for l in out.splitlines()
                if l.strip() and not l.startswith(";")]
        if rows or rc == 0:
            break  # first resolver that answers (even with empty result) wins
    _dns_cache[key] = rows
    return rows


def host_resolves(host: str) -> bool:
    """True if the host has A, AAAA, or CNAME — proves DNS plumbing works
    for this name. Used to distinguish 'real no-MX' from 'DNS is broken'."""
    return bool(dns_lookup(host, "A")
                or dns_lookup(host, "AAAA")
                or dns_lookup(host, "CNAME"))


def has_mx(host: str) -> bool:
    """True if the bare host (not parent zone) has an MX record."""
    return bool(dns_lookup(host, "MX"))


def resolve_cname(host: str) -> Optional[str]:
    rows = dns_lookup(host, "CNAME")
    return rows[0] if rows else None


def snmpget_alive(ip: str, community: str, timeout: float = 4.0) -> bool:
    """Probe sysDescr.0 (1.3.6.1.2.1.1.1.0) — definitive 'real or not'."""
    if not have("snmpget"):
        return False  # no tool ⇒ can't verify ⇒ caller decides
    rc, out = run(
        ["snmpget", "-v2c", "-c", community or "public",
         "-r", "1", "-t", str(int(timeout)), ip, "1.3.6.1.2.1.1.1.0"],
        timeout=timeout + 2,
    )
    return rc == 0 and "STRING" in out


# ─── Rules ────────────────────────────────────────────────────────────────────
class Rule:
    name: str = "unnamed"
    description: str = ""
    needs_network: bool = False

    def applies(self, f: Finding) -> bool:
        raise NotImplementedError

    def validate(self, f: Finding) -> Verdict:
        raise NotImplementedError


class StaleScopeRule(Rule):
    """Re-probe the URL/host of each HTTP-content finding at validation time.

    Suppress when the scope no longer hosts a real deployment:
      - vendor "deployment not found" / "no such app" / "404 site removed" pages
      - HTTP 000 / connection refused
      - NXDOMAIN
      - generic SaaS 404 + tiny body

    This is the FP-killer for nuclei + SSTI-style content matches that fired
    during the scan but whose target was decommissioned before the analyst
    reads the report.

    Findings whose category is purely DNS / TLS / port-level are left alone
    (the scope may legitimately not respond on HTTP).
    """
    name = "stale-scope"
    description = "scope no longer hosts a live deployment"
    needs_network = True

    # Categories whose validity depends on the URL still serving real content.
    # Keep DNS/TLS/port/email findings out of this list -- they're checked
    # against other layers (cert, DNS records, listen sockets).
    HTTP_CATEGORIES = (
        "SSTI", "Template Injection",
        "XSS", "Cross-Site Scripting", "DOM",
        "SQL Injection", "SQLi",
        "Path Traversal", "LFI", "RFI",
        "SSRF", "Open Redirect",
        "Admin Panel", "Default Credentials",
        "Default Page", "Backup File", "Sensitive File",
        "API", "GraphQL", "Swagger", "OpenAPI", "Schema",
        "Server", "Powered", "Header", "Cookie",
        "CORS", "CSP", "HSTS",
        "Cache", "BREACH",
        "Subdomain Takeover",
        "Authentication", "Login",
        "Web App", "WebApp",
        "Nuclei",  # generic nuclei finding category
        "Tilde", "IIS",
        "Federated", "OAuth", "OIDC", "SSO",
    )

    # Vendor / SaaS "this deployment / app / repo is gone" markers
    DEAD_MARKERS = (
        # Vercel / Next deployments
        "DEPLOYMENT_NOT_FOUND",
        "deployment could not be found",
        "DEPLOYMENT_DISABLED",
        # Heroku
        "no such app",
        "application error",
        "the site you were looking for couldn't be found",
        # GitHub Pages
        "there isn't a github pages",
        # Netlify
        "page not found netlify",
        # Surge
        "project not found",
        # Cloudflare error pages
        "error 1015",                            # rate limited
        "error 1016",                            # origin DNS error
        "error 1020",                            # access denied
        "error 1006",                            # access denied
        "origin dns error",
        "web server is returning an unknown error",
        "the requested url could not be retrieved",
        # GitLab / Bitbucket / repo hosts
        "repository not found",
        "404 not found gitlab",
        # Render / Fly / Railway / modern PaaS
        "render encountered an error",
        "no app on this host",                  # Fly.io
        "application failed to respond",        # Fly.io / Render
        "railway is down for maintenance",
        # SaaS apps shut down
        "help center closed",
        "this user voice site has been closed",
        "no settings were found",               # Tumblr
        # Shared-tenant defaults
        "this domain is not configured",        # Azure App Service shared
        "404 web site not found",               # IIS shared
        "default web site",                     # IIS placeholder
        "it works!",                            # Apache placeholder
        "welcome to nginx",                     # nginx placeholder
        "test page for the apache",             # CentOS apache placeholder
        # Cloudfront / AWS S3 access denied / no such bucket
        "<code>nosuchbucket</code>",
        "the specified bucket does not exist",
        "<code>accessdenied</code>",
        "the request could not be satisfied",   # CloudFront generic
        # Parked / for-sale
        "namecheap parkingpage",
        "this domain has been parked",
        "this domain may be for sale",
        "buy this domain",
        "this domain is for sale",
        "godaddy.com",                          # parking
        "sedoparking.com",
        "hugedomains.com",
        "afternic.com",
        "bodis.com",
        # Generic suspended / not-set-up
        "this account has been suspended",
        "site doesn't exist",
        "page doesn't exist",
        "the site cannot be reached",
        "we couldn't find the page",            # generic SaaS 404
        "no settings",
        # Coming soon / under construction (typical for vacant subdomains)
        "coming soon",
        "under construction",
    )

    # In-process cache so each URL is only probed once per validation run
    _probe_cache: dict[str, tuple[int, str]] = {}

    def applies(self, f: Finding) -> bool:
        cat = f.category or ""
        return any(k.lower() in cat.lower() for k in self.HTTP_CATEGORIES)

    def _probe(self, url: str) -> tuple[int, str]:
        if url in self._probe_cache:
            return self._probe_cache[url]
        # Two-step: 1) status code + size, 2) body for marker scan
        rc, out = run(["curl", "-sk", "-A", "berckley-validator/1.0",
                       "-o", "/tmp/_probe_body.txt",
                       "-w", "%{http_code}\n%{size_download}",
                       "--max-time", "6", url], timeout=10)
        code = 0
        size = 0
        if rc == 0 and out:
            parts = out.strip().split("\n")
            try:
                code = int(parts[0])
            except (ValueError, IndexError):
                code = 0
            try:
                size = int(parts[1]) if len(parts) > 1 else 0
            except ValueError:
                size = 0
        body = ""
        try:
            with open("/tmp/_probe_body.txt", "r", errors="ignore") as fh:
                body = fh.read(8000)  # first 8KB enough for marker detection
        except OSError:
            body = ""
        self._probe_cache[url] = (code, body)
        return code, body

    @staticmethod
    def _extract_url(scope: str) -> Optional[str]:
        s = (scope or "").strip().split()[0] if scope and scope.strip() else ""
        if not s:
            return None
        if s.startswith(("http://", "https://")):
            return s
        # Hostname / host:port → assume http://
        host = extract_host(s)
        if host:
            # If scope was host:443, prefer https
            port = ""
            m = _PORT_RE.search(s)
            if m:
                port = m.group(1)
            if port == "443":
                return f"https://{host}"
            return f"http://{host}"
        return None

    def validate(self, f: Finding) -> Verdict:
        url = self._extract_url(f.scope)
        if not url:
            return Verdict.keep()
        try:
            code, body = self._probe(url)
        except Exception:
            return Verdict.keep()
        # 0 = connection refused / DNS resolution failure
        if code == 0:
            return Verdict.suppress(
                self.name,
                "scope no longer responds (DNS / connection refused at validation time)",
            )
        # Vendor "deployment removed" markers
        body_lc = body.lower()
        for marker in self.DEAD_MARKERS:
            if marker.lower() in body_lc:
                return Verdict.suppress(
                    self.name,
                    f"scope returns dead-deployment page (matches '{marker[:40]}')",
                )
        # Hard 404 with a small body and no useful content → likely decommissioned
        if code == 404 and len(body) < 600:
            # But only suppress for content-driven findings -- keep "Missing
            # Header" alive for any HTTP response since headers apply to 404 too.
            cat_lc = (f.category or "").lower()
            if any(k.lower() in cat_lc for k in (
                "SSTI", "XSS", "SQL", "Traversal", "LFI", "Admin Panel",
                "Default Credentials", "Backup", "API", "GraphQL",
                "Open Redirect", "SSRF",
            )):
                return Verdict.suppress(
                    self.name,
                    f"scope returns 404 with <600B body -- content-based finding can't reproduce",
                )
        return Verdict.keep()


class WildcardHostRule(Rule):
    """Detect hosts whose web server serves the SAME body for any path
    (SPA fallback, catch-all reverse proxy, parked-domain template). On those
    hosts every path-based finding from nuclei/SSTI/admin-panel/etc. is a
    false positive — the matcher hit because the SPA's index always responds.

    Method: for each unique host across the finding set, fetch a random
    nonsense path. If it returns 200 with non-trivial body (>200 bytes) AND
    the body hash matches the matcher's hit, we have a wildcard host. Cache
    the verdict per host so each is probed at most once per validation run.
    """
    name = "wildcard-host"
    description = "host serves identical body for any path (SPA / catch-all)"
    needs_network = True

    # Same category gate as StaleScopeRule -- path-content findings only
    HTTP_CATEGORIES = StaleScopeRule.HTTP_CATEGORIES if False else (
        "SSTI", "Template Injection",
        "XSS", "Cross-Site Scripting",
        "SQL Injection", "SQLi",
        "Path Traversal", "LFI", "RFI",
        "SSRF", "Open Redirect",
        "Admin Panel", "Default Credentials",
        "Default Page", "Backup File", "Sensitive File",
        "API", "GraphQL", "Swagger", "OpenAPI",
        "Nuclei",
        "Federated", "OAuth", "OIDC", "SSO",
        "Exposed",
    )

    # host (scheme://host) → True if wildcard, False if not
    _verdict_cache: dict[str, bool] = {}

    def applies(self, f: Finding) -> bool:
        cat = (f.category or "")
        return any(k.lower() in cat.lower() for k in self.HTTP_CATEGORIES)

    @staticmethod
    def _site_root(scope: str) -> Optional[str]:
        s = (scope or "").strip().split()[0] if scope and scope.strip() else ""
        if not s:
            return None
        if not s.startswith(("http://", "https://")):
            host = extract_host(s)
            if not host:
                return None
            s = f"http://{host}"
        # Strip path/query, keep scheme://host[:port]
        m = re.match(r"(https?://[^/]+)", s)
        return m.group(1) if m else None

    def _is_wildcard(self, root: str) -> bool:
        if root in self._verdict_cache:
            return self._verdict_cache[root]
        import random
        nonce = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=24))
        random_url = f"{root}/__wildcard_check_{nonce}"
        # Fetch real and random; compare body hash
        rc1, body_random = run(["curl", "-sk", "-A", "berckley-validator/1.0",
                                "--max-time", "6", random_url], timeout=10)
        rc2, body_root   = run(["curl", "-sk", "-A", "berckley-validator/1.0",
                                "--max-time", "6", f"{root}/"], timeout=10)
        is_wild = False
        if rc1 == 0 and rc2 == 0 and body_random and body_root:
            # If random non-existent path returns 200 with body close to the
            # site's index body, it's a SPA / catch-all.
            len_random = len(body_random)
            len_root = len(body_root)
            if len_random > 200 and len_root > 200:
                # Bodies similar in size (within 5%) OR hash match → wildcard
                import hashlib
                h1 = hashlib.md5(body_random.encode("utf-8", "replace")).hexdigest()
                h2 = hashlib.md5(body_root.encode("utf-8", "replace")).hexdigest()
                size_close = abs(len_random - len_root) < max(50, 0.05 * len_root)
                is_wild = (h1 == h2) or size_close
        self._verdict_cache[root] = is_wild
        return is_wild

    def validate(self, f: Finding) -> Verdict:
        root = self._site_root(f.scope)
        if not root:
            return Verdict.keep()
        try:
            if self._is_wildcard(root):
                return Verdict.suppress(
                    self.name,
                    f"host {root} returns identical body on a random path -- SPA/catch-all FP",
                )
        except Exception:
            return Verdict.keep()
        return Verdict.keep()


class UserSuppressionRule(Rule):
    """Persistent user-curated suppression list. Runs before all other rules
    so a manually-suppressed finding never gets re-judged by automatic logic."""
    name = "user-suppression"
    description = "matched a persistent user suppression entry"

    # Lazily injected by run_validation so we load suppressions once per run.
    SUPPRESSIONS: list = []

    def applies(self, f: Finding) -> bool:
        return bool(self.SUPPRESSIONS)

    def validate(self, f: Finding) -> Verdict:
        try:
            import suppressions
        except Exception:
            return Verdict.keep()
        m = suppressions.find_match(f.category, f.scope, self.SUPPRESSIONS)
        if m:
            reason = f"user-suppressed: {m.reason}" if m.reason else "user-suppressed"
            return Verdict.suppress(self.name, reason)
        return Verdict.keep()


class Rfc1918Rule(Rule):
    """Any finding whose scope is an RFC1918/loopback/link-local IP is not
    actually externally exposed — by definition the external scanner couldn't
    reach it from the Internet, so it's a routing-table accident."""
    name = "rfc1918-not-external"
    description = "scope is private / link-local / loopback address"

    def applies(self, f: Finding) -> bool:
        ip = extract_ip(f.scope)
        return ip is not None and is_private(ip)

    def validate(self, f: Finding) -> Verdict:
        return Verdict.suppress(self.name, self.description)


class SnmpReverifyRule(Rule):
    """SNMP community sweeps are notorious for false positives — single UDP
    packets get rate-limited or fall into queues; a benign router returns
    a malformed reply that the scanner misreads as 'community accepted'.
    Re-probe with snmpget against sysDescr; if it doesn't actually return
    data, suppress."""
    name = "snmp-reverify"
    description = "re-probe with snmpget"
    needs_network = True

    _COMM_RE = re.compile(r"community '([^']*)' accepted")

    def applies(self, f: Finding) -> bool:
        return "SNMP" in f.category and "Community" in f.category

    def validate(self, f: Finding) -> Verdict:
        ip = extract_ip(f.scope)
        if ip is None:
            return Verdict.keep()
        m = self._COMM_RE.search(f.description or "")
        candidates = []
        if m:
            candidates.append(m.group(1) or "public")
        candidates += ["public", "private"]
        for c in candidates:
            if snmpget_alive(ip, c):
                return Verdict.keep()
        if not have("snmpget"):
            return Verdict.keep()  # can't verify → don't second-guess
        return Verdict.suppress(self.name, "snmpget got no reply — scan-time FP")


class EmailAuthNoMxRule(Rule):
    """SPF / DMARC absence is only impactful if the host can actually send
    email. A static subdomain (apps.example.com, www, blog) with no MX
    cannot originate mail — missing SPF/DMARC there is informational."""
    name = "email-auth-no-mx"
    description = "host has no MX record — cannot originate email"
    needs_network = True

    _CATS = ("SPF", "DMARC")

    def applies(self, f: Finding) -> bool:
        return any(k in f.category for k in self._CATS)

    def validate(self, f: Finding) -> Verdict:
        host = extract_host(f.scope)
        if has_mx(host):
            return Verdict.keep()
        # Fail-safe: if the host doesn't resolve at all, DNS is broken
        # (or the host was decommissioned mid-scan) — don't pretend to know
        # the MX answer, leave the finding intact.
        if not host_resolves(host):
            return Verdict.keep()
        if f.severity in ("HIGH", "MEDIUM"):
            return Verdict.downgrade(self.name, "LOW", self.description)
        return Verdict.keep()


class CertCnameSaasRule(Rule):
    """A 'certificate hostname mismatch' on a CNAME pointing at a third-party
    SaaS/CDN (Cloudfront, Azure App Service, GitHub Pages, etc.) is not the
    customer's mis-issued cert — it's the provider's shared cert. Downgrade
    so it's tracked but doesn't dominate the HIGH bucket."""
    name = "cert-mismatch-cname-to-saas"
    description = "host CNAMEs to a third-party SaaS / CDN"
    needs_network = True

    _SUFFIXES = (
        ".cloudfront.net", ".amazonaws.com",
        ".azurewebsites.net", ".azureedge.net", ".trafficmanager.net",
        ".windows.net", ".cloudapp.net", ".cloudapp.azure.com",
        ".herokuapp.com", ".github.io", ".githubusercontent.com",
        ".pages.dev", ".vercel.app", ".netlify.app", ".firebaseapp.com",
        ".shopify.com", ".myshopify.com", ".webflow.io",
        ".fastly.net", ".akamaitechnologies.com", ".akamaized.net",
        ".cdn.cloudflare.net", ".cloudflare.net",
        ".wpengine.com", ".kinsta.cloud", ".pantheonsite.io",
        ".hubspot.com", ".hubspotusercontent.com",
        ".sites.hubspot.net", ".freshservice.com", ".zendesk.com",
        ".readthedocs.io", ".gitbook.io",
    )

    def applies(self, f: Finding) -> bool:
        return "Hostname Mismatch" in f.category

    def validate(self, f: Finding) -> Verdict:
        host = extract_host(f.scope)
        cname = resolve_cname(host)
        if cname:
            cn = cname.lower()
            for s in self._SUFFIXES:
                if cn.endswith(s):
                    return Verdict.downgrade(
                        self.name, "MEDIUM",
                        f"CNAME → {cname} (third-party SaaS — cert is provider-controlled)",
                    )
        return Verdict.keep()


class OwnershipInfraRule(Rule):
    """Infra-level findings (TLS, cert, headers, server fingerprint, default
    pages, cipher, OCSP) only matter when the customer actually controls the
    infrastructure. If the host is on third-party SaaS / shared cloud / a CDN
    edge, the customer can't change the cert or set HSTS — downgrade. If it's
    a generic CDN edge, infra findings are noise — suppress."""
    name = "ownership-infra"
    description = "scope is on third-party infra"
    needs_network = False  # uses pre-built map

    INFRA_KEYS = (
        "TLS", "HSTS", "Cert", "Cipher", "OCSP", "Stapling",
        "CSP", "X-Frame", "X-Content", "X-XSS", "Referrer-Policy",
        "Permissions-Policy", "Security Headers", "security.txt",
        "Server", "Powered", "IIS", "Apache", "Nginx", "Tomcat",
        "Tilde", "Default", "Banner", "Cookie", "Cache-Control",
        "HTTP to HTTPS",
    )

    # Lazily injected by run_validation — host (lowercase) → Classification dict
    OWNERSHIP_MAP: dict[str, dict] = {}

    def applies(self, f: Finding) -> bool:
        return any(k in f.category for k in self.INFRA_KEYS)

    def validate(self, f: Finding) -> Verdict:
        if not self.OWNERSHIP_MAP:
            return Verdict.keep()
        host_or_ip = extract_host(f.scope) or extract_ip(f.scope) or ""
        c = self.OWNERSHIP_MAP.get(host_or_ip.lower())
        if not c:
            return Verdict.keep()
        cls = c.get("class", "")
        prov = c.get("provider", "") or "third-party"
        if cls == "CDN":
            return Verdict.suppress(self.name, f"scope is on a CDN edge ({prov}) — provider-managed")
        if cls in ("SAAS", "CLOUD_SHARED"):
            if f.severity in ("CRITICAL", "HIGH"):
                return Verdict.downgrade(self.name, "MEDIUM",
                                         f"scope is on {prov} ({cls}) — customer cannot remediate infra")
            if f.severity == "MEDIUM":
                return Verdict.downgrade(self.name, "LOW",
                                         f"scope is on {prov} ({cls}) — customer cannot remediate infra")
        if cls == "EXTERNAL":
            return Verdict.suppress(self.name, "scope is third-party domain — not customer-owned")
        return Verdict.keep()


# Registration order matters: user suppressions first (intent overrides auto),
# then cheap pure-filter rules, then network probes.
RULES: list[Rule] = [
    UserSuppressionRule(),
    Rfc1918Rule(),
    StaleScopeRule(),           # FP-killer for nuclei/SSTI/admin/etc when site is gone
    WildcardHostRule(),         # FP-killer for SPA/catch-all hosts returning same body
    SnmpReverifyRule(),
    EmailAuthNoMxRule(),
    CertCnameSaasRule(),
    OwnershipInfraRule(),
]


# ─── Orchestration ────────────────────────────────────────────────────────────
def load_findings(tsv: Path) -> list[Finding]:
    out: list[Finding] = []
    if not tsv.is_file():
        return out
    with tsv.open("r", errors="ignore") as f:
        for i, line in enumerate(f, start=1):
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 4:
                continue
            out.append(Finding(parts[0], parts[1], parts[2], parts[3], line_no=i))
    return out


def evaluate(f: Finding) -> Verdict:
    for rule in RULES:
        try:
            if rule.applies(f):
                v = rule.validate(f)
                if v.action != "KEEP":
                    return v
        except Exception as e:  # one bad rule shouldn't sink the run
            return Verdict.keep()  # fail open — keep the finding
    return Verdict.keep()


def validate_all(findings: list[Finding], workers: int = 16,
                 progress: Optional[Callable[[int, int], None]] = None
                 ) -> list[tuple[Finding, Verdict]]:
    """Evaluate every finding in parallel; preserves input order."""
    results: list[Optional[tuple[Finding, Verdict]]] = [None] * len(findings)
    total = len(findings)
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        fut_to_idx = {pool.submit(evaluate, f): i for i, f in enumerate(findings)}
        for fut in as_completed(fut_to_idx):
            idx = fut_to_idx[fut]
            try:
                v = fut.result()
            except Exception:
                v = Verdict.keep()
            results[idx] = (findings[idx], v)
            done += 1
            if progress:
                progress(done, total)
    return [r for r in results if r is not None]


def write_outputs(pairs: list[tuple[Finding, Verdict]], pentest_dir: Path) -> dict:
    """Write findings_validated.tsv (clean) + findings_audit.tsv (full trail)."""
    report = pentest_dir / "report"
    report.mkdir(parents=True, exist_ok=True)
    val_path = report / "findings_validated.tsv"
    audit_path = report / "findings_audit.tsv"

    stats = {
        "total": len(pairs),
        "kept": 0,
        "suppressed": 0,
        "downgraded": 0,
        "by_rule": {},
        "severity_before": {s: 0 for s in SEVERITIES},
        "severity_after": {s: 0 for s in SEVERITIES},
    }

    with val_path.open("w") as fv, audit_path.open("w") as fa:
        fa.write("ORIG_SEV\tNEW_SEV\tCATEGORY\tSCOPE\tDESCRIPTION\tVERDICT\tRULE\tREASON\n")
        for f, v in pairs:
            stats["severity_before"][f.severity] = stats["severity_before"].get(f.severity, 0) + 1
            new_sev = f.severity
            if v.action == "SUPPRESS":
                stats["suppressed"] += 1
                stats["by_rule"][v.rule] = stats["by_rule"].get(v.rule, 0) + 1
                fa.write(f"{f.severity}\t-\t{f.category}\t{f.scope}\t{f.description}\tSUPPRESS\t{v.rule}\t{v.reason}\n")
                continue
            if v.action == "DOWNGRADE":
                stats["downgraded"] += 1
                stats["by_rule"][v.rule] = stats["by_rule"].get(v.rule, 0) + 1
                new_sev = v.new_severity or f.severity
                fa.write(f"{f.severity}\t{new_sev}\t{f.category}\t{f.scope}\t{f.description}\tDOWNGRADE\t{v.rule}\t{v.reason}\n")
            else:
                stats["kept"] += 1
                fa.write(f"{f.severity}\t{new_sev}\t{f.category}\t{f.scope}\t{f.description}\tKEEP\t\t\n")
            fv.write(f"{new_sev}\t{f.category}\t{f.scope}\t{f.description}\n")
            stats["severity_after"][new_sev] = stats["severity_after"].get(new_sev, 0) + 1

    stats["validated_path"] = str(val_path)
    stats["audit_path"] = str(audit_path)
    return stats


def run_validation(pentest_dir: Path, workers: int = 16,
                   progress: Optional[Callable[[int, int], None]] = None) -> dict:
    pentest_dir = pentest_dir.resolve()
    tsv = pentest_dir / "report" / "findings.tsv"
    if not tsv.is_file():
        raise FileNotFoundError(f"no findings.tsv at {tsv}")
    findings = load_findings(tsv)
    started = time.time()

    # Load the persistent suppression list once per validation run.
    try:
        import suppressions
        UserSuppressionRule.SUPPRESSIONS = suppressions.load()
        sup_stats = {"user_suppressions_loaded": len(UserSuppressionRule.SUPPRESSIONS)}
    except Exception as e:
        UserSuppressionRule.SUPPRESSIONS = []
        sup_stats = {"user_suppressions_error": str(e)}

    # Build the ownership map first so OwnershipInfraRule has context.
    # Import here (not at module top) to avoid an import cycle with ownership.py.
    try:
        import ownership
        own_map = ownership.build_map(pentest_dir, workers=workers)
        OwnershipInfraRule.OWNERSHIP_MAP = {
            h.lower(): c.to_dict() for h, c in own_map.items()
        }
        ownership_stats = {
            "ownership_classified": len(own_map),
            "ownership_by_class": _count_classes(own_map),
        }
    except Exception as e:
        OwnershipInfraRule.OWNERSHIP_MAP = {}
        ownership_stats = {"ownership_error": str(e)}

    pairs = validate_all(findings, workers=workers, progress=progress)
    stats = write_outputs(pairs, pentest_dir)
    stats["duration_sec"] = round(time.time() - started, 2)
    stats["tools"] = {
        "dig": have("dig"),
        "snmpget": have("snmpget"),
        "whois": have("whois"),
    }
    stats.update(ownership_stats)
    stats.update(sup_stats)
    return stats


def _count_classes(m) -> dict:
    out: dict[str, int] = {}
    for c in m.values():
        k = c.owner_class.value
        out[k] = out.get(k, 0) + 1
    return out


# ─── CLI ──────────────────────────────────────────────────────────────────────
def _main() -> int:
    ap = argparse.ArgumentParser(description="Validate findings.tsv to reduce false positives.")
    ap.add_argument("pentest_dir", type=Path)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--json", action="store_true", help="emit stats as JSON")
    args = ap.parse_args()

    def prog(done: int, total: int) -> None:
        if not args.json:
            print(f"\r[validate] {done}/{total}", end="", file=sys.stderr, flush=True)

    stats = run_validation(args.pentest_dir, workers=args.workers, progress=prog)
    if not args.json:
        print(file=sys.stderr)
        print(f"[validate] total={stats['total']}  kept={stats['kept']}  "
              f"downgraded={stats['downgraded']}  suppressed={stats['suppressed']}  "
              f"({stats['duration_sec']}s)")
        print(f"[validate] before  : {stats['severity_before']}")
        print(f"[validate] after   : {stats['severity_after']}")
        print(f"[validate] by rule : {stats['by_rule']}")
        print(f"[validate] tools   : {stats['tools']}")
        print(f"[validate] wrote   : {stats['validated_path']}")
        print(f"[validate] audit   : {stats['audit_path']}")
    else:
        print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
