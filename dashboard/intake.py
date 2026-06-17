"""
intake.py — pre-flight scope discovery before launching a scan.

For each root domain the analyst enters, run quick passive checks (DNS resolve,
WHOIS owner, MX presence) and pull a subdomain list from crt.sh. Classify each
discovered host with a *lightweight* method (suffix table only, no per-IP WHOIS)
so the UI can suggest sensible defaults: include OWNED/SAAS by default, skip
CDN/INTERNAL edge hosts.

This module is intentionally fast: the full WHOIS-driven ownership pass runs
during validation, after the scan completes.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Optional

from validator import dns_lookup, extract_host, have, is_private, run
from ownership import (
    OwnerClass,
    _suffix_match,
    _is_subdomain_of,
)


# ─── Data ────────────────────────────────────────────────────────────────────
@dataclass
class Host:
    host: str
    resolves: bool = False
    ips: list[str] = field(default_factory=list)
    cname: str = ""
    owner_class: str = OwnerClass.UNKNOWN.value
    provider: str = ""
    note: str = ""
    include_default: bool = True   # UI's initial checkbox state


@dataclass
class RootResult:
    root: str
    resolves: bool
    ips: list[str]
    mx: bool
    whois_org: str
    cname: str
    discovered: list[Host]
    discovered_count: int          # before dedupe/cap
    error: str = ""


@dataclass
class IntakeResult:
    roots: list[RootResult]
    discovery_source: str = "crt.sh"
    duration_sec: float = 0.0


# ─── Primitives ──────────────────────────────────────────────────────────────
_CRTSH_TIMEOUT = 12
_CRTSH_CAP = 400          # hard upper bound to keep UI usable
_USER_AGENT = "berckley-intake/0.1 (+https://localhost)"


def _whois_org_for_domain(domain: str, timeout: float = 6.0) -> str:
    """Best-effort WHOIS Org for a DOMAIN (not IP). Returns '' on failure."""
    if not have("whois"):
        return ""
    rc, out = run(["whois", domain], timeout=timeout)
    for line in out.splitlines():
        s = line.strip()
        low = s.lower()
        for k in ("registrant organization:", "organization:", "org:",
                  "registrant:", "registrant name:"):
            if low.startswith(k):
                v = s.split(":", 1)[1].strip()
                if v and v.lower() not in ("redacted for privacy", "redacted"):
                    return v
    return ""


def _local_fallback_subdomains(domain: str) -> list[str]:
    """When crt.sh is unreachable, mine subdomain lists from prior scans of
    the same root. The scanner writes per-domain enum results to
    recon/subs_all_<domain>.txt, and we can also read ownership.tsv from prior
    validated runs. Both are deduped against the requested root."""
    import os
    root = (
        os.environ.get("PENTEST_ROOT")
        or str(__import__("pathlib").Path(__file__).resolve().parent.parent)
    )
    base = __import__("pathlib").Path(root)
    if not base.is_dir():
        return []
    found: dict[str, None] = {}
    domain_lc = domain.lower()
    for child in base.iterdir():
        if not child.is_dir() or not child.name.startswith("pentest"):
            continue
        # Direct per-domain enum file
        p1 = child / "recon" / f"subs_all_{domain}.txt"
        if p1.is_file():
            for line in p1.read_text(errors="ignore").splitlines():
                s = line.strip().lower()
                if s and (s == domain_lc or s.endswith("." + domain_lc)):
                    found.setdefault(s, None)
        # Ownership map (subdomains we already classified)
        p2 = child / "report" / "ownership.tsv"
        if p2.is_file():
            for line in p2.read_text(errors="ignore").splitlines():
                parts = line.split("\t")
                if not parts:
                    continue
                host = parts[0].strip().lower()
                if host and (host == domain_lc or host.endswith("." + domain_lc)):
                    found.setdefault(host, None)
    return list(found.keys())


def _crtsh_query(domain: str, attempts: int = 3) -> tuple[list[str], str]:
    """Hit crt.sh for `%.<domain>` and return a deduped list of hostnames.
    crt.sh is frequently flaky (502/timeout) — retry a few times with backoff
    before giving up. Returns (hosts, error_message)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    raw = ""
    last_err = ""
    import time
    for i in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=_CRTSH_TIMEOUT,
                                        context=ssl.create_default_context()) as r:
                raw = r.read().decode("utf-8", errors="replace")
                last_err = ""
                break
        except urllib.error.HTTPError as e:
            last_err = f"crt.sh HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError) as e:
            last_err = f"crt.sh unreachable: {type(e).__name__}"
        except Exception as e:
            last_err = f"crt.sh error: {type(e).__name__}"
        time.sleep(1.5 * (i + 1))
    if last_err:
        return [], last_err

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return [], "crt.sh returned non-JSON"

    seen: dict[str, None] = {}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        name_field = entry.get("name_value") or ""
        for raw_name in name_field.split("\n"):
            n = raw_name.strip().lower().lstrip("*.")
            if not n or n.startswith("*"):
                continue
            # filter to subdomains of the requested domain
            if not (n == domain or n.endswith("." + domain)):
                continue
            seen.setdefault(n, None)
    return list(seen.keys()), ""


def _light_classify(host: str, root_domains: list[str]) -> tuple[str, str, str, str]:
    """Cheap-only classification (no per-IP WHOIS).
    Returns (owner_class, provider, evidence, cname)."""
    h = (host or "").strip().lower()
    if not h:
        return OwnerClass.UNKNOWN.value, "", "empty host", ""

    # Direct host-suffix match (e.g., *.azurewebsites.net)
    m = _suffix_match(h)
    if m:
        cls, prov, suf = m
        return cls.value, prov, f"host suffix {suf}", ""

    # CNAME chain (first hop)
    cnames = dns_lookup(h, "CNAME")
    cname = cnames[0] if cnames else ""
    if cname:
        m = _suffix_match(cname)
        if m:
            cls, prov, suf = m
            return cls.value, prov, f"CNAME → {cname} ({suf})", cname

    # IP-based quick filter (RFC1918 only — full ASN lookup is too slow for intake)
    ips = dns_lookup(h, "A")
    if ips:
        ip = ips[0]
        if is_private(ip):
            return OwnerClass.INTERNAL.value, "", f"{h} → {ip} (private)", cname

    # Default: if it's a subdomain of one of the input roots, call it OWNED
    if _is_subdomain_of(h, root_domains):
        return OwnerClass.OWNED.value, "", "subdomain of input root", cname

    return OwnerClass.UNKNOWN.value, "", "no signal — needs full classification", cname


def _smart_default_include(owner_class: str, resolves: bool) -> tuple[bool, str]:
    """Decide whether a discovered host should be checked by default in the UI.
    Returns (include?, short note)."""
    if not resolves:
        return False, "does not resolve — likely stale crt.sh entry"
    if owner_class == "CDN":
        return False, "CDN edge — provider-managed, scanning yields little signal"
    if owner_class == "INTERNAL":
        return False, "RFC1918 — not reachable from external"
    if owner_class == "EXTERNAL":
        return False, "third-party — not in customer scope"
    if owner_class in ("SAAS", "CLOUD_SHARED"):
        return True, "third-party infra — findings will be auto-downgraded"
    if owner_class == "OWNED":
        return True, ""
    return True, ""


# ─── Drivers ─────────────────────────────────────────────────────────────────
def validate_root(domain: str, root_domains: list[str]) -> RootResult:
    """Per-root pre-flight: DNS, MX, WHOIS, crt.sh enum + light classify each."""
    domain = (domain or "").strip().lower()
    if not domain:
        return RootResult("", False, [], False, "", "", [], 0, "empty domain")

    ips = dns_lookup(domain, "A")
    aaaa = dns_lookup(domain, "AAAA")
    cnames = dns_lookup(domain, "CNAME")
    resolves = bool(ips or aaaa or cnames)
    mx = bool(dns_lookup(domain, "MX"))
    whois_org = _whois_org_for_domain(domain)

    discovered, err = _crtsh_query(domain)
    source_note = ""
    if not discovered:
        # crt.sh failed or returned nothing — try local prior-scan data.
        local = _local_fallback_subdomains(domain)
        if local:
            discovered = local
            source_note = f"crt.sh unavailable ({err}); using prior-scan data ({len(local)} hosts)"
            err = ""
    else:
        local = _local_fallback_subdomains(domain)
        if local:
            # Merge in any local-only hosts crt.sh missed (decommissioned certs etc.)
            existing = set(discovered)
            extra = [h for h in local if h not in existing]
            if extra:
                discovered.extend(extra)
                source_note = f"crt.sh + {len(extra)} extra from prior scans"
    discovered = [h for h in discovered if h != domain]
    discovered_count_full = len(discovered)
    if len(discovered) > _CRTSH_CAP:
        discovered = sorted(discovered)[:_CRTSH_CAP]

    hosts: list[Host] = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(_classify_one, h, root_domains): h for h in discovered}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                hosts.append(fut.result())
            except Exception:
                hosts.append(Host(host=h, owner_class=OwnerClass.UNKNOWN.value,
                                  note="classify error"))
    hosts.sort(key=lambda x: x.host)

    return RootResult(
        root=domain,
        resolves=resolves,
        ips=ips,
        mx=mx,
        whois_org=whois_org,
        cname=cnames[0] if cnames else "",
        discovered=hosts,
        discovered_count=discovered_count_full,
        error=err or source_note,
    )


def _classify_one(host: str, root_domains: list[str]) -> Host:
    ips = dns_lookup(host, "A")
    aaaa = dns_lookup(host, "AAAA")
    cnames = dns_lookup(host, "CNAME")
    resolves = bool(ips or aaaa or cnames)
    cls, prov, evidence, cname = _light_classify(host, root_domains)
    include, note = _smart_default_include(cls, resolves)
    return Host(
        host=host,
        resolves=resolves,
        ips=ips[:3],
        cname=cname or (cnames[0] if cnames else ""),
        owner_class=cls,
        provider=prov,
        note=note or evidence,
        include_default=include,
    )


def run_intake(domains: list[str]) -> IntakeResult:
    import time
    started = time.time()
    domains = [d.strip().lower() for d in domains if d and d.strip()]
    roots: list[RootResult] = []
    # roots are processed sequentially so crt.sh is rate-friendly; the inner
    # per-subdomain classifier already runs in a thread pool.
    for d in domains:
        roots.append(validate_root(d, domains))
    return IntakeResult(
        roots=roots,
        discovery_source="crt.sh + DNS",
        duration_sec=round(time.time() - started, 2),
    )


def to_payload(r: IntakeResult) -> dict:
    return {
        "duration_sec": r.duration_sec,
        "discovery_source": r.discovery_source,
        "roots": [
            {
                **asdict(root),
                "discovered": [asdict(h) for h in root.discovered],
            }
            for root in r.roots
        ],
    }
