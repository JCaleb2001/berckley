"""Regression tests for the security-domain classifier (taxonomy.py).

Pins the precedence decisions (e.g. SSL VPNs are network, not crypto; SNMP v3
NoAuth is access) and guarantees full coverage — no scanner finding should ever
fall through to the 'other' bucket.
"""
import subprocess
from pathlib import Path

import taxonomy as T

CASES = {
    "No SPF Record": "email_dns",
    "DNS CAA Record Missing": "email_dns",
    "Subdomain Takeover": "email_dns",
    "S3 Bucket Publicly Listable": "cloud",
    "SSRF to Cloud Metadata": "cloud",
    "AWS Access Key Leaked in JavaScript": "secrets",
    "Directory Listing Enabled": "secrets",
    "Weak TLS Cipher Suite": "crypto",
    "SSLv3 Protocol Enabled (POODLE)": "crypto",
    # Precedence fixes that were explicitly tuned:
    "Check Point SSL VPN Detected": "network",
    "Fortinet FortiGate SSL-VPN Exposed": "network",
    "SNMP v3 NoAuth Accepted": "access",
    "Redis Exposed (No Auth)": "access",
    "Redis Exposed": "network",
    "Default Credentials Accepted": "access",
    "Server-Side Template Injection (SSTI)": "webapp",
    "Missing Content-Security-Policy": "webapp",
    "Telnet Exposed": "network",
}


def test_classify_cases():
    wrong = {t: (T.classify(t), exp) for t, exp in CASES.items()
             if T.classify(t) != exp}
    assert not wrong, f"misclassified: {wrong}"


def test_no_other_bucket_for_scanner_titles():
    """Every distinct title the scanner can emit must map to a real domain."""
    scanner = Path(__file__).resolve().parents[2] / "extpentest.sh"
    if not scanner.is_file():
        return  # scanner not present in this checkout — skip
    out = subprocess.run(
        r"""grep -oE 'finding +(CRITICAL|HIGH|MEDIUM|LOW|INFO) +"[^"]+"' """
        + str(scanner)
        + r""" | sed -E 's/finding +[A-Z]+ +"([^"]+)"/\1/'""",
        shell=True, capture_output=True, text=True).stdout
    titles = sorted({t.strip() for t in out.splitlines() if t.strip()})
    assert titles, "no titles extracted from scanner"
    fell_through = [t for t in titles if T.classify(t) == "other"]
    assert not fell_through, f"fell through to 'other': {fell_through}"
