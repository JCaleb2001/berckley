"""Regression corpus for the confidence classifier (confidence.py).

Each case is (category, description, expected_band). These pin the FP-relevant
behavior: actively-proven findings are HIGH, single-observation/header findings
MEDIUM, and fingerprint/historical/tentative ones LOW — so retuning the marker
tables can't silently regress.
"""
import confidence as C

CASES = [
    # Actively proven → HIGH
    ("Redis Exposed", "Redis answered RESP probe (PING/NOAUTH/ERR)", "HIGH"),
    ("Default Credentials Accepted", "admin:admin accepted on the login form", "HIGH"),
    ("SSLv3 Protocol Enabled (POODLE)", "SSLv3 negotiated", "HIGH"),
    ("Weak TLS Cipher Suite", "Server negotiates CBC-only cipher suites", "HIGH"),
    ("No SPF Record", "No SPF record found", "HIGH"),
    ("Subdomain Takeover", "CNAME -> heroku shows unclaimed page -- takeover confirmed", "HIGH"),
    # Single observation / hygiene → MEDIUM
    ("Missing X-Frame-Options", "No X-Frame-Options header", "MEDIUM"),
    ("Microsoft Exchange OWA Exposed", "OWA login page exposed", "MEDIUM"),
    # Tentative / fingerprint / historical → LOW
    ("Reflected XSS Indicator", "payload reflected back in response -- potential XSS", "LOW"),
    ("Wildcard DNS", "Wildcard DNS (*.x) may cause false positives in subdomain scans", "LOW"),
    ("Historical Sensitive URLs", "Wayback Machine shows historically exposed files -- verify if still accessible", "LOW"),
    ("Citrix Gateway Detected", "Citrix fingerprint detected", "LOW"),
    ("JWT Algorithm Deserves Review", "alg=HS256 deserves review", "LOW"),
]


def test_band_cases():
    wrong = [(cat, C.confidence(cat, desc)["band"], exp)
             for cat, desc, exp in CASES
             if C.confidence(cat, desc)["band"] != exp]
    assert not wrong, f"misclassified: {wrong}"


def test_explicit_override_wins():
    # A header finding derives MEDIUM, but an explicit band from the scanner wins.
    assert C.confidence("Missing X-Frame-Options", "No header", "HIGH")["band"] == "HIGH"
    assert C.confidence("Redis Exposed", "answered RESP", "LOW")["band"] == "LOW"


def test_low_marker_beats_high_marker():
    # "may cause false positives" must win even next to an active-probe word.
    band = C.confidence("X", "negotiated TLS but may cause false positives")["band"]
    assert band == "LOW"


def test_band_shape():
    r = C.confidence("Missing CSP", "no header")
    assert set(r) == {"band", "score", "color"}
    assert r["band"] in C.BANDS
    assert 0 <= r["score"] <= 100
