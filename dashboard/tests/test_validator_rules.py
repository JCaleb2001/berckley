"""Regression tests for the category-specific re-probe rules in validator.py.

Network is mocked so these are deterministic and offline — they lock in the
false-positive logic (header present on final response, CORS reflection +
credentials, dangling-CNAME DNS re-check) added to cut FPs.
"""
import validator as V

F = V.Finding


# ─── HeaderPresenceRule ───────────────────────────────────────────────────────
def _hpr(monkeypatch, headers, code=200):
    monkeypatch.setattr(V, "_final_headers", lambda url, **kw: (code, headers))
    return V.HeaderPresenceRule()


def test_header_present_suppresses(monkeypatch):
    rule = _hpr(monkeypatch, {"strict-transport-security": "max-age=31536000"})
    v = rule.validate(F("LOW", "Missing HSTS", "https://x.example", ""))
    assert v.action == "SUPPRESS"


def test_header_absent_keeps(monkeypatch):
    rule = _hpr(monkeypatch, {"server": "nginx"})
    v = rule.validate(F("LOW", "Missing HSTS", "https://x.example", ""))
    assert v.action == "KEEP"


def test_header_fetch_fails_keeps(monkeypatch):
    monkeypatch.setattr(V, "_final_headers", lambda url, **kw: None)
    v = V.HeaderPresenceRule().validate(F("LOW", "Missing X-Frame-Options", "https://x.example", ""))
    assert v.action == "KEEP"  # fail open


def test_present_but_weak_not_handled():
    # "CSP unsafe-inline" / "HSTS Missing includeSubDomains" are present-but-weak,
    # not absence — the rule must not even apply to them.
    rule = V.HeaderPresenceRule()
    assert not rule.applies(F("MEDIUM", "CSP unsafe-inline / unsafe-eval", "https://x.example", ""))
    assert not rule.applies(F("LOW", "HSTS Missing includeSubDomains", "https://x.example", ""))


# ─── CorsReverifyRule ─────────────────────────────────────────────────────────
def _cors(monkeypatch, acao, acac):
    hdrs = {}
    if acao is not None:
        hdrs["access-control-allow-origin"] = acao
    if acac:
        hdrs["access-control-allow-credentials"] = "true"
    monkeypatch.setattr(V, "_final_headers", lambda url, **kw: (200, hdrs))
    return V.CorsReverifyRule()


def test_cors_reflected_with_creds_keeps(monkeypatch):
    rule = _cors(monkeypatch, V.CorsReverifyRule.PROBE_ORIGIN, True)
    v = rule.validate(F("HIGH", "CORS Origin Reflection with Credentials", "https://x.example", ""))
    assert v.action == "KEEP"


def test_cors_no_reflection_suppresses(monkeypatch):
    rule = _cors(monkeypatch, None, False)
    v = rule.validate(F("HIGH", "CORS Origin Reflection with Credentials", "https://x.example", ""))
    assert v.action == "SUPPRESS"


def test_cors_reflected_no_creds_downgrades(monkeypatch):
    rule = _cors(monkeypatch, V.CorsReverifyRule.PROBE_ORIGIN, False)
    v = rule.validate(F("HIGH", "CORS Origin Reflection with Credentials", "https://x.example", ""))
    assert v.action == "DOWNGRADE" and v.new_severity == "LOW"


# ─── TakeoverReverifyRule ─────────────────────────────────────────────────────
def test_takeover_dangling_cname_keeps(monkeypatch):
    monkeypatch.setattr(V, "resolve_cname", lambda h: "ghost.herokuapp.com")
    monkeypatch.setattr(V, "dns_lookup", lambda h, rt: [])   # target dead
    v = V.TakeoverReverifyRule().validate(F("CRITICAL", "Subdomain Takeover", "sub.example.com", ""))
    assert v.action == "KEEP"


def test_takeover_claimed_target_downgrades(monkeypatch):
    monkeypatch.setattr(V, "resolve_cname", lambda h: "app.herokuapp.com")
    monkeypatch.setattr(V, "dns_lookup", lambda h, rt: ["1.2.3.4"])  # target resolves
    v = V.TakeoverReverifyRule().validate(F("CRITICAL", "Subdomain Takeover", "sub.example.com", ""))
    assert v.action == "DOWNGRADE"


def test_takeover_host_gone_suppresses(monkeypatch):
    monkeypatch.setattr(V, "resolve_cname", lambda h: None)
    monkeypatch.setattr(V, "host_resolves", lambda h: False)
    v = V.TakeoverReverifyRule().validate(F("CRITICAL", "Subdomain Takeover", "sub.example.com", ""))
    assert v.action == "SUPPRESS"


# ─── Orchestration: confidence never causes suppression ───────────────────────
def test_low_confidence_is_not_suppressed():
    # No rule keys off confidence — a low-confidence finding with no matching
    # rule must be KEPT (fail-safe: confidence informs, never hides).
    f = F("LOW", "Citrix Gateway Detected", "1.2.3.4", "fingerprint detected")
    assert V.evaluate(f).action == "KEEP"


# ─── Telemetry + fail-open robustness ─────────────────────────────────────────
class _BoomRule(V.Rule):
    name = "boom"
    def applies(self, f): return True
    def validate(self, f): raise RuntimeError("kaboom")


def test_erroring_rule_does_not_skip_later_rules(monkeypatch):
    # A rule that raises must be logged + counted, and the remaining rules must
    # still run — here UserSuppression-style KEEP path still returns a verdict.
    monkeypatch.setattr(V, "RULES", [_BoomRule(), V.Rfc1918Rule()])
    V._reset_telemetry()
    # an RFC1918 host → the (later) Rfc1918Rule should still SUPPRESS it
    v = V.evaluate(F("HIGH", "Redis Exposed", "10.0.0.5:6379", ""))
    assert v.action == "SUPPRESS"           # later rule still ran
    assert V.RULE_TELEMETRY["boom"]["errored"] == 1


# ─── ServiceAliveRule ─────────────────────────────────────────────────────────
def test_service_alive_keeps_reachable(monkeypatch):
    monkeypatch.setattr(V, "_tcp_open", lambda h, p, timeout=4.0: True)
    v = V.ServiceAliveRule().validate(F("HIGH", "Redis Exposed", "10.0.0.5:6379", ""))
    assert v.action == "KEEP"


def test_service_alive_suppresses_unreachable(monkeypatch):
    monkeypatch.setattr(V, "_tcp_open", lambda h, p, timeout=4.0: False)
    v = V.ServiceAliveRule().validate(F("HIGH", "MongoDB Exposed", "10.0.0.5:27017", ""))
    assert v.action == "SUPPRESS"


def test_service_alive_default_port_from_category(monkeypatch):
    seen = {}
    def fake(h, p, timeout=4.0): seen["port"] = p; return True
    monkeypatch.setattr(V, "_tcp_open", fake)
    # scope has no :port → rule derives 6379 from "Redis"
    v = V.ServiceAliveRule().validate(F("HIGH", "Redis Exposed (No Auth)", "host.example.com", ""))
    assert v.action == "KEEP" and seen["port"] == 6379


def test_service_alive_skips_non_service():
    # A header finding must not be touched by ServiceAliveRule.
    assert not V.ServiceAliveRule().applies(F("LOW", "Missing HSTS", "https://x.example", ""))


class _SelectiveRule(V.Rule):
    name = "sel"
    def applies(self, f): return True
    def validate(self, f):
        return (V.Verdict.suppress("sel", "x") if f.severity == "HIGH"
                else V.Verdict.keep())


def test_telemetry_counts_applied_and_acted(monkeypatch):
    monkeypatch.setattr(V, "RULES", [_SelectiveRule()])
    V._reset_telemetry()
    V.evaluate(F("HIGH", "X", "s", ""))   # applies + acts
    V.evaluate(F("LOW", "X", "s", ""))    # applies, keeps
    t = V.RULE_TELEMETRY["sel"]
    assert t["applied"] == 2 and t["acted"] == 1 and t["errored"] == 0
