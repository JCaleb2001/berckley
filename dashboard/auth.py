"""Authentication for the Berckley console.

Session-cookie login, access gated to SOC analysts. The user store and signing
secret live under PENTEST_ROOT (mounted, git-ignored) so they persist on the
host and can be edited without rebuilding the image. Password hashes use
PBKDF2-HMAC-SHA256 from the stdlib (no extra dependencies).

CLI (manage users without touching the app):
    python auth.py add <user> [role] [--password PW]   # role default: soc_analyst
    python auth.py passwd <user> [--password PW]
    python auth.py role <user> <role>
    python auth.py enable|disable <user>
    python auth.py del <user>
    python auth.py list
Omitting --password generates a strong one and prints it once.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Optional

ROOT = Path(os.environ.get("PENTEST_ROOT", "/workspace")).resolve()
USERS_FILE = Path(os.environ.get("BERCKLEY_USERS_FILE", str(ROOT / ".berckley_users.json")))
SECRET_FILE = Path(os.environ.get("BERCKLEY_SECRET_FILE", str(ROOT / ".berckley_secret")))

SESSION_COOKIE = "berckley_session"
SESSION_TTL = int(os.environ.get("BERCKLEY_SESSION_TTL", str(12 * 3600)))  # seconds
ALLOWED_ROLES = {"soc_analyst"}   # only these roles may access the scanner
PBKDF2_ITERS = 200_000


# ─── secret (HMAC signing key) ────────────────────────────────────────────────
def _secret() -> bytes:
    try:
        if SECRET_FILE.exists():
            return SECRET_FILE.read_bytes()
    except OSError:
        pass
    sec = secrets.token_bytes(32)
    try:
        SECRET_FILE.write_bytes(sec)
        SECRET_FILE.chmod(0o600)
    except OSError:
        pass
    return sec


# ─── password hashing ─────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITERS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERS, base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    )


def verify_password(stored: str, pw: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt_b64), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(hash_b64))
    except Exception:
        return False


# ─── user store ───────────────────────────────────────────────────────────────
def load_users() -> dict:
    try:
        data = json.loads(USERS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_users(users: dict) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2, sort_keys=True))
    try:
        USERS_FILE.chmod(0o600)
    except OSError:
        pass


def authenticate(username: str, pw: str) -> Optional[dict]:
    uname = (username or "").strip().lower()
    u = load_users().get(uname)
    if not u or not u.get("active", True):
        return None
    if not verify_password(u.get("password", ""), pw):
        return None
    return {"username": uname, "role": u.get("role")}


# ─── sessions (HMAC-signed cookie value) ──────────────────────────────────────
def make_session(username: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = "{}|{}".format(username, exp)
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode("{}|{}".format(payload, sig).encode()).decode()


def verify_session(token: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, exp, sig = raw.rsplit("|", 2)
        expected = hmac.new(_secret(), "{}|{}".format(username, exp).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp) < int(time.time()):
            return None
        u = load_users().get(username)
        if not u or not u.get("active", True) or u.get("role") not in ALLOWED_ROLES:
            return None
        return {"username": username, "role": u.get("role")}
    except Exception:
        return None


def current_user(request) -> Optional[dict]:
    """Return the authenticated SOC-analyst dict for a request, or None."""
    tok = request.cookies.get(SESSION_COOKIE)
    return verify_session(tok) if tok else None


# ─── CLI ──────────────────────────────────────────────────────────────────────
def _gen_password(n: int = 16) -> str:
    return secrets.token_urlsafe(n)[:n]


def _cli(argv: list) -> int:
    if not argv:
        print(__doc__)
        return 1
    cmd, rest = argv[0], argv[1:]
    users = load_users()

    def _pw_from(flagargs):
        if "--password" in flagargs:
            return flagargs[flagargs.index("--password") + 1], False
        return _gen_password(), True

    if cmd == "list":
        if not users:
            print("(no users)")
        for name in sorted(users):
            u = users[name]
            print("{:16} role={:12} active={}".format(name, u.get("role", "?"), u.get("active", True)))
        return 0

    if cmd in ("add", "passwd"):
        if not rest:
            print("usage: {} <user> [role] [--password PW]".format(cmd)); return 1
        name = rest[0].strip().lower()
        flagargs = rest[1:]
        role = "soc_analyst"
        for a in flagargs:
            if a != "--password" and not a.startswith("-") and (flagargs.index(a) == 0):
                role = a
        pw, generated = _pw_from(flagargs)
        if cmd == "add":
            users[name] = {"role": role, "active": True, "password": hash_password(pw)}
        else:
            if name not in users:
                print("no such user: {}".format(name)); return 1
            users[name]["password"] = hash_password(pw)
        save_users(users)
        print("ok: {} {}".format(cmd, name))
        if generated:
            print("  password: {}".format(pw))
        return 0

    if cmd == "role" and len(rest) == 2:
        name = rest[0].strip().lower()
        if name not in users:
            print("no such user: {}".format(name)); return 1
        users[name]["role"] = rest[1]; save_users(users); print("ok: role {} = {}".format(name, rest[1])); return 0

    if cmd in ("enable", "disable") and rest:
        name = rest[0].strip().lower()
        if name not in users:
            print("no such user: {}".format(name)); return 1
        users[name]["active"] = (cmd == "enable"); save_users(users); print("ok: {} {}".format(cmd, name)); return 0

    if cmd == "del" and rest:
        name = rest[0].strip().lower()
        users.pop(name, None); save_users(users); print("ok: del {}".format(name)); return 0

    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
