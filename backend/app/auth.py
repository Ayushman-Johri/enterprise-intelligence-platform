"""JWT (HS256 pinned, exp/iat/iss/jti) delivered in an HttpOnly + SameSite=Lax cookie (JS can't read it).
- CSRF: double-submit token - cookie `eip_csrf` (readable) must equal header `X-CSRF-Token` on every
  state-changing request that authenticates via cookie.
- API clients (eval script, curl) may use `Authorization: Bearer <token>` instead (no CSRF needed).
- Logout revokes the token (jti blocklist); token_version bump revokes all sessions of a user.
- Account lockout per email after LOGIN_MAX_FAILS failures (uniform for existing/non-existing emails).
"""
import datetime as dt
import hmac
import re
import secrets
import string
from functools import wraps

import jwt
from flask import g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from . import db
from .config import Config, resolve_jwt_secret
from .services import ratelimit

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
SESSION_COOKIE, CSRF_COOKIE, CSRF_HEADER = "eip_session", "eip_csrf", "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ISSUER = "eip"


def password_problem(pw: str, email: str) -> str:
    if len(pw) < 8:
        return "password must be at least 8 characters"
    if len(pw) > 128:
        return "password too long"
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return "password must contain letters and numbers"
    if pw.lower() == email.lower() or pw.lower() in {"password1", "password123", "12345678a", "qwerty123"}:
        return "password is too easy to guess"
    return ""


def random_password() -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(12))
        if password_problem(pw, "user@example.com") == "":
            return pw


def create_user(email: str, password: str, name: str = "", role: str = "user") -> int:
    if role not in {"user", "admin"}:
        role = "user"
    return db.execute("INSERT INTO users (email, password_hash, name, role) VALUES (?,?,?,?)",
                      (email.lower().strip(), generate_password_hash(password), name.strip()[:80], role))


def ensure_admin():
    """Create or refresh the operator account from ADMIN_EMAIL and ADMIN_PASSWORD."""
    email, password = Config.ADMIN_EMAIL, Config.ADMIN_PASSWORD
    if not email or not EMAIL_RE.match(email) or password_problem(password, email):
        return
    hashed = generate_password_hash(password)
    row = db.query("SELECT id FROM users WHERE email=?", (email,), one=True)
    if row:
        db.execute("UPDATE users SET password_hash=?, role='admin', name=COALESCE(NULLIF(name, ''), 'Administrator') WHERE id=?",
                   (hashed, row["id"]))
        return
    db.execute("INSERT INTO users (email, password_hash, name, role) VALUES (?,?,?,?)",
               (email, hashed, "Administrator", "admin"))


# A real hash so unknown emails take the same time as wrong passwords (no user enumeration by timing)
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing-1")


def _lock_key(email: str) -> str:
    return f"loginfail:{email.lower().strip()}"


def is_locked(email: str) -> bool:
    return ratelimit.peek(_lock_key(email), Config.LOGIN_LOCK_MINUTES * 60) >= Config.LOGIN_MAX_FAILS


def verify_user(email: str, password: str):
    u = db.query("SELECT * FROM users WHERE email=?", (email.lower().strip(),), one=True)
    ok = check_password_hash(u["password_hash"] if u else _DUMMY_HASH, password)
    if u and ok:
        ratelimit.reset(_lock_key(email))
        return u
    ratelimit.hit(_lock_key(email), 10**9, Config.LOGIN_LOCK_MINUTES * 60)
    return None


def issue_token(user: dict) -> tuple:
    now = dt.datetime.now(dt.timezone.utc)
    exp = now + dt.timedelta(hours=Config.JWT_EXP_HOURS)
    payload = {"sub": str(user["id"]), "tv": int(user.get("token_version") or 0), "jti": secrets.token_hex(16),
               "iat": now, "exp": exp, "iss": ISSUER}
    return jwt.encode(payload, resolve_jwt_secret(), algorithm="HS256"), int(exp.timestamp())


def set_session_cookies(resp, token: str, exp_ts: int):
    max_age = Config.JWT_EXP_HOURS * 3600
    resp.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=True, secure=Config.COOKIE_SECURE,
                    samesite="Lax", path="/")
    resp.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(32), max_age=max_age, httponly=False,
                    secure=Config.COOKIE_SECURE, samesite="Lax", path="/")
    return resp


def clear_session_cookies(resp):
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        resp.delete_cookie(name, path="/", samesite="Lax", secure=Config.COOKIE_SECURE)
    return resp


def _decode(token: str) -> dict:
    return jwt.decode(token, resolve_jwt_secret(), algorithms=["HS256"], issuer=ISSUER,
                      options={"require": ["exp", "iat", "sub", "jti", "iss"]})


def revoke(payload: dict):
    db.execute("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?,?)",
               (payload["jti"], int(payload["exp"])))


def current_token():
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        return hdr[7:].strip(), "bearer"
    tok = request.cookies.get(SESSION_COOKIE)
    return (tok, "cookie") if tok else (None, None)


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        token, kind = current_token()
        if not token:
            return jsonify(error="authentication required"), 401
        try:
            payload = _decode(token)
        except jwt.ExpiredSignatureError:
            return jsonify(error="session expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="invalid session"), 401
        if kind == "cookie" and request.method not in SAFE_METHODS:
            sent, expected = request.headers.get(CSRF_HEADER, ""), request.cookies.get(CSRF_COOKIE, "")
            if not sent or not expected or not hmac.compare_digest(sent, expected):
                return jsonify(error="CSRF token missing or invalid"), 403
        if db.query("SELECT 1 FROM revoked_tokens WHERE jti=?", (payload["jti"],), one=True):
            return jsonify(error="session revoked"), 401
        user = db.query("SELECT id, email, name, role, token_version FROM users WHERE id=?",
                        (int(payload["sub"]),), one=True)
        if not user or int(user["token_version"]) != int(payload.get("tv", -1)):
            return jsonify(error="session revoked"), 401
        g.user, g.token_payload = user, payload
        return fn(*a, **kw)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if (g.user["role"] or "user") != "admin":
            return jsonify(error="admin only"), 403
        return fn(*a, **kw)
    return wrapper
