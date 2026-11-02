"""API & web security tests: cookie session, CSRF, lockout, revocation, rate limits, IDOR, headers, errors."""
import io
import itertools

import pytest

from app.factory import create_app
from app.config import Config
from app.services import llm

_n = itertools.count()
PW = "Passw0rd!xyz"


@pytest.fixture(scope="module")
def app():
    a = create_app()
    a.config["TESTING"] = True
    return a


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(c):
    ck = c.get_cookie("eip_csrf")
    return {"X-CSRF-Token": ck.value if ck else ""}


def register(c, email=None):
    from app import auth
    import sqlite3
    email = email or f"user{next(_n)}@test.com"
    try:
        auth.create_user(email, PW, "Test")
    except sqlite3.IntegrityError:
        pass
    r = c.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.get_json()
    return email


# ---------- session & cookies ----------
def test_login_sets_httponly_strict_cookie_and_no_token_in_body(client):
    email = register(client)
    r = client.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200 and "token" not in r.get_json()
    cookies = r.headers.getlist("Set-Cookie")
    sess = next(c for c in cookies if c.startswith("eip_session="))
    assert "HttpOnly" in sess and "SameSite=Lax" in sess
    assert client.get("/api/auth/me").status_code == 200


def test_bearer_token_for_api_clients(client):
    email = register(client)
    tok = client.post("/api/auth/login", json={"email": email, "password": PW, "return_token": True}).get_json()["token"]
    c2 = client.application.test_client()
    assert c2.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    # Bearer requests don't need CSRF
    assert c2.post("/api/conversations", json={}, headers={"Authorization": f"Bearer {tok}"}).status_code == 201


def test_csrf_required_for_cookie_writes(client):
    register(client)
    assert client.post("/api/conversations", json={}).status_code == 403
    assert client.post("/api/conversations", json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert client.post("/api/conversations", json={}, headers=csrf(client)).status_code == 201


def test_logout_revokes_token(client):
    email = register(client)
    tok = client.post("/api/auth/login", json={"email": email, "password": PW, "return_token": True}).get_json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401


def test_logout_all_and_password_change_revoke_sessions(client):
    email = register(client)
    tok = client.post("/api/auth/login", json={"email": email, "password": PW, "return_token": True}).get_json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = client.post("/api/auth/change-password", headers=h,
                    json={"current_password": PW, "new_password": "NewPassw0rd99"})
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401
    assert client.post("/api/auth/login", json={"email": email, "password": "NewPassw0rd99"}).status_code == 200


def test_tampered_and_alg_none_tokens_rejected(client):
    import jwt as pyjwt
    forged = pyjwt.encode({"sub": "1", "tv": 0, "jti": "x", "iat": 0, "exp": 9999999999, "iss": "eip"},
                          "attacker-guess-secret-attacker-guess", algorithm="HS256")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    none_tok = pyjwt.encode({"sub": "1"}, key="", algorithm="none") if hasattr(pyjwt, "encode") else "x.y."
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {none_tok}"}).status_code == 401


# ---------- brute force ----------
def test_account_lockout_after_failed_logins(client, monkeypatch):
    monkeypatch.setattr(Config, "LOGIN_MAX_FAILS", 3)
    email = register(client)
    for _ in range(3):
        assert client.post("/api/auth/login", json={"email": email, "password": "wrong1234"}).status_code == 401
    r = client.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 429                       # correct password still refused while locked


def test_lockout_is_uniform_for_unknown_emails(client, monkeypatch):
    monkeypatch.setattr(Config, "LOGIN_MAX_FAILS", 2)
    for _ in range(2):
        assert client.post("/api/auth/login", json={"email": "ghost@x.com", "password": "nope1234"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "ghost@x.com", "password": "nope1234"}).status_code == 429


def test_public_registration_is_closed(client):
    assert client.post("/api/auth/register", json={"email": "z@x.com", "password": PW}).status_code == 403


def test_admin_invites_a_user_and_members_cannot(client):
    from app import auth
    auth.create_user("admin@eip.local", PW, "Admin", role="admin")
    assert client.post("/api/auth/login", json={"email": "admin@eip.local", "password": PW}).status_code == 200
    created = client.post("/api/admin/users", headers=csrf(client),
                          json={"email": "invited@x.com", "name": "Invited"})
    assert created.status_code == 201, created.get_json()
    pw = created.get_json()["password"]
    assert client.post("/api/auth/login", json={"email": "invited@x.com", "password": pw}).status_code == 200
    listed = client.get("/api/admin/users")
    assert listed.status_code == 403
    register(client)
    denied = client.post("/api/admin/users", headers=csrf(client),
                         json={"email": "other@x.com", "name": "Other"})
    assert denied.status_code == 403


# ---------- abuse / cost ----------
def test_chat_rate_limit(client, monkeypatch):
    monkeypatch.setattr(Config, "CHAT_RATE_PER_MIN", 2)
    register(client)
    codes = [client.post("/api/chat", json={"message": "hello there"}, headers=csrf(client)).status_code
             for _ in range(3)]
    assert codes[:2] == [200, 200] and codes[2] == 429      # no docs -> relevance gate answers without LLM


def test_llm_error_is_generic_with_reference(client, monkeypatch):
    register(client)
    from app.services import rag
    monkeypatch.setattr(rag, "answer_question",
                        lambda *a, **k: (_ for _ in ()).throw(llm.LLMError("HTTP 401 invalid key gsk_123")))
    body = client.post("/api/chat", json={"message": "hi"}, headers=csrf(client)).get_json()
    assert "gsk_" not in str(body) and "error_ref" in body


def test_unknown_model_rejected(client):
    register(client)
    assert client.post("/api/chat", json={"message": "hi", "model": "evil/model"}, headers=csrf(client)).status_code == 400


# ---------- documents ----------
def test_upload_duplicate_and_idor(client, app):
    register(client)
    r = client.post("/api/documents", headers=csrf(client), content_type="multipart/form-data",
                    data={"files": (io.BytesIO(b"Pool size is 50."), "a.txt")})
    assert r.status_code == 202
    doc_id = r.get_json()["results"][0]["document_id"]
    r = client.post("/api/documents", headers=csrf(client), content_type="multipart/form-data",
                    data={"files": (io.BytesIO(b"Pool size is 50."), "copy.txt")})
    assert r.get_json()["results"][0]["status"] == "duplicate"
    other = app.test_client()
    register(other)
    assert other.get(f"/api/documents/{doc_id}").status_code == 404
    assert other.delete(f"/api/documents/{doc_id}", headers=csrf(other)).status_code == 404


def test_upload_rejects_bad_type_and_quota(client, monkeypatch):
    register(client)
    r = client.post("/api/documents", headers=csrf(client), content_type="multipart/form-data",
                    data={"files": (io.BytesIO(b"MZ"), "x.exe")})
    assert r.get_json()["results"][0]["status"] == "rejected"
    monkeypatch.setattr(Config, "MAX_DOCS_PER_USER", 0)
    r = client.post("/api/documents", headers=csrf(client), content_type="multipart/form-data",
                    data={"files": (io.BytesIO(b"hello quota"), "q.txt")})
    assert "limit" in r.get_json()["results"][0]["error"]


# ---------- headers / CORS / misc ----------
def test_security_headers_and_csp(client):
    r = client.get("/")
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert client.get("/api/health").headers["Cache-Control"] == "no-store"


def test_cors_is_not_wildcard(client):
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in r.headers


def test_cors_allow_list(client, monkeypatch):
    monkeypatch.setattr(Config, "CORS_ORIGINS", ["https://app.example.com"])
    r = client.get("/api/health", headers={"Origin": "https://app.example.com"})
    assert r.headers["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_path_traversal_on_static(client):
    r = client.get("/../backend/.env")
    assert b"GROQ_API_KEY" not in r.data
    r = client.get("/js/../../backend/app/config.py")
    assert b"class Config" not in r.data


def test_protected_routes_require_auth(client):
    for path in ("/api/documents", "/api/stats", "/api/logs", "/api/models", "/api/conversations"):
        assert client.get(path).status_code == 401
