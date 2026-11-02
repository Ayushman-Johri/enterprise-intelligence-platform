"""REST API. Every data query is scoped by g.user['id'] (prevents IDOR)."""
import json
import logging
import os
import secrets
import sqlite3
import time

from flask import Blueprint, g, jsonify, request
from werkzeug.security import generate_password_hash

from .. import auth, db
from ..agent import runner
from ..config import Config
from ..services import documents, embeddings, jobs, llm, memory, rag, ratelimit

api = Blueprint("api", __name__, url_prefix="/api")
log = logging.getLogger("eip.api")


def _body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _ip() -> str:
    return request.remote_addr or "unknown"


def _too_many(msg: str, retry: int):
    resp = jsonify(error=msg, retry_after=retry)
    resp.status_code = 429
    resp.headers["Retry-After"] = str(max(1, retry))
    return resp


def _error_ref(user_id, action: str, exc: Exception) -> str:
    ref = secrets.token_hex(4)
    log.exception("%s failed (ref %s)", action, ref)
    db.log_activity(user_id, action, {"error_ref": ref, "type": type(exc).__name__}, "error")
    return ref


@api.get("/health")
def health():
    out = {"status": "ok"}
    if not Config.IS_PROD:
        out.update(models=[p.model for p in llm.provider_chain()], embeddings=Config.EMBEDDING_BACKEND)
    return jsonify(out)


@api.get("/models")
@auth.login_required
def models():
    return jsonify(models=llm.models_status())


# ---------------- auth ----------------
@api.get("/auth/config")
def auth_config():
    return jsonify(registration=Config.ALLOW_REGISTRATION, invite_required=False)


@api.post("/auth/register")
def register():
    if not Config.ALLOW_REGISTRATION:
        return jsonify(error="self-registration is disabled - ask an administrator"), 403
    ok, retry = ratelimit.hit(f"register:{_ip()}", Config.REGISTER_RATE_PER_IP_HOUR, 3600)
    if not ok:
        return _too_many("too many registration attempts", retry)
    b = _body()
    email, pw = str(b.get("email", "")).strip().lower(), str(b.get("password", ""))
    if not auth.EMAIL_RE.match(email):
        return jsonify(error="valid email required"), 400
    problem = auth.password_problem(pw, email)
    if problem:
        return jsonify(error=problem), 400
    try:
        uid = auth.create_user(email, pw, str(b.get("name", "")))
    except sqlite3.IntegrityError:
        return jsonify(error="email already registered"), 409
    user = db.query("SELECT id, email, name, role, token_version FROM users WHERE id=?", (uid,), one=True)
    db.log_activity(uid, "auth.register", {"ip": _ip()})
    return _session_response(user, 201, b.get("return_token"))


@api.post("/auth/login")
def login():
    ok, retry = ratelimit.hit(f"login:{_ip()}", Config.LOGIN_RATE_PER_IP_5MIN, 300)
    if not ok:
        return _too_many("too many login attempts from this address, try later", retry)
    b = _body()
    email = str(b.get("email", "")).strip().lower()
    if auth.is_locked(email):
        db.log_activity(None, "security.login_locked", {"email": email[:100], "ip": _ip()}, "warning")
        return _too_many("too many failed attempts for this account, try again later",
                         Config.LOGIN_LOCK_MINUTES * 60)
    user = auth.verify_user(email, str(b.get("password", "")))
    if not user:
        db.log_activity(None, "security.login_failed", {"email": email[:100], "ip": _ip()}, "warning")
        return jsonify(error="invalid credentials"), 401
    db.log_activity(user["id"], "auth.login", {"ip": _ip()})
    return _session_response(user, 200, b.get("return_token"))


def _session_response(user: dict, code: int, return_token=False):
    token, exp = auth.issue_token(user)
    body = {"user": {"id": user["id"], "email": user["email"], "name": user.get("name"),
                     "role": user.get("role") or "user"}}
    if return_token is True:          # for API clients (eval script); browsers use the HttpOnly cookie
        body["token"] = token
    resp = jsonify(body)
    resp.status_code = code
    return auth.set_session_cookies(resp, token, exp)


@api.post("/auth/logout")
@auth.login_required
def logout():
    auth.revoke(g.token_payload)
    db.log_activity(g.user["id"], "auth.logout")
    return auth.clear_session_cookies(jsonify(ok=True))


@api.post("/auth/logout-all")
@auth.login_required
def logout_all():
    db.execute("UPDATE users SET token_version = token_version + 1 WHERE id=?", (g.user["id"],))
    db.log_activity(g.user["id"], "auth.logout_all")
    return auth.clear_session_cookies(jsonify(ok=True))


@api.post("/auth/change-password")
@auth.login_required
def change_password():
    b = _body()
    if not auth.verify_user(g.user["email"], str(b.get("current_password", ""))):
        return jsonify(error="current password is incorrect"), 403
    new = str(b.get("new_password", ""))
    problem = auth.password_problem(new, g.user["email"])
    if problem:
        return jsonify(error=problem), 400
    db.execute("UPDATE users SET password_hash=?, token_version = token_version + 1 WHERE id=?",
               (generate_password_hash(new), g.user["id"]))
    db.log_activity(g.user["id"], "auth.password_changed")
    return auth.clear_session_cookies(jsonify(ok=True, message="password changed - please log in again"))


@api.get("/auth/me")
@auth.login_required
def me():
    return jsonify(user={k: g.user[k] for k in ("id", "email", "name", "role")})


@api.get("/admin/users")
@auth.admin_required
def admin_users():
    rows = db.query("SELECT id, email, name, role, created_at FROM users ORDER BY id")
    return jsonify(users=[dict(r) for r in rows])


@api.post("/admin/users")
@auth.admin_required
def admin_invite():
    ok, retry = ratelimit.hit(f"invite:{g.user['id']}", 30, 3600)
    if not ok:
        return _too_many("too many invites", retry)
    b = _body()
    email, pw = str(b.get("email", "")).strip().lower(), str(b.get("password", ""))
    name = str(b.get("name", "")).strip()
    if not auth.EMAIL_RE.match(email):
        return jsonify(error="valid email required"), 400
    if email == Config.ADMIN_EMAIL:
        return jsonify(error="that email is reserved for the admin account"), 409
    problem = auth.password_problem(pw, email)
    if problem:
        return jsonify(error=problem), 400
    try:
        uid = auth.create_user(email, pw, name, role="user")
    except sqlite3.IntegrityError:
        return jsonify(error="email already registered"), 409
    db.log_activity(g.user["id"], "admin.invite", {"email": email})
    return jsonify(user={"id": uid, "email": email, "name": name, "role": "user"}), 201


# ---------------- documents ----------------
@api.post("/documents")
@auth.login_required
def upload():
    uid = g.user["id"]
    files = request.files.getlist("files") or ([request.files["file"]] if "file" in request.files else [])
    if not files:
        return jsonify(error="no file provided (field 'file' or 'files')"), 400
    if len(files) > 20:
        return jsonify(error="max 20 files per upload"), 400
    ok, retry = ratelimit.hit(f"upload:{uid}", Config.UPLOAD_RATE_PER_HOUR, 3600, cost=len(files))
    if not ok:
        return _too_many("upload limit reached, try later", retry)
    usage = db.query("SELECT COUNT(*) AS n, COALESCE(SUM(size_bytes),0) AS bytes FROM documents WHERE user_id=?",
                     (uid,), one=True)
    n_docs, used = usage["n"], usage["bytes"]
    results = []
    for f in files:
        name = documents.safe_filename(f.filename)
        data = f.read(Config.MAX_UPLOAD_MB * 1024 * 1024 + 1)
        try:
            ext = documents.validate_upload(name, data)
            if n_docs >= Config.MAX_DOCS_PER_USER:
                raise documents.ValidationError(f"document limit reached ({Config.MAX_DOCS_PER_USER})")
            if used + len(data) > Config.MAX_STORAGE_MB_PER_USER * 1024 * 1024:
                raise documents.ValidationError(f"storage quota reached ({Config.MAX_STORAGE_MB_PER_USER} MB)")
        except documents.ValidationError as e:
            results.append({"filename": name, "status": "rejected", "error": str(e)})
            db.log_activity(uid, "document.rejected", {"filename": name, "reason": str(e)}, "warning")
            continue
        h = documents.sha256(data)
        dup = db.query("SELECT id, filename FROM documents WHERE user_id=? AND content_hash=?", (uid, h), one=True)
        if dup:
            results.append({"filename": name, "status": "duplicate", "document_id": dup["id"],
                            "message": f"identical content already uploaded as '{dup['filename']}'"})
            continue
        user_dir = os.path.join(Config.UPLOAD_DIR, str(int(uid)))
        os.makedirs(user_dir, exist_ok=True)
        path = os.path.join(user_dir, f"{h[:16]}_{name}")
        with open(path, "wb") as out:
            out.write(data)
        try:
            did = db.execute("INSERT INTO documents (user_id, filename, file_type, file_path, content_hash, size_bytes) "
                             "VALUES (?,?,?,?,?,?)", (uid, name, ext, path, h, len(data)))
        except sqlite3.IntegrityError:
            results.append({"filename": name, "status": "duplicate"})
            continue
        n_docs, used = n_docs + 1, used + len(data)
        job = jobs.enqueue(did)
        db.log_activity(uid, "document.uploaded", {"document_id": did, "filename": name})
        results.append({"filename": name, "status": "queued", "document_id": did, "job": job})
    return jsonify(results=results), (202 if any(r["status"] == "queued" for r in results) else 200)


@api.get("/documents")
@auth.login_required
def list_docs():
    return jsonify(documents=db.query(
        "SELECT id, filename, file_type, size_bytes, status, error, num_chunks, num_chars, injection_flags, "
        "created_at, processed_at FROM documents WHERE user_id=? ORDER BY id DESC", (g.user["id"],)))


@api.get("/documents/<int:doc_id>")
@auth.login_required
def get_doc(doc_id):
    d = db.query("SELECT id, filename, file_type, size_bytes, status, error, num_chunks, num_chars, injection_flags, "
                 "created_at, processed_at FROM documents WHERE id=? AND user_id=?", (doc_id, g.user["id"]), one=True)
    if not d:
        return jsonify(error="not found"), 404
    d["chunks_preview"] = db.query("SELECT chunk_index, page, substr(text,1,300) AS text, suspicious, injection_reasons "
                                   "FROM chunks WHERE document_id=? ORDER BY suspicious DESC, chunk_index LIMIT 8", (doc_id,))
    d["jobs"] = db.query("SELECT id, status, attempts, error, created_at, finished_at FROM jobs WHERE document_id=? "
                         "ORDER BY id DESC", (doc_id,))
    return jsonify(document=d)


@api.post("/documents/<int:doc_id>/reprocess")
@auth.login_required
def reprocess(doc_id):
    if not db.query("SELECT id FROM documents WHERE id=? AND user_id=?", (doc_id, g.user["id"]), one=True):
        return jsonify(error="not found"), 404
    ok, retry = ratelimit.hit(f"upload:{g.user['id']}", Config.UPLOAD_RATE_PER_HOUR, 3600)
    if not ok:
        return _too_many("processing limit reached, try later", retry)
    return jsonify(jobs.enqueue(doc_id))


@api.delete("/documents/<int:doc_id>")
@auth.login_required
def delete_doc(doc_id):
    d = db.query("SELECT id, file_path FROM documents WHERE id=? AND user_id=?", (doc_id, g.user["id"]), one=True)
    if not d:
        return jsonify(error="not found"), 404
    db.execute("DELETE FROM documents WHERE id=? AND user_id=?", (doc_id, g.user["id"]))
    try:
        real = os.path.realpath(d["file_path"])
        if real.startswith(os.path.realpath(Config.UPLOAD_DIR) + os.sep):
            os.remove(real)
    except OSError:
        pass
    db.log_activity(g.user["id"], "document.deleted", {"document_id": doc_id})
    return jsonify(deleted=doc_id)


# ---------------- conversations & chat ----------------
@api.get("/conversations")
@auth.login_required
def list_convs():
    return jsonify(conversations=db.query(
        "SELECT id, title, created_at, updated_at FROM conversations WHERE user_id=? ORDER BY updated_at DESC",
        (g.user["id"],)))


@api.post("/conversations")
@auth.login_required
def new_conv():
    return jsonify(id=memory.create_conversation(g.user["id"], str(_body().get("title", "New conversation")))), 201


@api.get("/conversations/<int:cid>")
@auth.login_required
def get_conv(cid):
    conv = memory.get_conversation(cid, g.user["id"])
    if not conv:
        return jsonify(error="not found"), 404
    msgs = db.query("SELECT id, role, content, meta, created_at FROM messages WHERE conversation_id=? ORDER BY id", (cid,))
    for m in msgs:
        m["meta"] = json.loads(m["meta"] or "{}")
    return jsonify(conversation=conv, messages=msgs)


@api.delete("/conversations/<int:cid>")
@auth.login_required
def del_conv(cid):
    if not memory.get_conversation(cid, g.user["id"]):
        return jsonify(error="not found"), 404
    db.execute("DELETE FROM conversations WHERE id=? AND user_id=?", (cid, g.user["id"]))
    return jsonify(deleted=cid)


def tokens_used_today(uid: int) -> int:
    return db.query("SELECT COALESCE(SUM(total_tokens),0) AS t FROM llm_calls WHERE user_id=? "
                    "AND created_at >= date('now')", (uid,), one=True)["t"]


@api.post("/chat")
@auth.login_required
def chat():
    """mode: 'rag' (grounded Q&A) or 'agent' (multi-step tools). Optional 'model' = preferred Groq model."""
    uid = g.user["id"]
    b = _body()
    question = str(b.get("message", "")).strip()
    if not question:
        return jsonify(error="message is required"), 400
    if len(question) > 4000:
        return jsonify(error="message too long (max 4000 chars)"), 400
    mode = b.get("mode", "rag")
    if mode not in ("rag", "agent"):
        return jsonify(error="mode must be 'rag' or 'agent'"), 400
    model = b.get("model") or None
    if model is not None and (not isinstance(model, str) or model not in llm.configured_models()):
        return jsonify(error="unknown model"), 400

    # Abuse & cost protection
    for key, limit, win, msg in ((f"chat:min:{uid}", Config.CHAT_RATE_PER_MIN, 60, "too many requests per minute"),
                                 (f"chat:day:{uid}", Config.CHAT_RATE_PER_DAY, 86400, "daily request limit reached")):
        ok, retry = ratelimit.hit(key, limit, win)
        if not ok:
            db.log_activity(uid, "security.rate_limited", {"limit": key.split(":")[1]}, "warning")
            return _too_many(msg, retry)
    if Config.DAILY_TOKEN_BUDGET > 0 and tokens_used_today(uid) >= Config.DAILY_TOKEN_BUDGET:
        return _too_many("daily token budget used up - try again tomorrow", 3600)

    cid = b.get("conversation_id")
    try:
        conv = memory.get_conversation(int(cid), uid) if cid else None
    except (TypeError, ValueError):
        return jsonify(error="invalid conversation_id"), 400
    if cid and not conv:
        return jsonify(error="conversation not found"), 404
    if not conv:
        conv = memory.get_conversation(memory.create_conversation(uid, question[:60]), uid)

    doc_ids = b.get("document_ids") or None
    if doc_ids:
        try:
            owned = {r["id"] for r in db.query("SELECT id FROM documents WHERE user_id=?", (uid,))}
            doc_ids = [int(d) for d in doc_ids if int(d) in owned][:50]
        except (TypeError, ValueError):
            return jsonify(error="document_ids must be integers"), 400
    file_type = b.get("file_type")
    if file_type is not None and file_type not in Config.ALLOWED_EXTENSIONS:
        return jsonify(error="invalid file_type"), 400

    token = llm.preferred_model.set(model)
    t0 = time.time()
    try:
        if mode == "rag":
            result = rag.answer_question(uid, conv, question, doc_ids=doc_ids, file_type=file_type)
        else:
            result = runner.run_agent(uid, question, memory.history_for_prompt(conv), conv["id"])
    except llm.LLMError as e:
        ref = _error_ref(uid, "chat.llm_unavailable", e)
        return jsonify(error="The language model is unavailable right now, please retry.", error_ref=ref), 503
    except Exception as e:
        ref = _error_ref(uid, "chat.error", e)
        return jsonify(error="internal error", error_ref=ref), 500
    finally:
        llm.preferred_model.reset(token)

    memory.add_message(conv["id"], "user", question)
    meta = {k: v for k, v in result.items() if k != "answer"}
    meta["mode"], meta["requested_model"] = mode, model
    memory.add_message(conv["id"], "assistant", result["answer"], meta)
    memory.maybe_summarize(conv["id"], uid)
    total_tokens = sum(u.get("total_tokens", 0) for u in result.get("usage", []))
    db.log_activity(uid, f"chat.{mode}", {"conversation_id": conv["id"], "status": result.get("status"), "model": model,
                                          "tokens": total_tokens, "latency_ms": int((time.time() - t0) * 1000)})
    return jsonify(conversation_id=conv["id"], mode=mode, requested_model=model, total_tokens=total_tokens, **result)


# ---------------- dashboard / observability ----------------
@api.get("/stats")
@auth.login_required
def stats():
    uid = g.user["id"]
    docs = db.query("SELECT status, COUNT(*) AS n FROM documents WHERE user_id=? GROUP BY status", (uid,))
    llm_tot = db.query("""SELECT COUNT(*) AS calls, COALESCE(SUM(total_tokens),0) AS tokens,
                          COALESCE(AVG(CASE WHEN cached=0 AND success=1 THEN latency_ms END),0) AS avg_latency_ms,
                          COALESCE(SUM(CASE WHEN success=0 THEN 1 ELSE 0 END),0) AS errors,
                          COALESCE(SUM(fallback_used),0) AS fallbacks, COALESCE(SUM(cached),0) AS cache_hits
                          FROM llm_calls WHERE user_id=?""", (uid,), one=True)
    by_model = db.query("SELECT model, COUNT(*) AS calls, COALESCE(SUM(total_tokens),0) AS tokens, AVG(latency_ms) AS avg_latency_ms, "
                        "SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS errors FROM llm_calls WHERE user_id=? GROUP BY model", (uid,))
    by_day = db.query("SELECT date(created_at) AS day, COALESCE(SUM(total_tokens),0) AS tokens, COUNT(*) AS calls FROM llm_calls "
                      "WHERE user_id=? GROUP BY day ORDER BY day DESC LIMIT 14", (uid,))
    return jsonify(documents={r["status"]: r["n"] for r in docs}, llm=llm_tot, by_model=by_model,
                   by_day=list(reversed(by_day)),
                   conversations=db.query("SELECT COUNT(*) AS n FROM conversations WHERE user_id=?", (uid,), one=True)["n"],
                   agent_runs=db.query("SELECT COUNT(*) AS n FROM agent_runs WHERE user_id=?", (uid,), one=True)["n"],
                   embeddings=embeddings.backend_name(),
                   limits={"tokens_today": tokens_used_today(uid), "daily_token_budget": Config.DAILY_TOKEN_BUDGET,
                           "chat_per_min": Config.CHAT_RATE_PER_MIN, "chat_per_day": Config.CHAT_RATE_PER_DAY})


@api.get("/logs")
@auth.login_required
def logs():
    limit = max(1, min(200, request.args.get("limit", 50, type=int)))
    return jsonify(
        activity=db.query("SELECT level, action, detail, created_at FROM activity_logs WHERE user_id=? "
                          "ORDER BY id DESC LIMIT ?", (g.user["id"], limit)),
        llm_calls=db.query("SELECT purpose, provider, model, total_tokens, latency_ms, success, fallback_used, cached, "
                           "error, created_at FROM llm_calls WHERE user_id=? ORDER BY id DESC LIMIT ?", (g.user["id"], limit)))


@api.get("/agent/runs")
@auth.login_required
def agent_runs():
    rows = db.query("SELECT id, task, status, steps, created_at FROM agent_runs WHERE user_id=? ORDER BY id DESC LIMIT 20",
                    (g.user["id"],))
    for r in rows:
        r["steps"] = json.loads(r["steps"])
    return jsonify(runs=rows)
