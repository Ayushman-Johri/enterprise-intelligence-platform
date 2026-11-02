"""Flask application factory with security headers, strict CORS and safe error handling."""
import logging
import os
import secrets
import threading
from decimal import Decimal

from flask import Flask, jsonify, request, send_from_directory
from flask.json.provider import DefaultJSONProvider
from werkzeug.exceptions import HTTPException


class SafeJSONProvider(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, Decimal):
            return int(o) if o == o.to_integral_value() else float(o)
        return super().default(o)

from . import db
from .config import Config, resolve_jwt_secret

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
DOCS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "docs"))

CSP_APP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
           "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
CSP_DOCS = ("default-src 'self'; script-src 'self' https://unpkg.com 'unsafe-inline'; style-src 'self' https://unpkg.com "
            "'unsafe-inline'; img-src 'self' data: https://unpkg.com; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'")


def create_app() -> Flask:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("eip")
    app = Flask(__name__, static_folder=None)
    app.json_provider_class = SafeJSONProvider
    app.config["MAX_CONTENT_LENGTH"] = 20 * (Config.MAX_UPLOAD_MB + 1) * 1024 * 1024   # 20 files per request
    app.json.sort_keys = False

    resolve_jwt_secret()                       # fails fast in production without a strong secret
    if not Config.GROQ_API_KEY:
        log.warning("GROQ_API_KEY is not set - chat will fail until you add it to .env")
    if Config.IS_PROD and not Config.COOKIE_SECURE:
        log.warning("COOKIE_SECURE is off in production - session cookies will be sent over plain HTTP")

    if Config.TRUST_PROXY > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=Config.TRUST_PROXY, x_proto=Config.TRUST_PROXY,
                                x_host=Config.TRUST_PROXY)

    db.init_db()
    from .auth import ensure_admin
    ensure_admin()
    os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
    from .services import jobs, llm, ratelimit
    jobs.recover_stale_jobs()
    ratelimit.cleanup()
    if Config.GROQ_API_KEY and not app.config.get("TESTING") and Config.GROQ_DISCOVER_MODELS:
        threading.Thread(target=llm.discover_models, daemon=True).start()

    from .routes.api import api
    app.register_blueprint(api)

    @app.after_request
    def security_headers(resp):
        is_docs = request.path in ("/api/docs",)
        resp.headers["Content-Security-Policy"] = CSP_DOCS if is_docs else CSP_APP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if Config.COOKIE_SECURE:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        origin = request.headers.get("Origin", "").rstrip("/")
        if origin and origin in Config.CORS_ORIGINS:          # explicit allow-list only, never "*"
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-CSRF-Token"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
            resp.headers["Vary"] = "Origin"
        return resp

    @app.route("/api/<path:_any>", methods=["OPTIONS"])
    def preflight(_any):
        return ("", 204)

    @app.errorhandler(HTTPException)
    def http_error(e):
        msgs = {413: "upload too large", 404: "not found", 405: "method not allowed", 400: "bad request"}
        return jsonify(error=msgs.get(e.code, e.name.lower())), e.code

    @app.errorhandler(Exception)
    def unhandled(e):
        ref = secrets.token_hex(4)
        log.exception("Unhandled error (ref %s)", ref)
        return jsonify(error="internal server error", error_ref=ref), 500

    if Config.ENABLE_API_DOCS:
        @app.get("/api/openapi.yaml")
        def openapi():
            return send_from_directory(DOCS_DIR, "openapi.yaml", mimetype="text/yaml")

        @app.get("/api/docs")
        def swagger():
            return send_from_directory(DOCS_DIR, "swagger.html")

    @app.get("/favicon.ico")
    def favicon():
        return ("", 204)

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/<path:path>")
    def static_files(path):
        if path.startswith("api/"):
            return jsonify(error="not found"), 404
        if os.path.isfile(os.path.join(FRONTEND_DIR, path)):
            return send_from_directory(FRONTEND_DIR, path)      # safe_join prevents path traversal
        return send_from_directory(FRONTEND_DIR, "index.html")

    return app
