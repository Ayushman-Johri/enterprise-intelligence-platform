"""Vercel entrypoint. The Flask WSGI app must be named `app`."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

# A Vercel function can write only to /tmp, and that disk is not shared or durable.
os.environ.setdefault("DATABASE_PATH", "/tmp/eip.sqlite3")
os.environ.setdefault("UPLOAD_DIR", "/tmp/uploads")
os.environ.setdefault("EMBEDDING_CACHE_DIR", "/tmp/models")
os.environ.setdefault("EMBEDDING_BACKEND", "hashing")
os.environ.setdefault("PDF_SANDBOX", "false")
os.environ.setdefault("GROQ_DISCOVER_MODELS", "false")
os.environ.setdefault("TRUST_PROXY", "1")
os.environ.setdefault("COOKIE_SECURE", "true")
os.environ.setdefault("APP_ENV", "production")

from app.factory import create_app

app = create_app()
