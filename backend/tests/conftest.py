import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_tmp = tempfile.mkdtemp()
os.environ.pop("DATABASE_URL", None)
os.environ.pop("POSTGRES_URL", None)
os.environ.update({
    "APP_ENV": "development",
    "DATABASE_PATH": os.path.join(_tmp, "test.sqlite3"),
    "UPLOAD_DIR": os.path.join(_tmp, "uploads"),
    "EMBEDDING_BACKEND": "hashing",
    "ENABLE_QUERY_REWRITE": "false",
    "JWT_SECRET": "test-secret-0123456789-abcdefghijklmnopqrstuvwxyz",
    "GROQ_DISCOVER_MODELS": "false",
    "REGISTER_RATE_PER_IP_HOUR": "1000",
    "LOGIN_RATE_PER_IP_5MIN": "1000",
    "PROMPT_GUARD_ENABLED": "false",
})
os.environ.setdefault("GROQ_API_KEY", "test-key")
