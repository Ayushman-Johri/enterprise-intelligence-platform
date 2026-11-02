"""Central configuration loaded from environment variables."""
import os
import secrets

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

WEAK_SECRETS = {"", "change_me_to_a_long_random_string", "dev-only-secret-change-me", "secret", "changeme"}


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw and raw.strip() else default


def _list(name: str, default: str) -> list:
    raw = os.getenv(name)
    if raw is None and name == "GROQ_FALLBACK_MODELS":      # backward compatible single-model variable
        raw = os.getenv("GROQ_FALLBACK_MODEL")
    raw = default if raw is None else raw
    return [x.strip() for x in raw.split(",") if x.strip()]


class Config:
    APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
    IS_PROD = APP_ENV == "production"

    # LLM
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    GROQ_FALLBACK_MODELS = _list("GROQ_FALLBACK_MODELS", "openai/gpt-oss-20b,qwen/qwen3.8-27b")
    GROQ_REASONING_EFFORT = os.getenv("GROQ_REASONING_EFFORT", "low")
    GROQ_DISCOVER_MODELS = _bool("GROQ_DISCOVER_MODELS", True)
    SECONDARY_API_KEY = os.getenv("SECONDARY_API_KEY", "")
    SECONDARY_BASE_URL = os.getenv("SECONDARY_BASE_URL", "https://api.openai.com/v1")
    SECONDARY_MODEL = os.getenv("SECONDARY_MODEL", "gpt-4o-mini")
    LLM_TIMEOUT_SEC = _int("LLM_TIMEOUT_SEC", 90)
    LLM_MAX_RETRIES = _int("LLM_MAX_RETRIES", 2)

    # Auth / session
    JWT_SECRET = os.getenv("JWT_SECRET", "")
    JWT_EXP_HOURS = _int("JWT_EXP_HOURS", 8)
    COOKIE_SECURE = _bool("COOKIE_SECURE", IS_PROD)
    ALLOW_REGISTRATION = _bool("ALLOW_REGISTRATION", True)
    REGISTRATION_INVITE_CODE = os.getenv("REGISTRATION_INVITE_CODE", "")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
    LOGIN_MAX_FAILS = _int("LOGIN_MAX_FAILS", 5)
    LOGIN_LOCK_MINUTES = _int("LOGIN_LOCK_MINUTES", 15)
    LOGIN_RATE_PER_IP_5MIN = _int("LOGIN_RATE_PER_IP_5MIN", 30)
    REGISTER_RATE_PER_IP_HOUR = _int("REGISTER_RATE_PER_IP_HOUR", 10)
    TRUST_PROXY = _int("TRUST_PROXY", 0)
    CORS_ORIGINS = [o.rstrip("/") for o in _list("CORS_ORIGINS", "") if o != "*"]
    ENABLE_API_DOCS = _bool("ENABLE_API_DOCS", not IS_PROD)

    # Abuse / cost limits
    CHAT_RATE_PER_MIN = _int("CHAT_RATE_PER_MIN", 10)
    CHAT_RATE_PER_DAY = _int("CHAT_RATE_PER_DAY", 300)
    DAILY_TOKEN_BUDGET = _int("DAILY_TOKEN_BUDGET", 300000)
    UPLOAD_RATE_PER_HOUR = _int("UPLOAD_RATE_PER_HOUR", 60)
    MAX_DOCS_PER_USER = _int("MAX_DOCS_PER_USER", 200)
    MAX_STORAGE_MB_PER_USER = _int("MAX_STORAGE_MB_PER_USER", 300)

    # Storage / parsing
    DATABASE_PATH = os.getenv("DATABASE_PATH", "./data/eip.sqlite3")
    UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./data/uploads")
    MAX_UPLOAD_MB = _int("MAX_UPLOAD_MB", 15)
    MAX_PDF_PAGES = _int("MAX_PDF_PAGES", 300)
    MAX_EXTRACT_CHARS = _int("MAX_EXTRACT_CHARS", 2_000_000)
    MAX_CHUNKS_PER_DOC = _int("MAX_CHUNKS_PER_DOC", 3000)
    EXTRACT_TIMEOUT_SEC = _int("EXTRACT_TIMEOUT_SEC", 60)
    PDF_SANDBOX = _bool("PDF_SANDBOX", True)
    REJECT_ACTIVE_PDF = _bool("REJECT_ACTIVE_PDF", True)
    ALLOWED_EXTENSIONS = {"pdf", "txt", "md", "markdown", "csv"}

    # Prompt-injection defence
    INJECTION_ACTION = os.getenv("INJECTION_ACTION", "redact").strip().lower()
    PROMPT_GUARD_ENABLED = _bool("PROMPT_GUARD_ENABLED", False)
    PROMPT_GUARD_MODEL = os.getenv("PROMPT_GUARD_MODEL", "meta-llama/llama-prompt-guard-2-86m")
    PROMPT_GUARD_THRESHOLD = float(os.getenv("PROMPT_GUARD_THRESHOLD", "0.8"))
    PROMPT_GUARD_MAX_CHUNKS = _int("PROMPT_GUARD_MAX_CHUNKS", 150)
    REDACT_PII = _bool("REDACT_PII", False)

    # Retrieval
    EMBEDDING_BACKEND = os.getenv("EMBEDDING_BACKEND", "fastembed")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
    EMBEDDING_CACHE_DIR = os.getenv("EMBEDDING_CACHE_DIR", "./data/models")
    CHUNK_SIZE = _int("CHUNK_SIZE", 900)
    CHUNK_OVERLAP = _int("CHUNK_OVERLAP", 150)
    TOP_K = _int("TOP_K", 6)
    MIN_RELEVANCE = float(os.getenv("MIN_RELEVANCE", "0.25"))
    ENABLE_QUERY_REWRITE = _bool("ENABLE_QUERY_REWRITE", True)

    HISTORY_TURNS = _int("HISTORY_TURNS", 6)
    AGENT_MAX_STEPS = _int("AGENT_MAX_STEPS", 6)
    AGENT_TOOL_TIMEOUT_SEC = _int("AGENT_TOOL_TIMEOUT_SEC", 90)


def resolve_jwt_secret() -> str:
    """Production: a strong JWT_SECRET is mandatory. Development: generate once and persist."""
    s = Config.JWT_SECRET.strip()
    if s and s not in WEAK_SECRETS and len(s) >= 32:
        return s
    if Config.IS_PROD:
        raise RuntimeError("APP_ENV=production requires JWT_SECRET (>= 32 random characters). Refusing to start.")
    path = os.path.join(os.path.dirname(os.path.abspath(Config.DATABASE_PATH)), ".jwt_secret")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            saved = f.read().strip()
        if len(saved) >= 32:
            Config.JWT_SECRET = saved
            return saved
    saved = secrets.token_urlsafe(48)
    with open(path, "w", encoding="utf-8") as f:
        f.write(saved)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    Config.JWT_SECRET = saved
    return saved
