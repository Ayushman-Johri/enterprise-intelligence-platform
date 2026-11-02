"""SQLite data-access layer with versioned migrations (each .sql file applied exactly once)."""
import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager

from .config import Config

log = logging.getLogger("eip.db")
_lock = threading.Lock()
MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "migrations")


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(Config.DATABASE_PATH)), exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def get_conn():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _apply(conn, name: str, sql: str):
    try:
        conn.executescript(sql)
    except sqlite3.OperationalError as e:
        if "duplicate column" not in str(e).lower():
            raise
        # Partially applied earlier (e.g. column already exists) -> run statement by statement
        for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError as e2:
                if "duplicate column" not in str(e2).lower():
                    raise
    conn.execute("INSERT INTO schema_migrations (name) VALUES (?)", (name,))
    log.info("Applied migration %s", name)


def init_db() -> None:
    with _lock, get_conn() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, "
                     "applied_at TEXT NOT NULL DEFAULT (datetime('now')))")
        done = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
        for name in sorted(os.listdir(MIGRATIONS_DIR)):
            if name.endswith(".sql") and name not in done:
                with open(os.path.join(MIGRATIONS_DIR, name), encoding="utf-8") as f:
                    _apply(conn, name, f.read())


def query(sql: str, params: tuple = (), one: bool = False):
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    return (rows[0] if rows else None) if one else rows


def execute(sql: str, params: tuple = ()) -> int:
    with get_conn() as conn:
        return conn.execute(sql, params).lastrowid


def log_activity(user_id, action: str, detail=None, level: str = "info") -> None:
    try:
        if detail is not None and not isinstance(detail, str):
            detail = json.dumps(detail, default=str)[:4000]
        execute("INSERT INTO activity_logs (user_id, level, action, detail) VALUES (?,?,?,?)",
                (user_id, level, action, detail))
    except Exception:
        pass
