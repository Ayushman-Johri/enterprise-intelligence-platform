"""Persistent fixed-window rate limiter (SQLite) - survives restarts, shared by all threads."""
import time

from .. import db


def hit(key: str, limit: int, window_sec: int, cost: int = 1) -> tuple:
    """Count one event. Returns (allowed, retry_after_seconds)."""
    if limit <= 0:
        return True, 0
    now = int(time.time())
    win = now - now % window_sec
    with db.get_conn() as conn:
        conn.execute("INSERT INTO rate_limits (key, window, count) VALUES (?,?,?) "
                     "ON CONFLICT(key, window) DO UPDATE SET count = count + excluded.count", (key, win, cost))
        count = conn.execute("SELECT count FROM rate_limits WHERE key=? AND window=?", (key, win)).fetchone()["count"]
    if count > limit:
        return False, win + window_sec - now
    return True, 0


def peek(key: str, window_sec: int) -> int:
    now = int(time.time())
    row = db.query("SELECT count FROM rate_limits WHERE key=? AND window=?", (key, now - now % window_sec), one=True)
    return row["count"] if row else 0


def reset(key: str):
    db.execute("DELETE FROM rate_limits WHERE key=?", (key,))


def cleanup(max_age_sec: int = 2 * 86400):
    db.execute("DELETE FROM rate_limits WHERE window < ?", (int(time.time()) - max_age_sec,))
    db.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (int(time.time()),))
