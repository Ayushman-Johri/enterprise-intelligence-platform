"""SQL the app writes for SQLite must also be valid once translated for Postgres."""
from decimal import Decimal

from app import db


def test_postgres_translation_keeps_dates_and_placeholders():
    sql, _ = db._prepare(
        "SELECT COALESCE(SUM(total_tokens),0) AS t FROM llm_calls "
        "WHERE user_id=? AND created_at >= date('now')"
    )
    assert "?" not in sql and "%s" in sql
    assert "date(" not in sql
    assert "(CURRENT_DATE)::text" in sql


def test_postgres_translation_quotes_rate_limit_columns():
    sql, _ = db._prepare(
        "INSERT INTO rate_limits (key, window, count) VALUES (?,?,?) "
        "ON CONFLICT(key, window) DO UPDATE SET count = count + excluded.count"
    )
    assert '"window"' in sql
    assert 'rate_limits."count"' in sql
    assert "excluded.count" not in sql.lower() or "EXCLUDED" in sql


def test_postgres_translation_returns_ids_for_inserts():
    sql, returning = db._prepare(
        "INSERT INTO documents (user_id, filename) VALUES (?,?)", want_id=True
    )
    assert returning and sql.endswith("RETURNING id")


def test_decimal_and_memoryview_become_plain_values():
    assert db._plain(Decimal("3")) == 3
    assert db._plain(Decimal("1.5")) == 1.5
    assert db._plain(memoryview(b"abc")) == b"abc"
