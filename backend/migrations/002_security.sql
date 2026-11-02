-- Security hardening: token revocation, persistent rate limits, injection reasons
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chunks ADD COLUMN injection_reasons TEXT DEFAULT '';

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
    key         TEXT NOT NULL,
    window      INTEGER NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window)
);
CREATE INDEX IF NOT EXISTS idx_llm_calls_user_day ON llm_calls(user_id, created_at);
