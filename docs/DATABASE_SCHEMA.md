# Database schema

Versioned migrations in `backend/migrations/` (tracked in `schema_migrations`, each applied once).

| Table | Purpose |
|---|---|
| users | accounts (salted password hash), `token_version` for revoking all sessions |
| documents | files, status, SHA-256 (UNIQUE per user), injection flag count |
| chunks | text, page, embedding BLOB, `suspicious`, `injection_reasons` |
| jobs | background processing jobs |
| conversations | threads, rolling summary, focus docs |
| messages | messages + meta JSON |
| llm_calls | model, tokens, latency, success, fallback, cache, error code |
| response_cache | deterministic LLM response cache |
| activity_logs | audit + security events |
| agent_runs | agent task, status, step trace |
| revoked_tokens | logged-out JWT ids until expiry |
| rate_limits | fixed-window counters (chat, uploads, logins, lockouts) |
