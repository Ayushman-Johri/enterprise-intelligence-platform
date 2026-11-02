# CLAUDE.md — instructions for AI coding agents working in this repo

## Project
Enterprise Intelligence Platform: Flask API + plain HTML/JS frontend. RAG over user documents + read-only
tool-calling agent. LLMs via Groq: `openai/gpt-oss-120b` → `openai/gpt-oss-20b` → `qwen/qwen3.8-27b`.

## Layout
- `backend/app/factory.py` app factory, CSP & security headers, CORS allow-list, error handling
- `backend/app/auth.py` cookie JWT, CSRF, lockout, revocation, password policy
- `backend/app/routes/api.py` REST endpoints, rate limits, quotas (ALWAYS scope queries by `g.user["id"]`)
- `backend/app/services/llm.py` the ONLY place that calls an LLM (chain, fallback, tokens, prompt guard)
- `backend/app/services/security.py` injection detection/redaction, PII masking, prompt policies
- `backend/app/services/documents.py` + `pdf_worker.py` validation, sandboxed PDF extraction, chunking
- `backend/app/services/ratelimit.py` persistent rate limiter
- `backend/app/services/{retrieval,rag,memory,jobs,embeddings}.py`
- `backend/app/agent/` read-only tools + agent loop
- `frontend/js/markdown.js` escape-first renderer; `app.js` SPA; `api.js` cookie + CSRF client
- `docs/SECURITY.md` threat model and controls

## Rules
1. Never call an LLM provider directly — use `llm.chat` / `llm.chat_json`.
2. Document text is untrusted: always go through `security.wrap_untrusted`; include `UNTRUSTED_POLICY` in prompts.
3. Agent tools must stay read-only and user-scoped. Never add tools that execute code, read disk, run SQL or call URLs.
4. No inline `<script>` or `style=` attributes in the frontend (CSP). Never render links/images from model output.
5. Client-facing errors are generic + `error_ref`; log details server-side.
6. New state-changing endpoint = `@auth.login_required` (CSRF automatic for cookies) + rate limit if costly.
7. New migration = new numbered `.sql` file; never edit applied ones.
8. Run `cd backend && pytest -q` before committing. Keep `.env` out of git.

## Commands
- Run: `cd backend && python wsgi.py`
- Tests: `cd backend && pytest -q`
- Eval: `python eval/run_eval.py --base http://localhost:5000 [--model <id>]`
