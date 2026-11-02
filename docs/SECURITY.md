# Security

## Threat model (what we defend against)
| Attacker | Goal |
|---|---|
| Malicious document author (uploads a poisoned file) | Make the AI execute code, leak secrets/other users' data, or give a manipulated answer |
| Anonymous internet user | Take over accounts, brute-force logins, burn the Groq quota, overload the server |
| Logged-in user | Read or delete another user's data (IDOR) |
| Malicious website | Make a logged-in user's browser perform actions (CSRF), inject scripts (XSS) |

## Why "a script inside a file" can't run or leak passwords
- Uploaded files are **never executed** – only text is extracted (PDFs in an isolated child process).
- The LLM has **4 read-only tools**, all scoped to the calling user's own documents. There is no tool that
  runs code, reads disk, runs SQL, touches user accounts or makes network calls. Unknown tool names are rejected.
- Passwords are stored as salted hashes; API keys / JWT secret are never put into prompts.
- Answers pass an **output guard** that redacts API-key / password-hash / system-prompt patterns.
- The Markdown renderer never renders links or images, and the CSP blocks inline/external scripts – so a
  manipulated answer can't exfiltrate data through URLs or run JavaScript.

## Controls
| Area | Control | Where |
|---|---|---|
| Prompt injection | Normalization (NFKC, zero-width removal, spaced letters, leetspeak), EN + Hindi/Hinglish patterns, code-execution & credential-exfiltration patterns, base64 decoding | `services/security.py` |
| | Suspicious sentences are **redacted** before reaching the LLM (`INJECTION_ACTION=redact`), or the chunk is excluded / only flagged | `security.prepare_untrusted`, `retrieval.load_chunks` |
| | Optional ML classifier: Llama Prompt Guard 2 on Groq (`PROMPT_GUARD_ENABLED`) – fails open, regex still applies | `llm.classify_injection`, `jobs.scan_chunk` |
| | `<source>` delimiters, tag neutralization, explicit untrusted-data policy in every system prompt | `security.wrap_untrusted` |
| | Grounding verification + citation validation; ⚠️ badge and reasons shown in UI | `rag.py`, frontend |
| Session | JWT in **HttpOnly + SameSite=Strict** cookie (Secure in production); HS256 pinned; `exp/iat/iss/jti` required | `auth.py` |
| | **CSRF** double-submit token on every state-changing cookie request | `auth.login_required` |
| | Logout revokes the token (jti blocklist); logout-everywhere / password change bump `token_version` | `auth.py`, `/auth/logout*` |
| | Production refuses to start without a strong `JWT_SECRET`; dev auto-generates one (`data/.jwt_secret`) | `config.resolve_jwt_secret` |
| Brute force | IP throttling + **per-account lockout** (uniform for unknown emails, constant-time hash check) | `/auth/login` |
| | Password policy (8–128 chars, letters + digits, no trivial passwords) | `auth.password_problem` |
| Abuse / cost | Per-user chat rate (minute/day), **daily token budget**, upload rate, doc count & storage quota; persistent (SQLite) | `services/ratelimit.py`, `routes/api.py` |
| | Registration can be closed or **invite-code only** | `ALLOW_REGISTRATION`, `REGISTRATION_INVITE_CODE` |
| Uploads | Extension allow-list, magic-byte checks, executables/archives disguised as text rejected, PDFs with JavaScript/Launch rejected | `documents.validate_upload` |
| | PDF parsing in a **separate process** with hard timeout and memory cap; page / character / chunk limits; encrypted PDFs rejected | `documents._extract_pdf`, `pdf_worker.py` |
| | Filename sanitization, files stored under per-user dirs with hash prefix, delete only inside `UPLOAD_DIR` | `routes/api.py` |
| Data isolation | Every query filtered by `user_id` (also in joins); tests for IDOR | all services |
| Web | Strict **CSP** (`script-src 'self'`, no inline), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, HSTS (prod), `Cache-Control: no-store` for API | `factory.py` |
| | CORS: same-origin by default; explicit allow-list only, never `*` | `CORS_ORIGINS` |
| Errors | Clients get generic messages + `error_ref`; details only in server logs; provider errors never echo prompt content | `factory.py`, `llm._short_error` |
| Privacy | Optional **PII masking** (email, phone, Aadhaar, PAN, card) before text is sent to Groq | `REDACT_PII` |
| Ops | Server binds to `127.0.0.1` by default; Docker runs as non-root; Swagger off in production; proxy-aware client IP (`TRUST_PROXY`) | `wsgi.py`, `Dockerfile` |
| Audit | Security events (login failures, lockouts, rate limits, rejected uploads, injection detections) in activity log | `/api/logs` |

## Residual risks (honest list)
- **No prompt-injection filter is perfect.** Paraphrased or novel attacks can bypass regex; the classifier is
  optional and a preview model. Defence-in-depth (no dangerous tools, output guard, verification) limits impact
  to *a wrong answer about the user's own documents*, not code execution or data theft.
- Active-content detection in PDFs is best-effort (objects inside compressed streams aren't inspected); PDFs
  are never rendered or executed, so this is policy, not the main protection.
- Document text (minus redactions) is sent to Groq. For confidential data use `REDACT_PII=true`, a contract with the
  provider, or an on-prem model.
- SQLite + in-process queue = single instance. Rate limits are per instance.
- Swagger UI loads from a CDN (only on `/api/docs`, disabled in production by default).

## Production checklist
- [ ] `APP_ENV=production`, strong `JWT_SECRET` (≥32 chars), HTTPS (`COOKIE_SECURE=true`)
- [ ] `TRUST_PROXY=1` behind exactly one proxy (Render/Nginx)
- [ ] `ALLOW_REGISTRATION=false` or `REGISTRATION_INVITE_CODE` set
- [ ] Review limits: `CHAT_RATE_*`, `DAILY_TOKEN_BUDGET`, quotas
- [ ] `PROMPT_GUARD_ENABLED=true` if the model is available for your key
- [ ] `REDACT_PII=true` for personal data
- [ ] `.env` never committed; rotate the Groq key if it was ever shared
