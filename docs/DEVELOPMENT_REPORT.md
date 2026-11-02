# Development Report — AI Tool Usage & Engineering Decisions

> Fill this in honestly.

## AI tools used
| Tool | Used for |
|---|---|
| Microsoft 365 Copilot | scaffold of backend, frontend, tests, docs; debugging; security hardening |

## Problems found while running & fixes
| Problem | Cause | Fix |
|---|---|---|
| `pip install` failed on Windows | `numpy==1.26.4` has no Python 3.13 wheel | `numpy>=2.1`; gunicorn skipped on Windows |
| 404 `model_not_found` | Llama 3.x Enterprise-only on Groq | gpt-oss-120b → gpt-oss-20b → qwen chain; discovery |
| 400 `json_validate_failed` | reasoning used the token budget | `reasoning_effort=low`, bigger budgets, retry without strict JSON |
| Raw tables / `【S7】` / broken columns | renderer + CSS | escape-first renderer, cell lists, word wrapping |

## Security review & fixes
| Finding | Fix |
|---|---|
| Default JWT secret allowed forged tokens | production refuses weak secret; dev auto-generates |
| No chat rate limit; open registration (cost abuse) | per-user rate limits, daily token budget, invite-only option |
| Regex-only injection detection, easy to bypass | normalization, multilingual + base64 detection, sentence redaction, optional Prompt Guard |
| PDF bombs could hang the server | child-process parsing with timeout + memory cap, page/char/chunk limits |
| Token in localStorage | HttpOnly SameSite=Strict cookie + CSRF + CSP |
| CORS `*` | same-origin default, explicit allow-list |
| Error details returned to client | generic errors + `error_ref` |
| In-memory IP throttle only | persistent limits + per-account lockout |
| Data sent to Groq | optional PII masking |
| Swagger from CDN | disabled in production |

## Decisions I made / validated myself
- _add your own_

## How I validated
- `pytest` (unit, gateway, pipeline, API/web security)
- Manual test of every UI screen + `sample_docs/security_attack_test.txt`
- `eval/run_eval.py` against the deployed URL
