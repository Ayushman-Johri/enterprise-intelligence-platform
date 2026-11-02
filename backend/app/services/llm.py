"""
LLM gateway — every model runs through the Groq OpenAI-compatible API with one key.

Chain:  user-selected model (optional) -> GROQ_MODEL -> GROQ_FALLBACK_MODELS... -> optional SECONDARY provider

- retries with backoff on 429/5xx (honours Retry-After), automatic fallback to the next model
- model discovery: GET /models -> models the key can't access are skipped
- 404 model_not_found -> model disabled for the process
- 400 json_validate_failed -> retry without strict JSON mode + bigger token budget
- reasoning control: gpt-oss -> reasoning_effort ; qwen -> reasoning_format=hidden ; <think> blocks stripped
- token + latency tracking (llm_calls), response cache, structured JSON output with validation
- optional prompt-injection classifier (Llama Prompt Guard 2)
"""
import contextvars
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import requests

from ..config import Config
from .. import db

log = logging.getLogger("eip.llm")


class LLMError(Exception):
    pass


@dataclass
class Provider:
    name: str
    base_url: str
    api_key: str
    model: str


@dataclass
class LLMResult:
    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int = 0
    fallback_used: bool = False
    cached: bool = False
    tool_calls: list = field(default_factory=list)
    raw_message: dict = field(default_factory=dict)

    def usage(self) -> dict:
        return {"model": self.model, "provider": self.provider, "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens, "total_tokens": self.total_tokens,
                "latency_ms": self.latency_ms, "fallback_used": self.fallback_used, "cached": self.cached}


RETRYABLE = {408, 409, 429, 500, 502, 503, 504}
_dead_models: set = set()
_available: Optional[set] = None
_disc_lock = threading.Lock()
_disc_done = False

preferred_model: contextvars.ContextVar = contextvars.ContextVar("preferred_model", default=None)

MODEL_LABELS = {
    "openai/gpt-oss-120b": "GPT-OSS 120B (OpenAI open-weight, best quality)",
    "openai/gpt-oss-20b": "GPT-OSS 20B (OpenAI open-weight, fastest)",
    "qwen/qwen3.8-27b": "Qwen 3.8 27B (preview)",
}


def configured_models() -> list:
    return list(dict.fromkeys([Config.GROQ_MODEL] + Config.GROQ_FALLBACK_MODELS))


def discover_models(force: bool = False) -> Optional[set]:
    global _available, _disc_done
    if not Config.GROQ_API_KEY or not Config.GROQ_DISCOVER_MODELS:
        return None
    with _disc_lock:
        if _disc_done and not force:
            return _available
        _disc_done = True
        try:
            r = requests.get(f"{Config.GROQ_BASE_URL.rstrip('/')}/models",
                             headers={"Authorization": f"Bearer {Config.GROQ_API_KEY}"}, timeout=10)
            if r.status_code == 200:
                _available = {m["id"] for m in r.json().get("data", []) if m.get("active", True)}
                missing = [m for m in configured_models() if m not in _available]
                if missing:
                    log.warning("Groq models not available for this key (skipped): %s", ", ".join(missing))
        except Exception as e:
            log.warning("Model discovery failed (%s) - using configured list as-is", type(e).__name__)
    return _available


def _usable(model: str) -> bool:
    return model not in _dead_models and (_available is None or model in _available)


def provider_chain(preferred: Optional[str] = None) -> list:
    chain = []
    if Config.GROQ_API_KEY:
        discover_models()
        models = configured_models()
        pref = preferred or preferred_model.get()
        if pref and pref in models:
            models = [pref] + [m for m in models if m != pref]
        chain = [Provider("groq", Config.GROQ_BASE_URL, Config.GROQ_API_KEY, m) for m in models if _usable(m)]
        if not chain:
            chain = [Provider("groq", Config.GROQ_BASE_URL, Config.GROQ_API_KEY, m) for m in models
                     if m not in _dead_models]
    if Config.SECONDARY_API_KEY:
        chain.append(Provider("secondary", Config.SECONDARY_BASE_URL, Config.SECONDARY_API_KEY, Config.SECONDARY_MODEL))
    return chain


def models_status() -> list:
    discover_models()
    return [{"id": m, "label": MODEL_LABELS.get(m, m), "primary": i == 0, "available": _usable(m)}
            for i, m in enumerate(configured_models())]


def _record(user_id, purpose, res: Optional[LLMResult], provider: Provider, ok: bool, err: str = None, latency=0):
    try:
        db.execute(
            """INSERT INTO llm_calls (user_id, purpose, provider, model, prompt_tokens, completion_tokens,
               total_tokens, latency_ms, success, fallback_used, cached, error)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (user_id, purpose, provider.name, provider.model,
             res.prompt_tokens if res else 0, res.completion_tokens if res else 0,
             res.total_tokens if res else 0, res.latency_ms if res else latency,
             1 if ok else 0, 1 if (res and res.fallback_used) else 0,
             1 if (res and res.cached) else 0, (err or "")[:300]))
    except Exception:
        pass


def _post(provider: Provider, payload: dict) -> requests.Response:
    return requests.post(f"{provider.base_url.rstrip('/')}/chat/completions",
                         headers={"Authorization": f"Bearer {provider.api_key}", "Content-Type": "application/json"},
                         json=payload, timeout=Config.LLM_TIMEOUT_SEC)


_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.S | re.I)


def strip_thinking(text: str) -> str:
    text = _THINK_RE.sub("", text or "")
    if "<think>" in text.lower():
        text = re.split(r"<think>", text, flags=re.I)[0]
    return text.strip()


def _apply_reasoning_params(provider: Provider, payload: dict):
    if provider.name != "groq":
        return
    if provider.model.startswith("openai/gpt-oss"):
        payload["reasoning_effort"] = Config.GROQ_REASONING_EFFORT
    elif provider.model.startswith("qwen/"):
        payload["reasoning_format"] = "hidden"


def _short_error(status: int, body: str) -> str:
    """Keep the provider's error code/message, never echo request content back."""
    try:
        err = json.loads(body).get("error", {})
        return f"HTTP {status}: {err.get('code') or err.get('type') or ''} {str(err.get('message', ''))[:160]}".strip()
    except Exception:
        return f"HTTP {status}"


def _call_provider(provider: Provider, messages, temperature, max_tokens, tools, json_mode) -> LLMResult:
    payload: dict[str, Any] = {"model": provider.model, "messages": messages,
                               "temperature": temperature, "max_tokens": max_tokens}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    _apply_reasoning_params(provider, payload)

    last_err = None
    for attempt in range(Config.LLM_MAX_RETRIES + 2):
        t0 = time.time()
        try:
            resp = _post(provider, payload)
        except requests.RequestException as e:
            last_err = f"network: {type(e).__name__}"
            time.sleep(min(2 ** attempt, 8))
            continue
        latency = int((time.time() - t0) * 1000)

        if resp.status_code == 200:
            data = resp.json()
            choice = data["choices"][0]
            msg = choice["message"]
            usage = data.get("usage") or {}
            content = strip_thinking(msg.get("content") or "")
            if json_mode and not content and choice.get("finish_reason") == "length" and payload["max_tokens"] < 8000:
                payload["max_tokens"] = min(payload["max_tokens"] * 2, 8000)
                last_err = "empty output (finish_reason=length)"
                continue
            return LLMResult(content=content, model=provider.model, provider=provider.name,
                             prompt_tokens=usage.get("prompt_tokens", 0),
                             completion_tokens=usage.get("completion_tokens", 0),
                             total_tokens=usage.get("total_tokens", 0), latency_ms=latency,
                             tool_calls=msg.get("tool_calls") or [], raw_message=msg)

        body = resp.text
        last_err = _short_error(resp.status_code, body)

        if resp.status_code == 404 and "model_not_found" in body:
            _dead_models.add(provider.model)
            log.warning("Model %s not available - disabled for this session", provider.model)
            break
        if resp.status_code == 400 and ("reasoning_format" in body or "reasoning_effort" in body) \
                and ("reasoning_format" in payload or "reasoning_effort" in payload):
            payload.pop("reasoning_format", None)
            payload.pop("reasoning_effort", None)
            continue
        if resp.status_code == 400 and "json_validate_failed" in body and "response_format" in payload:
            payload.pop("response_format", None)
            payload["messages"] = list(messages) + [{
                "role": "user", "content": "Return ONLY one valid JSON object. No prose and no markdown fences."}]
            payload["max_tokens"] = min(max_tokens * 2, 8000)
            continue
        if resp.status_code in RETRYABLE:
            retry_after = resp.headers.get("retry-after")
            wait = float(retry_after) if retry_after and retry_after.replace(".", "").isdigit() else 2 ** attempt
            if resp.status_code == 429 and wait > 10:
                break
            time.sleep(min(wait, 10))
            continue
        break
    raise LLMError(last_err or "unknown LLM error")


def chat(messages: list, *, user_id=None, purpose: str = "chat", temperature: float = 0.2,
         max_tokens: int = 2000, tools: Optional[list] = None, json_mode: bool = False,
         use_cache: bool = False, model: Optional[str] = None) -> LLMResult:
    chain = provider_chain(model)
    if not chain:
        raise LLMError("No LLM provider configured. Set GROQ_API_KEY in .env")

    cache_key = None
    if use_cache and not tools:
        cache_key = hashlib.sha256(json.dumps([messages, temperature, json_mode, chain[0].model],
                                              sort_keys=True).encode()).hexdigest()
        hit = db.query("SELECT response FROM response_cache WHERE cache_key=?", (cache_key,), one=True)
        if hit:
            res = LLMResult(**json.loads(hit["response"]))
            res.cached, res.latency_ms = True, 0
            _record(user_id, purpose, res, chain[0], True)
            return res

    errors = []
    for i, provider in enumerate(chain):
        t0 = time.time()
        try:
            res = _call_provider(provider, messages, temperature, max_tokens, tools, json_mode)
            res.fallback_used = i > 0
            _record(user_id, purpose, res, provider, True)
            if cache_key and res.content:
                db.execute("INSERT OR REPLACE INTO response_cache (cache_key, response) VALUES (?,?)",
                           (cache_key, json.dumps(res.__dict__)))
            return res
        except LLMError as e:
            errors.append(f"{provider.model}: {e}")
            log.warning("LLM provider failed, trying fallback: %s", e)
            _record(user_id, purpose, None, provider, False, str(e), int((time.time() - t0) * 1000))
    raise LLMError("All LLM providers failed -> " + " | ".join(errors))


_JSON_RE = re.compile(r"\{.*\}", re.S)


def parse_json(text: str) -> dict:
    text = strip_thinking(text)
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = _JSON_RE.search(text)
        if m:
            return json.loads(m.group(0))
        raise


def chat_json(messages: list, validator: Optional[Callable[[dict], None]] = None, **kw) -> tuple:
    res = chat(messages, json_mode=True, **kw)
    try:
        data = parse_json(res.content)
        if validator:
            validator(data)
        return data, res
    except Exception as e:
        repair = messages + [
            {"role": "assistant", "content": res.content[:4000] or "(empty)"},
            {"role": "user", "content": f"Your previous output was invalid ({str(e)[:120]}). Return ONLY valid JSON matching the requested schema."},
        ]
        res2 = chat(repair, json_mode=True, **kw)
        data = parse_json(res2.content)
        if validator:
            validator(data)
        res2.prompt_tokens += res.prompt_tokens
        res2.completion_tokens += res.completion_tokens
        res2.total_tokens += res.total_tokens
        return data, res2


def normalize_citations(text: str) -> str:
    text = re.sub(r"【\s*(S\d+)[^】]*】", r"[\1]", text or "")
    return text.replace("【", "[").replace("】", "]")


_LABELS_BAD = ("malicious", "injection", "jailbreak", "unsafe")


def classify_injection(text: str, user_id=None) -> Optional[float]:
    """Llama Prompt Guard 2 via Groq. Returns probability (0-1) that the text is an attack, None if unavailable.
    Fails open (returns None) so a classifier outage never blocks ingestion - regex layer still applies."""
    if not (Config.PROMPT_GUARD_ENABLED and Config.GROQ_API_KEY) or Config.PROMPT_GUARD_MODEL in _dead_models:
        return None
    p = Provider("groq", Config.GROQ_BASE_URL, Config.GROQ_API_KEY, Config.PROMPT_GUARD_MODEL)
    t0 = time.time()
    try:
        r = _post(p, {"model": p.model, "messages": [{"role": "user", "content": (text or "")[:2000]}],
                      "max_tokens": 16, "temperature": 0})
        if r.status_code == 404:
            _dead_models.add(p.model)
            log.warning("Prompt Guard model %s not available for this key - disabled", p.model)
            return None
        if r.status_code != 200:
            _record(user_id, "prompt_guard", None, p, False, _short_error(r.status_code, r.text))
            return None
        out = (r.json()["choices"][0]["message"].get("content") or "").strip().lower()
        res = LLMResult(content=out, model=p.model, provider="groq", latency_ms=int((time.time() - t0) * 1000))
        _record(user_id, "prompt_guard", res, p, True)
        m = re.search(r"\d*\.?\d+", out)
        if m:
            score = float(m.group())
            return score if 0 <= score <= 1 else None
        if any(lbl in out for lbl in _LABELS_BAD):
            return 1.0
        if "benign" in out or "safe" in out:
            return 0.0
        return None
    except Exception as e:
        log.warning("Prompt Guard call failed: %s", type(e).__name__)
        return None
