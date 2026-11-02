"""LLM gateway: model chain, discovery, preferred model, 404 skip, JSON recovery, reasoning params, prompt guard."""
import json

import pytest

from app.services import llm


class FakeResp:
    def __init__(self, status, body, headers=None):
        self.status_code, self._body = status, body
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.headers = headers or {}

    def json(self):
        return self._body if isinstance(self._body, dict) else json.loads(self._body)


def ok(content):
    return FakeResp(200, {"choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                          "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}})


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    from app import db
    db.init_db()
    llm._dead_models.clear()
    monkeypatch.setattr(llm, "_available", None)
    monkeypatch.setattr(llm.Config, "GROQ_API_KEY", "k")
    monkeypatch.setattr(llm.Config, "GROQ_DISCOVER_MODELS", False)
    monkeypatch.setattr(llm.Config, "GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setattr(llm.Config, "GROQ_FALLBACK_MODELS", ["openai/gpt-oss-20b", "qwen/qwen3.8-27b"])
    monkeypatch.setattr(llm.Config, "SECONDARY_API_KEY", "")
    monkeypatch.setattr(llm.time, "sleep", lambda *_: None)


def test_chain_order_and_preferred_model():
    assert [p.model for p in llm.provider_chain()] == ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]
    assert llm.provider_chain("qwen/qwen3.8-27b")[0].model == "qwen/qwen3.8-27b"
    tok = llm.preferred_model.set("openai/gpt-oss-20b")
    try:
        assert llm.provider_chain()[0].model == "openai/gpt-oss-20b"
    finally:
        llm.preferred_model.reset(tok)


def test_discovery_filters_unavailable(monkeypatch):
    monkeypatch.setattr(llm, "_available", {"openai/gpt-oss-120b", "qwen/qwen3.8-27b"})
    assert [p.model for p in llm.provider_chain()] == ["openai/gpt-oss-120b", "qwen/qwen3.8-27b"]
    assert {m["id"]: m["available"] for m in llm.models_status()}["openai/gpt-oss-20b"] is False


def test_reasoning_params_per_model(monkeypatch):
    seen = []
    monkeypatch.setattr(llm, "_post", lambda p, payload: (seen.append(dict(payload)), ok("hi"))[1])
    llm.chat([{"role": "user", "content": "x"}])
    llm.chat([{"role": "user", "content": "x"}], model="qwen/qwen3.8-27b")
    assert seen[0]["reasoning_effort"] == "low" and "reasoning_format" not in seen[0]
    assert seen[1]["reasoning_format"] == "hidden" and "reasoning_effort" not in seen[1]


def test_json_validate_failed_recovers(monkeypatch):
    seen = []

    def post(provider, payload):
        seen.append(dict(payload))
        if "response_format" in payload:
            return FakeResp(400, '{"error":{"code":"json_validate_failed","failed_generation":""}}')
        return ok('{"supported": true, "support_score": 0.9}')
    monkeypatch.setattr(llm, "_post", post)
    data, _ = llm.chat_json([{"role": "user", "content": "x"}], max_tokens=500)
    assert data["supported"] is True and "response_format" not in seen[1] and seen[1]["max_tokens"] == 1000


def test_model_not_found_disabled_and_fallback(monkeypatch):
    def post(provider, payload):
        if payload["model"] == "openai/gpt-oss-120b":
            return FakeResp(503, "busy")
        if payload["model"] == "openai/gpt-oss-20b":
            return FakeResp(404, '{"error":{"code":"model_not_found"}}')
        return ok("from qwen")
    monkeypatch.setattr(llm, "_post", post)
    res = llm.chat([{"role": "user", "content": "x"}])
    assert res.content == "from qwen" and res.fallback_used and "openai/gpt-oss-20b" in llm._dead_models


def test_provider_error_text_is_not_echoed(monkeypatch):
    monkeypatch.setattr(llm, "_post", lambda p, payload: FakeResp(400, '{"error":{"code":"bad","message":"m"}}'))
    with pytest.raises(llm.LLMError) as e:
        llm.chat([{"role": "user", "content": "SECRET DOCUMENT TEXT"}])
    assert "SECRET DOCUMENT TEXT" not in str(e.value)


@pytest.mark.parametrize("out,expected", [("0.97", 0.97), ("MALICIOUS", 1.0), ("benign", 0.0), ("???", None)])
def test_prompt_guard_parsing(monkeypatch, out, expected):
    monkeypatch.setattr(llm.Config, "PROMPT_GUARD_ENABLED", True)
    monkeypatch.setattr(llm, "_post", lambda p, payload: ok(out))
    assert llm.classify_injection("text") == expected


def test_prompt_guard_fails_open(monkeypatch):
    monkeypatch.setattr(llm.Config, "PROMPT_GUARD_ENABLED", True)
    monkeypatch.setattr(llm, "_post", lambda p, payload: FakeResp(404, "{}"))
    assert llm.classify_injection("text") is None
