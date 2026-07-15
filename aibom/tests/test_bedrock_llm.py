"""Bedrock enrichment — mock ONLY the upstream provider (the boto3 client).

aibom/contract/testing: never mock the thing under test; mock only true externals
(here, the cloud SDK). Offline mode returns deterministic-only (None) with no AWS;
a mocked client returns text and caches; any client error returns None (fail-open).
"""
from __future__ import annotations

import sys
import types

import pytest

from aibom.enrich import bedrock_llm


@pytest.fixture(autouse=True)
def _clear_cache():
    bedrock_llm.cache_clear()
    yield
    bedrock_llm.cache_clear()


def _fake_boto3(text: str = "ENRICHED", calls: list | None = None) -> types.ModuleType:
    mod = types.ModuleType("boto3")

    class _Client:
        def converse(self, **kw):
            if calls is not None:
                calls.append(kw)
            return {"output": {"message": {"content": [{"text": text}]}}}

    mod.client = lambda *a, **k: _Client()  # type: ignore[attr-defined]
    return mod


def test_offline_returns_deterministic_only(monkeypatch) -> None:
    monkeypatch.setenv("AIBOM_LLM_OFFLINE", "1")
    # Short-circuits before any import/call — no AWS needed.
    assert bedrock_llm.enrich("hello", system="sys") is None


def test_online_returns_text_and_caches(monkeypatch) -> None:
    monkeypatch.delenv("AIBOM_LLM_OFFLINE", raising=False)
    calls: list = []
    monkeypatch.setitem(sys.modules, "boto3", _fake_boto3("ENRICHED", calls))

    out1 = bedrock_llm.enrich("classify this", system="you are x")
    out2 = bedrock_llm.enrich("classify this", system="you are x")  # identical -> cached

    assert out1 == "ENRICHED"
    assert out2 == "ENRICHED"
    assert len(calls) == 1, "second identical call must hit the sha256 LRU cache"
    # Haiku 4.5 regional profile + temperature=0 (temp XOR top_p), no top_p.
    assert "haiku-4-5" in calls[0]["modelId"]
    assert calls[0]["inferenceConfig"]["temperature"] == 0
    assert "topP" not in calls[0]["inferenceConfig"]


def test_client_error_is_fail_open(monkeypatch) -> None:
    monkeypatch.delenv("AIBOM_LLM_OFFLINE", raising=False)
    mod = types.ModuleType("boto3")

    def _boom(*a, **k):
        raise RuntimeError("no credentials")

    mod.client = _boom  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", mod)

    # Must swallow the error and return None — a scan never fails on enrichment.
    assert bedrock_llm.enrich("x") is None
