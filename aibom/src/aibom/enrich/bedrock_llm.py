"""Amazon Bedrock LLM enrichment — optional, deterministic-first, FAIL-OPEN.

Calls Bedrock's Converse API with an Anthropic **Haiku 4.5** regional inference
profile. Enrichment is *always* optional:

* ``AIBOM_LLM_OFFLINE=1`` -> :func:`enrich` returns ``None`` immediately (no
  boto3, no AWS) so callers fall back to deterministic-only output and tests run
  with zero AWS access.
* Any error (no creds, network, throttling, bad response) is caught and returns
  ``None`` — an LLM hiccup must NEVER fail a scan.

Results are cached (bounded LRU) keyed by ``sha256(model | system | prompt)`` for
determinism within a run. Haiku 4.5 is temperature XOR top_p — we send
``temperature=0`` only.

Config (env):
* ``AIBOM_BEDROCK_MODEL`` (default ``apac.anthropic.claude-haiku-4-5-20251001-v1:0``)
* ``AWS_REGION``          (default ``ap-south-1``)
* ``AIBOM_LLM_OFFLINE``   (``1`` -> disabled)
"""

from __future__ import annotations

import functools
import hashlib
import os

_DEFAULT_MODEL = "apac.anthropic.claude-haiku-4-5-20251001-v1:0"
_DEFAULT_REGION = "ap-south-1"
_MAX_TOKENS = 1024


def _offline() -> bool:
    return os.environ.get("AIBOM_LLM_OFFLINE", "") == "1"


def _model() -> str:
    return os.environ.get("AIBOM_BEDROCK_MODEL", _DEFAULT_MODEL)


def _region() -> str:
    return os.environ.get("AWS_REGION", _DEFAULT_REGION)


def _digest(model: str, system: str, prompt: str) -> str:
    return hashlib.sha256(f"{model}|{system}|{prompt}".encode()).hexdigest()


@functools.lru_cache(maxsize=512)
def _cached_converse(digest: str, model: str, region: str, system: str, prompt: str) -> str | None:
    """Bounded-LRU cached Bedrock call, keyed by ``digest`` (sha256 of the input).

    ``digest`` participates in the cache key, so identical (model, system, prompt)
    hits the cache. boto3 is imported lazily so the package never hard-depends on
    it. Returns ``None`` on ANY failure (fail-open).
    """
    try:
        import boto3  # lazy: only needed when actually calling out

        client = boto3.client("bedrock-runtime", region_name=region)
        resp = client.converse(
            modelId=model,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            system=[{"text": system}] if system else [],
            # Haiku 4.5: temperature XOR top_p — temperature only.
            inferenceConfig={"temperature": 0, "maxTokens": _MAX_TOKENS},
        )
        text = resp["output"]["message"]["content"][0]["text"]
        return text if isinstance(text, str) and text.strip() else None
    except Exception:
        # Never let an LLM error fail a scan — caller falls back to deterministic.
        return None


def enrich(prompt: str, *, system: str = "") -> str | None:
    """Return the model's text for ``prompt``, or ``None`` (offline / error).

    Fail-open + cached. Callers MUST treat ``None`` as "no enrichment" and proceed
    with their deterministic result.
    """
    if _offline() or not prompt:
        return None
    model, region = _model(), _region()
    return _cached_converse(_digest(model, system, prompt), model, region, system, prompt)


def cache_clear() -> None:
    """Clear the enrichment cache (test/maintenance helper)."""
    _cached_converse.cache_clear()


__all__ = ["enrich", "cache_clear"]
