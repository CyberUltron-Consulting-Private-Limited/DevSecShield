"""One assist request end to end: redact (optional) -> cache -> concurrency slot -> model -> validate -> restore.

Counters per outcome and one audit log line per request (user, team, subject, mode, model, prompt version, KB version,
latency, outcome; never the question, the prompt or the answer).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading
import time
from collections import Counter, OrderedDict
from typing import Any

import httpx

from backend.utilities.cbom_ai import prompt as P
from backend.utilities.cbom_ai import transport as T
from backend.utilities.cbom_ai import validator as V
from backend.utilities.cbom_ai.config import AiConfig
from backend.utilities.cbom_ai.grounding import Grounding, Item

log = logging.getLogger("backend.cbom_ai")
if not log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    log.addHandler(_handler)
    log.setLevel(logging.INFO)
    log.propagate = False

TIMEOUT_TEXT = "AI assistant did not answer in time. The knowledge-base remediation above is unaffected."
ERROR_TEXT = "AI assistant is unavailable right now. The knowledge-base remediation above is unaffected."
CACHE_SIZE = 256
CACHE_TTL_S = 24 * 3600

COUNTERS: Counter[str] = Counter()
_counter_lock = threading.Lock()
_cache: OrderedDict[tuple, tuple[float, dict[str, Any]]] = OrderedDict()
_cache_lock = threading.Lock()
_semaphores: dict[tuple[int, int], asyncio.Semaphore] = {}

# tests swap these for a stub endpoint
resolve = T.system_resolve
transport: httpx.AsyncBaseTransport | None = None


def count(name: str, n: int = 1) -> None:
    if n:
        with _counter_lock:
            COUNTERS[name] += n


def reset() -> None:
    with _counter_lock:
        COUNTERS.clear()
    with _cache_lock:
        _cache.clear()
    _semaphores.clear()
    T.reset_bedrock_clients()


def _semaphore(cfg: AiConfig) -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    key = (id(loop), cfg.concurrency)
    sem = _semaphores.get(key)
    if sem is None:
        sem = _semaphores[key] = asyncio.Semaphore(cfg.concurrency)
    return sem


def redact(grounding: Grounding) -> tuple[Grounding, dict[str, str]]:
    """Host names and addresses replaced by HOST_n in every item, command and URL; the map restores them."""
    mapping: dict[str, str] = {}
    for n, host in enumerate(grounding.hosts, start=1):
        mapping[host] = f"HOST_{n}"

    def sub(text: str | None) -> str | None:
        if text is None:
            return None
        for host, token in mapping.items():
            # whole names only: 10.20.0.1 must not eat the start of 10.20.0.15
            text = re.sub(r"(?<![\w.\-])" + re.escape(host) + r"(?![\w\-]|\.\w)", token, text)
        return text

    items = [Item(i.id, i.label, sub(i.text) or "", sub(i.command)) for i in grounding.items]
    base = grounding.baseline
    red = Grounding(subject_key=grounding.subject_key, items=items, baseline=base,
                    commands={sub(c) or "" for c in grounding.commands}, urls=set(grounding.urls), hosts=[])
    return red, {token: host for host, token in mapping.items()}


def restore(value: Any, back: dict[str, str]) -> Any:
    if not back:
        return value
    if isinstance(value, str):
        for token in sorted(back, key=len, reverse=True):  # HOST_12 before HOST_1
            value = value.replace(token, back[token])
        return value
    if isinstance(value, list):
        return [restore(v, back) for v in value]
    if isinstance(value, dict):
        return {k: restore(v, back) for k, v in value.items()}
    return value


def cache_key(cfg: AiConfig, grounding: Grounding, mode: str, question: str | None, kb_version: str) -> tuple:
    qsha = hashlib.sha256(P.clean_question(question).encode()).hexdigest() if mode == "question" else ""
    return (grounding.subject_key, kb_version, cfg.provider, cfg.model, P.PROMPT_VERSION, mode, qsha,
            grounding.digest(),
            cfg.redact_hosts)


def _cache_get(key: tuple) -> dict[str, Any] | None:
    with _cache_lock:
        hit = _cache.get(key)
        if hit is None:
            return None
        stored, value = hit
        if time.time() - stored > CACHE_TTL_S:
            _cache.pop(key, None)
            return None
        _cache.move_to_end(key)
        return value


def _cache_put(key: tuple, value: dict[str, Any]) -> None:
    with _cache_lock:
        _cache[key] = (time.time(), value)
        _cache.move_to_end(key)
        while len(_cache) > CACHE_SIZE:
            _cache.popitem(last=False)


def _items(grounding: Grounding) -> list[dict[str, str]]:
    return [{"id": i.id, "label": i.label} for i in grounding.items]


async def assist(cfg: AiConfig, grounding: Grounding, *, mode: str, question: str | None, kb_version: str,
                 team_id: int, user_id: int) -> dict[str, Any]:
    started = time.monotonic()
    key = cache_key(cfg, grounding, mode, question, kb_version)
    outcome = "ok"
    cached = _cache_get(key)
    result: dict[str, Any]
    if cached is not None:
        result, outcome = cached, "cache_hit"
    else:
        fitted = grounding.trimmed(P.MAX_PROMPT_CHARS)
        sent, back = redact(fitted) if cfg.redact_hosts else (fitted, {})
        messages = P.build(sent, mode, question)
        try:
            async def call() -> str:
                async with _semaphore(cfg):
                    if cfg.provider == "bedrock":
                        return await asyncio.to_thread(T.bedrock_chat, cfg, messages, resolve)
                    return await T.chat(cfg, messages, resolve=resolve, transport=transport)

            raw = await asyncio.wait_for(call(), timeout=cfg.timeout_s + 1)
        except (asyncio.TimeoutError, httpx.TimeoutException):
            outcome, raw = "timeout", None
            result = {"status": "timeout", "summary": "", "steps": [], "commands": [], "caveats": [TIMEOUT_TEXT],
                      "baseline": False, "dropped_commands": 0}
        except T.EndpointRefused as exc:
            outcome, raw = "endpoint_refused", None
            log.warning("cbom_ai endpoint refused: %s", exc)
            result = {"status": "error", "summary": "", "steps": [], "commands": [], "caveats": [ERROR_TEXT],
                      "baseline": False, "dropped_commands": 0}
        except (T.EndpointError, httpx.HTTPError, OSError) as exc:
            outcome, raw = "endpoint_error", None
            log.warning("cbom_ai endpoint error: %s", exc.__class__.__name__ if not isinstance(exc, T.EndpointError)
                        else exc)
            result = {"status": "error", "summary": "", "steps": [], "commands": [], "caveats": [ERROR_TEXT],
                      "baseline": False, "dropped_commands": 0}
        if raw is not None:
            checked = V.validate(raw, sent)
            if checked["status"] == "withheld":
                checked = {**checked, **V.baseline(grounding)}  # baseline from the real (unredacted) items
                outcome = {V.WITHHELD_UNKNOWN_ID: "withheld_unknown_id", V.WITHHELD_FORMAT: "withheld_format",
                           V.WITHHELD_UNCITED: "withheld_uncited"}.get(checked.get("withheld_reason") or "",
                                                                       "withheld")
            else:
                checked = restore(checked, back)
            result = checked
            count("dropped_commands", int(checked.get("dropped_commands") or 0))
            count("dropped_links", int(checked.get("dropped_links") or 0))
            _cache_put(key, result)
    count(outcome)
    latency_ms = int((time.monotonic() - started) * 1000)
    log.info("cbom_ai audit outcome=%s team=%s user=%s subject=%s mode=%s provider=%s model=%s prompt=%s kb=%s "
             "latency_ms=%d dropped_commands=%s unknown_ids=%d counters=%s", outcome, team_id, user_id,
             grounding.subject_key, mode, cfg.provider, cfg.model, P.PROMPT_VERSION, kb_version, latency_ms,
             result.get("dropped_commands", 0),
             len(result.get("unknown_ids") or []), dict(COUNTERS))
    public = {k: v for k, v in result.items() if k not in ("unknown_ids",)}
    return {**public, "provider": cfg.provider, "model": cfg.model, "region": cfg.region, "kb_version": kb_version,
            "prompt_version": P.PROMPT_VERSION,
            "items": _items(grounding), "cached": outcome == "cache_hit"}
