"""One assist request end to end: redact (optional) -> cache -> concurrency slot -> model -> validate -> restore.

Counters per outcome and one audit log line per request (user, team, subject, mode, model, prompt version, KB version,
latency, outcome; never the question, the prompt or the answer).
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
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
BUSY_TEXT = "AI assistant is busy with other requests; try again in a moment. The knowledge-base remediation above " \
            "is unaffected."
ERROR_TEXT = "AI assistant is unavailable right now. The knowledge-base remediation above is unaffected."
CACHE_SIZE = 256
CACHE_TTL_S = 24 * 3600

COUNTERS: Counter[str] = Counter()
_counter_lock = threading.Lock()
_cache: OrderedDict[tuple, tuple[float, dict[str, Any]]] = OrderedDict()
_cache_lock = threading.Lock()

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
    T.reset_bedrock_clients()


_ARN = re.compile(r"arn:aws[\w-]*:([a-z0-9-]+):([a-z0-9-]*):(\d{12})?:([A-Za-z0-9_+=,.@/:*-]+)")
_ALIAS = re.compile(r"(?<![\w/])alias/[\w/+=,.@-]+")
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
_V6_CANDIDATE = re.compile(r"(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(?![\w:])")


def _boundary(value: str) -> str:
    # whole values only: 10.20.0.1 must not eat the start of 10.20.0.15
    return r"(?<![\w.\-])" + re.escape(value) + r"(?![\w\-]|\.\w)"


def redact(grounding: Grounding) -> tuple[Grounding, dict[str, str]]:
    """Identifying values replaced by tokens in every item, command and allowed command: host names and addresses
    (IPv4 and IPv6) -> HOST_n, asset / source / DN names and non-network locations -> NAME_n, ARNs ->
    arn:aws:<service>:<region>:ACCOUNT_n:<resource type>/RESOURCE_n, key aliases -> alias/ALIAS_n, account ids ->
    ACCOUNT_n, e-mail addresses -> EMAIL_n. The returned map restores them after validation."""
    mapping: dict[str, str] = {}
    counters: Counter[str] = Counter()

    def token(original: str, kind: str) -> str:
        if original not in mapping:
            counters[kind] += 1
            mapping[original] = f"{kind}_{counters[kind]}"
        return mapping[original]

    texts = [i.text for i in grounding.items] + [i.command for i in grounding.items if i.command] + \
        list(grounding.commands)
    blob = "\n".join(texts)
    arns: dict[str, str] = {}
    for m in _ARN.finditer(blob):
        if m.group(0) in arns:
            continue
        service, region, account, resource = m.groups()
        rtype = re.split(r"[/:]", resource, maxsplit=1)[0] if re.search(r"[/:]", resource) else "resource"
        acct = token(account, "ACCOUNT") if account else ""
        counters["RESOURCE"] += 1
        arns[m.group(0)] = f"arn:aws:{service}:{region}:{acct}:{rtype}/RESOURCE_{counters['RESOURCE']}"
    for host in grounding.hosts:
        token(host, "HOST")
    for name in grounding.names:
        if name not in mapping and not _ARN.fullmatch(name):
            token(name, "NAME")
    for m in _ALIAS.finditer(blob):
        counters["ALIAS"] += 1
        mapping.setdefault(m.group(0), f"alias/ALIAS_{counters['ALIAS']}")
    for m in _EMAIL.finditer(blob):
        token(m.group(0), "EMAIL")
    for m in _V6_CANDIDATE.finditer(blob):
        candidate = m.group(0).strip(":") if m.group(0).count(":") >= 2 else ""
        for value in (m.group(0), candidate):
            try:
                if value and ipaddress.ip_address(value).version == 6:
                    token(value, "HOST")
                    break
            except ValueError:
                continue
    for m in _ACCOUNT.finditer(blob):
        token(m.group(0), "ACCOUNT")
    ordered = sorted(list(arns.items()) + list(mapping.items()), key=lambda kv: len(kv[0]), reverse=True)
    pattern = re.compile("|".join(_boundary(o) for o, _t in ordered)) if ordered else None
    lookup = dict(ordered)

    def sub(text: str | None) -> str | None:
        if text is None or pattern is None:
            return text
        return pattern.sub(lambda m: lookup[m.group(0)], text)

    items = [Item(i.id, i.label, sub(i.text) or "", sub(i.command)) for i in grounding.items]
    red = Grounding(subject_key=grounding.subject_key, items=items, baseline=grounding.baseline,
                    commands={sub(c) or "" for c in grounding.commands}, urls=set(grounding.urls), hosts=[],
                    allowed_ids=set(grounding.allowed_ids), names=[])
    return red, {t: o for o, t in ordered}


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


def cache_key(cfg: AiConfig, grounding: Grounding, mode: str, question: str | None, kb_version: str,
              team_id: int) -> tuple:
    qsha = hashlib.sha256(P.clean_question(question).encode()).hexdigest() if mode == "question" else ""
    return (team_id, grounding.subject_key, kb_version, cfg.provider, cfg.model, P.PROMPT_VERSION, mode, qsha,
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
    key = cache_key(cfg, grounding, mode, question, kb_version, team_id)
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
            if cfg.provider == "bedrock":
                # the boto call cannot be cancelled: its slot is taken and released inside the worker thread
                # (transport.bedrock_chat; a slot wait of at most SLOT_WAIT_S, then "busy"), botocore's connect +
                # read timeouts add up to CBOM_AI_TIMEOUT_S, and the wait covers both
                raw = await asyncio.wait_for(asyncio.to_thread(T.bedrock_chat, cfg, messages, resolve),
                                             timeout=T.bedrock_deadline_s(cfg))
            else:
                # one process-wide slot pool for both providers (not per event loop); the queue wait is not part of
                # the model's time: no slot within SLOT_WAIT_S -> "busy", nothing sent
                slot = T._slot(cfg)
                if not await asyncio.to_thread(slot.acquire, True, T.SLOT_WAIT_S):
                    raise T.Busy()
                try:
                    raw = await asyncio.wait_for(T.chat(cfg, messages, resolve=resolve, transport=transport),
                                                 timeout=cfg.timeout_s + 1)
                finally:
                    slot.release()
        except T.Busy:
            outcome, raw = "busy", None
            result = {"status": "busy", "summary": "", "steps": [], "commands": [], "caveats": [BUSY_TEXT],
                      "baseline": False, "dropped_commands": 0}
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
