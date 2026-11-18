"""One assist request end to end: redact (optional) -> cache -> concurrency slot -> model -> validate -> restore.

Bounded (#448, #449): each mode asks for an output budget that fits its answer (MODE_MAX_TOKENS); the whole request,
the slot wait, the model call and at most one retry, answers within CBOM_AI_DEADLINE_S (50 s: under a proxy's 60 s
read timeout), else with the app's own "took too long, try again". The one retry is for an answer cut at the
output-token cap (asked again shorter, with twice the room) or a dropped connection (asked again on a fresh one). A
cut-off answer is never reported as a format error: its complete part is shown, checked like any answer and labelled
as cut off, or it is withheld as too long.

Counters per outcome and one audit log line per request (user, team, subject, mode, model, prompt version, KB version,
latency, outcome, the stop reason of every attempt and its output budget; never the question, the prompt or the
answer).
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter, OrderedDict
from typing import Any

import httpx

from backend.utilities.cbom_ai import fix as FIX
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

TIMEOUT_TEXT = "The AI assistant took too long to answer, so the request was stopped. Try again in a minute; the " \
               "knowledge-base remediation above is unaffected."
BUSY_TEXT = "AI assistant is busy with other requests; try again in a moment. The knowledge-base remediation above " \
            "is unaffected."
ERROR_TEXT = "The AI assistant is unavailable right now. Try again later; if it keeps failing, ask your administrator " \
             "to check the AI settings. The knowledge-base remediation above is unaffected."
# mode "fix": the panel adds "Follow the knowledge-base steps under Standards."
FIX_TRUNCATED = FIX.WITHHELD_FIX.format("its rewrite was too long and was cut off before the end, also with twice the "
                                        "room, so it could not be checked")
_FIX_FORMAT = FIX.WITHHELD_FIX.format("it was not in the required format")
CACHE_SIZE = 256
CACHE_TTL_S = 24 * 3600

# Output tokens per mode, when CBOM_AI_MAX_TOKENS is unset. Plan and question fit the largest answer the validator
# keeps (a 600-character summary, 8 steps of 400, 6 commands of 300, 4 caveats of 300: about 6,800 characters of
# text, at about 3 characters a token for commands, ids and JSON); the old single 700-token cap cut every TLS / SSH /
# appliance plan (#448). Explain asks for 2-4 facts. A fix returns its whole code window.
MODE_MAX_TOKENS = {"explain": 1500, "plan": 2400, "question": 2400, "fix": FIX.FIX_MAX_TOKENS}
RETRY_MAX_TOKENS = 4096
MIN_RETRY_S = 12.0  # time a retry needs for a whole answer; with less left, the first answer is used as it is
# outcomes whose next step is "ask again": not served from the cache, so the next click really asks again
_NOT_CACHED = {"withheld_format"}

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


# host names and IPv4 addresses inside a code window (URLs' hosts, address literals)
_URL_HOST = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s'\"`@]*@)?(\[[0-9A-Fa-f:.]+\]|[^/\s'\"`:?#]+)")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def _window_hosts(lines: list[str]) -> list[str]:
    found: set[str] = set()
    for ln in lines:
        found |= {m.group(1).strip("[]") for m in _URL_HOST.finditer(ln)}
        for m in _IPV4.finditer(ln):
            try:
                ipaddress.ip_address(m.group(0))
                found.add(m.group(0))
            except ValueError:
                continue
    return sorted((h for h in found if len(h) >= 3 and not h.isdigit()), key=len, reverse=True)


def redact(grounding: Grounding) -> tuple[Grounding, dict[str, str]]:
    """Identifying values replaced by tokens in every item, command and allowed command: host names and addresses
    (IPv4 and IPv6) -> HOST_n, asset / source / DN names and non-network locations -> NAME_n, ARNs ->
    arn:aws:<service>:<region>:ACCOUNT_n:<resource type>/RESOURCE_n, key aliases -> alias/ALIAS_n, account ids ->
    ACCOUNT_n, e-mail addresses -> EMAIL_n. The returned map restores them after validation."""
    red, back, _window = redact_fix(grounding, None)
    return red, back


def redact_fix(grounding: Grounding, window: dict[str, Any] | None) -> tuple[Grounding, dict[str, str],
                                                                               dict[str, Any] | None]:
    """``redact`` over the grounding AND the code window sent with a fix request (the same tokens in both): the
    window's URL hosts and IPv4 / IPv6 addresses, e-mail addresses, account ids, ARNs and the grounding's own hosts
    and names become tokens; the fix is validated against the redacted window and ``restore`` puts them back."""
    mapping: dict[str, str] = {}
    counters: Counter[str] = Counter()

    def token(original: str, kind: str) -> str:
        if original not in mapping:
            counters[kind] += 1
            mapping[original] = f"{kind}_{counters[kind]}"
        return mapping[original]

    texts = [i.text for i in grounding.items] + [i.command for i in grounding.items if i.command] + \
        list(grounding.commands)
    window_lines = list(window["lines"]) if window else []
    blob = "\n".join(texts + window_lines)
    arns: dict[str, str] = {}
    for m in _ARN.finditer(blob):
        if m.group(0) in arns:
            continue
        service, region, account, resource = m.groups()
        rtype = re.split(r"[/:]", resource, maxsplit=1)[0] if re.search(r"[/:]", resource) else "resource"
        acct = token(account, "ACCOUNT") if account else ""
        counters["RESOURCE"] += 1
        arns[m.group(0)] = f"arn:aws:{service}:{region}:{acct}:{rtype}/RESOURCE_{counters['RESOURCE']}"
    for host in list(grounding.hosts) + _window_hosts(window_lines):
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
    red_window = {**window, "lines": [sub(ln) or "" for ln in window_lines]} if window else window
    return red, {t: o for o, t in ordered}, red_window


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


def token_budget(cfg: AiConfig, mode: str, *, retry: bool = False) -> int:
    """Output tokens for one call. CBOM_AI_MAX_TOKENS unset: the mode's budget (MODE_MAX_TOKENS), doubled up to
    RETRY_MAX_TOKENS for the retry after a cut-off answer. Set (a model with a small output or context limit): that
    cap for explain / plan / question, also on the retry (then only the shorter-answer instruction changes); a fix
    keeps at least FIX_MAX_TOKENS, as before."""
    if cfg.max_tokens:
        return max(cfg.max_tokens, FIX.FIX_MAX_TOKENS) if mode == "fix" else cfg.max_tokens
    base = MODE_MAX_TOKENS[mode]
    return min(base * 2, RETRY_MAX_TOKENS) if retry else base


def _shorter(messages: list[dict[str, str]], mode: str) -> list[dict[str, str]]:
    """The same request with the shorter-answer instruction at the end of the user turn."""
    out = [dict(m) for m in messages]
    out[-1]["content"] = out[-1]["content"] + "\n" + (P.COMPACT_FIX if mode == "fix" else P.COMPACT)
    return out


async def _attempt(cfg: AiConfig, messages: list[dict[str, str]], max_tokens: int, deadline: float) -> T.Reply:
    """One model call that ends by ``deadline`` (time.monotonic()). Raises like the transport, or TimeoutError."""
    call_cfg = dataclasses.replace(cfg, max_tokens=max_tokens)
    if cfg.provider == "bedrock":
        # the boto call cannot be cancelled: its slot is taken and released inside the worker thread
        # (transport.bedrock_chat; a slot wait of at most SLOT_WAIT_S, then "busy"), botocore's connect + read
        # timeouts end it before the request deadline (transport.bedrock_timeouts), and the wait stops at that deadline
        return await asyncio.wait_for(asyncio.to_thread(T.bedrock_chat, call_cfg, messages, resolve),
                                      timeout=max(0.0, deadline - time.monotonic()))
    # one process-wide slot pool for both providers (not per event loop); the queue wait is not part of the model's
    # time: no slot within SLOT_WAIT_S -> "busy", nothing sent
    slot = T._slot(cfg)
    if not await asyncio.to_thread(slot.acquire, True, max(0.0, min(T.SLOT_WAIT_S, deadline - time.monotonic()))):
        raise T.Busy()
    try:
        return await asyncio.wait_for(T.chat(call_cfg, messages, resolve=resolve, transport=transport),
                                      timeout=max(0.0, min(cfg.timeout_s + 1, deadline - time.monotonic())))
    finally:
        slot.release()


async def _try(cfg: AiConfig, messages: list[dict[str, str]], max_tokens: int, deadline: float) -> T.Reply | str:
    """The reply, or why there is none: busy / timeout / connection_lost / endpoint_refused / endpoint_error."""
    try:
        return await _attempt(cfg, messages, max_tokens, deadline)
    except T.Busy:
        return "busy"
    except (asyncio.TimeoutError, TimeoutError, httpx.TimeoutException):
        return "timeout"
    except T.ConnectionLost as exc:
        log.warning("cbom_ai endpoint error: %s", exc)
        return "connection_lost"
    except T.EndpointRefused as exc:
        log.warning("cbom_ai endpoint refused: %s", exc)
        return "endpoint_refused"
    except (T.EndpointError, httpx.HTTPError, OSError) as exc:
        log.warning("cbom_ai endpoint error: %s", exc.__class__.__name__ if not isinstance(exc, T.EndpointError)
                    else exc)
        return "endpoint_error"


def _cut_off(reply: T.Reply | str) -> bool:
    """A reply stopped at the output-token cap whose JSON never closed (a complete object is checked as it is)."""
    return isinstance(reply, T.Reply) and reply.truncated and V.parse(reply.text) is None


def _failed(outcome: str) -> dict[str, Any]:
    status, text = {"busy": ("busy", BUSY_TEXT), "timeout": ("timeout", TIMEOUT_TEXT)}.get(outcome, ("error", ERROR_TEXT))
    return {"status": status, "summary": "", "steps": [], "commands": [], "caveats": [text], "baseline": False,
            "dropped_commands": 0}


def public(cfg: AiConfig, grounding: Grounding, result: dict[str, Any], kb_version: str, *, cached: bool,
           mode: str = "") -> dict[str, Any]:
    """The response: the result without internal fields, plus where it came from and the citation labels."""
    out = {k: v for k, v in result.items() if k not in ("unknown_ids",)}
    return {**out, "provider": cfg.provider, "model": cfg.model, "region": cfg.region, "kb_version": kb_version,
            "prompt_version": FIX.FIX_PROMPT_VERSION if mode == "fix" else P.PROMPT_VERSION,
            "items": _items(grounding), "cached": cached}


async def assist(cfg: AiConfig, grounding: Grounding, *, mode: str, question: str | None, kb_version: str,
                 team_id: int, user_id: int, window: dict[str, Any] | None = None) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + cfg.deadline_s  # the whole request (both providers), under the proxy's read timeout
    key = cache_key(cfg, grounding, mode, question, kb_version, team_id) + (
        (FIX.FIX_PROMPT_VERSION, hashlib.sha256(json.dumps(window, sort_keys=True).encode()).hexdigest())
        if mode == "fix" else ())
    outcome = "ok"
    stops: list[str] = []
    budgets: list[int] = []
    cached = _cache_get(key)
    result: dict[str, Any]
    if cached is not None:
        result, outcome = cached, "cache_hit"
    else:
        fitted = grounding.trimmed(P.MAX_PROMPT_CHARS)
        # with redaction on, the code window is redacted too (same tokens): the fix is checked against what the
        # model saw and restored afterwards
        sent, back, sent_window = redact_fix(fitted, window) if cfg.redact_hosts else (fitted, {}, window)
        messages = FIX.build(sent, sent_window) if mode == "fix" else P.build(sent, mode, question)
        budgets.append(token_budget(cfg, mode))
        reply = await _try(cfg, messages, budgets[0], deadline)
        stops.append((reply.stop or "-") if isinstance(reply, T.Reply) else reply)
        # at most one retry: a cut-off answer is asked again shorter with more room, a dropped connection again on a
        # fresh one; only when there is time for a whole answer
        again = (_shorter(messages, mode), token_budget(cfg, mode, retry=True)) if _cut_off(reply) else \
            (messages, budgets[0]) if reply == "connection_lost" else None
        if again is not None and deadline - time.monotonic() >= MIN_RETRY_S:
            budgets.append(again[1])
            second = await _try(cfg, again[0], again[1], deadline)
            stops.append((second.stop or "-") if isinstance(second, T.Reply) else second)
            if isinstance(second, T.Reply) or not isinstance(reply, T.Reply):
                reply = second  # a retry that failed after a cut-off answer keeps the cut-off answer
        if not isinstance(reply, T.Reply):
            outcome = "endpoint_error" if reply == "connection_lost" else reply
            result = _failed(outcome)
        else:
            raw = reply.text
            if _cut_off(reply):
                if mode == "fix":  # part of a code window is no fix
                    checked = {**V.withheld(sent, FIX_TRUNCATED), "fix": None, "checks": [], "truncated": True}
                else:
                    checked = V.validate_truncated(raw, sent, need_steps=mode == "plan")
            else:
                checked = FIX.validate(raw, sent, sent_window) if mode == "fix" else V.validate(raw, sent)
            if checked["status"] == "withheld":
                checked = {**checked, **V.baseline(grounding)}  # baseline from the real (unredacted) items
                outcome = {V.WITHHELD_UNKNOWN_ID: "withheld_unknown_id", V.WITHHELD_FORMAT: "withheld_format",
                           V.WITHHELD_UNCITED: "withheld_uncited", V.WITHHELD_TRUNCATED: "withheld_truncated",
                           FIX_TRUNCATED: "withheld_truncated", _FIX_FORMAT: "withheld_format",
                           }.get(checked.get("withheld_reason") or "", "withheld_fix" if mode == "fix" else "withheld")
            else:
                checked = restore(checked, back)
                if checked.get("truncated"):
                    outcome = "ok_truncated"
            result = checked
            count("dropped_commands", int(checked.get("dropped_commands") or 0))
            count("dropped_links", int(checked.get("dropped_links") or 0))
            if outcome not in _NOT_CACHED:
                _cache_put(key, result)
    count(outcome)
    latency_ms = int((time.monotonic() - started) * 1000)
    log.info("cbom_ai audit outcome=%s team=%s user=%s subject=%s mode=%s provider=%s model=%s prompt=%s kb=%s "
             "latency_ms=%d stop=%s attempts=%d max_tokens=%s dropped_commands=%s unknown_ids=%d counters=%s",
             outcome, team_id, user_id, grounding.subject_key, mode, cfg.provider, cfg.model, P.PROMPT_VERSION,
             kb_version, latency_ms, ",".join(stops) or "-", len(stops), ",".join(map(str, budgets)) or "-",
             result.get("dropped_commands", 0), len(result.get("unknown_ids") or []), dict(COUNTERS))
    return public(cfg, grounding, result, kb_version, cached=outcome == "cache_hit", mode=mode)
