"""Deterministic checks between the model and the user (PLAN §6.4). Nothing the model writes reaches the user
without passing here.

1. Any CVE / CWE id anywhere in the model's text that is not in the subject's items -> the whole answer is withheld
   and the knowledge-base baseline is returned instead.
2. Citations must name existing items; a step (summary, caveat) without a valid citation is dropped.
3. A command is kept only if it equals (whitespace-normalised) a KB verify command or KB step command of this subject;
   command-like code spans inside text are held to the same rule.
4. URLs other than the subject's KB references are removed; every field is length-capped. Output is plain text.
"""
from __future__ import annotations

import json
import re
from typing import Any

from backend.utilities.cbom_ai.grounding import CVE_RE, CWE_RE, URL_RE, Grounding, command_forms, norm_command
from backend.utilities.cbom_ai.prompt import TEMPLATE_PHRASES

WITHHELD_UNKNOWN_ID = "AI answer withheld: it named an identifier not in the knowledge base"
WITHHELD_FORMAT = "AI answer withheld: it was not in the required format"
WITHHELD_UNCITED = "AI answer withheld: none of its statements cited the knowledge base"
NOT_IN_KB = "not in the knowledge base"

MAX_SUMMARY = 600
MAX_STEPS = 8
MAX_STEP = 400
MAX_COMMANDS = 6
MAX_COMMAND = 300
MAX_CAVEATS = 4
MAX_CAVEAT = 300

_CITE_BLOCK = re.compile(r"\[\s*([KF]\d+(?:\.[a-z]+\d*)?(?:\s*[,;]\s*[KF]\d+(?:\.[a-z]+\d*)?)*)\s*\]")
_CITE_ID = re.compile(r"[KF]\d+(?:\.[a-z]+\d*)?")
_CODE_SPAN = re.compile(r"`([^`\n]{1,400})`")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TAGS = re.compile(r"</?[A-Za-z][^>]{0,200}>")


def _cap(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def unknown_identifiers(raw: str, grounding: Grounding) -> list[str]:
    known = grounding.identifiers()
    found = [f"CVE-{a}-{b}" for a, b in CVE_RE.findall(raw)] + [f"CWE-{int(a)}" for a in CWE_RE.findall(raw)]
    return sorted({i for i in found if i not in known})


def parse(raw: str) -> dict[str, Any] | None:
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


class _Counts:
    def __init__(self) -> None:
        self.commands = 0
        self.links = 0
        self.steps = 0
        self.template = 0


def _clean_text(text: Any, grounding: Grounding, counts: _Counts) -> tuple[str, list[str]]:
    """Plain text with inline citations removed (returned separately, valid ones only), unknown URLs and
    unapproved command spans removed."""
    s = _CONTROL.sub(" ", str(text or "")) if not isinstance(text, (dict, list)) else ""
    s = _TAGS.sub("", s)
    cites: list[str] = []
    for block in _CITE_BLOCK.findall(s):
        cites += _CITE_ID.findall(block)
    s = _CITE_BLOCK.sub("", s)

    def url(m: re.Match[str]) -> str:
        u = m.group(0).rstrip(".,;:")
        tail = m.group(0)[len(u):]
        if u in grounding.urls:
            return m.group(0)
        counts.links += 1
        return "(link removed)" + tail

    s = URL_RE.sub(url, s)

    def span(m: re.Match[str]) -> str:
        inner = m.group(1).strip()
        if not re.search(r"\s", inner):  # an algorithm or file name, not a command
            return inner
        if norm_command(inner) in grounding.commands:
            return inner
        counts.commands += 1
        return "(command removed)"

    s = _CODE_SPAN.sub(span, s)
    s = re.sub(r"\s+([.,;:])", r"\1", " ".join(s.split()))
    valid = [c for c in dict.fromkeys(cites) if c in grounding.ids]
    if any(p in s.lower() for p in TEMPLATE_PHRASES):
        # the model copied the answer template instead of answering: not a statement, nothing to cite
        counts.template += 1
        return "", []
    return s.strip(), valid


def _valid_cites(values: Any, grounding: Grounding) -> list[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    out = []
    for v in values:
        for c in _CITE_ID.findall(str(v)):
            if c in grounding.ids:
                out.append(c)
    return out


def baseline(grounding: Grounding) -> dict[str, Any]:
    """The knowledge-base answer for this subject (no model), cited to its items."""
    b = grounding.baseline
    return {"summary": _cap(b.get("summary") or "", MAX_SUMMARY * 2),
            "steps": [{"text": _cap(s["text"], MAX_STEP * 2), "cites": s["cites"]} for s in b.get("steps") or []][:12],
            "commands": [c for c in b.get("commands") or [] if c.get("command")][:8],
            "caveats": []}


def withheld(grounding: Grounding, reason: str) -> dict[str, Any]:
    return {"status": "withheld", **baseline(grounding), "withheld_reason": reason, "baseline": True,
            "dropped_commands": 0, "dropped_links": 0, "dropped_steps": 0, "unknown_ids": []}


def validate(raw: str, grounding: Grounding) -> dict[str, Any]:
    unknown = unknown_identifiers(raw, grounding)
    if unknown:
        return {**withheld(grounding, WITHHELD_UNKNOWN_ID), "unknown_ids": unknown}
    data = parse(raw)
    if data is None:
        if NOT_IN_KB in raw.lower() and len(raw) < 400:
            return {"status": "ok", "summary": "Not in the knowledge base.", "steps": [], "commands": [], "caveats": [],
                    "baseline": False, "dropped_commands": 0, "dropped_links": 0, "dropped_steps": 0, "unknown_ids": []}
        return withheld(grounding, WITHHELD_FORMAT)
    counts = _Counts()

    summary, summary_cites = _clean_text(data.get("summary"), grounding, counts)
    not_in_kb = NOT_IN_KB in summary.lower()
    if not summary_cites and not not_in_kb:
        summary = ""

    steps: list[dict[str, Any]] = []
    raw_steps = data.get("steps") if isinstance(data.get("steps"), list) else []
    for step in raw_steps:
        text_value = step.get("text") if isinstance(step, dict) else step
        text, inline = _clean_text(text_value, grounding, counts)
        cites = list(dict.fromkeys(inline + (_valid_cites(step.get("cites"), grounding) if isinstance(step, dict) else [])))
        if not text or not cites:
            counts.steps += 1
            continue
        steps.append({"text": _cap(text, MAX_STEP), "cites": cites})
    if len(steps) > MAX_STEPS:
        counts.steps += len(steps) - MAX_STEPS
        steps = steps[:MAX_STEPS]

    commands: list[dict[str, str]] = []
    raw_commands = data.get("commands") if isinstance(data.get("commands"), list) else []
    for entry in raw_commands:
        command = entry.get("command") if isinstance(entry, dict) else entry
        command = _CONTROL.sub(" ", str(command or "")).strip().strip("`").strip()
        if not command:
            continue
        key = norm_command(command)
        if key not in grounding.commands or len(command) > MAX_COMMAND * 3:
            counts.commands += 1
            continue
        # the citation of a command is a KB item that holds it: the model's, when its item does, else the first one
        holders = [i.id for i in grounding.items if i.command and key in command_forms(i.command)]
        claimed = _valid_cites(entry.get("cite"), grounding) if isinstance(entry, dict) else []
        cite = [c for c in claimed if c in holders][:1] or holders[:1] or \
            [i.id for i in grounding.items if i.command and key in norm_command(i.command)][:1]
        if any(c["command"] == command for c in commands):
            continue
        commands.append({"command": command, "cite": cite[0] if cite else ""})
    if len(commands) > MAX_COMMANDS:
        commands = commands[:MAX_COMMANDS]

    caveats: list[str] = []
    raw_caveats = data.get("caveats") if isinstance(data.get("caveats"), list) else []
    for c in raw_caveats:
        text, cites = _clean_text(c, grounding, counts)
        if text and (cites or NOT_IN_KB in text.lower()):
            caveats.append(_cap(text, MAX_CAVEAT))
    caveats = caveats[:MAX_CAVEATS]
    if counts.commands:
        caveats.append(f"{counts.commands} command(s) not in the knowledge base were removed.")
    if counts.links:
        caveats.append(f"{counts.links} link(s) not in the knowledge base were removed.")

    if not summary and not steps and not commands:
        if not_in_kb or NOT_IN_KB in raw.lower():
            summary = "Not in the knowledge base."
        else:
            return {**withheld(grounding, WITHHELD_UNCITED), "dropped_commands": counts.commands,
                    "dropped_links": counts.links, "dropped_steps": counts.steps}
    return {"status": "ok", "summary": _cap(summary, MAX_SUMMARY), "steps": steps, "commands": commands,
            "caveats": caveats, "baseline": False, "dropped_commands": counts.commands,
            "dropped_links": counts.links, "dropped_steps": counts.steps, "unknown_ids": []}
