"""Deterministic checks between the model and the user (PLAN §6.4). Nothing the model writes reaches the user
without passing here.

1. Any CVE / CWE id anywhere in the model's text that is not in the subject's items -> the whole answer is withheld
   and the knowledge-base baseline is returned instead.
   Ids are read after JSON decoding and normalisation (NFKC, no zero-width characters, every dash a '-', look-alike
   letters folded, any separators), and only ids the KB attaches to the subject count as known.
2. Citations must name existing items; a step (summary, caveat) without a valid citation is dropped (an uncited
   "not in the knowledge base" becomes that fixed sentence, never the model's words).
3. A command is kept only if it equals (whitespace-normalised) a KB verify command or KB step command of this subject;
   a sentence of prose carrying any other command (an executable, a pipe, &&, $( ), redirection) is dropped.
4. Links (with or without a scheme, //host, bare domains) other than the subject's KB references and item text are
   removed; every field is length-capped. Output is plain text.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from backend.utilities.cbom_ai.grounding import URL_RE, Grounding, command_forms, norm_command
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
CANNED_NOT_IN_KB = "Not in the knowledge base."

# ------------------------------------------------------------------------------------------- identifier detection
# Look-alike letters a model (or a prompt injection) can use to spell CVE / CWE past a plain-ASCII pattern.
_CONFUSABLES = str.maketrans({
    "С": "C", "с": "c", "Е": "E", "е": "e", "Ѵ": "V", "ѵ": "v", "Ԝ": "W", "ԝ": "w", "В": "B", "Ѡ": "W", "ѡ": "w",
    "Ϲ": "C", "ϲ": "c", "Ε": "E", "ε": "e", "ν": "v", "Ν": "N", "ω": "w", "Ꮯ": "C", "Ꮩ": "V", "Ꭼ": "E",
    "Ꮃ": "W", "ⅽ": "c", "Ⅽ": "C", "ⅴ": "v", "Ⅴ": "V", "∨": "v", "\u2212": "-", "\u2010": "-", "\u2011": "-",
})
_ID_CVE = re.compile(r"(?<![a-z])c[\W_]{0,3}v[\W_]{0,3}e[\W_]{0,3}(\d{4})[\W_]{0,3}(\d{4,7})(?!\d)", re.I)
_ID_CWE = re.compile(r"(?<![a-z])c[\W_]{0,3}w[\W_]{0,3}e[\W_]{0,3}(\d{1,5})(?!\d)", re.I)
# a non-ASCII letter (an unfolded look-alike) right before a CVE-shaped number: treated as an unknown id
_ID_SUSPECT = re.compile(r"[^\W\d_a-zA-Z]{1,3}[\W_]{0,3}\d{4}[\W_]{1,3}\d{4,7}(?!\d)")


def _drop_format_chars(text: str) -> str:
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def id_view(text: str) -> str:
    """The text as the id check reads it: NFKC, no format characters (zero-width, soft hyphen), every dash a '-',
    look-alike letters folded to ASCII, all whitespace (newlines included) one space."""
    t = unicodedata.normalize("NFKC", str(text))
    t = _drop_format_chars(t)
    t = "".join("-" if unicodedata.category(ch) == "Pd" else ch for ch in t).translate(_CONFUSABLES)
    return " ".join(t.split())


def _ascii_digits(text: str) -> str:
    return "".join(str(unicodedata.digit(ch)) for ch in text)


def identifiers_in(text: str) -> set[str]:
    view = id_view(text)
    found = {f"CVE-{_ascii_digits(a)}-{_ascii_digits(b)}" for a, b in _ID_CVE.findall(view)}
    found |= {f"CWE-{int(_ascii_digits(a))}" for a in _ID_CWE.findall(view)}
    found |= {f"suspicious:{m.group(0)}" for m in _ID_SUSPECT.finditer(view)}
    return found


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _strings(k) + _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return [str(value)] if value is not None else []


def _cap(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def unknown_identifiers(raw: str, grounding: Grounding, data: Any = None) -> list[str]:
    """Every CVE / CWE id in the raw answer AND in each decoded string of it (a JSON escape such as \\u0043VE is
    only visible after decoding), after normalisation, that the knowledge base does not attach to this subject."""
    known = grounding.identifiers()
    found: set[str] = set()
    for text in [raw] + _strings(data):
        found |= identifiers_in(text)
    return sorted(i for i in found if i not in known)


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


# ------------------------------------------------------------------------------------- commands and links in prose
_EXEC_ANY = (r"sudo|doas|rm|curl|wget|bash|zsh|ksh|powershell|pwsh|iex|invoke-[a-z]+|iwr|irm|certutil|chmod|chown|"
             r"mkfs(?:\.\w+)?|systemctl|kubectl|msiexec|regedit|reg\.exe|setx|crontab|base64|netcat|ncat|scp|rsync|"
             r"bitsadmin|mshta|rundll32|wmic|schtasks|launchctl|osascript|eval")
_COMMAND_LIKE = re.compile(
    r"\|\s*[\w/.$-]|&&|\|\||\$\(|`|(?<![<>=!])>{1,2}\s*[/~$\w]|"         # pipe, and/or, substitution, redirection
    r"(?<![\w./-])(?:" + _EXEC_ANY + r")(?=\s|$)|"                           # an executable that is never prose
    r"(?<![\w./-])sh\s+(?:-|/|~|\$)|"                                        # sh -c / sh /path
    r";\s*(?:" + _EXEC_ANY + r"|sh|openssl|aws|az|gcloud|nmap|python3?|perl)\b|"
    r"(?<![\w./-])openssl\s+(?:s_client|s_server|x509|req|genrsa|genpkey|rsa|ec|enc|dgst|ca|pkcs12|ciphers|"
    r"version|list|speed|verify|rand)\b|"
    r"(?<![\w./-])(?:aws|az)\s+[a-z0-9-]+\s+[a-z0-9-]+|(?<![\w./-])gcloud\s+[a-z]|"
    r"(?<![\w./-])(?:nmap|keytool|apt-get|yum|dnf|zypper|python3?|perl|ruby|node|docker|git)\s+-{1,2}[a-z]|"
    r"(?<![\w./-])[a-z][\w.-]*\s+(?:--[a-z][\w-]+|-[a-zA-Z]{1,4})(?=[\s=]|$)")   # any word followed by a flag
_TLDS = ("com|net|org|io|info|biz|co|us|uk|de|ru|cn|in|xyz|top|site|online|app|dev|ai|me|tk|ml|ga|cf|gq|cloud|gov|"
         "edu|mil|eu|fr|jp|br|au|ca|nl|ch|se|pl|it|es|ly|to|cc|ws|link|live|club|shop|store|tech|pro|page|gl|gd|su|ir|"
         "kp|onion|zip|mov|click|download|work|support|tv|fm|am|nu|ae|sg|hk|tw|kr|za|mx|ar|id|ph|vn|my|pk|ng|ke|tr|"
         "ua|ro|cz|hu|gr|pt|ie|dk|fi|at|be|nz|il|run|sh")
_BARE_LINK = re.compile(
    r"(?<![\w@])//[^\s/]+\S*|"                                                  # //host/path
    r"(?<![\w@./-])(?:[a-z0-9-]+\.)+(?:" + _TLDS + r")(?::\d+)?(?:/\S*)?(?![\w-])|"   # host.tld[/path]
    r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/\S+", re.I)                    # 10.0.0.1/path


def _kb_text(grounding: Grounding) -> str:
    return " ".join(norm_command(i.text) for i in grounding.items if i.id.startswith("K"))


def _all_item_text(grounding: Grounding) -> str:
    return " ".join(i.text for i in grounding.items)


def _command_like(sentence: str, grounding: Grounding) -> bool:
    """True when the sentence carries a shell command that is not one of this subject's KB commands. KB commands
    (and KB text) inside it are taken out first; what is left must not look like a command."""
    norm = norm_command(sentence)
    if norm and norm.rstrip(".") in _kb_text(grounding):
        return False
    rest = norm
    for cmd in sorted((c for c in grounding.commands if len(c) >= 6), key=len, reverse=True):
        if cmd in rest:
            rest = rest.replace(cmd, " KB_COMMAND ")
    return bool(_COMMAND_LIKE.search(rest))


def _clean_text(text: Any, grounding: Grounding, counts: _Counts) -> tuple[str, list[str]]:
    """Plain text with inline citations removed (returned separately, valid ones only), links that are not KB
    references removed, and any sentence carrying a non-KB command dropped."""
    s = "" if isinstance(text, (dict, list)) else str(text or "")
    s = _drop_format_chars(unicodedata.normalize("NFKC", s))
    s = _CONTROL.sub(" ", s)
    s = _TAGS.sub("", s)
    cites: list[str] = []
    for block in _CITE_BLOCK.findall(s):
        cites += _CITE_ID.findall(block)
    s = _CITE_BLOCK.sub("", s)
    items_text = _all_item_text(grounding)

    def url(m: re.Match[str]) -> str:
        u = m.group(0).rstrip(".,;:")
        tail = m.group(0)[len(u):]
        if u in grounding.urls:
            return m.group(0)
        counts.links += 1
        return "(link removed)" + tail

    s = URL_RE.sub(url, s)

    def bare(m: re.Match[str]) -> str:
        token = m.group(0).rstrip(".,;:)")
        tail = m.group(0)[len(token):]
        if token in items_text or token in grounding.urls or token == "(link removed)":
            return m.group(0)
        counts.links += 1
        return "(link removed)" + tail

    s = _BARE_LINK.sub(bare, s)

    def span(m: re.Match[str]) -> str:
        inner = m.group(1).strip()
        if not re.search(r"\s", inner) and not _COMMAND_LIKE.search(inner):  # an algorithm or file name
            return inner
        if norm_command(inner) in grounding.commands:
            return inner
        counts.commands += 1
        return "(command removed)"

    s = _CODE_SPAN.sub(span, s)
    kept = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", s):
        if _command_like(sentence, grounding):
            counts.commands += 1
            continue
        kept.append(sentence)
    s = re.sub(r"\s+([.,;:])", r"\1", " ".join(" ".join(kept).split()))
    valid = [c for c in dict.fromkeys(cites) if c in grounding.ids]
    if any(p in s.lower() for p in TEMPLATE_PHRASES):
        # the model copied the answer template instead of answering: not a statement, nothing to cite
        counts.template += 1
        return "", []
    return s.strip(), valid


def _uncited(text: str) -> str:
    """An uncited field is never shown in the model's words: only the fixed sentence, when it said that."""
    return CANNED_NOT_IN_KB if NOT_IN_KB in text.lower() else ""


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


def _unique_commands(commands: list[dict[str, str]]) -> list[dict[str, str]]:
    """Each command once, with the first item that holds it (two KB entries may share a check)."""
    seen: set[str] = set()
    out = []
    for c in commands:
        key = norm_command(c.get("command"))
        if key and key not in seen:
            seen.add(key)
            out.append(c)
    return out


def baseline(grounding: Grounding) -> dict[str, Any]:
    """The knowledge-base answer for this subject (no model), cited to its items."""
    b = grounding.baseline
    return {"summary": _cap(b.get("summary") or "", MAX_SUMMARY * 2),
            "steps": [{"text": _cap(s["text"], MAX_STEP * 2), "cites": s["cites"]} for s in b.get("steps") or []][:12],
            "commands": _unique_commands(b.get("commands") or [])[:8],
            "caveats": []}


def withheld(grounding: Grounding, reason: str) -> dict[str, Any]:
    return {"status": "withheld", **baseline(grounding), "withheld_reason": reason, "baseline": True,
            "dropped_commands": 0, "dropped_links": 0, "dropped_steps": 0, "unknown_ids": []}


def validate(raw: str, grounding: Grounding) -> dict[str, Any]:
    data = parse(raw)
    unknown = unknown_identifiers(raw, grounding, data)
    if unknown:
        return {**withheld(grounding, WITHHELD_UNKNOWN_ID), "unknown_ids": unknown}
    if data is None:
        if NOT_IN_KB in raw.lower() and len(raw) < 400:
            return {"status": "ok", "summary": CANNED_NOT_IN_KB, "steps": [], "commands": [], "caveats": [],
                    "baseline": False, "dropped_commands": 0, "dropped_links": 0, "dropped_steps": 0, "unknown_ids": []}
        return withheld(grounding, WITHHELD_FORMAT)
    counts = _Counts()

    summary, summary_cites = _clean_text(data.get("summary"), grounding, counts)
    if not summary_cites:
        summary = _uncited(summary)

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
        command = _CONTROL.sub(" ", _drop_format_chars(unicodedata.normalize("NFKC", str(command or "")))
                               ).strip().strip("`").strip()
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
        text = text if cites else _uncited(text)
        if text and text not in caveats:
            caveats.append(_cap(text, MAX_CAVEAT))
    caveats = caveats[:MAX_CAVEATS]
    if counts.commands:
        caveats.append(f"{counts.commands} command(s) not in the knowledge base were removed.")
    if counts.links:
        caveats.append(f"{counts.links} link(s) not in the knowledge base were removed.")

    if not summary and not steps and not commands:
        if CANNED_NOT_IN_KB in caveats or NOT_IN_KB in raw.lower():
            summary = CANNED_NOT_IN_KB
            caveats = [c for c in caveats if c != CANNED_NOT_IN_KB]
        else:
            return {**withheld(grounding, WITHHELD_UNCITED), "dropped_commands": counts.commands,
                    "dropped_links": counts.links, "dropped_steps": counts.steps}
    return {"status": "ok", "summary": _cap(summary, MAX_SUMMARY), "steps": steps, "commands": commands,
            "caveats": caveats, "baseline": False, "dropped_commands": counts.commands,
            "dropped_links": counts.links, "dropped_steps": counts.steps, "unknown_ids": []}
