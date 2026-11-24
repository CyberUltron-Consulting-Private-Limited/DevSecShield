"""Detect inline model REFERENCES in source text via a known-model dictionary.

The model-repo scanner finds a model from its ``MODEL_CARD.md`` / ``config.json``.
But most AI usage is an inline reference in application code —
``model="gpt-4o"``, ``new OllamaEmbeddingFunction("all-minilm-l6-v2")`` — with no
model card at all. This module recognizes those references.

Each entry is a regex anchored to a model FAMILY token (``gpt-``, ``claude-``,
``all-minilm-``, …), so a match is a real model identifier, not arbitrary text.
The dictionary is the deterministic core; an optional LLM enrichment pass (see
``model_ref_scan``) can add fuzzy matches but is off by default. Patterns are
case-insensitive and bounded by non-identifier characters so a namespaced ref
(``xenova/all-MiniLM-L6-v2``) yields the model token (``all-MiniLM-L6-v2``).
"""

from __future__ import annotations

import re

# (pattern, vendor). Bounded by (?<![\w-]) / (?![\w-]) so we capture the whole
# model token and never a substring of a longer identifier. A leading '/' or '.'
# is allowed before (namespaced refs) because those are not in [\w-].
_B = r"(?<![\w-]){}(?![\w-])"

# Optional HuggingFace-style "org/" prefix for repo-id embedding models. The org
# IS part of the canonical model id ("Xenova/all-MiniLM-L6-v2"), so capturing it
# yields the faithful identifier. Restricted to known orgs to avoid grabbing an
# arbitrary preceding path segment.
_ORG = (
    r"(?:(?:xenova|sentence-transformers|baai|thenlper|intfloat|chroma|nomic-ai|"
    r"mixedbread-ai|jinaai|hkunlp|nvidia|snowflake)/)?"
)
# A model-id "segment": alphanumerics with dots allowed ONLY inside a numeric
# version ("3.5", "v3.0"), never between letters — so a match cannot run into a
# domain/path ("gpt-index.readthedocs.io" stops at the family boundary).
# A numeric version may carry a unit/size suffix ("0.5b", "1.5B", "v0.1"), so a
# dotted number continues with letters/digits; otherwise "Qwen2-0.5B" was cut to
# "Qwen2-0" (the "B" after "0.5" broke the match and the regex backtracked).
_SEG = r"[a-z0-9]+(?:\.\d+[a-z0-9]*)*"
# Tail after a constrained first character: rest of the first segment, an
# optional version, then more '-'-joined segments.
_TAIL = rf"[a-z0-9]*(?:\.\d+[a-z0-9]*)*(?:-{_SEG})*"

# Amazon Bedrock model ids (QA round 2, Q2-05): ``[<geo>.]<provider>.<model>[:N]``,
# e.g. ``anthropic.claude-3-5-sonnet-20240620-v1:0``,
# ``us.anthropic.claude-3-7-sonnet-20250219-v1:0`` (a cross-Region inference
# profile), ``meta.llama3-70b-instruct-v1:0``, ``amazon.nova-pro-v1:0`` and the
# provisioned-throughput form ``…-v1:0:200k``. The whole id is the model's
# identifier: the bare ``claude-…`` family pattern below used to keep only
# ``claude-3-5-sonnet-20240620-v1``. Each Bedrock provider prefix must be followed
# by one of its model families, so ``meta.json``, ``amazon.com`` or ``mistral.ai``
# are never model ids. Provider prefix -> (model family words, vendor).
_BEDROCK_PROVIDERS: dict[str, tuple[str, str]] = {
    "anthropic": ("claude", "Anthropic"),
    "meta": ("llama", "Meta"),
    "amazon": ("titan|nova", "Amazon"),
    "mistral": ("mistral|mixtral|pixtral|ministral|codestral", "Mistral"),
    "cohere": ("command|embed|rerank", "Cohere"),
    "ai21": ("jamba|j2", "AI21 Labs"),
}
# Cross-Region inference profile geographies (the id's first label).
_BEDROCK_GEOS = ("us-gov", "us", "eu", "apac", "global")
_BEDROCK_SUFFIX = r"(?::\d+(?::\d+k)?)?"  # ":0", ":1", ":0:200k"
_BEDROCK_RE = re.compile(
    rf"(?<![\w-])(?:(?P<geo>{'|'.join(_BEDROCK_GEOS)})\.)?"
    r"(?P<provider>"
    + "|".join(rf"{p}\.(?:{fam})" for p, (fam, _v) in _BEDROCK_PROVIDERS.items())
    + rf")[a-z0-9]*(?:-[a-z0-9]+)*{_BEDROCK_SUFFIX}"
    # end of the id: no further id character (a sentence's full stop is fine)
    r"(?![\w:-]|\.\w)",
    re.IGNORECASE,
)


def parse_bedrock_id(name: str) -> dict[str, str] | None:
    """``{"vendor", "provider_prefix", "profile"?}`` for a whole Bedrock model id, else
    None. ``profile`` is the cross-Region inference profile geography (``us``)."""
    m = _BEDROCK_RE.fullmatch(name or "")
    if m is None:
        return None
    prefix = m.group("provider").split(".", 1)[0].lower()
    out = {"vendor": _BEDROCK_PROVIDERS[prefix][1], "provider_prefix": prefix}
    if m.group("geo"):
        out["profile"] = m.group("geo").lower()
    return out


# (raw pattern, vendor, org_prefix). ``org_prefix`` True prepends the optional
# HuggingFace "org/" repo prefix (_ORG). Compiled with the _B boundary below.
# Family first-segments are constrained to real model-name starts (a digit or a
# known size/series word), so prose like "command", "claude-desktop",
# "gemini-api" is NOT mistaken for a model.
_RAW: list[tuple[str, str, bool]] = [
    # OpenAI — gpt model ids start with a digit (gpt-4o, gpt-3.5) or 'o' (gpt-oss)
    (rf"gpt-[0-9o]{_TAIL}", "OpenAI", False),
    # gpt- family words: gpt-image-1, gpt-realtime, gpt-audio, gpt-oss
    (rf"gpt-(?:image|realtime|audio|oss|4o|4-1){_TAIL}", "OpenAI", False),
    (rf"text-embedding-[a-z0-9]{_TAIL}", "OpenAI", False),
    (r"text-(?:davinci|curie|babbage|ada)-\d+", "OpenAI", False),
    (r"davinci-instruct[\w.-]*", "OpenAI", False),  # davinci-instruct-beta-v3
    (r"whisper-\d[\w.-]*", "OpenAI", False),        # whisper-1
    (r"dall-e-\d", "OpenAI", False),                # dall-e-3
    # o-series reasoning models: o3, o4-mini, o3-deep-research, o4-mini-2025-04-16
    (r"o[1-4](?:-(?:mini|preview|pro|deep-research))+[\w.-]*", "OpenAI", False),
    (r"o[1-4]-\d{4}-\d\d-\d\d", "OpenAI", False),
    # Anthropic
    (rf"claude-(?:[0-9]|instant|opus|sonnet|haiku){_TAIL}", "Anthropic", False),
    # Google
    (rf"gemini-(?:[0-9]|pro|nano|ultra|flash|embedding){_TAIL}", "Google", False),
    (r"embedding-00\d", "Google", False),  # embedding-001
    (r"textembedding-gecko(?:-\w+)?", "Google", False),
    # Cohere — require a series suffix so the bare word "command" is not a model
    (r"embed-(?:english|multilingual)[\w.-]*", "Cohere", False),
    (r"multilingual-\d+-\d+", "Cohere", False),  # multilingual-22-12
    (rf"command-(?:r(?:-plus)?|light|nightly)(?:-{_SEG})*", "Cohere", False),
    # Mistral
    (rf"(?:mistral|mixtral|codestral)-[a-z0-9]{_TAIL}", "Mistral", False),
    # Meta Llama
    (rf"(?:code)?llama-?[234]{_TAIL}", "Meta", False),
    # AWS Bedrock first-party models (Titan / Nova), incl. "amazon." purl prefix
    (r"(?:amazon\.)?titan-(?:text|embed|image|tg1)[\w.-]*", "Amazon", False),
    (r"(?:amazon\.)?nova-(?:micro|lite|pro|premier|canvas|reel)[\w.-]*",
     "Amazon", False),
    # sentence-transformers / HuggingFace embedding models (optional "org/" prefix)
    (r"all-minilm-l\d+-v\d+[\w.-]*", "sentence-transformers", True),
    (r"all-mpnet-base-v\d+", "sentence-transformers", True),
    (r"paraphrase-[\w.-]*minilm[\w.-]*", "sentence-transformers", True),
    (r"(?:multilingual-)?e5-(?:small|base|large)[\w.-]*", "HuggingFace", True),
    (r"bge-(?:small|base|large|m3)[\w.-]*", "HuggingFace", True),
    (r"gte-(?:small|base|large)[\w.-]*", "HuggingFace", True),
    (r"nomic-embed-text-v\d+(?:\.\d+)?", "Nomic", False),
    (r"jina-embeddings-v\d+[\w.-]*", "Jina", False),  # ...-v2-base-code
    # OpenAI speech / moderation / completion generations
    (r"tts-\d[\w.-]*", "OpenAI", False),                  # tts-1, tts-1-hd
    (r"omni-moderation[\w.-]*", "OpenAI", False),         # omni-moderation-latest
    (r"text-moderation[\w.-]*", "OpenAI", False),
    (r"(?:babbage|davinci)-\d{3}", "OpenAI", False),      # babbage-002, davinci-002
    # Alibaba Qwen (qwen2-vl-2b-instruct, qwen3-4b, qwen2.5-0.5b-instruct)
    (rf"qwen[\d.]+(?:-vl|-coder|-math|-audio)?{_TAIL}", "Alibaba", False),
    # Voyage AI embeddings (voyage-3-large, voyage-code-2)
    (
        r"voyage-(?:[0-9]|code|large|lite|finance|law|multilingual)[\w.-]*",
        "Voyage",
        False,
    ),
    # HKUNLP Instructor + SpanMarker NER embedding/encoder models
    (r"instructor-(?:xl|large|base)[\w.-]*", "HKUNLP", True),
    (r"span-marker-[\w.-]+", "HuggingFace", True),
]
_FAMILIES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(_B.format((_ORG + pat) if org else pat), re.I), vendor)
    for pat, vendor, org in _RAW
]


def _matches(text: str):
    """``(start, name, vendor)`` for every model reference in ``text``: Bedrock ids
    first, then the family patterns in order. A span one pattern claimed is not
    matched again by a later one, so a Bedrock id never also yields its bare
    ``claude-…`` tail."""
    claimed: list[tuple[int, int]] = []
    for m in _BEDROCK_RE.finditer(text):
        prefix = m.group("provider").split(".", 1)[0].lower()
        claimed.append(m.span())
        yield m.start(), m.group(0), _BEDROCK_PROVIDERS[prefix][1]
    for pattern, vendor in _FAMILIES:
        for m in pattern.finditer(text):
            start, end = m.span()
            if any(a < end and start < b for a, b in claimed):
                continue
            yield start, m.group(0), vendor


def find_model_refs(text: str) -> dict[str, str]:
    """Map every model reference in ``text`` to its vendor (first match wins).

    Keys preserve the source casing of the model id; de-dup is case-insensitive
    (the first occurrence's casing is kept). Returns ``{}`` for no matches.
    """
    found: dict[str, str] = {}
    lowered_seen: set[str] = set()
    for _start, name, vendor in _matches(text):
        low = name.lower()
        if low not in lowered_seen:
            lowered_seen.add(low)
            found[name] = vendor
    return found


# ── usage vs catalog disambiguation ──────────────────────────────────────────
# A model NAME in a provider's *supported-model registry* (a list/dict/enum the
# library ships) is NOT the same as a model the code actually USES. The first is
# CATALOG over-counting (most of chroma's "46"); the second is real USAGE. We
# classify each reference by the SYNTAX around it.

# The reference is being loaded/called -> USAGE.
_USAGE_CONTEXT = re.compile(
    r"(?:"
    r"\bmodel(?:_name|_id|_path)?\s*[=:]\s*['\"]|"  # model="…" / model_name: "…"
    r"from_pretrained\s*\(\s*['\"]|"  # AutoModel.from_pretrained("…")
    r"SentenceTransformer\s*\(\s*['\"]|"  # SentenceTransformer("…")
    r"\bpipeline\s*\(|"  # transformers pipeline(...)
    r"EmbeddingFunction\s*\(|OllamaEmbeddingFunction\s*\(|"
    r"\.(?:chat|completions|complete|embed|generate|invoke|converse)\s*\(|"
    r"\b(?:MODEL|LLM|EMBED(?:DING)?_MODEL|GEN_MODEL|CLAUDE_MODEL)\b\s*[:=]\s*['\"]|"
    # a *_model setting / field with the model as its value or default:
    #   judge_model: str = Field(default="gpt-4o")   embedding_model = "bge-m3"
    r"\b[a-z_]*_model(?:_name|_id)?\s*(?::\s*[\w\[\]|. ]+)?=\s*"
    r"(?:Field\s*\(\s*(?:default\s*=\s*)?)?['\"]|"
    # an environment / .env setting: OPENAI_MODEL=gpt-4o, ROUTER_JUDGE_MODEL="…"
    r"^\s*(?:export\s+)?[A-Z][A-Z0-9_]*_MODEL(?:_NAME|_ID)?\s*=\s*['\"]?|"
    # the default of an environment lookup: os.getenv("OPENAI_MODEL", "o3-mini"),
    # os.environ.get("M", "…"), process.env.MODEL || "…" / ?? "…"
    r"\b(?:getenv|environ\.get|env\.get)\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"]|"
    r"process\.env\.\w+\s*(?:\|\||\?\?)\s*['\"]"
    r")",
    re.IGNORECASE,
)
# A model as the value of a ``model`` key: a request body or payload dict
# (``json={"model": "gpt-4.1"}``, ``"model": "…",``) or an unquoted YAML value
# (``model: claude-3-5-sonnet-20241022``). Matched on the text right BEFORE the
# reference, so the reference is the key's value itself (a docstring such as
# ``model_name: Model name (e.g. "gpt-4")`` is not). Usage, unless the line or the
# line before reads as a catalog (a pricing / supported-models table also has
# ``"model"`` keys).
_KEYED_USAGE = re.compile(
    r"""(?:['"]model(?:_name|_id)?['"]\s*:\s*['"](?:[\w.-]+/)?|"""
    r"""^\s*-?\s*model(?:_name|_id)?\s*:\s*['"]?(?:[\w.-]+/)?)$""",
    re.IGNORECASE,
)
# A model id in a REST path: /v1beta/models/gemini-1.5-flash:generateContent,
# Bedrock /model/<id>/invoke.
_URL_PATH = re.compile(r"/models?/$", re.IGNORECASE)
# The reference sits in a registry / catalog / docs / comment -> CATALOG.
_CATALOG_HINT = re.compile(
    r"(?:supported|available|allowed|known|valid|registry|catalog|_models\b|"
    r"models\s*[:=]\s*[\[{(]|model_list|choices|enum|mapping|alias)",
    re.IGNORECASE,
)
# An environment lookup split over lines (black style): ``os.getenv(`` ends the line
# before, ``"NAME", "<model>"`` starts this one.
_ENV_CALL_OPEN = re.compile(r"\b(?:getenv|environ\.get|env\.get)\s*\(\s*$")
_ENV_DEFAULT_ARG = re.compile(r"""^\s*['"][^'"]*['"]\s*,\s*['"]""")
_COMMENT = re.compile(r"^\s*(?:#|//|\*|/\*|-{1,}|\|)")  # comment / md table / list row


def _classify(line: str, prev: str, before: str = "") -> str:
    """usage | catalog for a reference, from its line (+ the preceding line);
    ``before`` is the text of the line before the reference."""
    if _USAGE_CONTEXT.search(line) or (
        _ENV_CALL_OPEN.search(prev) and _ENV_DEFAULT_ARG.match(line)
    ):
        return "usage"
    if _COMMENT.match(line) or _CATALOG_HINT.search(line) or _CATALOG_HINT.search(prev):
        return "catalog"
    if _KEYED_USAGE.search(before) or _URL_PATH.search(before):
        return "usage"
    # A line that is just a quoted string in a collection ("foo", / 'foo':) with
    # no call around it reads as a catalog entry; default ambiguous -> catalog,
    # since catalog over-counting is the documented failure mode.
    if re.match(r"""^\s*['"][^'"]+['"]\s*[,:\]})]?\s*$""", line):
        return "catalog"
    return "catalog"


def find_model_refs_ctx(text: str) -> dict[str, tuple[str, str]]:
    """Map each model reference to ``(vendor, reference_type)``.

    ``reference_type`` is ``"usage"`` (the code loads/calls the model) or
    ``"catalog"`` (the name appears in a supported-model list/registry/doc). A
    name seen in BOTH contexts is promoted to ``"usage"`` (real use dominates).
    De-dup is case-insensitive; first occurrence's casing is kept.
    """
    lines = text.splitlines()
    # Map each match to the line it occurs on via cumulative offsets.
    offsets: list[int] = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1  # +1 for the stripped newline

    def line_index(idx: int) -> int:
        # binary-ish: last offset <= idx
        lo, hi = 0, len(offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if offsets[mid] <= idx:
                lo = mid
            else:
                hi = mid - 1
        return lo

    found: dict[str, tuple[str, str]] = {}
    casing: dict[str, str] = {}
    for pos, name, vendor in _matches(text):
        low = name.lower()
        li = line_index(pos) if offsets else 0
        line = lines[li] if li < len(lines) else ""
        prev = lines[li - 1] if li > 0 else ""
        start = offsets[li] if offsets else 0
        rtype = _classify(line, prev, text[start:pos])
        casing.setdefault(low, name)
        if low not in found:
            found[low] = (vendor, rtype)
        elif rtype == "usage" and found[low][1] != "usage":
            found[low] = (found[low][0], "usage")  # promote to usage
    return {casing[low]: v for low, v in found.items()}


__all__ = ["find_model_refs", "find_model_refs_ctx", "parse_bedrock_id"]
