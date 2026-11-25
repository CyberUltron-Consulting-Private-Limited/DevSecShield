"""Ollama model tags (``mistral:7b``, ``phi4``, ``gpt-oss:120b-cloud``) in Ollama calls.

A model named inside an Ollama call is an Ollama library tag ``name[:tag]``: open
weights the Ollama server pulls and runs, never the maker's hosted product
(``gpt-oss:20b`` in ``ollama.chat`` is not the OpenAI API; review 6062066749 of #498,
M2). A tag ending in ``-cloud`` runs on Ollama's hosted service (ollama.com).

The calls read: the ``ollama`` module functions (``ollama.chat(model=…)``), a client
variable built from ``ollama.Client`` / ``AsyncClient`` / JS ``new Ollama``,
LangChain's ``ChatOllama`` / ``OllamaLLM`` / ``OllamaEmbeddings``, and a JSON body
``{"model": …}`` in a file that posts to the Ollama REST API (``/api/chat``,
``/api/generate``, ``/api/embed``).

Licences are the open-weights licences of the families Ollama serves, as published
on the Ollama library page or the upstream Hugging Face model card (read on 25 Nov
2026). A family whose licence depends on the size or the version (qwen2.5, llava) is
not stated (NOASSERTION).
"""

from __future__ import annotations

import re

from aibom.scan.parsers.code_text import call_arguments, mask

# Licences per TAG, not per family: a family's sizes / versions can carry different
# licences (review 6063080163 of #498, R4-M1: mistral-small:22b is 2409 under the
# Mistral Research License, only :24b is Apache-2.0). Each rule cites its source, read
# on 25 Nov 2026: the Ollama library page (ollama.com/library/<name>[/tags]) and the
# upstream Hugging Face model card (``huggingface.co/api/models/<id>`` cardData
# license / license_name). A tag no rule resolves, or a bare / ``latest`` alias whose
# target moves, is NOASSERTION.
#
# (name regex, tag regex or None for any tag, publisher, licence or None, task)
_CHAT = "chat/completion"
_RULES: tuple[tuple[str, str | None, str | None, str | None, str], ...] = (
    # ollama.com/library/mistral: Mistral 7B v0.3 for every tag ("Apache license");
    # HF mistralai/Mistral-7B-Instruct-v0.3 apache-2.0
    (r"mistral", None, "Mistral", "Apache-2.0", _CHAT),
    # HF mistralai/Mistral-Nemo-Instruct-2407 apache-2.0
    (r"mistral-nemo", None, "Mistral", "Apache-2.0", _CHAT),
    # ollama.com/library/mistral-small/tags: 22b = 22b-instruct-2409; HF
    # mistralai/Mistral-Small-Instruct-2409 license_name mrl
    (r"mistral-small", r"22b.*|.*2409.*", "Mistral",
     "LicenseRef-Mistral-Research-License", _CHAT),
    # 24b = 24b-instruct-2501; HF Mistral-Small-24B-Instruct-2501, -3.1-24B-2503,
    # -3.2-24B-2506 apache-2.0
    (r"mistral-small", r"24b.*|.*25(?:01|03|06).*", "Mistral", "Apache-2.0", _CHAT),
    (r"mistral-small3\.[12]", None, "Mistral", "Apache-2.0", _CHAT),
    (r"mistral-small", None, "Mistral", None, _CHAT),  # bare / latest: moves
    # HF mistralai/Mixtral-8x7B-Instruct-v0.1 apache-2.0
    (r"mixtral", None, "Mistral", "Apache-2.0", _CHAT),
    # ollama.com/library/phi3 "MIT license"; HF Phi-3-mini-4k, Phi-3.5-mini, phi-4,
    # Phi-4-mini-instruct mit
    # HF microsoft/Phi-4-reasoning mit (restored: review 6063929550 m2)
    (r"phi3(?:\.5)?|phi4(?:-mini|-reasoning|-mini-reasoning)?", None, "Microsoft",
     "MIT",
     _CHAT),
    # ollama.com/library/deepseek-r1/tags: 671b = R1 (HF DeepSeek-R1 mit); 8b =
    # 8b-0528-qwen3 (HF DeepSeek-R1-0528-Qwen3-8B mit)
    (r"deepseek-r1", r"(?:671b|8b)(?:-.*)?", "DeepSeek", "MIT", _CHAT),
    # 1.5b / 7b / 14b / 32b = Qwen distills: the Ollama page "derived from Qwen-2.5
    # series … originally licensed under Apache 2.0", with DeepSeek's MIT
    (r"deepseek-r1", r"(?:1\.5b|7b|14b|32b)(?:-.*)?", "DeepSeek", "MIT AND Apache-2.0",
     _CHAT),
    # 70b = Llama distill: the Ollama page "derived from Llama3.3-70B-Instruct …
    # llama3.3 license"
    (r"deepseek-r1", r"70b(?:-.*)?", "DeepSeek",
     "MIT AND LicenseRef-llama3.3-community", _CHAT),
    (r"deepseek-r1", None, "DeepSeek", None, _CHAT),  # bare / latest: moves
    # HF meta-llama/CodeLlama-7b-hf license llama2
    (r"codellama", None, "Meta", "LicenseRef-llama2-community", "code generation"),
    # HF meta-llama/Llama-2-7b-hf llama2; Meta-Llama-3-8B llama3; Llama-3.1-8B
    # llama3.1; Llama-3.2-3B llama3.2; Llama-3.3-70B llama3.3
    (r"llama2", None, "Meta", "LicenseRef-llama2-community", _CHAT),
    (r"llama3", None, "Meta", "LicenseRef-llama3-community", _CHAT),
    (r"llama3\.1", None, "Meta", "LicenseRef-llama3.1-community", _CHAT),
    (r"llama3\.2(?:-vision)?", None, "Meta", "LicenseRef-llama3.2-community", _CHAT),
    (r"llama3\.3", None, "Meta", "LicenseRef-llama3.3-community", _CHAT),
    # ollama.com/library/gpt-oss "Apache 2.0"; HF openai/gpt-oss-20b apache-2.0
    (r"gpt-oss", None, "OpenAI", "Apache-2.0", _CHAT),
    # HF CohereLabs/c4ai-command-r-v01, -plus, -r7b-12-2024 cc-by-nc-4.0
    (r"command-r(?:-plus|7b)?", None, "Cohere", "CC-BY-NC-4.0", _CHAT),
    # HF google/gemma-2-9b, gemma-3-4b-it, codegemma-7b-it, gemma-3n-E4B-it license
    # gemma (gemma3n restored: review 6063929550 m2)
    (r"(?:code)?gemma\d*n?", None, "Google", "LicenseRef-Gemma-Terms-of-Use", _CHAT),
    # HF nomic-ai/nomic-embed-text-v1.5, mixedbread-ai/mxbai-embed-large-v1 apache-2.0
    (r"nomic-embed-text", None, "Nomic", "Apache-2.0", "text-embedding"),
    (r"mxbai-embed-large", None, "mixedbread", "Apache-2.0", "text-embedding"),
    # qwen2.5: the Ollama page "3B and 72B models are under the Qwen license"; HF
    # Qwen2.5-3B-Instruct license_name qwen-research, -72B qwen; 0.5B / 1.5B / 7B /
    # 14B / 32B apache-2.0
    (r"qwen2\.5", r"3b(?:-.*)?", "Alibaba", "LicenseRef-Qwen-Research-License", _CHAT),
    (r"qwen2\.5", r"72b(?:-.*)?", "Alibaba", "LicenseRef-Qwen-License", _CHAT),
    (r"qwen2\.5", r"(?:0\.5b|1\.5b|7b|14b|32b)(?:-.*)?", "Alibaba", "Apache-2.0",
     _CHAT),
    # qwen2.5-coder: HF Qwen2.5-Coder-3B-Instruct license_name qwen-research; 0.5B /
    # 1.5B / 7B / 14B / 32B apache-2.0 (review 6063929550 m2)
    (r"qwen2\.5-coder", r"3b(?:-.*)?", "Alibaba", "LicenseRef-Qwen-Research-License",
     "code generation"),
    (r"qwen2\.5-coder", r"(?:0\.5b|1\.5b|7b|14b|32b)(?:-.*)?", "Alibaba", "Apache-2.0",
     "code generation"),
    # Note: the rules match the WHOLE name part, so ``qwen2.5-coder`` / ``qwen2.5-vl``
    # never fall to the plain ``qwen2.5`` rules; an unlisted variant or the bare alias
    # reaches the NOASSERTION catch-alls below.
    (r"qwen2\.5(?:-coder|-vl)?", None, "Alibaba", None, _CHAT),  # bare / latest …
    # HF Qwen/Qwen3-8B, Qwen3-235B-A22B apache-2.0 (every Qwen3 size)
    (r"qwen3", None, "Alibaba", "Apache-2.0", _CHAT),
    # HF ibm-granite/granite-3.1-8b-instruct, -3b-a800m-instruct apache-2.0
    (r"granite3\.1-(?:dense|moe)", None, "IBM", "Apache-2.0", _CHAT),
    # HF HuggingFaceTB/SmolLM2-1.7B-Instruct, -135M-Instruct apache-2.0
    (r"smollm2", None, "Hugging Face", "Apache-2.0", _CHAT),
    # llava: 7b is v1.6-mistral (apache-2.0), 13b / 34b are built on Vicuna / Yi:
    # not stated
    (r"llava(?:-llama3|-phi3)?", None, "LLaVA", None, "image-text-to-text"),
    (r"qwen\d*(?:\.\d+)?(?:-coder|-vl)?", None, "Alibaba", None, _CHAT),
)
_RULE_RES = [
    (re.compile(name, re.IGNORECASE), re.compile(tag, re.IGNORECASE) if tag else None,
     vendor, licence, task)
    for name, tag, vendor, licence, task in _RULES
]

_TAG = re.compile(r"^[a-z0-9][\w.-]*(?::[\w.-]+)?$", re.IGNORECASE)
_MODEL_LITERAL = re.compile(r"""\bmodel['"]?\s*[=:]\s*['"](?P<tag>[^'"\s]+)['"]""")
_OLLAMA_IMPORT = re.compile(
    r"""(?:^|\n)\s*(?:import\s+(?:[\w.]+\s*,\s*)*ollama\b|from\s+ollama\b)|"""
    r"""from\s+['"]ollama(?:/browser)?['"]|require\(\s*['"]ollama['"]\s*\)"""
)
_LANGCHAIN_OLLAMA_IMPORT = re.compile(
    r"""langchain_ollama|langchain_community|@langchain/ollama|langchain/llms/ollama"""
)
_MODULE_CALL = re.compile(
    r"\bollama\.(?:chat|generate|embed|embeddings|pull|show)\s*\("
)
_CLIENT_VAR = re.compile(
    r"(?P<var>\b[A-Za-z_]\w*)\s*=\s*(?:await\s+)?(?:new\s+)?"
    r"(?:ollama\.)?(?:Async)?(?:Client|Ollama)\s*\("
)
_LANGCHAIN_CALL = re.compile(
    r"(?<!\w)(?:new\s+)?(?:ChatOllama|OllamaLLM|OllamaEmbeddings|Ollama)\s*\("
)
_REST = re.compile(r"/api/(?:chat|generate|embed|embeddings)\b")
_LITELLM_ROUTE = re.compile(
    r"""['"]ollama(?:_chat)?/(?P<tag>[a-z0-9][\w.-]*(?::[\w.-]+)?)['"]""",
    re.IGNORECASE,
)
_YAML_ROUTE = re.compile(
    r"""(?im)^[ \t]*(?:-[ \t]+)?model:[ \t]*['"]?ollama(?:_chat)?/"""
    r"""(?P<tag>[a-z0-9][\w.-]*(?::[\w.-]+)?)['"]?[ \t]*(?:#.*)?$"""
)
_JSON_MODEL = re.compile(r"""['"]model['"]\s*:\s*['"](?P<tag>[^'"\s]+)['"]""")


def ollama_family(tag: str) -> tuple[str | None, str | None, str]:
    """``(publisher, licence, task)`` of an Ollama tag ``name[:tag]``, resolved per
    tag (``(None, None, …)`` for a family the table does not know)."""
    name, _, variant = tag.partition(":")
    name = name.split("/")[-1]
    variant = "" if variant.lower() in ("", "latest") else variant
    for name_re, tag_re, vendor, licence, task in _RULE_RES:
        if not name_re.fullmatch(name):
            continue
        if tag_re is not None and not (variant and tag_re.fullmatch(variant)):
            continue
        return vendor, licence, task
    return None, None, _CHAT


def is_ollama_family(name: str) -> bool:
    """Whether ``name`` (before the ``:``) is a family the Ollama library serves."""
    return any(n.fullmatch(name) for n, *_r in _RULE_RES)


def is_cloud_tag(tag: str) -> bool:
    """Ollama's hosted models carry a ``-cloud`` tag (``gpt-oss:120b-cloud``)."""
    return tag.lower().endswith("-cloud")


def find_ollama_tags(text: str, lang: str = "py") -> list[str]:
    """The model tags the file passes to Ollama, in order of first appearance."""
    code, bare = mask(text, lang)
    opens: list[int] = []
    if _OLLAMA_IMPORT.search(code):
        opens += [m.end() - 1 for m in _MODULE_CALL.finditer(bare)]
        for var in {m.group("var") for m in _CLIENT_VAR.finditer(bare)}:
            call = re.compile(
                rf"\b{re.escape(var)}\.(?:chat|generate|embed|embeddings)\s*\("
            )
            opens += [m.end() - 1 for m in call.finditer(bare)]
    if _LANGCHAIN_OLLAMA_IMPORT.search(code):
        opens += [m.end() - 1 for m in _LANGCHAIN_CALL.finditer(bare)]
    found: list[str] = []
    for paren in sorted(set(opens)):
        args = call_arguments(bare, paren)
        if args is None:
            continue
        span = code[paren + 1 : paren + 1 + len(args)]
        # comments are blanked in ``code``: a commented-out model is never found
        found += [m.group("tag") for m in _MODEL_LITERAL.finditer(span)]
    if _REST.search(code):
        found += [m.group("tag") for m in _JSON_MODEL.finditer(code)]
    # LiteLLM's Ollama provider: model="ollama/llama3:8b" / "ollama_chat/…"
    # (review 6063929550 of #498, m5)
    found += [m.group("tag") for m in _LITELLM_ROUTE.finditer(code)]
    # a LiteLLM proxy config.yaml ``model: ollama/phi3:mini`` (review 6065595627 of
    # #498, m2)
    found += [m.group("tag") for m in _YAML_ROUTE.finditer(code)]
    out: list[str] = []
    for tag in found:
        if _TAG.match(tag) and tag.lower() not in {t.lower() for t in out}:
            out.append(tag)
    return out


_TAG_LITERAL = re.compile(r"""['"](?P<tag>[a-z][\w.-]*:[\w.-]+)['"]""", re.IGNORECASE)
# The tag part of a real Ollama tag: a size (8b, 0.5b, 135m, 8x7b, e4b), latest, a
# known variant word, optionally followed by more -/_/. parts (8b-instruct-q4_K_M,
# 120b-cloud). ``llama3:hits`` is no tag (review 6063929550 of #498, R5-M1).
_TAG_PART = re.compile(
    r"^(?:\d+(?:\.\d+)?[bmk]|\d+x\d+(?:\.\d+)?b|e\d+b|a\d+(?:\.\d+)?b|latest|mini|"
    r"small|medium|large|instruct|chat|text|vision|code|cloud|fp16|q\d\w*)"
    r"(?:[-_.][\w.]+)*$",
    re.IGNORECASE,
)
# What tells the scan the repository uses Ollama at all: real code or deployment use
# only (review 6065595627 of #498, R6-M1). In application source: the SDK imported
# (``import ollama``, ``from 'ollama'``), a LangChain Ollama class or package, a
# LiteLLM ``ollama/`` route, an Ollama URL (``:11434``) or a REST call to the API
# (``/api/chat`` in a file that names Ollama outside a plain string). In deployment
# files: the ``ollama/ollama`` image or a LiteLLM proxy ``ollama/`` route. The caller
# reads only application files (no docs, tests, examples or env templates) and adds
# OLLAMA_HOST set in the application's real environment. A README line, a test's
# import, ``PROVIDERS = ["openai", "ollama"]`` or a manifest dependency never counted
# on its own.
_EV_LANGCHAIN = re.compile(
    r"\b(?:ChatOllama|OllamaLLM|OllamaEmbeddings)\b|\blangchain[_-]ollama\b|"
    r"@langchain/ollama|langchain_community\.(?:llms|chat_models|embeddings)\.ollama"
)
_EV_ROUTE = re.compile(r"""['"`]ollama(?:_chat)?/[\w.:-]+['"`]""")
_EV_URL = re.compile(r"""['"`]https?://[^'"`\s]*:11434\b""")
_EV_REST = re.compile(r"/api/(?:chat|generate|embed|embeddings|tags|pull|show)\b")
_EV_IMAGE = re.compile(
    r"""(?im)^\s*(?:-\s*)?image:\s*['"]?(?:[\w.-]+(?::\d+)?/)?ollama/ollama\b|"""
    r"""^\s*FROM\s+(?:--\S+\s+)*(?:[\w.-]+(?::\d+)?/)?ollama/ollama\b"""
)
_EV_YAML_ROUTE = re.compile(r"""(?m)^\s*(?:-\s*)?model:\s*['"]?ollama(?:_chat)?/""")


def ollama_code_evidence(text: str, lang: str = "py") -> bool:
    """Whether application source uses Ollama (see the comment above)."""
    code, bare = mask(text, lang)
    if lang == "py":
        for a, b in _docstring_spans(code):  # prose, not code
            code = code[:a] + " " * (b - a) + code[b:]
            bare = bare[:a] + " " * (b - a) + bare[b:]
    if (_OLLAMA_IMPORT.search(code) or _EV_LANGCHAIN.search(bare)
            or _EV_ROUTE.search(code) or _EV_URL.search(code)):
        return True
    # a REST call: the API path in a file that names Ollama in code (an identifier
    # such as OLLAMA_URL, the OLLAMA_HOST variable or the port), not in a plain string
    return bool(_EV_REST.search(code)) and bool(
        re.search(r"ollama", bare, re.IGNORECASE) or "OLLAMA_HOST" in code
        or ":11434" in code
    )


def ollama_deploy_evidence(text: str) -> bool:
    """Whether a compose / Kubernetes / Dockerfile / LiteLLM proxy file runs or routes
    to Ollama: the ``ollama/ollama`` image or an ``ollama/`` model route."""
    return bool(_EV_IMAGE.search(text) or _EV_YAML_ROUTE.search(text))


# a key / cache / log argument (``r.set("mistral:7b", 1)``) is never a model
_KEY_CALL = re.compile(
    r"\.(?:set|get|setex|setnx|incr|incrby|decr|hget|hset|hincrby|delete|expire|exists|"
    r"lpush|rpush|sadd|zadd|zincrby|pop|getdel|cache|memoize)\s*\(\s*$"
)
_ASSIGN_TARGET = re.compile(r"(?P<name>[A-Za-z_][\w.]*)\s*(?::[^=\n]+)?=\s*$")
_MODELISH = re.compile(r"model|llm|chat|embed|gen|complet|default|ollama|tag", re.I)


def valid_tag(tag: str) -> bool:
    """``family:part`` with a family Ollama serves and a real tag part."""
    name, _, part = tag.partition(":")
    return is_ollama_family(name) and bool(_TAG_PART.match(part))


def _docstring_spans(text: str) -> list[tuple[int, int]]:
    return [m.span() for m in re.finditer(r'("""|\'\'\')(?:.|\n)*?\1', text)]


def _enclosing_open(bare: str, pos: int) -> int | None:
    """The unmatched ``[`` / ``(`` / ``{`` before ``pos`` in masked text, if any."""
    depth = 0
    for k in range(pos - 1, max(-1, pos - 4000), -1):
        ch = bare[k]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                return k
            depth -= 1
    return None


def find_ollama_tag_literals(
    text: str, lang: str | None = "py", config: bool = False
) -> list[tuple[str, str]]:
    """``[(tag, "usage" | "catalog")]``: string literals with Ollama tag syntax
    (a family Ollama serves and a real tag part) outside comments and docstrings.

    Usage: a value a model-like name is assigned (``PROD_MODEL = "llama3.1:70b"``),
    a lone call argument (``ask("mistral:7b")``) or a ``"model": …`` value. A
    catalogue: an element of a list / tuple / set holding several tags (a picker),
    a dict key (a benchmark table), or a literal assigned to another name. A key
    argument (``r.set("mistral:7b", 1)``) is never recorded (review 6063929550 of
    #498, R5-M1). The caller treats usage as a model in use only when the repository
    has Ollama evidence."""
    code, bare = mask(text, lang or "py") if lang else (text, text)
    docs = _docstring_spans(text) if lang == "py" else []
    out: dict[str, tuple[str, str]] = {}
    for m in _TAG_LITERAL.finditer(code):
        tag = m.group("tag")
        if "://" in tag or not valid_tag(tag):
            continue
        start, end = m.span()
        if any(a <= start < b for a, b in docs):
            continue  # prose in a docstring
        before = code[max(0, start - 200) : start]
        after = code[end : end + 40]
        if _KEY_CALL.search(before):
            continue  # a cache / log / store key
        kind = "usage"
        model_key = re.search(r"['\"]model['\"]\s*:\s*$", before)
        if re.match(r"\s*:", after) and not model_key:
            kind = "catalog"  # a dict key (a benchmark / price table)
        else:
            open_at = _enclosing_open(bare, start)
            if open_at is not None:
                opener = bare[open_at]
                head = bare[max(0, open_at - 60) : open_at]
                is_call = opener == "(" and re.search(r"[\w)\]]\s*$", head)
                if not is_call:
                    close = {"[": "]", "(": ")", "{": "}"}[opener]
                    depth, k = 0, open_at
                    while k < len(bare):
                        if bare[k] in "([{":
                            depth += 1
                        elif bare[k] in ")]}":
                            depth -= 1
                            if depth == 0:
                                break
                        k += 1
                    inner = code[open_at + 1 : k]
                    if bare[k : k + 1] == close and len(
                        [t for t in _TAG_LITERAL.findall(inner) if valid_tag(t)]
                    ) >= 2 and not re.search(r"['\"]model['\"]\s*:\s*$", before):
                        kind = "catalog"  # several tags in one collection: a picker
            if kind == "usage":
                target = _ASSIGN_TARGET.search(before)
                if target and not _MODELISH.search(target.group("name")):
                    kind = "catalog"  # ``log = "phi3:mini"``: not a model setting
        _keep(out, tag, kind)
    if config:
        # an unquoted YAML / .env / TOML value: ``model: llama3.1:8b`` is typed as
        # ``{"model": "llama3.1:8b"}`` in JSON (review 6063929550 of #498, m5)
        for m in _CONFIG_VALUE.finditer(text):
            tag = m.group("tag")
            if not valid_tag(tag):
                continue
            key = m.group("key")
            kind = "usage" if key and _MODELISH.search(key) else "catalog"
            _keep(out, tag, kind)
    return list(out.values())


# ``model: llama3.1:8b`` / ``OLLAMA_MODEL=mistral:7b`` / ``- phi3:mini`` (a list item)
_CONFIG_VALUE = re.compile(
    r"(?m)^[ \t]*(?:-[ \t]+)?(?:(?P<key>[A-Za-z_][\w.-]*)[ \t]*[:=][ \t]*)?"
    r"(?P<tag>[a-z][\w.-]*:[\w.-]+)[ \t]*(?:#.*)?$",
    re.IGNORECASE,
)


def _keep(out: dict[str, tuple[str, str]], tag: str, kind: str) -> None:
    key = tag.lower()
    if key not in out:
        out[key] = (tag, kind)
    elif kind == "usage":
        out[key] = (out[key][0], "usage")  # usage anywhere wins


__all__ = [
    "find_ollama_tag_literals",
    "ollama_code_evidence",
    "ollama_deploy_evidence",
    "valid_tag",
    "find_ollama_tags",
    "is_cloud_tag",
    "is_ollama_family",
    "ollama_family",
]
