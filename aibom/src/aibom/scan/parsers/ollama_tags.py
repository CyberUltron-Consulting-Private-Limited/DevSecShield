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
    (r"phi3(?:\.5)?|phi4(?:-mini)?", None, "Microsoft", "MIT", _CHAT),
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
    # HF google/gemma-2-9b, gemma-3-4b-it, codegemma-7b-it license gemma
    (r"(?:code)?gemma\d*", None, "Google", "LicenseRef-Gemma-Terms-of-Use", _CHAT),
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
    (r"qwen2\.5", None, "Alibaba", None, _CHAT),  # bare / latest / -coder …
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
    out: list[str] = []
    for tag in found:
        if _TAG.match(tag) and tag.lower() not in {t.lower() for t in out}:
            out.append(tag)
    return out


_TAG_LITERAL = re.compile(r"""['"](?P<tag>[a-z][\w.-]*:[\w.-]+)['"]""", re.IGNORECASE)


def find_ollama_tag_literals(text: str, lang: str = "py") -> list[str]:
    """String literals with Ollama tag syntax (``family:size``, the family one the
    Ollama library serves) anywhere in source code, outside comments: the model a
    constant names (``PROD_MODEL = "llama3.1:70b"``) or a wrapper is called with
    (``ask("mistral:7b")``) in another file than the Ollama call (review 6063080163
    of #498, R4-M3). ``name:tag`` is Ollama syntax: such a model is self-hosted open
    weights, never its maker's hosted product."""
    code, _bare = mask(text, lang)
    out: list[str] = []
    for m in _TAG_LITERAL.finditer(code):
        tag = m.group("tag")
        if "://" in tag or not is_ollama_family(tag.split(":", 1)[0]):
            continue
        if tag.lower() not in {t.lower() for t in out}:
            out.append(tag)
    return out


__all__ = [
    "find_ollama_tag_literals",
    "find_ollama_tags",
    "is_cloud_tag",
    "is_ollama_family",
    "ollama_family",
]
