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

# (family regex on the tag's name part, publisher, licence or None, task)
_FAMILIES: tuple[tuple[str, str | None, str | None, str], ...] = (
    # ollama.com/library/mistral "Apache license"; HF mistralai/Mistral-7B-* apache-2.0
    (r"mistral(?:-nemo|-small[\d.]*)?", "Mistral", "Apache-2.0", "chat/completion"),
    # HF mistralai/Mixtral-8x7B-Instruct-v0.1 apache-2.0
    (r"mixtral", "Mistral", "Apache-2.0", "chat/completion"),
    # ollama.com/library/phi3 "MIT license"; HF microsoft/phi-4 mit
    (r"phi3(?:\.5)?|phi4(?:-mini|-reasoning)?", "Microsoft", "MIT", "chat/completion"),
    # ollama.com/library/deepseek-r1 "MIT License"; HF deepseek-ai/DeepSeek-R1 mit
    (r"deepseek-r1", "DeepSeek", "MIT", "chat/completion"),
    # HF meta-llama/CodeLlama-7b-hf license llama2
    (r"codellama", "Meta", "LicenseRef-llama2-community", "code generation"),
    (r"llama[234](?:\.\d+)?(?:-vision)?", "Meta", "LicenseRef-llama-community",
     "chat/completion"),
    # ollama.com/library/gpt-oss "Apache 2.0"; HF openai/gpt-oss-20b apache-2.0
    (r"gpt-oss", "OpenAI", "Apache-2.0", "chat/completion"),
    # HF CohereLabs/c4ai-command-r-v01 cc-by-nc-4.0
    (r"command-r(?:-plus|7b)?", "Cohere", "CC-BY-NC-4.0", "chat/completion"),
    # HF google/gemma-2-9b license gemma
    (r"(?:code)?gemma\d*(?:n)?", "Google", "LicenseRef-Gemma-Terms-of-Use",
     "chat/completion"),
    # HF nomic-ai/nomic-embed-text-v1.5 apache-2.0
    (r"nomic-embed-text", "Nomic", "Apache-2.0", "text-embedding"),
    # HF mixedbread-ai/mxbai-embed-large-v1 apache-2.0
    (r"mxbai-embed-large", "mixedbread", "Apache-2.0", "text-embedding"),
    # qwen2.5: Apache-2.0 for most sizes, the Qwen licence for 3B / 72B (ollama.com
    # lists both): not stated
    (r"qwen\d*(?:\.\d+)?(?:-coder|-vl)?", "Alibaba", None, "chat/completion"),
    # llava: v1.6-mistral apache-2.0, v1.5 no licence on its card: not stated
    (r"llava(?:-llama3|-phi3)?", "LLaVA", None, "image-text-to-text"),
)
_FAMILY_RES = [(re.compile(rf"{pat}", re.IGNORECASE), v, lic, task)
               for pat, v, lic, task in _FAMILIES]

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
    """``(publisher, licence, task)`` of an Ollama tag (``(None, None, …)`` for a
    family this table does not know)."""
    name = tag.split(":", 1)[0].split("/")[-1]
    for pattern, vendor, licence, task in _FAMILY_RES:
        if pattern.fullmatch(name):
            return vendor, licence, task
    return None, None, "chat/completion"


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


__all__ = ["find_ollama_tags", "is_cloud_tag", "ollama_family"]
