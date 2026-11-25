"""Scanner: inline model REFERENCES in source -> model components.

Walks the repo's code / config / doc files and recognizes model identifiers via
the known-model dictionary (:mod:`aibom.scan.parsers.model_refs`) — the half of
AI inventory that lives in application code (``model="gpt-4o"``) rather than in a
model card. Each distinct reference becomes a ``model`` component (kind=model)
with its vendor as publisher.

Deterministic: known-model KB only. No network / no LLM.

Bounded for big repos: only an extension allowlist is read, files over
``_MAX_BYTES`` are skipped, and build/vendor/VCS directories are pruned.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from aibom.model.component import ModelCard, ModelComponent, PedigreeAncestor
from aibom.scan.parsers import model_kb
from aibom.scan.parsers.code_imports import notebook_text
from aibom.scan.parsers.code_text import call_arguments, language_of, mask
from aibom.scan.parsers.licenses import license_choice
from aibom.scan.parsers.model_lookup import ProjectLiterals
from aibom.scan.parsers.model_refs import (
    find_hf_repo_ids,
    find_model_refs_ctx,
    hf_purl,
    parse_bedrock_id,
)
from aibom.scan.parsers.ollama_tags import (
    find_ollama_tag_literals,
    find_ollama_tags,
    is_cloud_tag,
    ollama_code_evidence,
    ollama_deploy_evidence,
    ollama_family,
    valid_tag,
)
from aibom.scan.path_roles import (
    evidence_rank,
    is_doc_path,
    is_env_file,
    is_env_template,
    is_example_path,
    is_test_path,
)
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.safe_files import read_text, walk_files


def _apply_card(card: ModelCard, fields: dict) -> None:
    """Populate ModelCard modelParameters + lineage from a KB field dict.

    Only the four ``modelParameters`` fields + ``lineage`` (pedigree) are touched;
    unrelated keys (e.g. ``license``) are ignored. No-op for an empty dict so the
    card degrades to "—" gracefully.
    """
    if not fields:
        return
    if fields.get("approach_type"):
        card.approach_type = fields["approach_type"]
    if fields.get("task"):
        card.task = fields["task"]
    if fields.get("architecture_family"):
        card.architecture_family = fields["architecture_family"]
    if fields.get("model_architecture"):
        card.model_architecture = fields["model_architecture"]
    for ancestor in fields.get("lineage") or []:
        card.pedigree_ancestors.append(PedigreeAncestor(name=ancestor))


# Small known-model licensing map, keyed by vendor. Hosted/commercial models are
# licensed (proprietary terms), NOT "unlicensed"; common OSS embedding families
# carry their real OSS license. A model whose vendor isn't here gets a SOFT
# MODEL_LICENSE_UNKNOWN flag — never the library "unlicensed" treatment.
_MODEL_LICENSE_BY_VENDOR: dict[str, str] = {
    "OpenAI": "LicenseRef-proprietary",
    "Anthropic": "LicenseRef-proprietary",
    "Google": "LicenseRef-proprietary",
    "Cohere": "LicenseRef-proprietary",
    # Amazon Titan / Nova: AWS service models, offered only through Amazon Bedrock
    "Amazon": "LicenseRef-proprietary",
    # no "Mistral" entry: its licence depends on the model (Apache-2.0 for Mistral
    # 7B / Mixtral / Small, MNPL for Codestral, MRL for Large 2407 / 2411, premier
    # API models): the model KB states each one (QA round 2, Q2-07)
    "Meta": "LicenseRef-llama-community",
    "sentence-transformers": "Apache-2.0",
    "HuggingFace": "Apache-2.0",
    "Nomic": "Apache-2.0",
    "Jina": "Apache-2.0",
}

_EXTS = {
    ".py",
    ".pyi",
    ".ipynb",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".tf",
    ".md",
    ".mdx",
    ".txt",
    ".env",
}
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".next",
    "out",
    ".idea",
    ".gradle",
    "vendor",
    "site-packages",
    ".ruff_cache",
    "coverage",
}
_MAX_BYTES = 256 * 1024
_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(name: str) -> str:
    return _SLUG.sub("-", name.lower()).strip("-")


# A reference's type, strongest first: the code uses it, a catalog / doc / example
# lists it, only test code names it.
_TYPE_RANK = {"usage": 0, "catalog": 1, "test": 2}

# A gateway that serves other vendors' models, named next to the reference (QA round
# 2, Q2-06): zsh_codex's ``GROQ_DEFAULT_MODEL = "llama-3.2-11b-text-preview"`` is
# Llama served by Groq, not by Meta. Read from the reference's own line, then back
# to the start of its class / function (at most _HINT_LINES lines), nearest first.
# The linker uses a hint only when a service of that gateway is in the scan.
_GATEWAY_HINT = re.compile(
    r"(groq|bedrock|together|openrouter|ollama|deepseek|azure|vertex)", re.IGNORECASE
)
_BLOCK_START = re.compile(
    r"^\s*(?:class|def|async\s+def|function|export\s+(?:async\s+)?function)\b"
)
_HINT_LINES = 15
# An import names a library, not where a reference is sent: ``from langchain_aws
# import ChatBedrock`` above ``ChatOpenAI(model="gpt-4o")`` is no Bedrock hint
# (review of #498 round 3).
_IMPORT_LINE = re.compile(
    r"^\s*(?:from\s+\S+\s+import\b|import\s|const\s+\w+\s*=\s*require\(|"
    r"(?:const|let|var)\s*\{[^}]*\}\s*=\s*require\()"
)
# A client given a literal base URL on the reference's own line is a gateway of
# its own (the net-env scanner makes it an "AI gateway" service)
_LITERAL_BASE_HINT = re.compile(
    r"""\b(?:base_url|api_base|baseURL|openai_api_base)['"]?\s*[=:]\s*['"]https?://"""
)


_RECEIVER_CALL = re.compile(r"\b(?P<var>[A-Za-z_]\w*)(?:\.\w+)+\s*\(")
_URL_HOST = re.compile(r"""['"]https?://(?:[^\s/'"@]*@)?(?P<host>[^\s/'"?#]+)""")
_ENV_NAME = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[\[(]|getenv\s*\()\s*['"](?P<a>[A-Z_][A-Z0-9_]*)"""
    r"""|process\.env\.(?P<b>[A-Z_][A-Z0-9_]*)"""
)
_BASE_KW = re.compile(
    r"\b(?:base_url|api_base|baseURL|openai_api_base|anthropic_api_url|host|"
    r"azure_endpoint)\s*[=:]"
)


def _client_hint(text: str, idx: int) -> str | None:
    """Call-site scope (review 6062066749 of #498, M1): the client object whose call
    holds the reference at ``idx`` (``client.chat.completions.create(model=…)``),
    resolved to the endpoint its constructor names: ``host:<host[:port]>`` for a
    literal base URL, ``env:<NAME>`` for one read from the environment, ``ollama``
    for an Ollama client; None when the call is not on a client the file builds."""
    _code, bare = mask(text, "py")
    for m in _RECEIVER_CALL.finditer(bare, max(0, idx - 2000), idx):
        args = call_arguments(bare, m.end() - 1)
        if args is None or not (m.end() <= idx <= m.end() + len(args)):
            continue
        var = m.group("var")
        ctor = re.search(
            rf"(?m)^\s*{re.escape(var)}\s*=\s*(?:await\s+)?(?:new\s+)?"
            rf"(?P<cls>[\w.]+)\s*\(",
            bare,
        )
        if ctor is None:
            continue
        cargs = call_arguments(bare, ctor.end() - 1)
        if cargs is None:
            return None
        span = text[ctor.end() : ctor.end() + len(cargs)]
        cls = ctor.group("cls")
        is_ollama = "ollama" in cls.lower() or (
            cls.endswith("Client")
            and re.search(r"\bfrom\s+ollama\b|\bimport\s+[\w., ]*ollama\b", text)
        )
        positional = is_ollama and cargs.strip() and "=" not in cargs.split(",", 1)[0]
        if not _BASE_KW.search(cargs) and not positional:
            return "ollama" if is_ollama else None
        url = _URL_HOST.search(span)
        if url:
            return f"host:{url.group('host').lower()}"
        env = _ENV_NAME.search(span)
        if env:
            return f"env:{env.group('a') or env.group('b')}"
        return "ollama" if is_ollama else None
    return None


def _gateway_hint(text: str, name: str) -> str | None:
    """The gateway named nearest a reference, within its code block, or None."""
    # the reference itself, never the same text inside a longer id
    # ("claude-3-7-sonnet-…" inside a Bedrock "us.anthropic.claude-3-7-sonnet-…")
    found = re.search(
        rf"(?<![\w.-]){re.escape(name)}(?![\w:-]|\.\w)", text, re.IGNORECASE
    )
    if found is None:
        return None
    idx = found.start()
    client = _client_hint(text, idx)
    if client is not None:
        return client
    lines = text[: idx + len(name)].splitlines()
    for back, line in enumerate(reversed(lines[-_HINT_LINES:])):
        if back == 0:
            line = line.replace(name, " ")  # "openrouter/…" ids aside, the id itself
            rest = text[idx + len(name) :].split("\n", 1)[0]
            if _LITERAL_BASE_HINT.search(line + rest):
                return "gateway"
        if _IMPORT_LINE.match(line):
            continue
        hits = _GATEWAY_HINT.findall(line)
        if hits:
            return hits[-1].lower()
        if back and _BLOCK_START.match(line):
            return None
    return None


# Source files whose comments are read as comments (a reference there is a
# mention, never usage): Python and ``#``-comment configuration, JavaScript /
# TypeScript; a notebook's code cells. Markdown and JSON are not masked.
_HASH_COMMENT = {".py", ".pyi", ".yaml", ".yml", ".toml", ".env", ".sh", ".cfg"}
_JS_SOURCE = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}


#: configuration files whose values are unquoted (``model: llama3.1:8b``)
_CONFIG_SUFFIXES = frozenset({".yaml", ".yml", ".toml", ".cfg", ".ini", ".env"})


def _source_lang(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in _JS_SOURCE:
        return language_of(path.name)
    if suffix in _HASH_COMMENT or is_env_file(path):
        return "py"
    return None


def _walk(root: Path) -> Iterator[Path]:
    # ``.env`` / ``.env.example`` have no usable suffix: matched by name
    yield from walk_files(
        root, _SKIP_DIRS, lambda p: p.suffix.lower() in _EXTS or is_env_file(p)
    )


def _application_file(path: Path, root: Path) -> bool:
    """Not a test, a doc, an example / sample file or an env template."""
    return not (is_test_path(path, root) or is_doc_path(path)
                or is_example_path(path, root) or is_env_template(path))


def repo_uses_ollama(root: Path) -> bool:
    """Whether the application uses Ollama: real code or deployment use only (review
    6065595627 of #498, R6-M1). Application source that imports the SDK, uses a
    LangChain / LiteLLM Ollama class or route, or calls the REST API; a compose /
    Kubernetes / Dockerfile that runs ``ollama/ollama`` or a LiteLLM proxy route;
    OLLAMA_HOST in the application's real environment (``.env``, its own workload's
    ``env``). Docs, tests, examples, env templates, a plain "ollama" string and a
    declared-but-never-imported dependency (package.json and requirements alike) are
    not evidence."""
    from aibom.scan.scanners.net_env_scan import CONFLICT, env_values

    configs: list[tuple[str, str]] = []
    dockerfiles = walk_files(root, _SKIP_DIRS, lambda p: p.name.lower().startswith(
        "dockerfile") or p.name.lower().endswith(".dockerfile"))
    for path in [*_walk(root), *dockerfiles]:
        if not _application_file(path, root):
            continue
        text = read_text(path, _MAX_BYTES)
        if text is None:
            continue
        suffix = path.suffix.lower()
        if suffix == ".ipynb":
            if ollama_code_evidence(notebook_text(text)[0], "py"):
                return True
        elif suffix in _CODE_EVIDENCE:
            if ollama_code_evidence(text, language_of(path.name)):
                return True
        elif (suffix in (".yaml", ".yml") or path in dockerfiles) and (
            ollama_deploy_evidence(text)
        ):
            return True
        if is_env_file(path) or suffix in (".yaml", ".yml"):
            try:
                configs.append((path.relative_to(root).as_posix(), text))
            except ValueError:
                configs.append((path.name, text))
    env = env_values(configs, root.name)
    return "OLLAMA_HOST" in env or "OLLAMA_HOST" + CONFLICT in env


#: the client classes of Ollama calls (net-env ``_SDK_MODEL_CALLS`` and LangChain)
_OLLAMA_CLASSES = frozenset({"Ollama", "ChatOllama", "OllamaLLM", "OllamaEmbeddings"})
#: source files read for Ollama code evidence
_CODE_EVIDENCE = frozenset({".py", ".pyi", *_JS_SOURCE})


@register
class ModelRefScanner(Scanner):
    name = "model-ref"
    order = 25  # after model-repo (20): its carded model (if any) wins the bom_ref
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        # normalized name -> {name, vendor, type, source, rank}; the strongest type
        # wins. A reference the application USES is a model of this system. A name
        # only in a supported-model table / pricing catalog / docs / example file
        # ("catalog") or only in test code ("test") stays in the BOM, tagged with
        # its ``model:reference_type``, but is not counted: the findings, the score,
        # the compliance checks and the PDF count only models in use (SmarterRouter
        # listed 71 "models", 6 real). Dropping them instead turned every gap in the
        # usage patterns into data loss (review of #487 M1).
        seen: dict[str, dict[str, Any]] = {}
        loose_tags: set[str] = set()
        # does the repository use Ollama at all (an SDK import / call, a LangChain
        # wrapper, the REST API, OLLAMA_HOST, the container image, a LiteLLM route)?
        uses_ollama = repo_uses_ollama(ctx.root)
        # module-level dicts / constants and settings classes of the application, for
        # models chosen by a lookup (review 6065595627 of #498, R6-M2)
        literals = ProjectLiterals.from_root(
            ctx.root, keep=lambda p: _application_file(p, ctx.root))
        for path in _walk(ctx.root):
            # None: a link, not a regular file, or over the limit
            text = read_text(path, _MAX_BYTES)
            if text is None:
                continue
            if is_test_path(path, ctx.root):
                role = "test"
            elif is_doc_path(path) or is_example_path(path, ctx.root):
                role = "catalog"  # prose and sample data mention, never use
            else:
                role = None
            try:
                source = path.relative_to(ctx.root).as_posix()
            except ValueError:
                source = path.name
            rank = evidence_rank(path)
            lang = _source_lang(path)
            if path.suffix.lower() == ".ipynb":
                # a notebook's code cells are Python source (the JSON escapes every
                # quote, so Hub ids and comments are read from the cells themselves)
                text, readable = notebook_text(text)
                lang = "py"
                if not readable:
                    ctx.unreadable_notebooks.add(path.name)
            # name -> (vendor, reference_type)
            refs = dict(find_model_refs_ctx(text, lang))
            # Hugging Face Hub ids the code loads: the family name the dictionary
            # found keeps its name and gains the Hub id (its purl); an id of a family
            # the dictionary does not know is a model under its Hub id
            hub_of: dict[str, str] = {}
            known = {n.lower(): n for n in refs}
            for hub_id, hub_vendor in find_hf_repo_ids(text, lang).items():
                tail = hub_id.split("/")[-1]
                name = known.get(hub_id.lower()) or known.get(tail.lower())
                if name is None:
                    name = hub_id
                    refs[name] = (hub_vendor, "usage")
                else:
                    refs[name] = (refs[name][0], "usage")
                hub_of[name] = hub_id
            # a model chosen by a lookup (``ollama.chat(model=OPTIONS["fast"])``,
            # ``ChatOpenAI(model=CFG["m"])``): the value the project's literals give,
            # or, for a key known only at run time, every model the dict holds as a
            # low-confidence candidate of that call (review 6065595627 of #498, R6-M2)
            looked: dict[str, tuple[bool, str]] = {}  # name -> (candidate, call)
            looked_tags: list[str] = []
            suffix = path.suffix.lower()
            if role is None and (suffix in _CODE_EVIDENCE or suffix == ".ipynb"):
                from aibom.scan.scanners.net_env_scan import lookup_model_calls

                direct = {n.lower() for n, (_v, t) in refs.items() if t == "usage"}
                calls = lookup_model_calls(
                    text, "notebook.py" if suffix == ".ipynb" else path.name, literals)
                for cls, names, exact, call in calls:
                    ollama_call = cls in _OLLAMA_CLASSES
                    for value in names:
                        if ollama_call or (valid_tag(value) and uses_ollama):
                            found = {value: ("", "usage")}
                            looked_tags.append(value)
                        else:
                            found = find_model_refs_ctx(f'model="{value}"\n', "py")
                        for name, (vendor, _t) in found.items():
                            if name.lower() in direct:
                                continue  # named literally in this file too
                            if name not in looked_tags:
                                refs[name] = (vendor, "usage")
                            was = looked.get(name.lower())
                            looked[name.lower()] = (
                                (not exact) and (was is None or was[0]),
                                (was[1] + "; " if was else "") + f"{call} in {source}",
                            )
            # Ollama library tags in Ollama calls (review 6062066749 of #498, M2):
            # open weights the Ollama server runs, never the maker's hosted product.
            # The tag (``mistral:7b``) is the model's id; a family-dictionary hit on
            # the same name (``gpt-oss`` → OpenAI) is replaced by it.
            ollama_of: dict[str, str] = {}
            in_call = find_ollama_tags(text, lang or "py") if lang else []
            in_call += [t for t in looked_tags
                        if t.lower() not in {c.lower() for c in in_call}]
            # a ``family:size`` literal outside an Ollama call (a constant, a
            # wrapper's argument) is an Ollama tag too, at low confidence (review
            # 6063080163 of #498, R4-M3)
            # Only with Ollama evidence in the repository is such a literal a model
            # in use; a picker list, a table's keys or any literal in a repository
            # that never uses Ollama is a catalogue mention (review 6063929550 of
            # #498, R5-M1)
            in_call_low = {c.lower() for c in in_call}
            loose_found = [
                (t, k) for t, k in find_ollama_tag_literals(
                    text, lang,
                    config=path.suffix.lower() in _CONFIG_SUFFIXES or is_env_file(path))
                if t.lower() not in in_call_low
            ]
            loose = [t for t, k in loose_found if k == "usage" and uses_ollama]
            listed = [t for t, k in loose_found if t not in loose]
            # a bare alias the code names itself (``gemma3n``) is a model of its own
            # next to its tagged forms (``gemma3n:e4b``): only a dictionary hit on the
            # tag's own text is replaced (review 6065595627 of #498, m4)
            named = {t.lower() for t in in_call + loose + listed}
            for tag in in_call + loose + listed:
                base = tag.split(":", 1)[0].lower()
                for other in [n for n in refs if n.lower() == tag.lower() or (
                        n.lower() == base and base not in named)]:
                    del refs[other]
                vendor_t, _lic, _task = ollama_family(tag)
                if tag in listed:
                    refs[tag] = (vendor_t or "", "catalog")
                    continue
                refs[tag] = (vendor_t or "", "usage")
                ollama_of[tag] = "ollama-cloud" if is_cloud_tag(tag) else "ollama"
                if tag in loose:
                    loose_tags.add(tag.lower())
            for name, (vendor, rtype) in refs.items():
                kind = role or rtype
                low = name.lower()
                # ``gemma3n:latest`` is the bare alias ``gemma3n`` (Ollama's own
                # default tag): one model, named as the code names it bare (m4)
                skey = low.removesuffix(":latest")
                entry = seen.get(skey)
                if entry is not None and entry["name"].lower().endswith(
                    ":latest"
                ) and not low.endswith(":latest"):
                    entry["name"] = name
                if entry is None or _TYPE_RANK[kind] < _TYPE_RANK[entry["type"]] or (
                    kind == entry["type"] == "usage" and rank < entry["rank"]
                ):
                    # usage evidenced by application code outranks configuration
                    # (m11): discovery:source names the strongest evidence
                    bare_kept = entry is not None and low.endswith(":latest") and (
                        not entry["name"].lower().endswith(":latest"))
                    seen[skey] = {"name": entry["name"] if bare_kept else name,
                                  "vendor": vendor, "type": kind,
                                 "source": source, "rank": rank,
                                 "gateway": _gateway_hint(text, name),
                                 "hub": hub_of.get(name)
                                 or (entry or {}).get("hub"),
                                 "ollama": ollama_of.get(name)
                                 or (entry or {}).get("ollama"),
                                 "loose": low in loose_tags and not (
                                     entry and entry.get("ollama")
                                     and not entry.get("loose")),
                                 "lookup": looked.get(low) if kind == "usage" else None}
                    if entry is not None and entry.get("lookup") and seen[skey][
                        "lookup"
                    ] is None and kind == entry["type"] == "usage":
                        # usage named literally elsewhere: no candidate any more
                        seen[skey]["lookup"] = (False, entry["lookup"][1])
                elif hub_of.get(name) and not entry.get("hub"):
                    entry["hub"] = hub_of[name]
                elif kind == entry["type"] == "usage":
                    mine = looked.get(low) if role is None else None
                    if entry.get("lookup") and (mine is None or not mine[0]):
                        # a literal use or an exact lookup elsewhere: not a candidate
                        entry["lookup"] = (False, entry["lookup"][1])
        for kind in ("catalog", "test"):
            n = sum(1 for v in seen.values() if v["type"] == kind)
            if n:
                ctx.properties[f"aibom:model_mentions_{kind}"] = str(n)

        for key in sorted(seen):
            entry = seen[key]
            name, vendor, rtype, source = (
                entry["name"], entry["vendor"], entry["type"], entry["source"]
            )
            bom_ref = f"modelref-{_slug(name)}"
            if ctx.has_ref(bom_ref):
                continue  # a carded model already owns this ref — don't double-add
            # Card fields: known-model KB only. Unknown models stay "—".
            kb = model_kb.lookup(name)
            card_fields = kb if kb is not None else {}
            hub = entry.get("hub")
            served_via = entry.get("ollama")
            # License: KB (model-specific) wins, else the vendor map. A Hub model's
            # licence is its own card's (open weights): the vendor's hosted-model
            # terms never apply to it (``openai/whisper-large-v3`` is no proprietary
            # OpenAI API model), so without a KB entry it is unknown.
            spdx = (kb.get("license") if kb else None) or (
                None if hub else _MODEL_LICENSE_BY_VENDOR.get(vendor)
            )
            if served_via or (":" in name and valid_tag(name)):
                # an Ollama tag (in use or only listed): the open-weights licence of
                # its family per tag (a hosted vendor's terms never apply), else
                # unknown: one licence id per model version on every path
                # (an unknown family stays unknown: ``tinyllama`` is no Llama-licensed
                # model although the dictionary's "llama" token is in its name)
                _vendor_t, spdx, task_t = ollama_family(name)
                card_fields = {"task": task_t}
            props = {"model:reference_type": rtype, "discovery:source": source}
            if served_via:
                # read by the linker: served by the Ollama server the call uses
                props["model:served_via"] = served_via
                props["model:weights"] = "open"
                if entry.get("loose"):
                    # named outside an Ollama call: the tag syntax is the evidence
                    props["discovery:confidence"] = "low"
            lookup = entry.get("lookup")
            if lookup:
                # chosen by a lookup at the call (R6-M2): the call is the evidence; a
                # dynamic key makes each value of the dict a candidate
                props["discovery:method"] = "config-lookup"
                props["discovery:snippet"] = lookup[1][:500]
                if lookup[0]:
                    props["discovery:confidence"] = "low"
                    props["model:selection"] = "candidate"
            if hub:
                # read by the model-graph linker: a Hub model is loaded from the Hub
                # and run by the application (never "served by" its maker's API)
                props["model:hub_id"] = hub
            bedrock = parse_bedrock_id(name)
            if bedrock is not None:
                # a Bedrock model id: the vendor makes it, Amazon Bedrock serves it
                props["model:provider"] = "bedrock"
                if "profile" in bedrock:
                    props["model:bedrock_inference_profile"] = bedrock["profile"]
            elif entry.get("gateway") and rtype == "usage":
                # read and removed by the model-graph linker
                props["discovery:gateway"] = entry["gateway"]
            comp = ModelComponent(
                bom_ref=bom_ref,
                name=name,
                publisher=vendor or None,
                licenses=[license_choice(spdx)] if spdx else None,
                purl=hf_purl(hub) if hub else None,
                # usage = the code loads/calls it; catalog = listed in a
                # supported-model registry / doc / example; test = test code only
                # (catalog and test are NOT models in use).
                properties=props,
            )
            _apply_card(comp.model_card, card_fields)
            ctx.add_component(comp)
            if spdx is None and rtype == "usage":
                # SOFT finding — a model with no known license is NOT a library
                # "unlicensed"; it needs manual model-licensing classification.
                ctx.add_flag(
                    "MODEL_LICENSE_UNKNOWN",
                    bom_ref,
                    severity="note",
                    message=(
                        f"Model {name!r} ({vendor}) has no known license mapping; "
                        "classify its model licensing manually (distinct from a "
                        "library with an unresolved license)."
                    ),
                )


__all__ = ["ModelRefScanner"]
