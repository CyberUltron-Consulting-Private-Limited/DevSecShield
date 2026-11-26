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

import json
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
    MANIFESTS,
    evidence_rank,
    is_doc_path,
    is_env_file,
    is_env_template,
    is_example_path,
    is_test_path,
    is_vendored_path,
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


# LiteLLM provider prefix -> the linker's service key (net-env PROVIDER_KEY values)
_LITELLM_PROVIDER_KEY = {
    "openai": "openai", "anthropic": "anthropic", "gemini": "google",
    "vertex_ai": "vertex", "mistral": "mistral", "groq": "groq",
    "together_ai": "together", "deepseek": "deepseek", "cohere": "cohere",
    "cohere_chat": "cohere", "xai": "xai", "openrouter": "openrouter",
    "bedrock": "bedrock", "azure": "azure",
}
_ROUTE_PREFIX = re.compile(r"""['"](?P<prov>[\w-]+)/(?:[\w.-]+/)*$""")


#: hint for a LiteLLM model whose provider LiteLLM cannot infer: no service serves it
LITELLM_UNROUTED = "litellm-unrouted"


def _in_litellm_call(text: str, idx: int) -> bool:
    """Whether ``idx`` is inside the arguments of a LiteLLM call."""
    from aibom.scan.scanners.net_env_scan import _LITELLM_CALL, _LITELLM_IMPORT

    if not _LITELLM_IMPORT.search(text):
        return False
    _code, bare = mask(text, "py")
    for m in _LITELLM_CALL.finditer(bare, max(0, idx - 3000), idx):
        args = call_arguments(bare, m.end() - 1)
        if args is not None and m.end() <= idx <= m.end() + len(args):
            return True
    return False


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
    # a LiteLLM route names its provider in its own prefix (``"openai/gpt-4o"``,
    # ``"together_ai/meta-llama/…"``): that decides, before any nearby hint (review
    # 6066180782 of #498, R7-M3: gpt-4o after a groq/ route was "served by Groq")
    route = _ROUTE_PREFIX.search(text[max(0, idx - 200) : idx])
    if route is not None:
        key = _LITELLM_PROVIDER_KEY.get(route.group("prov").lower())
        if key:
            return key
    elif _in_litellm_call(text, idx):
        # no prefix: LiteLLM routes the name by its own model map, never by an earlier
        # route's provider (review 6066860842 of #498, R8-M1)
        from aibom.scan.scanners.net_env_scan import litellm_default_provider

        prov = litellm_default_provider(name)
        return _LITELLM_PROVIDER_KEY.get(prov or "", LITELLM_UNROUTED)
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


_DOC_DIRS = frozenset({"docs", "doc"})
#: a top-level directory under one of these is a package of its own, manifest or
#: not (review 6066860842 of #498, m2)
_PACKAGE_PARENTS = frozenset({"services", "apps", "packages"})


def _application_file(path: Path, root: Path) -> bool:
    """Not a test, a doc (also a ``.py`` under docs/), an example / sample file, an
    env template or vendored third-party code."""
    try:
        parts = path.relative_to(root).parts[:-1]
    except ValueError:
        parts = ()
    return not (is_test_path(path, root) or is_doc_path(path)
                or is_example_path(path, root) or is_env_template(path)
                or any(p.lower() in _DOC_DIRS for p in parts)
                or is_vendored_path(path, root))


def package_root(path: Path, root: Path, cache: dict[Path, str] | None = None) -> str:
    """The repository-relative directory of the package ``path`` belongs to ("" for
    the repository root): the nearest directory with a manifest, or a top-level
    directory under services/, apps/ or packages/. One package of a monorepo."""
    cache = {} if cache is None else cache
    here = path.parent
    seen: list[Path] = []
    found = ""
    while True:
        if here in cache:
            found = cache[here]
            break
        seen.append(here)
        if here == root or root not in here.parents:
            found = ""
            break
        rel = here.relative_to(root).parts
        if any((here / m).is_file() for m in MANIFESTS) or (
            len(rel) == 2 and rel[0].lower() in _PACKAGE_PARENTS
        ):
            found = here.relative_to(root).as_posix()
            break
        here = here.parent
    for d in seen:
        cache[d] = found
    return found


ALL_PACKAGES = "*"
_OLLAMA_IMAGE = re.compile(r"(?:^|/)ollama/ollama(?::|@|$)", re.IGNORECASE)


def _compose_reach(text: str, root: Path, cache: dict[Path, str]) -> set[str] | None:
    """The packages a repository-root compose file gives Ollama to (review 6066860842
    of #498, m2): when it runs ``ollama/ollama``, the packages of the services it
    builds or runs; and the packages of the services whose environment sets
    OLLAMA_HOST. A service is a package by its ``build`` context (or dockerfile) or
    by an image named after a package directory; ``build: .`` is every package. None
    when the file is no compose file."""
    if "services:" not in text:
        return None
    import yaml

    try:
        doc = yaml.safe_load(text)
    except (yaml.YAMLError, ValueError, RecursionError):
        return None
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict) or not all(
        isinstance(v, dict) for v in services.values()
    ):
        return None
    from aibom.scan.scanners.net_env_scan import _container_env

    runs_ollama = any(_OLLAMA_IMAGE.search(str(svc.get("image") or ""))
                      for svc in services.values())
    reach: set[str] = set()
    for name, svc in services.items():
        if _OLLAMA_IMAGE.search(str(svc.get("image") or "")):
            continue
        targets = _service_packages(str(name), svc, root, cache)
        env = _container_env(svc.get("environment"))
        sets_host = any(k == "OLLAMA_HOST" for k, _v in env)
        if runs_ollama or sets_host:
            reach |= targets
    if runs_ollama and not reach:
        reach.add(ALL_PACKAGES)  # nothing names the application: every package
    return reach


def _service_packages(
    name: str, svc: dict, root: Path, cache: dict[Path, str]
) -> set[str]:
    build = svc.get("build")
    dirs: list[str] = []
    if isinstance(build, str):
        dirs.append(build)
    elif isinstance(build, dict):
        context = str(build.get("context") or ".")
        dockerfile = build.get("dockerfile")
        if isinstance(dockerfile, str) and "/" in dockerfile:
            dirs.append(f"{context}/{dockerfile.rsplit('/', 1)[0]}")
        else:
            dirs.append(context)
    out: set[str] = set()
    for d in dirs:
        rel = Path(d.strip()).as_posix()  # Path drops a leading "./"
        rel = "" if rel == "." else rel
        if not rel or ".." in Path(rel).parts:
            out.add(ALL_PACKAGES)
            continue
        out.add(package_root(root / rel / "_", root, cache) or ALL_PACKAGES)
    if not dirs:
        image = str(svc.get("image") or "").rsplit("/", 1)[-1]
        image = image.split(":", 1)[0].split("@", 1)[0]
        for cand in {image, name}:
            for parent in ("", *_PACKAGE_PARENTS):
                d = root / parent / cand if parent else root / cand
                if cand and d.is_dir():
                    pkg = package_root(d / "_", root, cache)
                    if pkg:
                        out.add(pkg)
    return out


def repo_uses_ollama(root: Path) -> set[str]:
    """The packages whose application uses Ollama: real code or deployment use only
    (review 6065595627 of #498, R6-M1). Application source that imports the SDK, uses
    a LangChain / LiteLLM Ollama class or route, or calls the REST API (also through
    a vendored client module it imports); a compose / Kubernetes / Dockerfile that
    runs ``ollama/ollama`` or a LiteLLM proxy route; OLLAMA_HOST in the application's
    real environment (``.env``, its own workload's ``env``). Docs (also ``.py`` under
    docs/), tests, examples, env templates, vendored third-party code itself, a plain
    "ollama" string and a declared-but-never-imported dependency are not evidence.

    Evidence is scoped to the package (:func:`package_root`; reviews 6066180782 and
    6066860842 of #498, m2): one package's Ollama never makes another package's
    constants models in use. A root compose file reaches only the packages it builds
    or runs; other root deployment files and env configure every package
    (:data:`ALL_PACKAGES`)."""
    from aibom.scan.scanners.net_env_scan import CONFLICT, env_values

    cache: dict[Path, str] = {}
    found: set[str] = set()
    configs: dict[str, list[tuple[str, str]]] = {}
    dockerfiles = walk_files(root, _SKIP_DIRS, lambda p: p.name.lower().startswith(
        "dockerfile") or p.name.lower().endswith(".dockerfile"))
    paths = [*_walk(root), *dockerfiles]
    # vendored client modules that call Ollama: the application uses Ollama through
    # them when it imports one (review 6066860842 of #498, m1)
    vendored_clients: list[str] = []
    for path in paths:
        if path.suffix.lower() in (".py", ".pyi") and is_vendored_path(path, root):
            text = read_text(path, _MAX_BYTES)
            if text and ollama_code_evidence(text, "py"):
                rel = path.relative_to(root).with_suffix("")
                parts = rel.parts[:-1] if rel.name == "__init__" else rel.parts
                vendored_clients.append(".".join(parts))
    for path in paths:
        if not _application_file(path, root):
            continue
        pkg = package_root(path, root, cache)
        text = read_text(path, _MAX_BYTES)
        if text is None:
            continue
        suffix = path.suffix.lower()
        if suffix == ".ipynb":
            if ollama_code_evidence(notebook_text(text)[0], "py"):
                found.add(pkg)
        elif suffix in _CODE_EVIDENCE:
            if ollama_code_evidence(text, language_of(path.name)) or any(
                re.search(rf"(?m)^\s*(?:from\s+{re.escape(mod)}\s+import\b|"
                          rf"import\s+{re.escape(mod)}\b)", text)
                for mod in vendored_clients
            ):
                found.add(pkg)
        elif suffix in (".yaml", ".yml") and not pkg and (
            (reach := _compose_reach(text, root, cache)) is not None
        ):
            found |= reach  # a root compose file: only the packages it deploys
            continue
        elif (suffix in (".yaml", ".yml") or path in dockerfiles) and (
            ollama_deploy_evidence(text)
        ):
            found.add(pkg or ALL_PACKAGES)
        if is_env_file(path) or suffix in (".yaml", ".yml"):
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                rel = path.name
            configs.setdefault(pkg, []).append((rel, text))
    for pkg, files in configs.items():
        env = env_values(files, root.name)
        if "OLLAMA_HOST" in env or "OLLAMA_HOST" + CONFLICT in env:
            found.add(pkg or ALL_PACKAGES)
    return found


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
        # one entry per candidate set chosen at run time (R7-M1)
        groups: dict[tuple[str, ...], dict[str, Any]] = {}
        loose_tags: set[str] = set()
        # does the repository use Ollama at all (an SDK import / call, a LangChain
        # wrapper, the REST API, OLLAMA_HOST, the container image, a LiteLLM route)?
        ollama_packages = repo_uses_ollama(ctx.root)
        package_cache: dict[Path, str] = {}
        # module-level dicts / constants and settings classes of the application, for
        # models chosen by a lookup (review 6065595627 of #498, R6-M2)
        literals = ProjectLiterals.from_root(
            ctx.root, keep=lambda p: _application_file(p, ctx.root))
        for path in _walk(ctx.root):
            # None: a link, not a regular file, or over the limit
            text = read_text(path, _MAX_BYTES)
            if text is None:
                continue
            if is_vendored_path(path, ctx.root):
                continue  # third-party code: no models of the application (m1)
            uses_ollama = ALL_PACKAGES in ollama_packages or (
                package_root(path, ctx.root, package_cache) in ollama_packages)
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
            # ``ChatOpenAI(model=CFG["m"])``): the value the project's literals give
            # (review 6065595627 of #498, R6-M2). A key known only at run time makes
            # the call ONE model in use whose candidates are evidence, never models
            # of their own (review 6066180782 of #498, R7-M1: see _candidate_groups)
            looked: dict[str, tuple[bool, str]] = {}  # name -> (candidate, call)
            looked_tags: list[str] = []
            suffix = path.suffix.lower()
            if role is None and (suffix in _CODE_EVIDENCE or suffix == ".ipynb"):
                from aibom.scan.scanners.net_env_scan import lookup_model_calls

                direct = {n.lower() for n, (_v, t) in refs.items() if t == "usage"}
                calls = lookup_model_calls(
                    text, "notebook.py" if suffix == ".ipynb" else path.name, literals)
                for cls, names, exact, call, pos in calls:
                    ollama_call = cls in _OLLAMA_CLASSES
                    if not exact:
                        _add_candidates(groups, names, ollama_call, uses_ollama,
                                        f"{call} in {source}", source,
                                        _call_client(text, pos, cls, ollama_call))
                        continue
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
        # a value that is only a candidate of a run-time choice (a dict value that the
        # loose-literal reading took for usage) is a catalogue mention: the call's one
        # entry counts it (R7-M1)
        candidate_names = {n.lower() for g in groups.values() for n in g["names"]}
        for low_name, entry in seen.items():
            if entry["type"] == "usage" and entry.get("loose") and (
                low_name in candidate_names
            ):
                entry["type"] = "catalog"
                entry["ollama"] = None
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
        _emit_candidate_groups(ctx, groups)


# -------------------------------------------------------------- run-time choices

#: candidates shown in the reason / evidence text before "and N more"
CANDIDATE_SHOWN = 10
_HOSTED_TERMS_VENDORS = frozenset(
    v for v, lic in _MODEL_LICENSE_BY_VENDOR.items() if lic == "LicenseRef-proprietary"
)


def _candidate_provider(value: str, ollama_call: bool, uses_ollama: bool) -> str:
    """Who runs a candidate: "Ollama" for an Ollama tag (or a bare family named in an
    Ollama call), "Ollama Cloud" for a ``-cloud`` tag, else the vendor the model
    dictionary names, else "unknown"."""
    name = value.split(":", 1)[0]
    if valid_tag(value) and (ollama_call or uses_ollama):
        return "Ollama Cloud" if is_cloud_tag(value) else "Ollama"
    if ollama_call and ":" not in value and ollama_family(name)[0] is not None and (
        not find_model_refs_ctx(f'model="{value}"\n', "py")
    ):
        return "Ollama"
    found = find_model_refs_ctx(f'model="{value}"\n', "py")
    vendor = next((v for v, _t in found.values() if v), "")
    return vendor or "unknown"


#: a client class -> the provider key of the vendor API it calls by default
_CLIENT_KEY = (
    (re.compile(r"Azure"), "azure"), (re.compile(r"Bedrock"), "bedrock"),
    (re.compile(r"OpenAI"), "openai"), (re.compile(r"Anthropic"), "anthropic"),
    (re.compile(r"Google"), "google"), (re.compile(r"Groq"), "groq"),
    (re.compile(r"Mistral"), "mistral"), (re.compile(r"Cohere"), "cohere"),
)


def _call_client(text: str, pos: int, cls: str, ollama_call: bool) -> str:
    """Which client a run-time choice is sent through (review 6066860842 of #498,
    R8-M2): "ollama"; the call-site client's endpoint ("host:…" / "env:…"); the
    vendor API a vendor client calls by default ("key:openai"); or "generic" (LiteLLM,
    whose provider comes from the model itself)."""
    if ollama_call:
        return "ollama"
    if cls == "LiteLLM":
        return "generic"
    hint = _client_hint(text, pos + 1)
    if hint == "ollama":
        return "ollama"
    if hint:
        return hint
    key = next((k for pat, k in _CLIENT_KEY if pat.search(cls)), None)
    return f"key:{key}" if key else "generic"


def _add_candidates(
    groups: dict[tuple[str, ...], dict[str, Any]],
    names: list[str],
    ollama_call: bool,
    uses_ollama: bool,
    call: str,
    source: str,
    client: str,
) -> None:
    """Record one run-time choice (``ollama.chat(model=OPTIONS[choice])``): calls on
    the same candidate set through the same client are one entry with every call
    site."""
    key = (*sorted({n.lower() for n in names}), "@" + client)
    group = groups.get(key)
    if group is None:
        group = groups[key] = {
            "names": list(dict.fromkeys(names)),
            "providers": [_candidate_provider(n, ollama_call, uses_ollama)
                          for n in dict.fromkeys(names)],
            "calls": [], "sources": [], "client": client,
        }
    if call not in group["calls"]:
        group["calls"].append(call)
    if source not in group["sources"]:
        group["sources"].append(source)


def candidate_summary(names: list[str], providers: list[str]) -> str:
    """``"a (Ollama), b (OpenAI) … and 30 more"``: the first candidates, then the rest
    as a count."""
    shown = [f"{n} ({p})" for n, p in zip(names, providers, strict=False)]
    head = ", ".join(shown[:CANDIDATE_SHOWN])
    rest = len(shown) - CANDIDATE_SHOWN
    return head + (f" and {rest} more" if rest > 0 else "")


def candidate_identity(names: list[str], call_site: str) -> str:
    """A stable id of a run-time choice: a hash of the sorted candidate set and the
    call site, never the count (review 6066860842 of #498, m3)."""
    import hashlib

    data = json.dumps([sorted({n.lower() for n in names}), call_site])
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:10]


def _emit_candidate_groups(
    ctx: ScanContext, groups: dict[tuple[str, ...], dict[str, Any]]
) -> None:
    """One model in use per run-time choice (review 6066180782 of #498, R7-M1, the
    coordinator's design): ``unidentified model (run-time choice <id>)``. Its
    candidates are evidence (``model:candidates``, a JSON array of ``{name,
    provider}``), never components of their own; counts and compliance see one
    model, needs-information. The id is :func:`candidate_identity`.

    Where it runs follows the client actually called (review 6066860842 of #498,
    R8-M2): an Ollama call is served by its Ollama server and self-hosted, the
    hosted-looking names noted in the evidence; a vendor client by the endpoint it
    calls (``model:client``, linked by the model-graph linker); a generic client
    (LiteLLM) by an endpoint the scan cannot name, a possible external processor."""
    ordered = sorted(groups.values(), key=lambda g: (g["sources"][0], g["calls"][0]))
    for group in ordered:
        names, providers = group["names"], group["providers"]
        n = len(names)
        call_site = sorted(group["calls"])[0]
        ident = candidate_identity(names, call_site)
        name = f"unidentified model (run-time choice {ident})"
        client = group["client"]
        props = {
            "model:reference_type": "usage",
            "model:identified": "false",
            "model:selection": "candidates",
            "model:candidate_count": str(n),
            "model:candidates": json.dumps(
                [{"name": c, "provider": p}
                 for c, p in zip(names, providers, strict=False)]
            ),
            "model:unidentified_reason": (
                f"chosen at run time from {n} candidates: "
                f"{candidate_summary(names, providers)}"
            ),
            "model:client": client,
            "discovery:source": group["sources"][0],
            "discovery:sources": ",".join(group["sources"]),
            "discovery:method": "config-lookup",
            "discovery:confidence": "low",
            "discovery:snippet": "; ".join(group["calls"])[:500],
        }
        publisher: str | None = None
        licence: str | None = None
        kinds = set(providers)
        if client == "ollama":
            props["model:served_via"] = "ollama"
            props["model:weights"] = "open"
            hosted = [c for c, p in zip(names, providers, strict=False)
                      if p != "Ollama"]
            if hosted:
                props["model:candidate_note"] = (
                    "names that look hosted are not Ollama library tags; through this "
                    "Ollama server they run only as Ollama Cloud models or not at all: "
                    + ", ".join(hosted[:CANDIDATE_SHOWN])
                    + (f" and {len(hosted) - CANDIDATE_SHOWN} more"
                       if len(hosted) > CANDIDATE_SHOWN else "")
                )
            else:
                licences = {ollama_family(c)[1] for c in names}
                if len(licences) == 1:
                    licence = next(iter(licences))
        else:
            if len(kinds) == 1 and next(iter(kinds)) not in (
                "unknown", "Ollama", "Ollama Cloud"
            ):
                publisher = next(iter(kinds))
                if publisher in _HOSTED_TERMS_VENDORS:
                    licence = "LicenseRef-proprietary"
            if client == "generic":
                props["model:server"] = "unknown"
        comp = ModelComponent(
            bom_ref=f"modelref-runtime-choice-{ident}",
            name=name,
            publisher=publisher,
            licenses=[license_choice(licence)] if licence else None,
            properties=props,
        )
        comp.model_card.task = "chat/completion"
        ctx.add_component(comp)


__all__ = ["ModelRefScanner", "candidate_identity", "candidate_summary"]
