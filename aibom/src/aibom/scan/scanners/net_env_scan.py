"""Level-3 scanner: .env + source -> network AI endpoints / cloud APIs.

Detects calls to managed LLM APIs and local inference endpoints by hostname in
``.env`` files and source (api.openai.com, api.anthropic.com, Bedrock runtime,
localhost:11434, …), emitting ``cloud_service`` / ``endpoint`` components — the
shadow-AI usage that never appears in a manifest. The emitters render both kinds
as CycloneDX ``services`` (endpoints, authentication, trust boundary, data flow).

Each component records what the emitters need, as ``service:`` properties:

* ``service:endpoint`` — the service's base URL: scheme, host, port and the
  leading API-version path segments only (``https://api.openai.com/v1``), else
  ``https://<host>`` (``http://`` for loopback). User information
  (``user:pass@``), the query string and the fragment are never kept, and the
  path stops at the first segment that is not a version, so an API key in
  ``?key=`` / ``api-key=`` or in a later path segment never reaches the BOM;
* ``service:trust_zone`` — ``external`` (a third-party SaaS API, so data crosses a
  trust boundary) or ``local`` (loopback inference such as Ollama);
* ``service:authenticated`` — ``true`` for the hosted APIs (each requires an API
  key or cloud credentials), ``false`` for Ollama (no authentication by default),
  absent when not known.

``discovery:source`` is the repository-relative path of the first application
file that names the host. A host named only in test code or in an example /
sample data file is not a service of this application: it is left out and
counted in the BOM property ``aibom:services_excluded_test_example``. Amazon
Bedrock reached through the AWS SDK gets its regional endpoint
(``https://bedrock-runtime.<region>.amazonaws.com``) only when the file names the
region as a literal (``region_name="ap-south-1"``); otherwise no endpoint is
recorded. A registry entry.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.model.component import (
    CloudServiceComponent,
    EndpointComponent,
    ModelComponent,
)
from aibom.scan.parsers.code_imports import notebook_text
from aibom.scan.parsers.code_text import call_arguments, language_of, mask
from aibom.scan.parsers.licenses import license_choice
from aibom.scan.parsers.model_lookup import (
    ProjectLiterals,
    follow,
    is_model_name,
    looks_like_lookup,
)
from aibom.scan.path_roles import (
    is_env_file,
    is_env_template,
    is_example_path,
    is_test_path,
)
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.safe_files import read_text, walk_files

# (host regex, kind, display name, vendor, authenticated) — the host regex is
# matched case-insensitively and must name the whole host (no substring of a
# longer host). ``authenticated`` None = not known.
_HOSTS: tuple[tuple[str, str, str, str, bool | None], ...] = (
    (r"api\.openai\.com", "cloud_service", "OpenAI API", "OpenAI", True),
    (r"api\.anthropic\.com", "cloud_service", "Anthropic API", "Anthropic", True),
    (
        r"generativelanguage\.googleapis\.com",
        "cloud_service",
        "Google Gemini API",
        "Google",
        True,
    ),
    (
        r"(?:[a-z0-9-]+-)?aiplatform\.googleapis\.com",
        "cloud_service",
        "Google Vertex AI",
        "Google",
        True,
    ),
    (r"api\.cohere\.(?:ai|com)", "cloud_service", "Cohere API", "Cohere", True),
    (r"api\.mistral\.ai", "cloud_service", "Mistral API", "Mistral", True),
    (
        r"[a-z0-9-]+\.openai\.azure\.com",
        "cloud_service",
        "Azure OpenAI",
        "Microsoft",
        True,
    ),
    (
        r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com",
        "cloud_service",
        "Amazon Bedrock Runtime",
        "Amazon",
        True,
    ),
    (r"api\.groq\.com", "cloud_service", "Groq API", "Groq", True),
    (
        r"api\.together\.(?:xyz|ai)",
        "cloud_service",
        "Together AI API",
        "Together AI",
        True,
    ),
    (r"openrouter\.ai", "cloud_service", "OpenRouter API", "OpenRouter", True),
    (r"api\.deepseek\.com", "cloud_service", "DeepSeek API", "DeepSeek", True),
    (r"api\.x\.ai", "cloud_service", "xAI API", "xAI", True),
    (
        r"(?:api-inference|router)\.huggingface\.co",
        "cloud_service",
        "Hugging Face Inference API",
        "Hugging Face",
        True,
    ),
    (r"huggingface\.co", "endpoint", "Hugging Face Hub", "Hugging Face", None),
    (r"localhost:11434", "endpoint", "Ollama (local)", "local", False),
    (r"127\.0\.0\.1:11434", "endpoint", "Ollama (local)", "local", False),
    (r"localhost:8000", "endpoint", "Local inference (:8000)", "local", None),
)
# Service label -> the platform's ModelProvider value (worker enums.py), so a model
# served by the service can say where it runs (``model:provider``).
PROVIDER_KEY: dict[str, str] = {
    "OpenAI API": "openai",
    "Anthropic API": "anthropic",
    "Google Gemini API": "google",
    "Google Vertex AI": "vertex",
    "Cohere API": "cohere",
    "Mistral API": "mistral",
    "Azure OpenAI": "azure",
    "Amazon Bedrock Runtime": "bedrock",
    "Groq API": "groq",
    "Together AI API": "together",
    "OpenRouter API": "openrouter",
    "DeepSeek API": "deepseek",
    "xAI API": "xai",
    "Hugging Face Inference API": "huggingface",
    "Hugging Face Hub": "huggingface",
    "Ollama (local)": "ollama",
}
# Bedrock is reached through the AWS SDK as often as by URL.
_BEDROCK_SDK = re.compile(
    r"""client\(\s*(?:service_name\s*=\s*)?['"]bedrock-runtime['"]|"""
    r"""BedrockRuntimeClient\b|@aws-sdk/client-bedrock-runtime""",
    re.IGNORECASE,
)
# The region of a Bedrock SDK client, when written as a literal.
_BEDROCK_REGION = re.compile(
    r"""region(?:_name)?\s*[=:]\s*['"](?P<region>[a-z]{2}(?:-gov)?-[a-z]+-\d)['"]""",
    re.IGNORECASE,
)
# A vendor SDK client the application constructs IS a call to that vendor's API
# (QA round 2, Q2-06: zsh_codex calls Gemini, Groq and Mistral through their SDKs
# and named none of their hosts, so none of them was a service). A file must both
# import the SDK and construct its client; an import alone is not a call. The
# endpoint is the SDK's documented default base URL, marked
# ``service:endpoint_basis = sdk-default``; a client given another base URL
# (``OpenAI(base_url="https://api.deepseek.com")``) is not that vendor's API, and
# the host it names is found by the URL patterns above.
# (import regex, client-construction regex, label, vendor, default endpoint)
_SDK_CLIENTS: tuple[tuple[str, str, str, str, str], ...] = (
    (
        r"""(?:^|\n)\s*(?:from\s+openai\b|import\s+openai\b)|from\s+['"]openai['"]|"""
        r"""require\(\s*['"]openai['"]\s*\)""",
        r"""(?<!\w)(?:new\s+)?(?:Async)?OpenAI\s*\(|\bopenai\.(?:chat\.completions|"""
        r"""completions|responses|embeddings|ChatCompletion|Completion|Embedding)\."""
        r"""create\s*\(""",
        "OpenAI API", "OpenAI", "https://api.openai.com/v1",
    ),
    (
        r"""(?:^|\n)\s*(?:from\s+anthropic\b|import\s+anthropic\b)|"""
        r"""from\s+['"]@anthropic-ai/sdk['"]|require\(\s*['"]@anthropic-ai/sdk['"]\s*\)""",
        r"""(?<!\w)(?:new\s+)?(?:Async)?Anthropic\s*\(""",
        "Anthropic API", "Anthropic", "https://api.anthropic.com",
    ),
    (
        r"""(?:^|\n)\s*(?:from\s+google\s+import\s+genai\b|import\s+google\.generativeai\b|"""
        r"""from\s+google\.generativeai\b|from\s+google\.genai\b)|"""
        r"""from\s+['"]@google/(?:generative-ai|genai)['"]""",
        r"""\bgenai\.(?:configure|GenerativeModel|Client)\s*\(|"""
        r"""\bnew\s+(?:GoogleGenerativeAI|GoogleGenAI)\s*\(""",
        "Google Gemini API", "Google", "https://generativelanguage.googleapis.com",
    ),
    (
        r"""(?:^|\n)\s*(?:from\s+groq\b|import\s+groq\b)|from\s+['"]groq-sdk['"]|"""
        r"""require\(\s*['"]groq-sdk['"]\s*\)""",
        r"""(?<!\w)(?:new\s+)?(?:Async)?Groq\s*\(""",
        "Groq API", "Groq", "https://api.groq.com",
    ),
    (
        r"""(?:^|\n)\s*(?:from\s+mistralai\b|import\s+mistralai\b)|"""
        r"""from\s+['"]@mistralai/mistralai['"]""",
        r"""(?<!\w)(?:new\s+)?(?:Mistral|MistralClient|MistralAsyncClient)\s*\(""",
        "Mistral API", "Mistral", "https://api.mistral.ai",
    ),
    (
        r"""(?:^|\n)\s*(?:from\s+cohere\b|import\s+cohere\b)|"""
        r"""from\s+['"]cohere-ai['"]""",
        r"""\bcohere\.(?:Async)?Client(?:V2)?\s*\(|(?<!\w)(?:new\s+)?"""
        r"""CohereClient(?:V2)?\s*\(""",
        "Cohere API", "Cohere", "https://api.cohere.com",
    ),
)
# LangChain's chat / LLM / embedding wrappers are clients of the same vendor APIs
# (``ChatOpenAI()`` calls https://api.openai.com/v1 unless given another base URL):
# the most common way an application calls a model (review of #498 round 3:
# alejandro-ao/ask-multiple-pdfs calls OpenAI only through ``ChatOpenAI()`` and
# ``OpenAIEmbeddings()``, and the BOM had no AI service). Python packages
# ``langchain*`` and the JS ``@langchain/*`` / ``langchain/*`` modules.
_LANGCHAIN_IMPORT = (
    r"""(?:^|\n)\s*(?:from|import)\s+langchain[\w.]*\b|"""
    r"""from\s+['"](?:@langchain/[\w-]+|langchain(?:/[\w/-]+)?)['"]|"""
    r"""require\(\s*['"](?:@langchain/[\w-]+|langchain(?:/[\w/-]+)?)['"]\s*\)"""
)
_LANGCHAIN_CLIENTS: tuple[tuple[str, str, str, str], ...] = (
    (r"ChatOpenAI|OpenAIEmbeddings|OpenAI", "OpenAI API", "OpenAI",
     "https://api.openai.com/v1"),
    (r"ChatAnthropic|AnthropicLLM", "Anthropic API", "Anthropic",
     "https://api.anthropic.com"),
    (r"ChatGoogleGenerativeAI|GoogleGenerativeAIEmbeddings|GoogleGenerativeAI",
     "Google Gemini API", "Google", "https://generativelanguage.googleapis.com"),
    (r"ChatGroq", "Groq API", "Groq", "https://api.groq.com"),
    (r"ChatMistralAI|MistralAIEmbeddings", "Mistral API", "Mistral",
     "https://api.mistral.ai"),
    (r"ChatCohere|CohereEmbeddings|CohereRerank", "Cohere API", "Cohere",
     "https://api.cohere.com"),
)
_SDK_CLIENTS = _SDK_CLIENTS + tuple(
    (_LANGCHAIN_IMPORT, rf"(?<!\w)(?:new\s+)?(?:{names})\s*\(", label, vendor, url)
    for names, label, vendor, url in _LANGCHAIN_CLIENTS
)
# LangChain's Bedrock wrappers are Amazon Bedrock Runtime clients
_LANGCHAIN_IMPORT_RE = re.compile(_LANGCHAIN_IMPORT, re.IGNORECASE)
_LANGCHAIN_BEDROCK = re.compile(
    r"(?<!\w)(?:new\s+)?(?:ChatBedrock(?:Converse)?|BedrockChat|BedrockLLM|"
    r"BedrockEmbeddings|Bedrock)\s*\("
)
# Ollama: a local model server. Its SDK (Python ``ollama``, JS ``ollama``) and
# LangChain's Ollama wrappers default to http://127.0.0.1:11434 (ollama-python
# ``_parse_host``: host 127.0.0.1, port 11434). A file that calls it and names no
# host is that local endpoint (#498 round 3 follow-up: an ``ollama.chat(...)`` app
# had no Ollama node, so its models read as external vendor services).
_OLLAMA_IMPORT = re.compile(
    r"""(?:^|\n)\s*(?:import\s+(?:[\w.]+\s*,\s*)*ollama\b|from\s+ollama\b)|"""
    r"""from\s+['"]ollama(?:/browser)?['"]|require\(\s*['"]ollama['"]\s*\)""",
    re.IGNORECASE,
)
_OLLAMA_CALL = re.compile(
    r"\bollama\.(?:chat|generate|embed|embeddings|Client|AsyncClient)\s*\(|"
    r"(?<!\w)new\s+Ollama\s*\("
)
_OLLAMA_FROM_CLIENT = re.compile(
    r"(?:^|\n)\s*from\s+ollama\s+import\s+[^\n]*\b(?:Async)?Client\b"
)
_OLLAMA_BARE_CLIENT = re.compile(r"(?<![\w.])(?:Async)?Client\s*\(")
_LANGCHAIN_OLLAMA = re.compile(
    r"(?<!\w)(?:new\s+)?(?:ChatOllama|OllamaLLM|OllamaEmbeddings|Ollama)\s*\("
)
_OLLAMA_DEFAULT = "http://127.0.0.1:11434"
# LangChain model wrappers whose MODEL is a constructor argument: one built with no
# model argument runs the library's default model, which depends on the installed
# version, so the BOM states the call instead of guessing a model (#498 round 3:
# ask-multiple-pdfs' ``ChatOpenAI()`` / ``OpenAIEmbeddings()`` read as "0 models").
_LANGCHAIN_MODEL_CLASSES = re.compile(
    r"(?<![\w.])(?:new\s+)?(?P<cls>ChatOpenAI|OpenAIEmbeddings|AzureChatOpenAI|"
    r"AzureOpenAIEmbeddings|ChatAnthropic|ChatGoogleGenerativeAI|"
    r"GoogleGenerativeAIEmbeddings|ChatGroq|ChatMistralAI|MistralAIEmbeddings|"
    r"ChatCohere|CohereEmbeddings|ChatBedrock(?:Converse)?|BedrockLLM|"
    r"BedrockEmbeddings|ChatOllama|OllamaLLM|OllamaEmbeddings)\s*\("
)
_MODEL_KWARG = re.compile(
    r"\b(?:model|model_name|modelName|model_id|deployment_name|azure_deployment|"
    r"deploymentName)\s*[=:]"
)


# wrapper class -> (vendor, task): who serves the default model and what it does
_UNNAMED_VENDOR = (
    (re.compile(r"Azure"), "Microsoft"), (re.compile(r"Bedrock"), "Amazon"),
    (re.compile(r"OpenAI"), "OpenAI"), (re.compile(r"Anthropic"), "Anthropic"),
    (re.compile(r"Google"), "Google"), (re.compile(r"Groq"), "Groq"),
    (re.compile(r"Mistral"), "Mistral"), (re.compile(r"Cohere"), "Cohere"),
    (re.compile(r"Ollama"), "local"),
)
# a hosted vendor's API models are all used under its terms, whichever is the default
_HOSTED_TERMS = frozenset({"OpenAI", "Anthropic", "Google", "Cohere", "Microsoft"})
# direct SDK calls whose model is an argument: (call regex, client label, import regex)
_SDK_MODEL_CALLS: tuple[tuple[re.Pattern[str], str, re.Pattern[str]], ...] = (
    (re.compile(
        r"\.(?:chat\.completions|completions|responses|embeddings)\.create\s*\("),
     "OpenAI", re.compile(r"""\bopenai\b""")),
    (re.compile(r"\.messages\.(?:create|stream)\s*\("), "Anthropic",
     re.compile(r"""\banthropic\b|@anthropic-ai/sdk""")),
    (re.compile(r"\bollama\.(?:chat|generate|embed|embeddings)\s*\("), "Ollama",
     re.compile(r"""\bollama\b""")),
)
_MODEL_VALUE = re.compile(
    r"\b(?:model|model_name|modelName|model_id|deployment_name|azure_deployment|"
    r"deploymentName)\s*[=:]\s*"
)
_ENV_KEY = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[\[(]|os\.getenv\s*\(|getenv\s*\(|"""
    r"""process\.env\.|settings\.|config\.|cfg\.)\s*['"]?(?P<key>[A-Za-z_][\w.]*)"""
)
_STRING = re.compile(r"""['"][^'"\n]*['"]""")
_REASON_DEFAULT = "library default model applies"
_REASON_CONFIG = "model from configuration"


def _arg_value(code: str, start: int) -> str:
    """The argument expression starting at ``start`` (to the next top-level comma
    or the closing parenthesis), trimmed."""
    depth = 0
    for k in range(start, min(len(code), start + 300)):
        ch = code[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return code[start:k].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return code[start:k].strip()
    return code[start : start + 300].strip()


_MODULE_CONST = re.compile(
    r"""(?m)^(?:export\s+)?(?:(?:const|let|var)\s+)?(?P<name>[A-Za-z_]\w*)\s*"""
    r"""(?::[^=\n]+)?=\s*['"](?P<value>[^'"\n{}]+)['"]\s*;?\s*$"""
)
_DEF = re.compile(
    r"(?m)^[ \t]*(?:async\s+)?(?:def|function)\s+(?P<fn>[A-Za-z_]\w*)\s*"
    r"\((?P<params>[^)]*)\)"
)


def _split_args(args: str) -> list[str]:
    """Top-level comma-separated arguments of a (masked) argument text."""
    out, depth, cur = [], 0, []
    for ch in args:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return [a.strip() for a in out]


class ProjectIndex:
    """What the repository names across files, for model arguments that are not
    literals at the call (review 6063080163 of #498, R4-M3): module-level string
    constants (``MODEL = "qwen2.5:7b"`` in cfg.py, imported where the call is) and
    the string literals a wrapper is called with one hop away (``ask("mistral:7b")``
    for ``def ask(m, q): return ollama.chat(model=m)``)."""

    def __init__(self, files: list[tuple[str, str]]) -> None:
        self.files = files
        # module-level dicts / constants and settings classes (review 6065595627
        # of #498, R6-M2)
        self.literals = ProjectLiterals(files)
        self.constants: dict[str, str] = {}
        for _source, text in files:
            code, _bare = mask(text, "py")
            for m in _MODULE_CONST.finditer(code):
                self.constants.setdefault(m.group("name"), m.group("value"))

    def imported_constant(self, code: str, value: str) -> bool:
        """``MODEL`` imported from another module of the repository (``from cfg
        import MODEL``), or ``cfg.MODEL`` with ``import cfg``, that assigns it a
        literal."""
        name = value.rsplit(".", 1)[-1]
        if name not in self.constants:
            return False
        if "." in value:
            mod = value.rsplit(".", 1)[0]
            return bool(re.search(rf"\bimport\s+[\w., ]*\b{re.escape(mod)}\b", code))
        return bool(re.search(
            rf"(?m)^\s*from\s+[\w.]+\s+import\s+[^\n]*\b{re.escape(name)}\b|"
            rf"\bimport\s*\{{[^}}]*\b{re.escape(name)}\b", code))

    def wrapper_called_with_literal(self, code: str, value: str, pos: int) -> bool:
        """``value`` is a parameter of the function the call is in, and some call of
        that function in the repository passes a string literal for it."""
        defs = [d for d in _DEF.finditer(code) if d.start() < pos]
        if not defs:
            return False
        d = defs[-1]
        params = [
            p.split(":")[0].split("=")[0].strip().lstrip("*")
            for p in d.group("params").split(",")
        ]
        if value not in params:
            return False
        method = bool(params) and params[0] in ("self", "cls")
        idx = params.index(value) - (1 if method else 0)
        call = re.compile(rf"(?<![\w.]){re.escape(d.group('fn'))}\s*\(")
        attr_call = re.compile(rf"\.{re.escape(d.group('fn'))}\s*\(")
        for _source, text in self.files:
            code2, bare2 = mask(text, "py")
            for m in list(call.finditer(bare2)) + list(attr_call.finditer(bare2)):
                head = bare2[bare2.rfind("\n", 0, m.start()) + 1 : m.start()]
                if re.search(r"\b(?:def|function)\s*$", head):
                    continue
                args = call_arguments(bare2, m.end() - 1)
                if args is None:
                    continue
                raw = _split_args(code2[m.end() : m.end() + len(args)])
                kw = [a for a in raw if re.match(rf"{re.escape(value)}\s*=", a)]
                pick = kw[0].split("=", 1)[1].strip() if kw else (
                    raw[idx] if 0 <= idx < len(raw) and "=" not in raw[idx] else "")
                if pick[:1] in "'\"" and pick[-1:] == pick[:1] and len(pick) > 2:
                    return True
        return False


_INDEX: list[ProjectIndex] = []  # the index of the scan in progress


def _config_model(code: str, value: str, pos: int = -1) -> str | None:
    """The configuration key a non-literal model argument reads (``M`` for
    ``os.environ["M"]``, ``settings.MODEL`` …), "" for another expression, or None
    when the model is in fact known: a string literal, a default that names a model
    (``os.getenv(KEY, "<model>")``, an argparse ``default=``), a variable the file
    assigns a literal to (the model-reference scanner reads those), or a lookup the
    project's literals resolve (``OPTIONS["fast"]``, ``settings.llm_model``; a dynamic
    key's candidates are listed by the model-reference scan: review 6065595627 of
    #498, R6-M2)."""
    if not value:
        return None
    template = value[0] == "`" and "${" in value
    if re.match(r"""(?:[rRbB]?[fF]|[fF][rR])['"]""", value) or template:
        return ""  # an f-string / template literal: built at run time (review nit)
    if value[0] in "'\"`":
        return None
    literals = _STRING.findall(value)
    if literals and re.search(r"['\"]\s*\+|\+\s*['\"]", value):
        return ""  # a concatenation ("gpt-" + version): built at run time
    target = follow(value, code)
    if target != value:
        # ``M = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")`` then ``model=M``: the
        # assignment decides, so the default and the call are one model (m1)
        return _config_model(code, target, pos)
    if re.fullmatch(r"[A-Za-z_]\w*", value) and re.search(
        rf"(?m)^\s*(?:(?:export\s+)?(?:const|let|var)\s+)?{re.escape(value)}\s*"
        rf"(?::[^=\n]+)?=\s*['\"`]", code
    ):
        return None  # a variable the file assigns a literal to
    if _INDEX and looks_like_lookup(value) and _INDEX[-1].literals.resolve(value, code):
        return None
    env = _ENV_KEY.search(value)
    # a literal in the expression names the model only when it IS a model name (a
    # dict key ``CFG["m"]`` or ``cfg.get("m")`` does not)
    if any(is_model_name(lit[1:-1]) for lit in literals):
        return None
    if _argparse_default(code, value):
        return None  # ``args.model`` with ``add_argument("--model", default=…)``
    if _INDEX and not env and (
        _INDEX[-1].imported_constant(code, value)
        or (pos >= 0 and _INDEX[-1].wrapper_called_with_literal(code, value, pos))
    ):
        return None  # named elsewhere in the repository: the model-ref scan reads it
    if env:
        return env.group("key")
    return ""


_ADD_ARGUMENT = re.compile(r"\.add_argument\s*\(")


def _argparse_default(code: str, value: str) -> bool:
    """``args.model`` / ``a.model_name`` is an argparse option the file declares
    with a literal model ``default=`` (``add_argument("--model-name", default=…)``):
    the default and the call are one model (review 6065595627 of #498, m1)."""
    m = re.fullmatch(r"[A-Za-z_]\w*\.(?P<dest>[A-Za-z_]\w*)", value.strip())
    if m is None:
        return False
    dest = m.group("dest")
    _code, bare = mask(code, "py")
    for call in _ADD_ARGUMENT.finditer(bare):
        args = call_arguments(bare, call.end() - 1)
        if args is None:
            continue
        span = code[call.end() : call.end() + len(args)]
        names = re.findall(r"""['"](-{1,2}[\w-]+)['"]""", span)
        dests = re.findall(r"""\bdest\s*=\s*['"](\w+)['"]""", span)
        longs = [n for n in names if n.startswith("--")] or names
        own = dests[0] if dests else (longs[0].lstrip("-").replace("-", "_")
                                       if longs else "")
        if own != dest:
            continue
        default = re.search(r"""\bdefault\s*=\s*['"]([^'"]+)['"]""", span)
        return bool(default and is_model_name(default.group(1)))
    return False


def _model_value(code: str, bare: str, open_paren: int) -> str | None:
    """The model argument's expression; "" with no model argument; None when the
    arguments cannot be read or a ``**kwargs`` / spread may name the model."""
    args = call_arguments(bare, open_paren)
    if args is None or _SPREAD.search(args):
        return None
    m = _MODEL_VALUE.search(args)
    if m is None:
        return ""
    return _arg_value(code, open_paren + 1 + m.end())


def _model_calls(code: str, bare: str):  # noqa: ANN202 - a generator of tuples
    """``(client class, call match, model expression)`` for each model client call
    of a file: LangChain wrappers and direct SDK calls (see :func:`_model_value`)."""
    if _LANGCHAIN_IMPORT_RE.search(code):
        for m in _LANGCHAIN_MODEL_CLASSES.finditer(bare):
            head = bare[bare.rfind("\n", 0, m.start()) + 1 : m.start()]
            if _DEFINITION.search(head):
                continue
            yield m.group("cls"), m, _model_value(code, bare, m.end() - 1)
    for call_re, cls, imp in _SDK_MODEL_CALLS:
        if not imp.search(code):
            continue
        for m in call_re.finditer(bare):
            yield cls, m, _model_value(code, bare, m.end() - 1)


def unidentified_calls(text: str, source: str) -> list[tuple[str, str, str]]:
    """``[(client class, reason, call text)]``: model clients the file uses without
    naming the model: a LangChain wrapper built with no model argument (the
    library's default model applies), or any model argument that is not a literal
    (``ChatOpenAI(model=os.environ["M"])``, ``client.chat.completions.create(
    model=settings.MODEL)``: the model comes from configuration; review 6062066749
    of #498, M4). Readable arguments only; ``**kwargs`` / spread may name one."""
    code, bare = mask(text, language_of(source))
    out: list[tuple[str, str, str]] = []
    for cls, m, value in _model_calls(code, bare):
        if value is None:
            continue
        if not value:
            if cls not in _SDK_LIBRARY_CLASSES:
                args = call_arguments(bare, m.end() - 1) or ""
                first = args.split(",", 1)[0].strip()
                if first and "=" not in first and ":" not in first:
                    continue  # a positional first argument may be the model
                out.append((cls, _REASON_DEFAULT, f"{cls}()"))
            continue  # an SDK call with no model argument: not one the scan can judge
        if _config_model(code, value, m.end() - 1) is None:
            continue
        if cls in _SDK_LIBRARY_CLASSES:
            label = "chat" if cls == "Ollama" else "create"
            out.append((cls, _REASON_CONFIG, f"{cls} {label}(model={value[:60]})"))
        else:
            out.append((cls, _REASON_CONFIG, f"{cls}(model={value[:60]})"))
    return out


_SDK_LIBRARY_CLASSES = frozenset(cls for _re, cls, _imp in _SDK_MODEL_CALLS)


def lookup_model_calls(
    text: str, source: str, literals: ProjectLiterals
) -> list[tuple[str, list[str], bool, str]]:
    """``[(client class, model names, exact, call text)]``: model calls whose model
    argument is a lookup the project's literals resolve (review 6065595627 of #498,
    R6-M2): ``OPTIONS["fast"]`` gives its value (exact); ``OPTIONS[choice]`` gives
    every model the dict holds (candidates). The model-reference scan records them
    as models in use of that call; :func:`_config_model` then adds no unidentified
    model for the same call."""
    code, bare = mask(text, language_of(source))
    out: list[tuple[str, list[str], bool, str]] = []
    for cls, m, value in _model_calls(code, bare):
        if not value:
            continue
        target = follow(value, code)
        if not looks_like_lookup(target):
            continue
        got = literals.resolve(target, code)
        if got is None:
            continue
        callee = re.search(r"[\w.]+$", code[: m.end() - 1])
        head = callee.group(0) if callee else cls
        out.append((cls, got[0], got[1], f"{head}(model={value[:60]})"))
    return out


def unnamed_model_calls(text: str, source: str) -> list[str]:
    """The calls of :func:`unidentified_calls` (``"ChatOpenAI()"``)."""
    return [call for _cls, _reason, call in unidentified_calls(text, source)]


def unidentified_models(
    calls: list[tuple[str, str, str, str]], library: dict[str, str] | None = None
) -> list[ModelComponent]:
    """One low-confidence model entry per client class in the scan (review
    6062066749 of #498, m1): ``unidentified model (ChatOpenAI)``, with every call
    site as evidence. ``calls`` = ``[(class, reason, call text, source file)]``. The
    checks read ``model:identified = false`` as "needs information", never as a
    pass or as "no AI model"."""
    by_cls: dict[str, list[tuple[str, str, str]]] = {}
    for cls, reason, call, source in calls:
        by_cls.setdefault(cls, []).append((reason, call, source))
    out: list[ModelComponent] = []
    for cls in sorted(by_cls):
        sites = by_cls[cls]
        vendor = next((v for pat, v in _UNNAMED_VENDOR if pat.search(cls)), "unknown")
        reasons = sorted({r for r, _c, _s in sites})
        sources = sorted({s for _r, _c, s in sites})
        keys = sorted({
            k.group("key") for _r, c, _s in sites if (k := _ENV_KEY.search(c))
        })
        props = {
            "model:reference_type": "usage",
            "model:identified": "false",
            "model:unidentified_reason": "; ".join(reasons),
            "discovery:source": sites[0][2],
            "discovery:sources": ",".join(sources),
            "discovery:method": "model-not-named",
            "discovery:confidence": "low",
            "discovery:snippet": "; ".join(f"{c} in {s}" for _r, c, s in sites[:20]),
        }
        if keys:
            props["model:config_keys"] = ",".join(keys)
        if vendor == "local":
            props["model:served_via"] = "ollama"
        comp = ModelComponent(
            bom_ref="modelref-unidentified-" + re.sub(r"[^a-z0-9]+", "-", cls.lower()),
            name=f"unidentified model ({cls})",
            publisher=None if vendor in ("unknown", "local") else vendor,
            licenses=[license_choice("LicenseRef-proprietary")]
            if vendor in _HOSTED_TERMS
            else None,
            properties=props,
        )
        comp.model_card.task = "text-embedding" if "Embeddings" in cls else (
            "chat/completion")
        out.append(comp)
    return out


# Azure OpenAI: always Azure (never the OpenAI API); the endpoint is the literal
# ``azure_endpoint`` when there is one, else unknown, with the environment variable
# that holds it recorded (review 6037909737 of #498, M2)
_AZURE_IMPORT = re.compile(
    r"""(?:^|\n)\s*(?:from\s+openai\b|import\s+openai\b)|from\s+['"]openai['"]|"""
    r"""from\s+['"]@azure/openai['"]|""" + _LANGCHAIN_IMPORT,
    re.IGNORECASE,
)
# the SDK's AzureOpenAI and LangChain's AzureChatOpenAI / AzureOpenAIEmbeddings
_AZURE_CALL = re.compile(
    r"(?<!\w)(?:new\s+)?(?:(?:Async)?AzureOpenAI|AzureChatOpenAI|AzureOpenAIEmbeddings)"
    r"\s*\("
)
_AZURE_ENDPOINT = re.compile(
    r"""\b(?:azure_endpoint|endpoint|baseURL)\s*[=:]\s*(?:['"](?P<url>https?://[^'"]+)['"]|"""
    r"""(?:os\.environ(?:\.get)?\s*[\[(]|os\.getenv\s*\(|process\.env\.)\s*['"]?"""
    r"""(?P<env>[A-Z][A-Z0-9_]*))"""
)
# An OpenAI-compatible gateway the code points a client at by a literal base URL
# (a LiteLLM / vLLM / internal proxy): a service of its own, so the models behind it
# read as served by that gateway, not as local (review 6037909737 of #498, m4). A
# known vendor host is left to the host patterns above.
_LITERAL_BASE = re.compile(
    r"""\b(?:base_url|api_base|baseURL|openai_api_base)['"]?\s*[=:]\s*['"]"""
    r"""(?P<url>https?://[^'"\s]+)['"]"""
)
# ``import os, openai`` names the SDK as much as ``import openai`` (review 6063080163
# of #498, m6): every ``import\s+<sdk>`` also matches a comma-separated import list
_IMPORT_LIST = r"import\s+(?:[\w.]+\s*(?:as\s+\w+\s*)?,\s*)*"
_SDK_RES = [
    (re.compile(imp.replace(r"import\s+", _IMPORT_LIST), re.IGNORECASE),
     re.compile(call), label, vendor, endpoint)
    for imp, call, label, vendor, endpoint in _SDK_CLIENTS
]
# A ``**kwargs`` / ``...spread`` argument: the base URL may be in it, so it is unknown
_SPREAD = re.compile(r"(?<![\w*])\*\*\s*\w|\.\.\.\s*\w")
_OTHER_BASE = re.compile(
    r"\b(?:base_url|baseURL|api_base|openai_api_base|anthropic_api_url|vertexai)"
    r"\s*[=:]",
    re.IGNORECASE,
)
_DEFINITION = re.compile(r"\b(?:class|def|function|interface|type)\s+$")
# module-level configuration that points the legacy SDK elsewhere (openai.api_base = …)
_MODULE_BASE = re.compile(r"\bopenai\.(?:api_base|base_url)\s*=")
# Anthropic's Bedrock / Vertex clients are those platforms, never the Anthropic API.
_ANTHROPIC_BEDROCK = re.compile(r"(?<!\w)(?:new\s+)?(?:Async)?AnthropicBedrock\s*\(")
_ANTHROPIC_VERTEX = re.compile(r"(?<!\w)(?:new\s+)?(?:Async)?AnthropicVertex\s*\(")
# A bare ``localhost:8000`` is any development web server, not necessarily an
# inference endpoint: recorded, at low confidence.
_LOW_CONFIDENCE_HOSTS = frozenset({"localhost:8000"})

# the vendor host patterns alone, for telling a gateway host from a vendor host
_HOST_RES_BARE = [(re.compile(pat, re.IGNORECASE), kind) for pat, kind, *_r in _HOSTS]
_HOST_RES = [
    (
        re.compile(rf"(?<![\w.-])(?:(?P<scheme>https?)://(?:[^\s/?#@'\"`<>]*@)?)?"
                   rf"(?P<host>{pat})"
                   r"(?P<path>/[^\s'\"`<>)\]},;]*)?", re.IGNORECASE),
        kind,
        label,
        vendor,
        auth,
    )
    for pat, kind, label, vendor, auth in _HOSTS
]

# JS / TS route and module files too: a Next.js route calling an SDK is a .tsx / .mjs
# file (review 6037909737 of #498, m5)
_SUFFIXES = {".env", ".py", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs", ".mts",
             ".cts", ".ipynb",
             ".yaml", ".yml", ".toml", ".sh", ".cfg"}
_LOOPBACK = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]")
# An API version path segment: v1, v2, v1beta, v1alpha2, v2preview, 2023-05-15. Only
# the real version words may follow the number, so a key-shaped segment such as
# ``v2abcdefFAKEghij123`` is not taken for a version (second review of #487, m-a).
_VERSION_SEGMENT = re.compile(
    r"^(?:v\d+(?:(?:alpha|beta|preview)\d*)?|\d{4}-\d{2}-\d{2})$", re.IGNORECASE
)


def _scan_files(root: Path) -> list[Path]:
    return walk_files(
        root, keep=lambda p: is_env_file(p) or p.suffix.lower() in _SUFFIXES
    )


def base_url(scheme: str | None, host: str, path: str | None) -> str:
    """The service's base URL: scheme, host[:port] and the leading version segments.

    User information is never part of ``host`` (the pattern consumes it before the
    host); the query string and fragment are dropped, and the path stops at the
    first segment that is not an API version, so ``?key=…`` (Gemini),
    ``api-key=…`` (Azure) or a token in a later path segment never reaches the
    BOM.
    """
    host = host.lower()
    local = host.startswith(_LOOPBACK)
    scheme = (scheme or ("http" if local else "https")).lower()
    raw = re.split(r"[?#]", path or "", maxsplit=1)[0]
    kept: list[str] = []
    for segment in raw.split("/"):
        if not segment:
            continue
        if not _VERSION_SEGMENT.match(segment):
            break
        kept.append(segment.lower())
    return f"{scheme}://{host}" + "".join(f"/{s}" for s in kept)


def _endpoint(match: re.Match[str]) -> str:
    """The base URL of a matched host (see :func:`base_url`)."""
    return base_url(match.group("scheme"), match.group("host"), match.group("path"))


def _ref(kind: str, host: str) -> str:
    """``<kind>-<host slug>``, stable across scans (cloud_service-api-openai-com)."""
    return f"{kind}-" + re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")


def _component(
    kind: str,
    label: str,
    vendor: str,
    auth: bool | None,
    endpoint: str | None,
    source: str,
    host: str | None = None,
) -> CloudServiceComponent | EndpointComponent:
    """One service. ``endpoint`` None: the scan saw the service (an SDK client) but
    not its URL, so none is recorded; ``host`` then names the service for its ref."""
    if endpoint is not None:
        host = endpoint.split("://", 1)[-1].split("/", 1)[0]
    host = host or label.lower()
    props = {
        "discovery:source": source,
        "service:trust_zone": "local" if host.startswith(_LOOPBACK) else "external",
    }
    if endpoint is not None:
        props["discovery:host"] = host
        props["service:endpoint"] = endpoint
    if host in _LOW_CONFIDENCE_HOSTS:
        props["discovery:confidence"] = "low"
    if auth is not None:
        props["service:authenticated"] = "true" if auth else "false"
    cls = EndpointComponent if kind == "endpoint" else CloudServiceComponent
    return cls(
        bom_ref=_ref(kind, host),
        name=label,
        publisher=vendor,
        properties=props,
    )


@register
class NetEnvScanner(Scanner):
    name = "net-env"
    level = 3
    order = 31

    def matches(self, root: Path) -> bool:
        return bool(_scan_files(root))

    def scan(self, ctx: ScanContext) -> None:
        seen: set[str] = set()
        excluded: set[str] = set()  # refs named only in test / example files
        # model clients that name no model: (class, reason, call, file)
        unnamed: list[tuple[str, str, str, str]] = []
        files: list[tuple[Path, str, str]] = []
        for path in _scan_files(ctx.root):
            text = read_text(path)
            if text is None:
                continue
            try:
                source = path.relative_to(ctx.root).as_posix()
            except ValueError:
                source = path.name
            if path.suffix.lower() == ".ipynb":
                # a notebook's code cells (review 6062066749 of #498, m4)
                text, readable = notebook_text(text)
                if not readable:
                    ctx.unreadable_notebooks.add(path.name)
            files.append((path, text, source))
        # OLLAMA_HOST and other endpoints set in env / compose files (M1)
        env = env_values([(src, t) for _p, t, src in files], ctx.root.name)
        index = ProjectIndex(
            [(src, t) for p_, t, src in files
             if p_.suffix.lower() not in (".yaml", ".yml") and not is_env_file(p_)])
        # lookups resolve against application code only (not tests or examples)
        index.literals = ProjectLiterals([
            (src, t) for p_, t, src in files
            if not (is_test_path(p_, ctx.root) or is_example_path(p_, ctx.root))])
        _INDEX.append(index)
        try:
            self._scan_files(ctx, files, env, seen, excluded, unnamed)
        finally:
            _INDEX.pop()
        _merge_ollama_rows(ctx)
        excluded -= seen
        if excluded:
            ctx.properties["aibom:services_excluded_test_example"] = str(len(excluded))
        if not unnamed:
            return
        for model in unidentified_models(unnamed):
            if not ctx.has_ref(model.bom_ref):
                ctx.add_component(model)
        unnamed_calls = [f"{call} in {source}" for _c, _r, call, source in unnamed]
        if unnamed_calls:
            # stated, never guessed: the library's default model applies
            ctx.properties["aibom:model_unnamed_calls"] = str(len(unnamed_calls))
            ctx.properties["aibom:model_unnamed_detail"] = "; ".join(unnamed_calls[:20])
            ctx.properties["aibom:model_unnamed_classes"] = ",".join(
                sorted({c for c, _r, _call, _s in unnamed}))

    @staticmethod
    def _scan_files(ctx, files, env, seen, excluded, unnamed) -> None:  # noqa: ANN001
        for path, text, source in files:
            # an env template (``.env.example``) documents settings: never a service
            # row of its own (review 6065595627 of #498, R6-M1)
            not_app = (is_test_path(path, ctx.root) or is_example_path(path, ctx.root)
                       or is_env_template(path))
            lang_source = source[: -len(".ipynb")] + ".py" if source.endswith(
                ".ipynb") else source
            if not not_app:
                for cls, reason, call in unidentified_calls(text, lang_source):
                    unnamed.append((cls, reason, call, source))
            found = _services_in(text, lang_source, env)
            for comp in found:
                comp.properties["discovery:source"] = source
                if comp.properties.get("service:endpoint_basis") == "unknown" and (
                    comp.properties.get("service:kind") == "gateway"
                ) and not not_app:
                    ctx.opaque_client_files.add(source)
            for comp in found:
                if not not_app:
                    ctx.service_files.setdefault(comp.bom_ref, set()).add(source)
                if comp.bom_ref in seen or ctx.has_ref(comp.bom_ref):
                    continue
                if not_app:
                    excluded.add(comp.bom_ref)
                    continue
                seen.add(comp.bom_ref)
                ctx.add_component(comp)


def _merge_ollama_rows(ctx: ScanContext) -> None:
    """One row per Ollama server (review 6065595627 of #498, m3).

    * The compose ``ollama/ollama`` container the application reaches by its service
      name (``OLLAMA_HOST: http://ollama:11434``) IS that server: the container row
      is folded into the server row, which keeps the image and the runtime licence.
    * When the deployment sets OLLAMA_HOST to different hosts, a host-only row that a
      config file's value produced (``127.0.0.1:11434`` in a manifest) is no server
      the application is known to use: the "endpoint unknown" row lists it."""
    comps = ctx.components
    servers = [c for c in comps if c.kind in ("endpoint", "cloud_service") and (
        (c.properties or {}).get("service:platform") == "ollama"
        or PROVIDER_KEY.get(c.name) == "ollama")]
    drop: set[str] = set()
    for box in [c for c in comps if c.kind == "container"
                and (c.properties or {}).get("service:platform") == "ollama"]:
        name = (box.properties or {}).get("discovery:compose_service", "").lower()
        if not name:
            continue
        for server in servers:
            host = (server.properties or {}).get("discovery:host", "").lower()
            if host.rsplit(":", 1)[0] == name:
                server.properties = {
                    **(server.properties or {}),
                    "discovery:image": (box.properties or {}).get(
                        "discovery:image", ""),
                    "discovery:compose_service": name,
                }
                if box.licenses and not server.licenses:
                    server.licenses = box.licenses
                drop.add(box.bom_ref)
                break
    candidates = {
        _split_url(v.strip())[0].lower()
        for c in servers
        if (c.properties or {}).get("service:endpoint_basis") == "conflicting"
        for v in (c.properties or {}).get("service:endpoint_candidates", "").split(",")
        if v.strip()
    }
    for server in servers:
        props = server.properties or {}
        source = props.get("discovery:source", "")
        if (candidates and props.get("service:endpoint_basis") is None
                and props.get("discovery:host", "").lower() in candidates
                and source.lower().endswith((".yaml", ".yml", ".env"))
                and not ctx.service_files.get(server.bom_ref, set()) - {source}):
            drop.add(server.bom_ref)
    if drop:
        ctx.components[:] = [c for c in comps if c.bom_ref not in drop]


def _default_client_called(
    code: str, bare: str, call: re.Pattern[str], label: str
) -> bool:
    """Whether the file constructs / calls the SDK client at its default base URL.

    ``code`` / ``bare`` are the file with comments (and, in ``bare``, string
    contents) masked (:func:`aibom.scan.parsers.code_text.mask`): a commented-out
    ``# client = OpenAI()`` is not a call. The arguments are read to the balanced
    closing parenthesis; arguments that cannot be read, or a ``**kwargs`` /
    ``...spread`` argument, may carry another base URL, so they never claim the
    vendor's default endpoint (review 6037909737 of #498, M1)."""
    if label == "OpenAI API" and _MODULE_BASE.search(code):
        return False
    for m in call.finditer(bare):
        head = bare[bare.rfind("\n", 0, m.start()) + 1 : m.start()]
        if _DEFINITION.search(head):
            continue  # ``class MistralClient(BaseClient):`` defines, never calls
        args = call_arguments(bare, m.end() - 1)
        if args is None or _SPREAD.search(args) or _OTHER_BASE.search(args):
            continue
        return True
    return False


def _azure_services(
    code: str, bare: str, source: str
) -> list[CloudServiceComponent | EndpointComponent]:
    out: list[CloudServiceComponent | EndpointComponent] = []
    if not (_AZURE_IMPORT.search(code) and _AZURE_CALL.search(bare)):
        return out
    for m in _AZURE_CALL.finditer(bare):
        args_bare = call_arguments(bare, m.end() - 1)
        if args_bare is None:
            continue
        args = code[m.end() : m.end() + len(args_bare)]
        found = _AZURE_ENDPOINT.search(args)
        if found and found.group("url"):
            endpoint = base_url(None, *_split_url(found.group("url")))
            comp = _component("cloud_service", "Azure OpenAI", "Microsoft", True,
                              endpoint, source)
        else:
            comp = _component("cloud_service", "Azure OpenAI", "Microsoft", True, None,
                              source, host="azure-openai")
            if found and found.group("env"):
                comp.properties["service:endpoint_env"] = found.group("env")
        comp.properties["discovery:method"] = "sdk-client"
        out.append(comp)
    return out


OLLAMA_CLOUD_REF = "cloud_service-ollama-com"
_OLLAMA_CLOUD_HOSTS = ("ollama.com", "www.ollama.com")
_POSITIONAL_HOST_CTOR = re.compile(r"(?:ollama\.)?(?:Async)?Client\s*\($")
_HOST_KWARG = re.compile(r"\b(?:host|base_url|baseUrl)\s*[=:]\s*")
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1")
_ENV_REF = re.compile(
    r"""(?:os\.environ(?:\.get)?\s*[\[(]|os\.getenv\s*\(|getenv\s*\()\s*['"]"""
    r"""(?P<a>[A-Z_][A-Z0-9_]*)['"]|process\.env\.(?P<b>[A-Z_][A-Z0-9_]*)"""
)
_ENV_ASSIGN = re.compile(
    r"""(?m)^\s*(?:export\s+|-\s+)?(?P<k>[A-Z_][A-Z0-9_]*)\s*[=:]\s*['"]?"""
    r"""(?P<v>[^\s'"#]+)"""
)


def ollama_cloud_service(source: str) -> CloudServiceComponent | EndpointComponent:
    """Ollama's hosted service (ollama.com: ``-cloud`` tags, or a client whose host
    is ollama.com): outside the trust boundary."""
    comp = _component("cloud_service", "Ollama Cloud", "Ollama", True,
                      "https://ollama.com", source)
    comp.properties["service:platform"] = "ollama-cloud"
    comp.properties["discovery:method"] = "sdk-client"
    return comp


_K8S_ENV = re.compile(
    r"""-\s*name:\s*['"]?(?P<k>[A-Z_][A-Z0-9_]*)['"]?\s*\n\s*value:\s*['"]?"""
    r"""(?P<v>[^\s'"#]+)"""
)
_CODE_ENV_SET = re.compile(
    r"""os\.environ\s*\[\s*['"](?P<k>[A-Z_][A-Z0-9_]*)['"]\s*\]\s*=\s*['"](?P<v>[^'"]+)['"]|"""
    r"""os\.environ\.setdefault\s*\(\s*['"](?P<k2>[A-Z_][A-Z0-9_]*)['"]\s*,\s*"""
    r"""['"](?P<v2>[^'"]+)['"]|"""
    r"""os\.putenv\s*\(\s*['"](?P<k3>[A-Z_][A-Z0-9_]*)['"]\s*,\s*['"](?P<v3>[^'"]+)['"]|"""
    r"""process\.env\.(?P<k4>[A-Z_][A-Z0-9_]*)\s*=\s*['"](?P<v4>[^'"]+)['"]"""
)
_EXAMPLE_FILE = re.compile(
    r"\.(?:example|sample|template|dist|tmpl)$|\.(?:example|sample|template)\.",
    re.IGNORECASE,
)
EXAMPLE = "@example"  # env key suffix: a value from an example / template file


# env key suffix: the deployment sets the name to different values
CONFLICT = "@conflict"

#: workload names that are the application itself (a container / compose service
#: that runs the repository's code), besides the repository's own name
_APP_NAMES = frozenset({"app", "api", "web", "server", "backend", "worker", "main",
                        "service", "application"})
_WORKLOAD_KINDS = ("containers:", "services:")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _is_app(name: object, image: object, built: bool, repo: str) -> bool:
    """A Kubernetes container / compose service runs the repository's code: it is
    built from the repository, or its name or image names the repository or a
    generic application role (review 6063929550 of #498, m1). An unrelated tool's
    container (Open WebUI, a gateway) does not configure the application."""
    if built:
        return True
    repo_slug = _slug(repo)
    image_name = str(image or "").rsplit("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
    for cand in (str(name or ""), image_name):
        slug = _slug(cand)
        if not slug:
            continue
        if cand.lower() in _APP_NAMES or (
            repo_slug and (repo_slug in slug or slug in repo_slug)
        ):
            return True
    return False


def _container_env(env: object) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(env, list):
        for item in env:
            if isinstance(item, dict) and isinstance(item.get("name"), str) \
                    and isinstance(item.get("value"), (str, int, float)):
                out.append((item["name"], str(item["value"])))
            elif isinstance(item, str) and "=" in item:
                k, _, v = item.partition("=")
                out.append((k.strip(), v.strip()))
    elif isinstance(env, dict):
        out += [(str(k), str(v)) for k, v in env.items()
                if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
    return out


def _workload_env(text: str, repo: str) -> list[tuple[str, str]] | None:
    """``[(NAME, value)]`` from the app workloads of a Kubernetes manifest or a
    compose file, None when the file is neither (or does not parse: a Helm
    template keeps the plain reading)."""
    if not any(k in text for k in _WORKLOAD_KINDS):
        return None
    import yaml

    try:
        docs = list(yaml.safe_load_all(text))
    except (yaml.YAMLError, ValueError, RecursionError):
        return None  # a Helm template / broken YAML keeps the plain reading
    if not docs:
        return None
    found = False
    out: list[tuple[str, str]] = []
    visited: set[int] = set()  # an alias is walked once (no billion-laughs walk)

    def containers(node: object, depth: int = 0) -> None:
        nonlocal found
        if depth > 12 or id(node) in visited:
            return
        visited.add(id(node))
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("containers", "initContainers") and isinstance(value, list):
                    found = True
                    for c in value:
                        if isinstance(c, dict) and _is_app(
                            c.get("name"), c.get("image"), False, repo
                        ):
                            out.extend(_container_env(c.get("env")))
                elif isinstance(value, (dict, list)):
                    containers(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                containers(item, depth + 1)

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        services = doc.get("services")
        if isinstance(services, dict) and all(
            isinstance(v, dict) for v in services.values()
        ):
            found = True
            for name, svc in services.items():
                if _is_app(name, svc.get("image"), "build" in svc, repo):
                    out.extend(_container_env(svc.get("environment")))
            continue
        containers(doc)
    return out if found else None


def env_values(files: list[tuple[str, str]], repo: str = "") -> dict[str, str]:
    """``NAME -> literal value`` that configures the deployment: env and compose
    files, Kubernetes / Helm ``env`` name / value pairs and ``values.yaml`` keys, and
    in-code ``os.environ[NAME] = …`` / ``setdefault`` / ``putenv`` (review
    6063080163 of #498, R4-M4). A value from an example / template file
    (``.env.example``, ``.sample``, ``.template``) is not the deployment's: it is
    kept as ``NAME@example``, a default at most.

    Only the workloads that are the application configure it: a Kubernetes
    container or compose service of an unrelated tool is skipped. A name the
    deployment sets to different values is ``NAME@conflict`` (the values, comma
    separated), never one of them picked silently (review 6063929550 of #498, m1)."""
    seen: dict[str, list[str]] = {}

    def put(key: str, value: str) -> None:
        values = seen.setdefault(key, [])
        if value not in values:
            values.append(value)

    for name, text in files:
        example = bool(_EXAMPLE_FILE.search(name))
        suffix = EXAMPLE if example else ""
        if name.endswith((".py", ".js", ".ts", ".mjs", ".cjs", ".ipynb")):
            for m in _CODE_ENV_SET.finditer(text):
                k = m.group("k") or m.group("k2") or m.group("k3") or m.group("k4")
                v = m.group("v") or m.group("v2") or m.group("v3") or m.group("v4")
                put(k + suffix, v)
            continue
        workload = (_workload_env(text, repo)
                    if name.lower().endswith((".yaml", ".yml")) else None)
        if workload is not None:
            for k, v in workload:
                if re.fullmatch(r"[A-Z_][A-Z0-9_]*", k) and v and not v.startswith("$"):
                    put(k + suffix, v)
            continue
        for m in _K8S_ENV.finditer(text):
            put(m.group("k") + suffix, m.group("v"))
        for m in _ENV_ASSIGN.finditer(text):
            put(m.group("k") + suffix, m.group("v"))
    out: dict[str, str] = {}
    for key, values in seen.items():
        if len(values) == 1 or key.endswith(EXAMPLE):
            out[key] = values[0]
        else:
            out[key + CONFLICT] = ", ".join(values)
    return out


def _ollama_server(
    host_value: str | None,
    basis: str,
    source: str,
    env_name: str | None = None,
    default: str | None = None,
    candidates: str | None = None,
) -> CloudServiceComponent | EndpointComponent:
    """The Ollama server a client talks to. ``host_value`` None: the endpoint is not
    known (a variable, an environment value the repository does not set): never the
    local default (review 6062066749 of #498, M1)."""
    if host_value is None:
        comp = _component("endpoint", "Ollama server (endpoint unknown)", "self-hosted",
                          None, None, source,
                          host=f"ollama-{(env_name or 'unknown').lower()}")
        comp.properties["service:trust_zone"] = "unknown"
        comp.properties["service:kind"] = "model_server"
        comp.properties["service:platform"] = "ollama"
        comp.properties["service:endpoint_basis"] = basis
        if env_name:
            comp.properties["service:endpoint_env"] = env_name
        if default:
            # the fallback the code (or an example file) gives: a default, not the
            # deployment's endpoint
            comp.properties["service:endpoint_default"] = default
        if candidates:
            # the hosts the deployment sets the variable to (review 6063929550, m1)
            comp.properties["service:endpoint_candidates"] = candidates
        return comp
    url = host_value if "://" in host_value else f"http://{host_value}"
    host, path = _split_url(url)
    if ":" not in host.rsplit("]", 1)[-1]:
        host = f"{host}:{443 if url.startswith('https') else 11434}"
    bare_host = host.rsplit(":", 1)[0].strip("[]").lower()
    if bare_host in _OLLAMA_CLOUD_HOSTS:
        return ollama_cloud_service(source)
    scheme = url.split("://", 1)[0].lower()
    endpoint = base_url(scheme, host, None)
    if bare_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        comp = _component("endpoint", "Ollama (local)", "local", False, endpoint,
                          source)
        comp.properties["service:trust_zone"] = "local"
    else:
        # a self-hosted / remote Ollama: a model server of its own, not this machine
        comp = _component("endpoint", f"Ollama server ({host.lower()})", "self-hosted",
                          None, endpoint, source)
        comp.properties["service:trust_zone"] = "external"
    comp.properties["service:kind"] = "model_server"
    comp.properties["service:platform"] = "ollama"
    comp.properties["service:endpoint_basis"] = basis
    if env_name:
        comp.properties["service:endpoint_env"] = env_name
    return comp


_OLLAMA_REST_URL = re.compile(
    r"https?://(?:[^\s/'\"@]*@)?(?:(?P<host>[A-Za-z0-9._-]+):11434"
    r"/api/(?:chat|generate|embed|embeddings|tags|pull|show)\b|(?P<bind>0\.0\.0\.0):11434)"
)


def _ollama_services(
    code: str, bare: str, source: str, env: dict[str, str]
) -> list[CloudServiceComponent | EndpointComponent]:
    """The Ollama servers a file's Ollama clients talk to (review 6062066749 of #498,
    M1). The host is read from a positional first argument of ``Client`` /
    ``AsyncClient``, a ``host=`` / ``base_url=`` / ``baseUrl:`` argument, or, for a
    client given none, ``OLLAMA_HOST`` (which ollama-python reads): from the
    repository's env files when set there, else the SDK default 127.0.0.1:11434. A
    host held in a variable or an environment value the repository does not set is
    "endpoint unknown", never local."""
    calls: list[re.Match[str]] = []
    if _OLLAMA_IMPORT.search(code):
        calls += list(_OLLAMA_CALL.finditer(bare))
        if _OLLAMA_FROM_CLIENT.search(code):
            calls += list(_OLLAMA_BARE_CLIENT.finditer(bare))
    if _LANGCHAIN_IMPORT_RE.search(code):
        calls += list(_LANGCHAIN_OLLAMA.finditer(bare))
    out: dict[str, CloudServiceComponent | EndpointComponent] = {}
    for m in sorted(calls, key=lambda x: x.start()):
        head = bare[bare.rfind("\n", 0, m.start()) + 1 : m.start()]
        if _DEFINITION.search(head):
            continue
        open_paren = m.end() - 1
        args = call_arguments(bare, open_paren)
        if args is None or _SPREAD.search(args):
            comp = _ollama_server(None, "unknown", source)
            out.setdefault(comp.bom_ref, comp)
            continue
        value: str | None = None
        kw = _HOST_KWARG.search(args)
        if kw is not None:
            value = _arg_value(code, open_paren + 1 + kw.end())
        elif _POSITIONAL_HOST_CTOR.search(bare[m.start() : m.end()]) and args.strip():
            first = args.split(",", 1)[0]
            if "=" not in first:
                lead = len(first) - len(first.lstrip())
                value = _arg_value(code, open_paren + 1 + lead)
        if value is None:
            # no host given: ollama-python reads OLLAMA_HOST, else 127.0.0.1:11434
            if "OLLAMA_HOST" + CONFLICT in env:
                # set to different hosts: which one runs is not known, never local
                comp = _ollama_server(None, "conflicting", source, "OLLAMA_HOST",
                                      candidates=env["OLLAMA_HOST" + CONFLICT])
            elif "OLLAMA_HOST" in env:
                comp = _ollama_server(env["OLLAMA_HOST"], "env-file", source,
                                      "OLLAMA_HOST")
            elif "OLLAMA_HOST" + EXAMPLE in env:
                # only an example file sets it: configurable, its value a default
                comp = _ollama_server(None, "example", source, "OLLAMA_HOST",
                                      env["OLLAMA_HOST" + EXAMPLE])
            else:
                comp = _ollama_server(_OLLAMA_DEFAULT, "sdk-default", source)
        elif value[:1] in "'\"`" and value[-1:] == value[:1]:
            comp = _ollama_server(value[1:-1], "literal", source)
        else:
            ref = _ENV_REF.search(value)
            name = (ref.group("a") or ref.group("b")) if ref else None
            if name and name + CONFLICT in env:
                comp = _ollama_server(None, "conflicting", source, name,
                                      candidates=env[name + CONFLICT])
            elif name and name in env:
                comp = _ollama_server(env[name], "env-file", source, name)
            else:
                # read from the environment at run time: unknown, its fallback
                # (``getenv("OLLAMA_HOST", "http://localhost:11434")``) only a default
                lit = _STRING.findall(value)
                fallback = lit[-1][1:-1] if len(lit) > 1 or (lit and not ref) else None
                if name and not fallback:
                    fallback = env.get(name + EXAMPLE)
                comp = _ollama_server(None, "unknown", source, name, fallback)
        out.setdefault(comp.bom_ref, comp)
    return list(out.values())


# LiteLLM routes a call by the model's provider prefix (docs.litellm.ai/docs/providers):
# ``ollama/<tag>`` / ``ollama_chat/<tag>`` go to an Ollama server, ``api_base`` when
# given, else ``OLLAMA_API_BASE``, else LiteLLM's default http://localhost:11434; a
# hosted prefix goes to that provider's API (review 6065595627 of #498, m2).
_LITELLM_IMPORT = re.compile(r"(?:^|\n)\s*(?:import\s+(?:[\w.]+\s*,\s*)*litellm\b|"
                             r"from\s+litellm\b)")
_LITELLM_CALL = re.compile(
    r"(?<![\w.])(?:litellm\.)?a?(?:completion|embedding|text_completion|"
    r"image_generation|transcription|responses)\s*\("
)
_LITELLM_MODEL = re.compile(
    r"""\bmodel\s*=\s*['"](?P<prov>[\w-]+)/(?P<rest>[^'"\s]+)['"]"""
)
_LITELLM_DEFAULT_OLLAMA = "http://localhost:11434"
#: LiteLLM provider prefix -> the hosted service it calls (label in ``_HOSTS``)
_LITELLM_HOSTED: dict[str, tuple[str, str, str]] = {
    "openai": ("OpenAI API", "OpenAI", "https://api.openai.com/v1"),
    "anthropic": ("Anthropic API", "Anthropic", "https://api.anthropic.com"),
    "gemini": ("Google Gemini API", "Google", "https://generativelanguage.googleapis.com"),
    "mistral": ("Mistral API", "Mistral", "https://api.mistral.ai"),
    "groq": ("Groq API", "Groq", "https://api.groq.com"),
    "together_ai": ("Together AI API", "Together AI", "https://api.together.xyz"),
    "deepseek": ("DeepSeek API", "DeepSeek", "https://api.deepseek.com"),
    "cohere": ("Cohere API", "Cohere", "https://api.cohere.com"),
    "cohere_chat": ("Cohere API", "Cohere", "https://api.cohere.com"),
    "xai": ("xAI API", "xAI", "https://api.x.ai"),
    "openrouter": ("OpenRouter API", "OpenRouter", "https://openrouter.ai"),
}


def _litellm_route(
    prov: str, api_base: str | None, env: dict[str, str], source: str,
    api_base_env: str | None = None,
) -> CloudServiceComponent | EndpointComponent | None:
    """The service one LiteLLM route calls (see the comment above)."""
    prov = prov.lower()
    if prov in ("ollama", "ollama_chat"):
        if api_base:
            # the Ollama server itself, never an OpenAI-compatible gateway
            return _ollama_server(api_base, "literal", source)
        if api_base_env:
            if api_base_env in env:
                return _ollama_server(env[api_base_env], "env-file", source,
                                      api_base_env)
            return _ollama_server(None, "unknown", source, api_base_env)
        if "OLLAMA_API_BASE" in env:
            return _ollama_server(env["OLLAMA_API_BASE"], "env-file", source,
                                  "OLLAMA_API_BASE")
        comp = _ollama_server(_LITELLM_DEFAULT_OLLAMA, "litellm-default", source)
        return comp
    hosted = _LITELLM_HOSTED.get(prov)
    if hosted is None or api_base or api_base_env:
        return None  # another base URL: the gateway / endpoint rules name it
    label, vendor, endpoint = hosted
    comp = _component("cloud_service", label, vendor, True, endpoint, source)
    comp.properties["discovery:method"] = "litellm-route"
    comp.properties["service:endpoint_basis"] = "sdk-default"
    return comp


def _litellm_services(
    code: str, bare: str, source: str, env: dict[str, str]
) -> list[CloudServiceComponent | EndpointComponent]:
    """The services LiteLLM calls in a file route to (``litellm.completion(model=
    "ollama/llama3:8b", api_base=…)``)."""
    out: list[CloudServiceComponent | EndpointComponent] = []
    if not _LITELLM_IMPORT.search(code):
        return out
    for m in _LITELLM_CALL.finditer(bare):
        head = bare[bare.rfind("\n", 0, m.start()) + 1 : m.start()]
        if _DEFINITION.search(head):
            continue
        args_bare = call_arguments(bare, m.end() - 1)
        if args_bare is None:
            continue
        span = code[m.end() : m.end() + len(args_bare)]
        route = _LITELLM_MODEL.search(span)
        if route is None:
            continue
        base = re.search(r"""\b(?:api_base|base_url)\s*=\s*(?P<v>[^,\n)]+)""", span)
        literal = env_name = None
        if base:
            value = base.group("v").strip()
            if value[:1] in "'\"" and value[-1:] == value[:1]:
                literal = value[1:-1]
            else:
                ref = _ENV_REF.search(value)
                env_name = (ref.group("a") or ref.group("b")) if ref else "unknown"
        comp = _litellm_route(route.group("prov"), literal, env, source, env_name)
        if comp is not None:
            out.append(comp)
    return out


def litellm_proxy_services(
    text: str, source: str, env: dict[str, str]
) -> list[CloudServiceComponent | EndpointComponent]:
    """The services a LiteLLM proxy ``config.yaml`` routes its ``model_list`` to."""
    if "model_list" not in text or "litellm_params" not in text:
        return []
    import yaml

    try:
        docs = list(yaml.safe_load_all(text))
    except (yaml.YAMLError, ValueError, RecursionError):
        return []
    out: list[CloudServiceComponent | EndpointComponent] = []
    for doc in docs:
        entries = doc.get("model_list") if isinstance(doc, dict) else None
        for entry in entries if isinstance(entries, list) else []:
            params = entry.get("litellm_params") if isinstance(entry, dict) else None
            if not isinstance(params, dict):
                continue
            model = params.get("model")
            if not isinstance(model, str) or "/" not in model:
                continue
            base = params.get("api_base") or params.get("base_url")
            literal = env_name = None
            if isinstance(base, str) and base.startswith("os.environ/"):
                env_name = base.split("/", 1)[1]  # LiteLLM's env reference syntax
            elif isinstance(base, str) and base:
                literal = base
            comp = _litellm_route(
                model.split("/", 1)[0], literal, env, source, env_name)
            if comp is not None:
                out.append(comp)
    return out


def _opaque_clients(
    code: str, bare: str, source: str
) -> list[CloudServiceComponent | EndpointComponent]:
    """OpenAI-compatible clients whose base URL the scan cannot read
    (``OpenAI(base_url=os.environ["TOGETHER_URL"])``, ``OpenAI(**cfg)``): a
    processor whose endpoint is unknown. It stays a potentially external service, so
    the vendor checks (RBI FREE-AI 19-1, NIST GV-2) assess it, and no local server
    is inferred for the file (review 6062066749 of #498, M1)."""
    out: dict[str, CloudServiceComponent | EndpointComponent] = {}
    for imp, call, label, _vendor, _endpoint in _SDK_RES:
        if label not in ("OpenAI API", "Anthropic API") or not imp.search(code):
            continue
        for m in call.finditer(bare):
            head = bare[bare.rfind("\n", 0, m.start()) + 1 : m.start()]
            if _DEFINITION.search(head):
                continue
            args = call_arguments(bare, m.end() - 1)
            if args is not None and not _SPREAD.search(args) and not _OTHER_BASE.search(
                args
            ):
                continue  # the vendor's default endpoint
            span = code[m.end() : m.end() + len(args)] if args is not None else ""
            if _LITERAL_BASE.search(span):
                continue  # a literal gateway URL: the gateway service names it
            if (args is None or _SPREAD.search(args)) and _LITERAL_BASE.search(code):
                continue  # ``OpenAI(**cfg)`` with the literal base URL in the file
            ref = _ENV_REF.search(span)
            name = (ref.group("a") or ref.group("b")) if ref else None
            label_ = f"AI endpoint ({name or 'endpoint unknown'})"
            comp = _component("cloud_service", label_,
                              f"{label.split()[0]}-compatible endpoint", True, None,
                              source, host=f"ai-endpoint-{(name or 'unknown').lower()}")
            comp.properties["service:kind"] = "gateway"
            comp.properties["service:trust_zone"] = "unknown"
            comp.properties["service:endpoint_basis"] = "unknown"
            comp.properties["discovery:method"] = "sdk-client"
            if name:
                comp.properties["service:endpoint_env"] = name
            out.setdefault(comp.bom_ref, comp)
    return list(out.values())


def _split_url(url: str) -> tuple[str, str | None]:
    """``(host[:port], path)`` of an http(s) URL with user information dropped."""
    rest = url.split("://", 1)[-1]
    hostpart, _, path = rest.partition("/")
    return hostpart.rsplit("@", 1)[-1], ("/" + path) if path else None


def _gateway_services(
    code: str, source: str, claimed_hosts: set[str]
) -> list[CloudServiceComponent | EndpointComponent]:
    """A literal base URL on a host no vendor pattern knows: an OpenAI-compatible
    gateway service (endpoint = scheme, host and version segments only)."""
    out: list[CloudServiceComponent | EndpointComponent] = []
    for m in _LITERAL_BASE.finditer(code):
        url = m.group("url")
        scheme = url.split("://", 1)[0].lower()
        host, path = _split_url(url)
        if not host or host.lower() in claimed_hosts:
            continue
        if any(pat.fullmatch(host) for pat, *_r in _HOST_RES_BARE):
            continue  # a vendor host: the host patterns name that service
        endpoint = base_url(scheme, host, path)
        comp = _component("cloud_service", f"AI gateway ({host.lower()})",
                          "OpenAI-compatible gateway", None, endpoint, source)
        comp.properties["discovery:method"] = "literal-base-url"
        comp.properties["service:kind"] = "gateway"
        out.append(comp)
        claimed_hosts.add(host.lower())
    return out


def _services_in(
    text: str, source: str, env: dict[str, str] | None = None
) -> list[CloudServiceComponent | EndpointComponent]:
    """The AI services one file names, longer / more specific hosts first: once a
    span is claimed by api-inference.huggingface.co it is not also the generic Hub."""
    out: list[CloudServiceComponent | EndpointComponent] = []
    claimed: list[tuple[int, int]] = []
    for pattern, kind, label, vendor, auth in _HOST_RES:
        for match in pattern.finditer(text):
            span = match.span("host")
            if any(a <= span[0] < b for a, b in claimed):
                continue
            claimed.append(span)
            out.append(_component(kind, label, vendor, auth, _endpoint(match), source))
    code, bare = mask(text, language_of(source))
    for imp, call, label, vendor, endpoint in _SDK_RES:
        if imp.search(code) and _default_client_called(code, bare, call, label):
            comp = _component("cloud_service", label, vendor, True, endpoint, source)
            comp.properties["discovery:method"] = "sdk-client"
            comp.properties["service:endpoint_basis"] = "sdk-default"
            out.append(comp)
    out.extend(_azure_services(code, bare, source))
    known = {c.bom_ref for c in out}
    ollama = _ollama_services(code, bare, source, env or {})
    # an Ollama REST URL: port 11434 with its /api path (a remote server, or the
    # 0.0.0.0 bind address) is an Ollama server (review 6063080163 of #498, m4)
    for m in _OLLAMA_REST_URL.finditer(code):
        host = (m.group("host") or m.group("bind")).lower()
        if host in ("localhost", "127.0.0.1"):
            continue  # the host patterns name the local one
        ollama.append(_ollama_server(f"http://{host}:11434", "literal", source))
    ollama.extend(_litellm_services(code, bare, source, env or {}))
    if source.lower().endswith((".yaml", ".yml")):
        ollama.extend(litellm_proxy_services(text, source, env or {}))
    for comp in ollama:
        if comp.bom_ref not in known:
            out.append(comp)
            known.add(comp.bom_ref)
    # a URL that is only an Ollama client's fallback (``getenv("OLLAMA_HOST",
    # "http://localhost:11434")``) is a default, never a second, local server
    # (review 6063080163 of #498, R4-M4)
    defaults = {
        _split_url(d if "://" in d else f"http://{d}")[0].lower()
        for c in ollama
        if (d := (c.properties or {}).get("service:endpoint_default"))
    }
    if defaults:
        out = [
            c for c in out
            if not (c.name == "Ollama (local)"
                    and (c.properties or {}).get("discovery:host", "").lower()
                    in defaults
                    and (c.properties or {}).get("service:endpoint_basis") is None)
        ]
    out.extend(_opaque_clients(code, bare, source))
    claimed_hosts = {
        (c.properties or {}).get("discovery:host", "").lower() for c in out
    } - {""}
    out.extend(_gateway_services(code, source, claimed_hosts))
    if _ANTHROPIC_VERTEX.search(bare):
        comp = _component("cloud_service", "Google Vertex AI", "Google", True, None,
                          source, host="aiplatform")
        comp.properties["discovery:method"] = "sdk-client"
        out.append(comp)
    if (
        _BEDROCK_SDK.search(code)
        or _ANTHROPIC_BEDROCK.search(bare)
        or (_LANGCHAIN_IMPORT_RE.search(code) and _LANGCHAIN_BEDROCK.search(bare))
    ):
        region = _BEDROCK_REGION.search(code)
        if region:
            host = f"bedrock-runtime.{region.group('region').lower()}.amazonaws.com"
            out.append(_component("cloud_service", "Amazon Bedrock Runtime", "Amazon",
                                  True, f"https://{host}", source))
        else:
            out.append(_component("cloud_service", "Amazon Bedrock Runtime", "Amazon",
                                  True, None, source, host="bedrock-runtime"))
    return out
