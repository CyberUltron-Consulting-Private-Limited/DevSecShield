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

from aibom.model.component import CloudServiceComponent, EndpointComponent
from aibom.scan.path_roles import is_env_file, is_example_path, is_test_path
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
_SDK_RES = [
    (re.compile(imp, re.IGNORECASE), re.compile(call), label, vendor, endpoint)
    for imp, call, label, vendor, endpoint in _SDK_CLIENTS
]
# The arguments of one call, with one level of nested parentheses (os.getenv(...)).
_CALL_ARGS = re.compile(r"\((?P<args>[^()]*(?:\([^()]*\)[^()]*)*)\)")
_OTHER_BASE = re.compile(
    r"\b(?:base_url|baseURL|api_base|vertexai)\s*[=:]", re.IGNORECASE
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

_SUFFIXES = {".env", ".py", ".ts", ".js", ".yaml", ".yml", ".toml", ".sh", ".cfg"}
_LOOPBACK = ("localhost", "127.0.0.1")
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
        for path in _scan_files(ctx.root):
            text = read_text(path)
            if text is None:
                continue
            try:
                source = path.relative_to(ctx.root).as_posix()
            except ValueError:
                source = path.name
            not_app = is_test_path(path, ctx.root) or is_example_path(path, ctx.root)
            for comp in _services_in(text, source):
                if comp.bom_ref in seen or ctx.has_ref(comp.bom_ref):
                    continue
                if not_app:
                    excluded.add(comp.bom_ref)
                    continue
                seen.add(comp.bom_ref)
                ctx.add_component(comp)
        excluded -= seen
        if excluded:
            ctx.properties["aibom:services_excluded_test_example"] = str(len(excluded))


def _default_client_called(text: str, call: re.Pattern[str], label: str) -> bool:
    """Whether ``text`` constructs / calls the SDK client at its default base URL."""
    if label == "OpenAI API" and _MODULE_BASE.search(text):
        return False
    for m in call.finditer(text):
        head = text[text.rfind("\n", 0, m.start()) + 1 : m.start()]
        if _DEFINITION.search(head):
            continue  # ``class MistralClient(BaseClient):`` defines, never calls
        args = _CALL_ARGS.match(text, m.end() - 1)
        if args is None or not _OTHER_BASE.search(args.group("args")):
            return True
    return False


def _services_in(
    text: str, source: str
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
    for imp, call, label, vendor, endpoint in _SDK_RES:
        if imp.search(text) and _default_client_called(text, call, label):
            comp = _component("cloud_service", label, vendor, True, endpoint, source)
            comp.properties["discovery:method"] = "sdk-client"
            comp.properties["service:endpoint_basis"] = "sdk-default"
            out.append(comp)
    if _ANTHROPIC_VERTEX.search(text):
        comp = _component("cloud_service", "Google Vertex AI", "Google", True, None,
                          source, host="aiplatform")
        comp.properties["discovery:method"] = "sdk-client"
        out.append(comp)
    if _BEDROCK_SDK.search(text) or _ANTHROPIC_BEDROCK.search(text):
        region = _BEDROCK_REGION.search(text)
        if region:
            host = f"bedrock-runtime.{region.group('region').lower()}.amazonaws.com"
            out.append(_component("cloud_service", "Amazon Bedrock Runtime", "Amazon",
                                  True, f"https://{host}", source))
        else:
            out.append(_component("cloud_service", "Amazon Bedrock Runtime", "Amazon",
                                  True, None, source, host="bedrock-runtime"))
    return out
