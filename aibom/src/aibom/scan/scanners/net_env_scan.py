"""Level-3 scanner: .env + source -> network AI endpoints / cloud APIs.

Detects calls to managed LLM APIs and local inference endpoints by hostname in
``.env`` files and source (api.openai.com, api.anthropic.com, Bedrock runtime,
localhost:11434, …), emitting ``cloud_service`` / ``endpoint`` components — the
shadow-AI usage that never appears in a manifest. The emitters render both kinds
as CycloneDX ``services`` (endpoints, authentication, trust boundary, data flow).

Each component records what the emitters need, as ``service:`` properties:

* ``service:endpoint`` — the URL seen in the code (scheme, host, port, path up to
  the first quote/space), else ``https://<host>`` (``http://`` for loopback);
* ``service:trust_zone`` — ``external`` (a third-party SaaS API, so data crosses a
  trust boundary) or ``local`` (loopback inference such as Ollama);
* ``service:authenticated`` — ``true`` for the hosted APIs (each requires an API
  key or cloud credentials), ``false`` for Ollama (no authentication by default),
  absent when not known.

``discovery:source`` is the repository-relative path of the first file that names
the host. A registry entry.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.model.component import CloudServiceComponent, EndpointComponent
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
# Bedrock is reached through the AWS SDK as often as by URL.
_BEDROCK_SDK = re.compile(
    r"""client\(\s*(?:service_name\s*=\s*)?['"]bedrock-runtime['"]|"""
    r"""BedrockRuntimeClient\b|@aws-sdk/client-bedrock-runtime""",
    re.IGNORECASE,
)
_BEDROCK_URL = "https://bedrock-runtime.amazonaws.com"

_HOST_RES = [
    (
        re.compile(rf"(?<![\w.-])(?:(?P<scheme>https?)://)?(?P<host>{pat})"
                   r"(?P<path>/[^\s'\"`<>)\]},;]*)?", re.IGNORECASE),
        kind,
        label,
        vendor,
        auth,
    )
    for pat, kind, label, vendor, auth in _HOSTS
]

_SUFFIXES = {".env", ".py", ".ts", ".js", ".yaml", ".yml", ".toml", ".sh", ".cfg"}
_ENV_NAMES = {".env", ".env.local", ".env.example", ".env.production"}
_LOOPBACK = ("localhost", "127.0.0.1")


def _scan_files(root: Path) -> list[Path]:
    return walk_files(
        root, keep=lambda p: p.name in _ENV_NAMES or p.suffix.lower() in _SUFFIXES
    )


def _endpoint(match: re.Match[str]) -> str:
    """The URL as written (scheme + host + path), with a default scheme."""
    host = match.group("host").lower()
    local = host.startswith(_LOOPBACK)
    scheme = (match.group("scheme") or ("http" if local else "https")).lower()
    path = (match.group("path") or "").rstrip(".")
    return f"{scheme}://{host}{path}"


def _ref(kind: str, host: str) -> str:
    """``<kind>-<host slug>``, stable across scans (cloud_service-api-openai-com)."""
    return f"{kind}-" + re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")


def _component(
    kind: str, label: str, vendor: str, auth: bool | None, endpoint: str, source: str
) -> CloudServiceComponent | EndpointComponent:
    host = endpoint.split("://", 1)[-1].split("/", 1)[0]
    props = {
        "discovery:source": source,
        "discovery:host": host,
        "service:endpoint": endpoint,
        "service:trust_zone": "local" if host.startswith(_LOOPBACK) else "external",
    }
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
        for path in _scan_files(ctx.root):
            text = read_text(path)
            if text is None:
                continue
            try:
                source = path.relative_to(ctx.root).as_posix()
            except ValueError:
                source = path.name
            # longer / more specific hosts first: once a span is claimed by
            # api-inference.huggingface.co it is not also the generic Hub.
            claimed: list[tuple[int, int]] = []
            for pattern, kind, label, vendor, auth in _HOST_RES:
                for match in pattern.finditer(text):
                    span = match.span("host")
                    if any(a <= span[0] < b for a, b in claimed):
                        continue
                    claimed.append(span)
                    url = _endpoint(match)
                    comp = _component(kind, label, vendor, auth, url, source)
                    if comp.bom_ref in seen or ctx.has_ref(comp.bom_ref):
                        continue
                    seen.add(comp.bom_ref)
                    ctx.add_component(comp)
            if _BEDROCK_SDK.search(text):
                comp = _component(
                    "cloud_service", "Amazon Bedrock Runtime", "Amazon", True,
                    _BEDROCK_URL, source,
                )
                if comp.bom_ref not in seen and not ctx.has_ref(comp.bom_ref):
                    seen.add(comp.bom_ref)
                    ctx.add_component(comp)


__all__ = ["NetEnvScanner"]
