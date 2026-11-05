"""Level-3 scanner: .env + source -> network AI endpoints / cloud APIs.

Detects calls to managed LLM APIs and local inference endpoints by hostname in
``.env`` files and source (api.openai.com, api.anthropic.com, localhost:11434,
…), emitting ``cloud_service`` / ``endpoint`` components — the shadow-AI usage
that never appears in a manifest. A registry entry.
"""

from __future__ import annotations

from pathlib import Path

from aibom.model.component import CloudServiceComponent, EndpointComponent
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.safe_files import read_text, walk_files

# hostname substring -> (kind, display name, vendor)
_HOSTS = {
    "api.openai.com": ("cloud_service", "OpenAI API", "OpenAI"),
    "api.anthropic.com": ("cloud_service", "Anthropic API", "Anthropic"),
    "generativelanguage.googleapis.com": (
        "cloud_service",
        "Google Gemini API",
        "Google",
    ),
    "api.cohere.ai": ("cloud_service", "Cohere API", "Cohere"),
    "api.mistral.ai": ("cloud_service", "Mistral API", "Mistral"),
    "openai.azure.com": ("cloud_service", "Azure OpenAI", "Microsoft"),
    "localhost:11434": ("endpoint", "Ollama (local)", "local"),
    "127.0.0.1:11434": ("endpoint", "Ollama (local)", "local"),
    "localhost:8000": ("endpoint", "Local inference (:8000)", "local"),
    "huggingface.co": ("endpoint", "Hugging Face Hub", "Hugging Face"),
}

_SUFFIXES = {".env", ".py", ".ts", ".js", ".yaml", ".yml", ".toml", ".sh", ".cfg"}
_ENV_NAMES = {".env", ".env.local", ".env.example", ".env.production"}


def _scan_files(root: Path) -> list[Path]:
    return walk_files(
        root, keep=lambda p: p.name in _ENV_NAMES or p.suffix.lower() in _SUFFIXES
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
            text = text.lower()
            for host, (kind, label, vendor) in _HOSTS.items():
                if host in text:
                    ref = f"{kind}-{host.replace(':', '-').replace('.', '-')}"
                    if ref in seen:
                        continue
                    seen.add(ref)
                    props = {"discovery:source": path.name, "discovery:host": host}
                    comp = (
                        EndpointComponent(
                            bom_ref=ref, name=label, publisher=vendor, properties=props
                        )
                        if kind == "endpoint"
                        else CloudServiceComponent(
                            bom_ref=ref, name=label, publisher=vendor, properties=props
                        )
                    )
                    ctx.add_component(comp)


__all__ = ["NetEnvScanner"]
