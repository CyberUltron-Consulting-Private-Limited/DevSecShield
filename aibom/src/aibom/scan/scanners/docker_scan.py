"""Level-2 scanner: Dockerfile / docker-compose -> AI runtime containers.

Detects self-hosted AI runtimes (Ollama, vLLM, Triton) and vector stores
(Chroma, Qdrant, Weaviate, Milvus, pgvector) declared in container images, and
emits ``container`` / ``vector_store`` components. A registry entry — one file.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.model.component import ContainerComponent, VectorStoreComponent
from aibom.scan.parsers.licenses import license_choice
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.safe_files import is_regular_file, read_text

# image substring -> (component-builder kind, display name)
_RUNTIMES = {
    "ollama": ("container", "Ollama"),
    "vllm": ("container", "vLLM"),
    "tritonserver": ("container", "NVIDIA Triton"),
    "triton": ("container", "NVIDIA Triton"),
    "text-generation-inference": ("container", "TGI"),
    "localai": ("container", "LocalAI"),
    "chromadb": ("vector_store", "Chroma"),
    "chroma": ("vector_store", "Chroma"),
    "qdrant": ("vector_store", "Qdrant"),
    "weaviate": ("vector_store", "Weaviate"),
    "milvus": ("vector_store", "Milvus"),
    "pgvector": ("vector_store", "pgvector"),
}

_IMAGE_RE = re.compile(r"(?:image:\s*|FROM\s+)([\w./-]+(?::[\w.-]+)?)", re.IGNORECASE)


# runtimes that serve models (the container is a model server) -> platform key
_MODEL_SERVERS = {
    "ollama": "ollama", "vllm": "vllm", "tritonserver": "triton", "triton": "triton",
    "text-generation-inference": "tgi", "localai": "localai",
}
# the runtime software's own licence: Ollama (github.com/ollama/ollama LICENSE: MIT),
# vLLM (PyPI vllm 0.34.0 license_expression Apache-2.0)
_RUNTIME_LICENCE = {"ollama": "MIT", "vllm": "Apache-2.0"}


def _compose_files(root: Path) -> list[Path]:
    names = {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }
    return sorted(
        p for p in root.iterdir() if p.name.lower() in names and is_regular_file(p)
    )


def _compose_services(text: str) -> dict[str, str]:
    """``image -> compose service name`` of a compose file ({} for a Dockerfile or
    a file that does not parse)."""
    if "services:" not in text:
        return {}
    import yaml

    try:
        doc = yaml.safe_load(text)
    except (yaml.YAMLError, ValueError, RecursionError):
        return {}
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return {}
    return {
        str(svc["image"]): str(name)
        for name, svc in services.items()
        if isinstance(svc, dict) and isinstance(svc.get("image"), str)
    }


@register
class DockerScanner(Scanner):
    name = "docker"
    level = 2
    order = 30

    def matches(self, root: Path) -> bool:
        return bool(_compose_files(root))

    def scan(self, ctx: ScanContext) -> None:
        seen: set[str] = set()
        for path in _compose_files(ctx.root):
            text = read_text(path) or ""
            service_of = _compose_services(text)
            for image in _IMAGE_RE.findall(text):
                low = image.lower()
                for needle, (kind, label) in _RUNTIMES.items():
                    if needle in low:
                        ref = f"{kind}-{needle}"
                        if ref in seen:
                            break
                        seen.add(ref)
                        props = {
                            "discovery:source": path.name,
                            "discovery:image": image,
                        }
                        if needle in _MODEL_SERVERS:
                            # a model server the repository runs as a container:
                            # self-hosted, never an external provider (review
                            # 6063080163 of #498, m8)
                            props["service:kind"] = "model_server"
                            props["service:platform"] = _MODEL_SERVERS[needle]
                            if image in service_of:
                                # the compose service name is the host the app
                                # reaches it by: net-env merges the two rows
                                # (review 6065595627 of #498, m3)
                                props["discovery:compose_service"] = service_of[image]
                        comp = (
                            VectorStoreComponent(
                                bom_ref=ref, name=label, properties=props
                            )
                            if kind == "vector_store"
                            else ContainerComponent(
                                bom_ref=ref, name=label, properties=props,
                                licenses=[license_choice(_RUNTIME_LICENCE[needle])]
                                if needle in _RUNTIME_LICENCE
                                else None,
                            )
                        )
                        ctx.add_component(comp)
                        break


__all__ = ["DockerScanner"]
