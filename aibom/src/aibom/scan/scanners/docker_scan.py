"""Level-2 scanner: Dockerfile / docker-compose -> AI runtime containers.

Detects self-hosted AI runtimes (Ollama, vLLM, Triton) and vector stores
(Chroma, Qdrant, Weaviate, Milvus, pgvector) declared in container images, and
emits ``container`` / ``vector_store`` components. A registry entry — one file.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.model.component import ContainerComponent, VectorStoreComponent
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
            for image in _IMAGE_RE.findall(read_text(path) or ""):
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
                        comp = (
                            VectorStoreComponent(
                                bom_ref=ref, name=label, properties=props
                            )
                            if kind == "vector_store"
                            else ContainerComponent(
                                bom_ref=ref, name=label, properties=props
                            )
                        )
                        ctx.add_component(comp)
                        break


__all__ = ["DockerScanner"]
