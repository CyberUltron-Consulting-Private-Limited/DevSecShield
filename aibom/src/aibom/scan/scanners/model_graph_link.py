"""Finalize scanner: link model nodes into the supply-chain graph.

The model-ref scanner emits model components but leaves them disconnected —
ORPHAN nodes the graph-traversing compliance/HIPAA/lineage checks cannot see.
This linker runs LAST and guarantees every model has >=1 edge:

* ``model --depends_on--> <framework>`` when the model's vendor SDK is present as
  a framework component (openai / anthropic / sentence-transformers / chromadb …);
* otherwise ``model --served_by--> <provider>``, creating a provider service node
  for the vendor on demand.

Models a card already linked (``trained_on`` / ``depends_on`` / ``served_by``
present) are left untouched. Lanes (``aibom/contract/lanes``): emits components +
edges only, never scores. Edge types are from the locked vocab
(``aibom/contract/edges``): ``depends_on`` / ``served_by``.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.model.component import ServiceComponent
from aibom.model.result import REL_DEPENDS_ON, REL_SERVED_BY
from aibom.scan.registry import ScanContext, Scanner, register

# Vendor -> candidate SDK/framework package names (normalized, first match wins).
_VENDOR_SDK: dict[str, tuple[str, ...]] = {
    "OpenAI": ("openai",),
    "Anthropic": ("anthropic",),
    "Google": ("google-generativeai", "google-genai", "vertexai"),
    "Cohere": ("cohere",),
    "Mistral": ("mistralai",),
    "Meta": ("transformers", "llama-cpp-python"),
    "sentence-transformers": ("sentence-transformers", "chromadb", "transformers"),
    "HuggingFace": ("transformers", "sentence-transformers", "huggingface-hub"),
    "Nomic": ("nomic", "chromadb"),
    "Jina": ("jina",),
}
_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(name: str) -> str:
    return _SLUG.sub("-", name.lower()).strip("-") or "unknown"


@register
class ModelGraphLinker(Scanner):
    name = "model-graph-link"
    order = 90  # last: every component-producing scanner has already run
    level = 1

    def matches(self, root: Path) -> bool:
        return True

    def scan(self, ctx: ScanContext) -> None:
        # Only the model-REF scanner's inline models are ours to link. A CARDED
        # model (model_repo) is already graph-integrated — or deliberately not
        # (e.g. a served_by ref rejected by the collision guard); we must not
        # override that decision. model-ref components use the ``modelref-`` ref.
        models = [
            c
            for c in ctx.components
            if c.kind == "model" and c.bom_ref.startswith("modelref-")
        ]
        if not models:
            return

        already_linked = {e.src for e in ctx.edges}
        frameworks = {
            c.name.lower(): c.bom_ref for c in ctx.components if c.kind == "framework"
        }
        providers: dict[str, str] = {}  # vendor -> provider bom_ref (created on demand)

        for model in models:
            if model.bom_ref in already_linked:
                continue  # a card already wired this model — don't second-guess it

            vendor = (model.publisher or "").strip()
            sdk_ref = next(
                (frameworks[s] for s in _VENDOR_SDK.get(vendor, ()) if s in frameworks),
                None,
            )
            if sdk_ref is not None:
                ctx.add_edge(model.bom_ref, REL_DEPENDS_ON, sdk_ref)
                continue

            # No SDK framework present -> attach a provider service node + served_by.
            if vendor not in providers:
                ref = f"provider-{_slug(vendor)}"
                if not ctx.has_ref(ref):
                    ctx.add_component(
                        ServiceComponent(
                            bom_ref=ref,
                            name=vendor or "unknown-provider",
                            properties={"provider:kind": "model_provider"},
                        )
                    )
                providers[vendor] = ref
            ctx.add_edge(model.bom_ref, REL_SERVED_BY, providers[vendor])


__all__ = ["ModelGraphLinker"]
