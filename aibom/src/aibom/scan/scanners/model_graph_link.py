"""Finalize scanner: link model nodes into the supply-chain graph.

The model-ref scanner emits model components but leaves them disconnected —
ORPHAN nodes the graph-traversing compliance/HIPAA/lineage checks cannot see.
This linker runs LAST and gives every model the service it is served by, from the
facts the scan has, strongest first (QA round 2, Q2-06):

1. a Bedrock model id (``anthropic.claude-…-v1:0``) is served by Amazon Bedrock;
2. a gateway named in the reference's own code block (``GROQ_DEFAULT_MODEL =
   "llama-…"``: Llama served by Groq), when that gateway's service is in the scan;
3. the vendor's own API, when the code calls it (a URL or an SDK client);
4. otherwise, when no SDK of the vendor is present either, a provider node for the
   vendor (the only fact left: who makes the model).

``model --depends_on--> <framework>`` is added too when the model's vendor SDK is a
framework component (openai / anthropic / sentence-transformers / chromadb …). A
vendor reached only through another gateway gets no node of its own: Claude via
Bedrock is ``served_by`` Bedrock, never by an endpoint-less "Anthropic" service.
The resolved service's platform is recorded on the model as ``model:provider``.

Models a card already linked (``trained_on`` / ``depends_on`` / ``served_by``
present) are left untouched. Lanes (``aibom/contract/lanes``): emits components +
edges only, never scores. Edge types are from the locked vocab
(``aibom/contract/edges``): ``depends_on`` / ``served_by``.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.model.component import (
    AIComponent,
    CloudServiceComponent,
    ServiceComponent,
    is_model_mention,
)
from aibom.model.result import REL_DEPENDS_ON, REL_SERVED_BY
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.scanners.net_env_scan import PROVIDER_KEY

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
# Vendor -> its own API's provider key (a model of the vendor served by the vendor).
_VENDOR_API: dict[str, str] = {
    "OpenAI": "openai",
    "Anthropic": "anthropic",
    "Google": "google",
    "Cohere": "cohere",
    "Mistral": "mistral",
    "Amazon": "bedrock",  # Titan / Nova run on Amazon Bedrock only
}
_BEDROCK_REF = "cloud_service-bedrock-runtime"
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
            if c.kind == "model"
            and c.bom_ref.startswith("modelref-")
            and not is_model_mention(c)  # a catalog / test mention is served by nothing
        ]
        if not models:
            return

        already_linked = {e.src for e in ctx.edges}
        frameworks = {
            c.name.lower(): c.bom_ref for c in ctx.components if c.kind == "framework"
        }
        # provider key -> the scan's service for it (net-env: a URL the code names or
        # an SDK client it constructs). First seen wins (component order is stable).
        services: dict[str, str] = {}
        for comp in ctx.components:
            if comp.kind in ("cloud_service", "endpoint"):
                key = PROVIDER_KEY.get(comp.name)
                if key:
                    services.setdefault(key, comp.bom_ref)
        vendor_nodes: dict[str, str] = {}  # vendor -> provider node (created on demand)

        for model in models:
            props = model.properties if model.properties is not None else {}
            hint = props.pop("discovery:gateway", None)
            if model.bom_ref in already_linked:
                continue  # a card already wired this model — don't second-guess it

            vendor = (model.publisher or "").strip()
            sdk_ref = next(
                (frameworks[s] for s in _VENDOR_SDK.get(vendor, ()) if s in frameworks),
                None,
            )
            if sdk_ref is not None:
                # The SDK is how the code calls it; the service is where it runs (and
                # where the data goes): record both.
                ctx.add_edge(model.bom_ref, REL_DEPENDS_ON, sdk_ref)

            key, ref = self._gateway(ctx, model, hint, vendor, services)
            if ref is not None:
                ctx.add_edge(model.bom_ref, REL_SERVED_BY, ref)
                model.properties = {**props, "model:provider": key}
                continue
            model.properties = props
            if sdk_ref is not None:
                continue  # served through its SDK at an endpoint the scan did not see

            # Nothing else is known: a provider node for the vendor + served_by.
            if vendor not in vendor_nodes:
                ref = f"provider-{_slug(vendor)}"
                if not ctx.has_ref(ref):
                    ctx.add_component(
                        ServiceComponent(
                            bom_ref=ref,
                            name=vendor or "unknown-provider",
                            properties={"provider:kind": "model_provider"},
                        )
                    )
                vendor_nodes[vendor] = ref
            ctx.add_edge(model.bom_ref, REL_SERVED_BY, vendor_nodes[vendor])

    @staticmethod
    def _gateway(
        ctx: ScanContext,
        model: AIComponent,
        hint: str | None,
        vendor: str,
        services: dict[str, str],
    ) -> tuple[str, str | None]:
        """``(provider key, service ref)`` that serves the model, or ``("", None)``."""
        props = model.properties or {}
        if props.get("model:provider") == "bedrock":
            if "bedrock" not in services:
                # the id itself proves Bedrock; its regional endpoint is not known
                ctx.add_component(
                    CloudServiceComponent(
                        bom_ref=_BEDROCK_REF,
                        name="Amazon Bedrock Runtime",
                        publisher="Amazon",
                        properties={
                            "discovery:source": props.get("discovery:source", ""),
                            "service:trust_zone": "external",
                            "service:authenticated": "true",
                        },
                    )
                )
                services["bedrock"] = _BEDROCK_REF
            return "bedrock", services["bedrock"]
        if hint and hint in services:
            return hint, services[hint]
        own = _VENDOR_API.get(vendor)
        if own and own in services:
            return own, services[own]
        return "", None


__all__ = ["ModelGraphLinker"]
