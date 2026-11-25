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
from aibom.scan.scanners.net_env_scan import (
    OLLAMA_CLOUD_REF as _OLLAMA_CLOUD_REF,
)
from aibom.scan.scanners.net_env_scan import PROVIDER_KEY, ollama_cloud_service

# Vendor -> candidate SDK/framework package names (normalized, first match wins).
_VENDOR_SDK: dict[str, tuple[str, ...]] = {
    "OpenAI": ("openai",),
    "Anthropic": ("anthropic",),
    "Google": ("google-generativeai", "google-genai", "vertexai"),
    "Cohere": ("cohere",),
    # open weights loaded locally (transformers / llama.cpp) are not API-served
    "Mistral": ("mistralai", "transformers", "llama-cpp-python"),
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
    "DeepSeek": "deepseek",
}
# A Hugging Face Hub model (``model:hub_id``) is downloaded and run by the
# application through one of these libraries; its maker's API does not serve it.
_HUB_LOADERS: tuple[str, ...] = (
    "transformers", "sentence-transformers", "diffusers", "pyannote-audio",
    "pyannote.audio", "llama-cpp-python", "vllm", "huggingface-hub",
)
# Vendor -> other platforms that serve its models (beyond its own API).
_SERVES: dict[str, tuple[str, ...]] = {
    "OpenAI": ("azure",),
    "Anthropic": ("bedrock", "vertex"),
    "Google": ("vertex",),
    "Mistral": ("bedrock", "azure", "vertex"),
    "Meta": ("bedrock", "groq", "together", "azure", "vertex"),
    "Cohere": ("bedrock", "azure"),
    "AI21 Labs": ("bedrock",),
    "DeepSeek": ("deepseek", "bedrock", "azure"),
    "Writer": ("bedrock",),
    "Alibaba": ("bedrock",),
}
_BEDROCK_REF = "cloud_service-bedrock-runtime"
# A local model server runs open weights only (Ollama pulls weights; it serves no
# hosted API model such as gpt-4o or Claude).
_LOCAL_SERVERS = ("ollama",)
_PROPRIETARY = "LicenseRef-proprietary"


def _service_key(comp: AIComponent) -> str:
    props = comp.properties or {}
    return props.get("service:platform") or (
        "gateway" if props.get("service:kind") == "gateway"
        else PROVIDER_KEY.get(comp.name, "")
    )


def _resolve_hint(ctx: ScanContext, hint: str | None) -> tuple[str, str] | None:
    """``(provider key, service ref)`` of the service a call-site hint names:
    ``host:<host>`` (the client's literal base URL) or ``env:<NAME>`` (its base URL
    read from the environment); None otherwise."""
    if not hint or ":" not in hint or hint.split(":", 1)[0] not in ("host", "env"):
        return None
    kind, value = hint.split(":", 1)
    for comp in ctx.components:
        if comp.kind not in ("cloud_service", "endpoint"):
            continue
        props = comp.properties or {}
        if (kind == "host" and props.get("discovery:host", "").lower() == value) or (
            kind == "env" and props.get("service:endpoint_env") == value
        ):
            key = _service_key(comp)
            if key:
                return key, comp.bom_ref
    return None


def _open_weights(model: AIComponent) -> bool:
    """Whether the model is not known to be a hosted, proprietary-terms model: a
    local server can serve it (#498 round 3 follow-up: llama3.1 and gemma2 called
    through Ollama were "served by" endpoint-less Meta / Google vendor nodes)."""
    for choice in model.licenses or []:
        lic = choice.get("license") if isinstance(choice, dict) else None
        if isinstance(lic, dict) and _PROPRIETARY in (lic.get("id"), lic.get("name")):
            return False
    return True
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
        # A gateway (a literal base URL on an unknown host) has the key "gateway".
        services: dict[str, str] = {}
        # application file -> [(provider key, service ref)] of the services it calls
        by_file: dict[str, list[tuple[str, str]]] = {}
        all_by_key: dict[str, list[str]] = {}
        for comp in ctx.components:
            if comp.kind not in ("cloud_service", "endpoint"):
                continue
            props = comp.properties or {}
            # a model server names its platform ("ollama", "ollama-cloud"); a gateway
            # (a literal or unreadable base URL on an unknown host) is "gateway"
            key = props.get("service:platform") or (
                "gateway" if props.get("service:kind") == "gateway"
                else PROVIDER_KEY.get(comp.name, "")
            )
            if not key:
                continue
            services.setdefault(key, comp.bom_ref)
            all_by_key.setdefault(key, []).append(comp.bom_ref)
            files = ctx.service_files.get(comp.bom_ref) or {
                props.get("discovery:source", "")
            }
            for f in files:
                by_file.setdefault(f, []).append((key, comp.bom_ref))
        vendor_nodes: dict[str, str] = {}  # vendor -> provider node (created on demand)

        for model in models:
            props = model.properties if model.properties is not None else {}
            hint = props.pop("discovery:gateway", None)
            if model.bom_ref in already_linked:
                continue  # a card already wired this model — don't second-guess it

            served_via = props.get("model:served_via")
            if served_via:
                # an Ollama tag (review 6062066749 of #498, M2): served by the Ollama
                # server its call uses, never by the maker's API or a vendor node
                exact = _resolve_hint(ctx, hint)
                if exact is not None and exact[0] in ("ollama", "ollama-cloud"):
                    # the client the call is made on names its Ollama server
                    ctx.add_edge(model.bom_ref, REL_SERVED_BY, exact[1])
                    model.properties = {**props, "model:provider": exact[0]}
                    continue
                self._link_served_via(
                    ctx, model, props, served_via, by_file, all_by_key, frameworks
                )
                continue
            vendor = (model.publisher or "").strip()
            hub = bool(props.get("model:hub_id"))
            candidates = _HUB_LOADERS if hub else _VENDOR_SDK.get(vendor, ())
            if hub:
                # the org's own library first: pyannote/… is loaded by pyannote.audio
                org = str(props.get("model:hub_id", "")).split("/", 1)[0].lower()
                candidates = tuple(
                    sorted(candidates, key=lambda s: not s.startswith(org))
                )
            sdk_ref = next(
                (frameworks[s] for s in candidates if s in frameworks),
                None,
            )
            if sdk_ref is not None:
                # The SDK is how the code calls it; the service is where it runs (and
                # where the data goes): record both.
                ctx.add_edge(model.bom_ref, REL_DEPENDS_ON, sdk_ref)

            key, ref = self._gateway(ctx, model, hint, vendor, services, by_file)
            if ref is not None:
                ctx.add_edge(model.bom_ref, REL_SERVED_BY, ref)
                # a gateway is no ModelProvider value: the vendor's own stays
                model.properties = (
                    {**props, "model:provider": key} if key != "gateway" else props
                )
                continue
            model.properties = props
            if sdk_ref is not None or hub:
                # served through its SDK at an endpoint the scan did not see, or
                # open weights from the Hub that the application runs itself
                continue

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
    def _link_served_via(
        ctx: ScanContext,
        model: AIComponent,
        props: dict,
        served_via: str,
        by_file: dict[str, list[tuple[str, str]]],
        all_by_key: dict[str, list[str]],
        frameworks: dict[str, str],
    ) -> None:
        """Link an Ollama-tag model: the Ollama service of its own file, else the one
        Ollama service of the repository (an Ollama tag is Ollama-served by
        construction), else for a ``-cloud`` tag Ollama Cloud; else no service."""
        model.properties = props
        for lib in ("ollama", "langchain-ollama"):
            if lib in frameworks:
                ctx.add_edge(model.bom_ref, REL_DEPENDS_ON, frameworks[lib])
                break
        same = [r for k, r in by_file.get(props.get("discovery:source", ""), [])
                if k == served_via]
        refs = same or (all_by_key.get(served_via, []) if len(
            set(all_by_key.get(served_via, []))) == 1 else [])
        if not refs and served_via == "ollama-cloud":
            if not ctx.has_ref(_OLLAMA_CLOUD_REF):
                source = props.get("discovery:source", "")
                ctx.add_component(ollama_cloud_service(source))
            refs = [_OLLAMA_CLOUD_REF]
            all_by_key.setdefault(served_via, []).append(_OLLAMA_CLOUD_REF)
        if refs:
            ctx.add_edge(model.bom_ref, REL_SERVED_BY, refs[0])
            model.properties = {**props, "model:provider": served_via}

    @staticmethod
    def _gateway(
        ctx: ScanContext,
        model: AIComponent,
        hint: str | None,
        vendor: str,
        services: dict[str, str],
        by_file: dict[str, list[tuple[str, str]]],
    ) -> tuple[str, str | None]:
        """``(provider key, service ref)`` that serves the model, or ``("", None)``.

        Strongest first: a Bedrock id; a gateway named in the reference's code block;
        a service the model's OWN file calls that can serve the vendor's models (its
        own API first, then e.g. Azure OpenAI for a GPT model, or a gateway); the
        vendor's own API anywhere in the repository; else the one service in the
        repository that can serve the vendor (review 6037909737 of #498, M2)."""
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
        open_weights = _open_weights(model)
        exact = _resolve_hint(ctx, hint)
        if exact is not None and (open_weights or exact[0] not in _LOCAL_SERVERS):
            # the client object the call is made on names this endpoint
            return exact
        if hint and hint in services and (open_weights or hint not in _LOCAL_SERVERS):
            # a nearby "ollama" names no server for a hosted model (gpt-4o, Claude)
            return hint, services[hint]
        if props.get("model:hub_id"):
            # open weights from the Hub: served only by a gateway or the Hugging Face
            # Inference API that the model's own file calls, never by its maker's API
            # (openai/whisper-large-v3 is not the OpenAI API's whisper-1)
            hosted = [
                (k, r)
                for k, r in by_file.get(props.get("discovery:source", ""), [])
                if k in ("gateway", "huggingface")
            ]
            return hosted[0] if hosted else ("", None)
        own = _VENDOR_API.get(vendor)
        able = _SERVES.get(vendor, ())
        source_file = props.get("discovery:source", "")
        same_file = by_file.get(source_file, [])
        if open_weights and all(k in _LOCAL_SERVERS for k, _r in same_file):
            # the model's own file calls only a local model server: it runs the
            # weights. A file that also builds another client (a gateway, an endpoint
            # the scan could not read) proves nothing: no local link (review
            # 6062066749 of #498, M1)
            server = next(((k, r) for k, r in same_file if k in _LOCAL_SERVERS), None)
            if server is not None and source_file not in ctx.opaque_client_files:
                return server
        local = [
            (k, r)
            for k, r in same_file
            if k == own or k in able or k == "gateway"
        ]
        if local:
            return next(((k, r) for k, r in local if k == own), local[0])
        if own and own in services:
            return own, services[own]
        # never a local server repo-wide: another file's Ollama says nothing about
        # where this file's model runs (review 6062066749 of #498, M1)
        others = [k for k in able if k in services]
        if len(others) == 1:
            return others[0], services[others[0]]
        return "", None


__all__ = ["ModelGraphLinker"]
