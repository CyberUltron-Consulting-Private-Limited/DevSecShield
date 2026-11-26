"""Finalize scanner: model-card ``considerations`` from facts the scan holds.

CycloneDX 1.6 ``modelCard.considerations`` (QA round 2, G-D5-5: no model card had
any). A model referenced in code has no author-written card, so this fills only
what is KNOWN, never invented, and marks the block ``derived``:

* ``useCases``: the task the model KB records, the service it is served by (the
  model-graph linker's ``served_by``) and the application file that calls it;
* ``technicalLimitations``: facts of the reference and the serving graph: a
  provider-hosted model's weights, training data and evaluation are not in the
  repository; a moving alias (``…-latest``) can change model without a code change;
  a Bedrock cross-Region (geographic) inference profile can serve the request from
  another AWS Region of that geography (AWS Bedrock user guide, "Geographic
  cross-Region inference");
* ``out_of_scope``: uses the model's licence excludes, from the licence's published
  terms, as the model KB records them (Codestral 22B open weights: Mistral AI
  Non-Production License). A Mistral model served by an API is used under the
  provider's commercial terms: its licence is ``LicenseRef-proprietary`` and no
  open-weights exclusion applies.

Ethical, fairness and environmental considerations are never derived: nothing in a
code reference states them, so they are omitted. Only models referenced in code
(``modelref-``) are filled: a carded model's author decides what its card says. A
model only named in a catalog, doc or test, and a model with none of the facts
above, gets no considerations.

Runs after the linker (order 90). Lanes: components only, never flags or scores.
"""

from __future__ import annotations

from pathlib import Path

from aibom.model.component import Considerations, ModelComponent, is_model_mention
from aibom.model.result import REL_SERVED_BY
from aibom.scan.parsers import model_kb
from aibom.scan.parsers.licenses import license_choice
from aibom.scan.registry import ScanContext, Scanner, register

_PROVIDER_TERMS = "LicenseRef-proprietary"
_HOSTED = (
    "provider-hosted: the weights, training data and evaluation results are not in "
    "this repository; the provider's model documentation states its limitations"
)


def _external(services: list) -> list:
    """The serving services outside the trust boundary: not a loopback endpoint, and
    not the linker's endpoint-less vendor node (who makes the model is no proof that
    an API serves it)."""
    return [
        s
        for s in services
        if (s.properties or {}).get("service:trust_zone") != "local"
        and (s.properties or {}).get("provider:kind") != "model_provider"
        # a self-hosted model server (a remote Ollama) runs open weights; it is no
        # provider's hosted product (review 6062066749 of #498, M2)
        and (s.properties or {}).get("service:kind") != "model_server"
    ]


def _api_served(comp: ModelComponent, services: list) -> bool:
    """A Mistral model that a provider's API serves (Mistral, Bedrock, Azure, Vertex,
    Groq …: the linker records it as ``model:provider``) is used under that
    provider's terms. A self-hosted OpenAI-compatible gateway (vLLM / LiteLLM in
    front of the weights) sets no provider: the open-weights licence still applies
    (review of #498 round 3: mistral-7b behind ``http://vllm.internal:8000`` read
    LicenseRef-proprietary)."""
    return (
        comp.publisher == "Mistral"
        and bool((comp.properties or {}).get("model:provider"))
        and bool(_external(services))
    )


def _alias(name: str) -> str | None:
    if name.lower().endswith("-latest"):
        return (
            f"{name!r} is a moving alias: the provider can change the model behind it "
            "without a code change, so this BOM cannot pin the model version"
        )
    return None


def _profile(geo: str | None) -> str | None:
    if not geo:
        return None
    return (
        f"Amazon Bedrock cross-Region inference profile {geo + '.'!r}: a request can "
        f"be served from any AWS Region of the {geo!r} geography, not only the "
        "calling Region"
    )


@register
class ModelConsiderations(Scanner):
    name = "model-considerations"
    order = 95  # after model-graph-link (90): the serving service is known
    level = 1

    def matches(self, root: Path) -> bool:
        return True

    def scan(self, ctx: ScanContext) -> None:
        by_ref = {c.bom_ref: c for c in ctx.components}
        served: dict[str, list[str]] = {}
        for e in ctx.edges:
            if e.rel == REL_SERVED_BY and e.dst in by_ref:
                served.setdefault(e.src, []).append(e.dst)
        for comp in ctx.components:
            if not isinstance(comp, ModelComponent) or is_model_mention(comp):
                continue
            if not comp.bom_ref.startswith("modelref-"):
                continue  # a carded model: its author's card says what is known
            services = [by_ref[r] for r in served.get(comp.bom_ref, [])]
            if _api_served(comp, services):
                # served by an API (Mistral, Bedrock, Azure …): used under the
                # provider's commercial terms, not an open-weights licence (review
                # 6037909737 of #498, M6)
                comp.licenses = [license_choice(_PROVIDER_TERMS)]
                ctx.flags[:] = [
                    f
                    for f in ctx.flags
                    if not (
                        f.code == "MODEL_LICENSE_UNKNOWN" and f.target == comp.bom_ref
                    )
                ]
            if comp.model_card.considerations is not None:
                continue
            cons = self._derive(comp, services)
            if cons is not None:
                comp.model_card.considerations = cons

    @staticmethod
    def _derive(comp: ModelComponent, services: list) -> Considerations | None:
        props = comp.properties or {}
        kb = model_kb.lookup(comp.name) or {}
        source = props.get("discovery:source")
        task = comp.model_card.task or kb.get("task")
        use_cases: list[str] = []
        if task and source:
            via = ", ".join(sorted({s.name for s in services}))
            use_cases.append(
                f"{task} through {via}, called from {source}"
                if via
                else f"{task}, called from {source}"
            )
        external = _external(services)
        limitations = [
            text
            for text in (
                _HOSTED if external else None,
                _alias(comp.name),
                _profile(props.get("model:bedrock_inference_profile")),
            )
            if text
        ]
        # an open-weights licence's excluded uses do not apply to an API-served model
        api_served = _api_served(comp, services)
        out_of_scope = [] if api_served else list(kb.get("out_of_scope") or [])
        if not (use_cases or limitations or out_of_scope):
            return None
        return Considerations(
            use_cases=use_cases,
            technical_limitations=limitations,
            out_of_scope=out_of_scope,
            derived=True,
        )


__all__ = ["ModelConsiderations"]
