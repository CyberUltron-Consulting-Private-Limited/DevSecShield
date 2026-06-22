"""Scanner: a model repo's ``config.json`` + ``MODEL_CARD.md`` + dataset card +
weight file -> a model component, its dataset(s), the edges between them, and
semantic flags.

Runs after the requirements scanner so it can link ``depends_on`` edges to the
frameworks already in the context. Produces:

* the ``model`` component (modelParameters from config.json; identity / metrics /
  considerations / clinical+regulatory from the model card; weight-file hash),
* the ``dataset`` component(s) from dataset cards,
* edges: ``trained_on`` / ``depends_on`` / ``served_by`` / ``deployed_at``,
* flags: ``MODEL_NO_LICENSE``, ``MODEL_EU_AI_ACT_HIGH_RISK``,
  ``MODEL_PHI_AT_INFERENCE``, ``DATASET_NO_DEIDENT``,
  ``DATASET_DECLARED_NOT_FOUND``, ``SERVICE_REF_COLLISION``,
  ``SITE_REF_COLLISION``.

It also sets the BOM subject (the deployed SaMD application) and BOM-level
promoted properties. It does NOT compute scores.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aibom.model.component import (
    InfraComponent,
    MetadataComponent,
    ModelCard,
    ModelComponent,
    ServiceComponent,
    is_deidentified,
)
from aibom.model.result import (
    REL_DEPENDS_ON,
    REL_DEPLOYED_AT,
    REL_SERVED_BY,
    REL_TRAINED_ON,
)
from aibom.scan.parsers.config_json import parse_config
from aibom.scan.parsers.dataset_card import parse_dataset_card
from aibom.scan.parsers.model_card import ParsedModelCard, parse_model_card
from aibom.scan.parsers.model_file import find_model_files, sha256_hash
from aibom.scan.registry import ScanContext, Scanner, register

_MODEL_CARD_NAMES = {"model_card.md", "modelcard.md"}


def _markdown_files(root: Path) -> list[Path]:
    """Sorted .md files under ``root`` (case-insensitive extension match).

    ``Path.glob('*.md')`` is case-SENSITIVE even on case-insensitive volumes, so
    a ``MODEL_CARD.MD`` would be silently skipped; iterate + compare suffixes.
    """
    return sorted(
        p for p in root.iterdir() if p.is_file() and p.suffix.lower() == ".md"
    )


def _find_model_card(root: Path) -> Path | None:
    for p in _markdown_files(root):
        if p.name.lower() in _MODEL_CARD_NAMES:
            return p
    return None


def _find_dataset_cards(root: Path) -> list[Path]:
    return [
        p
        for p in _markdown_files(root)
        if "dataset" in p.name.lower() and "card" in p.name.lower()
    ]


def _build_model(
    card: ParsedModelCard, config_params: dict, weights_root: Path
) -> ModelComponent:
    model_card = ModelCard(
        approach_type=config_params.get("approach_type"),
        task=config_params.get("task"),
        architecture_family=config_params.get("architecture_family"),
        model_architecture=config_params.get("model_architecture"),
        datasets=list(card.datasets),
        inputs=list(config_params.get("inputs", [])),
        outputs=list(config_params.get("outputs", [])),
        performance_metrics=card.performance_metrics,
        considerations=card.considerations,
        pedigree_ancestors=card.pedigree_ancestors,
        intended_use=card.intended_use,
        modality=card.modality,
        body_part=card.body_part,
        pacs_ae_title=card.pacs_ae_title,
        fda_product_code=card.fda_product_code,
        device_class=card.device_class,
        eu_ai_act_risk_tier=card.eu_ai_act_risk_tier,
        uses_sensitive_personal_information=card.uses_sensitive_personal_information,
        human_oversight=card.human_oversight,
    )
    hashes = [sha256_hash(p) for p in find_model_files(weights_root)] or None
    return ModelComponent(
        bom_ref=card.bom_ref,
        name=card.name,
        version=card.version,
        publisher=card.publisher,
        licenses=card.licenses,
        hashes=hashes,
        external_references=card.external_references or None,
        model_card=model_card,
    )


def _bom_properties(card: ParsedModelCard) -> dict[str, str]:
    props: dict[str, str] = {}
    if card.modality:
        props["clinical:modality"] = card.modality
    if card.fda_product_code:
        props["regulatory:fda_product_code"] = card.fda_product_code
    if card.device_class:
        props["regulatory:device_class"] = card.device_class
    if card.eu_ai_act_risk_tier:
        props["regulatory:eu_ai_act_risk"] = card.eu_ai_act_risk_tier
    return props


def _baa_value(raw: Any) -> str:
    """Normalize a BAA flag to the tri-state service:baa enum."""
    if raw is True:
        return "true"
    if raw is False:
        return "false"
    text = str(raw or "unknown").strip().lower()
    return text if text in {"true", "false", "unknown"} else "unknown"


def _service_node(spec: dict[str, Any]) -> ServiceComponent | None:
    """Build the inference-service node (carries service:baa) from a card spec."""
    name = str(spec.get("name") or "").strip()
    if not name:
        return None
    bom_ref = str(spec.get("bom_ref") or f"service-{name.lower().replace(' ', '-')}")
    return ServiceComponent(
        bom_ref=bom_ref,
        name=name,
        properties={"service:baa": _baa_value(spec.get("baa"))},
    )


def _site_node(spec: dict[str, Any]) -> InfraComponent | None:
    """Build a deployment-site node (version/last_validated/drift_status)."""
    name = str(spec.get("name") or "").strip()
    if not name:
        return None
    bom_ref = str(spec.get("bom_ref") or f"site-{name.lower().replace(' ', '-')}")
    props: dict[str, str] = {}
    for key in ("version", "last_validated", "drift_status"):
        val = spec.get(key)
        if val is not None and str(val).strip():
            props[f"site:{key}"] = str(val).strip()
    return InfraComponent(bom_ref=bom_ref, name=name, properties=props or None)


def _link_node(
    ctx: ScanContext,
    model_ref: str,
    node: ServiceComponent | InfraComponent | None,
    rel: str,
    collision_flag: str,
) -> None:
    """Add an inline-built node + its edge, guarding bom_ref uniqueness.

    Author-supplied service/site bom_refs are untrusted. A ref that collides
    with an existing component (e.g. the model itself, or a duplicate site)
    would make ``by_ref()``/``neighbors()`` resolve the edge to the WRONG node,
    silently corrupting the graph-only HIPAA / deployment checks. So, like the
    ``trained_on`` guard, we skip a colliding node and raise an advisory flag
    rather than emit two components sharing one bom_ref.
    """
    if node is None:
        return
    if ctx.has_ref(node.bom_ref):
        ctx.add_flag(
            collision_flag,
            model_ref,
            severity="warning",
            message=(
                f"{rel} bom_ref {node.bom_ref!r} collides with an existing "
                "component; skipped to keep bom_refs unique (a colliding ref "
                "would corrupt the graph lookups that compliance checks read)."
            ),
        )
        return
    ctx.add_component(node)
    ctx.add_edge(model_ref, rel, node.bom_ref)


@register
class ModelRepoScanner(Scanner):
    name = "model-repo"
    order = 20  # runs after framework producers so depends_on edges can resolve

    def matches(self, root: Path) -> bool:
        return _find_model_card(root) is not None or (root / "config.json").is_file()

    def scan(self, ctx: ScanContext) -> None:
        root = ctx.root

        # Datasets first, so the model can link trained_on edges to them.
        for dc_path in _find_dataset_cards(root):
            dataset = parse_dataset_card(dc_path)
            if dataset is None:
                continue
            ctx.add_component(dataset)
            if not is_deidentified(dataset):
                ctx.add_flag(
                    "DATASET_NO_DEIDENT",
                    dataset.bom_ref,
                    severity="error",
                    message=(
                        f"Dataset {dataset.name!r} has no evidence of "
                        "de-identification; HIPAA de-identification required."
                    ),
                )

        card_path = _find_model_card(root)
        card = parse_model_card(card_path) if card_path else None
        if card is None:
            return

        config_params = parse_config(root / "config.json")
        model = _build_model(card, config_params, root)
        ctx.add_component(model)
        ctx.subject = card.application or MetadataComponent(
            name=card.name, version=card.version
        )
        ctx.properties = _bom_properties(card)

        # Edges: trained_on (declared datasets). A declared ref that resolves to
        # no component is a provenance gap -> flag it (advisory) rather than drop
        # the relationship silently.
        for ref in card.datasets:
            if ctx.has_ref(ref):
                ctx.add_edge(model.bom_ref, REL_TRAINED_ON, ref)
            else:
                ctx.add_flag(
                    "DATASET_DECLARED_NOT_FOUND",
                    model.bom_ref,
                    severity="warning",
                    message=(
                        f"Model {model.name!r} declares training dataset {ref!r} "
                        "but no matching dataset component was found "
                        "(expected a DATASET_CARD.md with that bom_ref)."
                    ),
                )
        # Edges: depends_on every discovered framework.
        for framework in ctx.components_of_kind("framework"):
            ctx.add_edge(model.bom_ref, REL_DEPENDS_ON, framework.bom_ref)

        # PHI as a GRAPH FACT: materialize clinical:processes_phi on the model
        # node (authoritative). A Phase-3 HIPAA check reads this property + the
        # served_by edge's service:baa, NEVER the MODEL_PHI_AT_INFERENCE flag
        # (which remains only as the scoring echo, parallel to this fact).
        if card.uses_sensitive_personal_information == "yes":
            model.properties = {
                **(model.properties or {}),
                "clinical:processes_phi": "true",
            }

        # Edge: served_by the inference service (its node carries service:baa,
        # so the HIPAA check can verify a PHI model is served by a BAA'd vendor).
        if card.served_by:
            _link_node(
                ctx, model.bom_ref, _service_node(card.served_by),
                REL_SERVED_BY, "SERVICE_REF_COLLISION",
            )

        # Edges: deployed_at each site (each node carries version/last_validated/
        # drift_status for multi-site governance).
        for site_spec in card.deployed_at:
            _link_node(
                ctx, model.bom_ref, _site_node(site_spec),
                REL_DEPLOYED_AT, "SITE_REF_COLLISION",
            )

        # Flags (semantic findings; scoring happens later).
        if not model.licenses:
            ctx.add_flag(
                "MODEL_NO_LICENSE",
                model.bom_ref,
                severity="error",
                message=f"Model {model.name!r} declares no license.",
            )
        tier = card.eu_ai_act_risk_tier or ""
        if "high" in tier.lower():
            ctx.add_flag(
                "MODEL_EU_AI_ACT_HIGH_RISK",
                model.bom_ref,
                severity="warning",
                message=(
                    f"Model {model.name!r} is EU AI Act high-risk ({tier}); "
                    "Annex IV technical documentation required."
                ),
            )
        if card.uses_sensitive_personal_information == "yes":
            ctx.add_flag(
                "MODEL_PHI_AT_INFERENCE",
                model.bom_ref,
                severity="warning",
                message=(
                    f"Model {model.name!r} uses sensitive personal information "
                    "(PHI) at inference; HIPAA BAA + §524B risk analysis required."
                ),
            )


__all__ = ["ModelRepoScanner"]
