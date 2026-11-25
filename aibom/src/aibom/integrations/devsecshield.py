"""DevSecShield native-scanner adapter for the clinithread-aibom engine.

Makes the standalone engine a drop-in for DevSecShield's ``ai_bom`` scanner. The
worker task body becomes a single call::

    from aibom.integrations.devsecshield import scan_to_devsecshield
    return scan_to_devsecshield(repo_path, progress=state_update_writer)

and the returned dict is exactly the locked run-object the platform stores in
``Scan.scan_data`` and serves back through ``GET …/scan/{id}`` (contract
``devsecshield/contract/result-schema``).

Design (verified against the Phase-5 recon):

* **Engine internals unchanged / lanes intact.** :func:`run_native_scan` only
  *invokes* the engine (``scan_repo`` then the compliance checks); it adds no
  flags and computes no scores — the scorer and checks run inside the engine.
* **Decoupled from the host.** :func:`normalize` emits plain dicts with
  *string* enum values that match ``helpers/context/enums.py`` — it imports
  nothing from the worker, so neither package depends on the other.
* **Findings = flags.** Each engine :class:`Flag` (the risk unit) becomes one
  ``AIComponentVulnerability``, enriched with its target component's metadata.
  The full inventory + relationships survive as ``ai_bom_json`` (CycloneDX) and
  ``ai_bom_graph`` (nodes + edges) so the frontend can render the dependency
  graph; the full per-framework tri-state compliance breakdown (pass /
  pass_with_evidence / fail / out_of_scope / not_bom_evidenceable / na +
  coverage + per-requirement reasons) is preserved verbatim.

The run-object adds fields beyond the four locked ones; all additions are
additive (``ai_bom_spdx``, ``ai_bom_sarif``, ``ai_bom_graph``, ``ai_bom_scores``)
and never remove or rename a locked field.
"""

from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import aibom.compliance as _compliance
from aibom.emit import get_reporter
from aibom.graph_view import (
    COMPACT_MAX_NODES,
    EXPANDED_MAX_NODES,
    build_graph_view,
    compact_aibom_graph,
)
from aibom.model.component import AIComponent, is_model_mention
from aibom.model.result import REL_SERVED_BY, Flag, ScanResult
from aibom.owasp import OWASP_LLM_LABELS as _OWASP_2025_LABELS
from aibom.owasp import categories_for_component as _owasp_categories
from aibom.scan.parsers.license_resolver import resolve_license
from aibom.scan.pipeline import scan_repo

# --- enum mappings (values mirror worker helpers/context/enums.py) ---------- #

# component.kind -> AIComponentType value. Unknown kinds fall back to the
# closest umbrella, external_provider (a discovered external AI surface).
# AIComponentType for a self-hosted model server (worker enums.AIComponentType)
LOCAL_MODEL_SERVER = "local_model_server"
# a model server the organisation runs elsewhere (a remote / self-hosted Ollama, or one
# whose endpoint the scan could not read): not this machine, not a hosted vendor
SELF_HOSTED_MODEL_SERVER = "self_hosted_model_server"
# a model run by a self-hosted model server (an Ollama tag): no weight file in the
# repository, no hosted vendor product (review 6062066749 of #498, m6)
SELF_HOSTED_MODEL = "self_hosted_model"
_SERVICE_KINDS = ("service", "cloud_service", "endpoint")
_KIND_TO_AI_TYPE = {
    # a model the scan saw served by a provider is external_provider (see
    # _component_type); a model with no serving service, and a weight file, are local
    "model": "local_model_file",
    "model_file": "local_model_file",
    "dataset": "dataset",
    "framework": "ml_framework",
    "prompt": "prompt_asset",
    "embedding_model": "embedding_model",
    "service": "external_provider",
    "cloud_service": "external_provider",
    "endpoint": "external_provider",
}

# flag.code -> Impact (overrides the severity default below).
_CODE_IMPACT = {
    "DATASET_NO_DEIDENT": "Critical",
    "MODEL_PHI_AT_INFERENCE": "High",
    "MODEL_NO_LICENSE": "High",
    "MODEL_EU_AI_ACT_HIGH_RISK": "High",
    "UNSANCTIONED_COMPONENT": "High",
}
_SEVERITY_IMPACT = {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}

# flag.code -> AIRiskCategory value. Default: missing_model_card_lineage
# (an ungoverned/under-documented component) — the conservative governance bucket.
_CODE_RISK = {
    "MODEL_NO_LICENSE": "license_compliance_gap",
    "FRAMEWORK_NO_LICENSE": "license_compliance_gap",  # library declaring no licence
    "FRAMEWORK_LICENSE_UNKNOWN": "license_compliance_gap",  # not resolved offline
    "MODEL_LICENSE_UNKNOWN": "license_compliance_gap",  # model with no known license
    "HARDCODED_SECRET": "model_theft_exposure",  # leaked credential -> model access
    "DATASET_NO_DEIDENT": "data_privacy_training_config",
    "MODEL_PHI_AT_INFERENCE": "data_privacy_training_config",
    "MODEL_EU_AI_ACT_HIGH_RISK": "missing_model_card_lineage",
    "UNSANCTIONED_COMPONENT": "missing_model_card_lineage",
    "DATASET_DECLARED_NOT_FOUND": "missing_model_card_lineage",
    "SERVICE_REF_COLLISION": "missing_model_card_lineage",
    "SITE_REF_COLLISION": "missing_model_card_lineage",
}
_DEFAULT_RISK = "missing_model_card_lineage"

# flag.code -> a concrete remediation. Default below.
_CODE_FIX = {
    "MODEL_NO_LICENSE": "Add a concluded license to the model card so downstream "
    "use can be assessed for compliance.",
    "DATASET_NO_DEIDENT": "De-identify training data (Safe Harbor / Expert "
    "Determination) and record the anonymization method on the dataset card.",
    "MODEL_PHI_AT_INFERENCE": "Confirm a signed BAA with the serving vendor and "
    "minimize PHI sent at inference.",
    "MODEL_EU_AI_ACT_HIGH_RISK": "Complete the EU AI Act Annex IV technical "
    "documentation for this high-risk model.",
    "UNSANCTIONED_COMPONENT": "Review this component against the AI allowlist; "
    "sanction it or remove it from the deployment.",
}
_DEFAULT_FIX = "Review this AI/ML component and bring it under AI governance."

_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# Display labels must match frontend/lib/owasp-compliance-labels.ts so dashboard
# aggregation (map VALUES) renders correctly on AiBomResults Compliance Controls.
_COMPLIANCE_PRIVACY = {
    "ISO42001_2": "ISO 42001 - Data Governance and Transparency",
    "NIST80053_AC": "NIST 800-53 - Access Control",
}
_COMPLIANCE_SUPPLY = {
    "ISO42001_1": "ISO 42001 - AI Risk Management",
    "ISO42001_3": "ISO 42001 - Model Lifecycle Management",
}
_PRIVACY_FLAG_CODES = frozenset(
    {
        "HARDCODED_SECRET",
        "MODEL_PHI_AT_INFERENCE",
        "DATASET_NO_DEIDENT",
    }
)
_SUPPLY_FLAG_CODES = frozenset(
    {
        "FRAMEWORK_NO_LICENSE",
        "FRAMEWORK_LICENSE_UNKNOWN",
        "MODEL_NO_LICENSE",
        "MODEL_LICENSE_UNKNOWN",
        "UNSANCTIONED_COMPONENT",
        "DATASET_DECLARED_NOT_FOUND",
        "MODEL_EU_AI_ACT_HIGH_RISK",
    }
)

ProgressCb = Callable[[int, str], None]


def _provider(
    publisher: str | None,
    name: str,
    kind: str,
    *,
    location: str = "",
    props: dict[str, Any] | None = None,
) -> str:
    """Infer a ModelProvider value from a component's vendor/name/kind/path.

    Never returns ``unknown`` — every inventory row gets a concrete label
    (cloud vendor, ``pypi``, ``credential``, or ``local``).
    """
    props = props or {}
    # where the model runs, as the linker resolved it (Bedrock for an
    # ``anthropic.claude-…`` id, Groq for Llama behind the Groq API): never the
    # vendor's name when another platform serves it (QA round 2, Q2-06)
    if props.get("model:provider"):
        return str(props["model:provider"])
    text = " ".join(
        str(x)
        for x in (
            publisher or "",
            name,
            location,
            props.get("discovery:source", ""),
            props.get("discovery:host", ""),
            props.get("discovery:snippet", ""),
        )
        if x
    ).lower()
    # Ordered: more-specific aliases before broad substrings (openai before open).
    for needle, value in (
        ("anthropic", "anthropic"),
        ("claude", "anthropic"),
        ("bedrock", "bedrock"),
        ("amazon-bedrock", "bedrock"),
        ("aws-bedrock", "bedrock"),
        ("azure", "azure"),
        ("vertex", "vertex"),
        ("cohere", "cohere"),
        ("mistral", "mistral"),
        ("hugging", "huggingface"),
        ("ollama", "ollama"),
        ("openrouter", "openrouter"),
        ("groq", "groq"),
        ("together.xyz", "together"),
        ("together.ai", "together"),
        ("together ai", "together"),
        ("deepseek", "deepseek"),
        ("api.x.ai", "xai"),
        ("xai api", "xai"),
        # Alibaba Cloud: Qwen's publisher node, DashScope; a local Qwen weight file
        # names none of these and stays ``local`` (second review of #487, n-a)
        ("alibaba", "alibaba"),
        ("dashscope", "alibaba"),
        ("aliyun", "alibaba"),
        ("openai", "openai"),
        # after vertex: the Gemini API (generativelanguage.googleapis.com) and
        # Google's models are Google's SaaS, never ``local`` (review of #487 m7)
        ("gemini", "google"),
        ("googleapis", "google"),
        ("google", "google"),
    ):
        if needle in text:
            return value

    name_l = (name or "").lower()
    kind_l = (kind or "").lower()
    # Framework / library inventory → PyPI ecosystem (not a hosted AI vendor).
    if kind_l in ("framework",) or "framework" in kind_l:
        return "pypi"
    # Secrets without a path-named vendor → credential bucket.
    if "credential" in name_l or "secret" in name_l or kind_l in ("secret", "credential"):
        return "credential"
    # Models, embeddings, weight artifacts, datasets, prompts → local.
    if (
        kind_l in ("model", "embedding_model", "dataset", "prompt")
        or name_l.endswith(".bin")
        or name_l.endswith(".safetensors")
        or name_l.endswith(".gguf")
        or name_l.endswith(".pt")
        or name_l.endswith(".pth")
        or name_l.endswith(".onnx")
    ):
        return "local"
    return "local"


def _component_type(
    kind: str, comp: AIComponent | None = None, result: ScanResult | None = None
) -> str:
    """The AIComponentType of a component. A model is ``external_provider`` when it
    is provider-served (``model:provider``, or ``served_by`` a service outside the
    trust boundary), else ``local_model_file``; a weight file is
    ``local_model_file`` (QA round 2, Q2-06; first noted on #487)."""
    if kind == "model" and comp is not None and _provider_served(comp, result):
        return "external_provider"
    if kind == "model" and comp is not None and _self_hosted_model(comp, result):
        return SELF_HOSTED_MODEL
    if kind in _SERVICE_KINDS and comp is not None and _is_local_server(comp):
        # a self-hosted model server on the machine (Ollama on localhost): inside
        # the trust boundary, never an external provider (#498 round 3 follow-up)
        return LOCAL_MODEL_SERVER
    if kind in _SERVICE_KINDS and comp is not None and _is_model_server(comp):
        return SELF_HOSTED_MODEL_SERVER
    return _KIND_TO_AI_TYPE.get(kind, "external_provider")


def _is_model_server(comp: AIComponent) -> bool:
    return (comp.properties or {}).get("service:kind") == "model_server"


def _self_hosted_model(comp: AIComponent, result: ScanResult | None) -> bool:
    """A model an Ollama call names (``model:served_via`` ollama), or one served by a
    model server: run by a self-hosted server, never a weight file in the repo."""
    if (comp.properties or {}).get("model:served_via") == "ollama":
        return True
    if result is None:
        return False
    return any(
        _is_model_server(svc) or _is_local_server(svc)
        for svc in result.neighbors(comp.bom_ref, REL_SERVED_BY)
    )


def _is_local_server(comp: AIComponent) -> bool:
    return (comp.properties or {}).get("service:trust_zone") == "local"


def _served_model_licence(comp: AIComponent, result: ScanResult | None) -> str:
    """A local model server's row licence: the open-weights licence of the models it
    serves when they share one, else NOASSERTION. Never a provider's terms: nothing
    is used under a hosted provider's terms on a self-hosted server."""
    if result is None:
        return LICENSE_UNKNOWN
    served = [
        e.src for e in result.edges if e.rel == REL_SERVED_BY and e.dst == comp.bom_ref
    ]
    by_ref = {c.bom_ref: c for c in result.components}
    licences = {
        _license_str(getattr(by_ref.get(ref), "licenses", None)) or "" for ref in served
    }
    licences.discard("")
    if len(licences) == 1:
        (only,) = licences
        if only != "LicenseRef-proprietary":
            return only
    return LICENSE_UNKNOWN


def _provider_served(comp: AIComponent, result: ScanResult | None) -> bool:
    provider = (comp.properties or {}).get("model:provider")
    if provider:
        return provider not in ("ollama", "local")
    if result is None:
        return False
    return any(
        (svc.properties or {}).get("service:trust_zone") != "local"
        for svc in result.neighbors(comp.bom_ref, REL_SERVED_BY)
    )


def _is_catalog_model(comp: AIComponent) -> bool:
    """A model merely LISTED in a registry/catalog (``model:reference_type ==
    "catalog"``) — e.g. a supported-models table — rather than one the scanned code
    actually instantiates/uses. Kept in the full CycloneDX BOM (``ai_bom_json``) for
    completeness, but excluded from the risk-asset findings + dashboard graph so the
    headline model count reflects the models the application USES (not the catalog
    over-count)."""
    return is_model_mention(comp)


def _inventory(result: ScanResult) -> list[AIComponent]:
    """The components surfaced as risk-assets / graph nodes: every component EXCEPT
    catalog-only model references (which remain in the complete BOM)."""
    return [c for c in result.components if not _is_catalog_model(c)]


def _card_summary(comp: AIComponent) -> dict[str, Any] | None:
    """Populated model-card fields for a model component (None if no card / empty) —
    so the dashboard's governance-readiness score can see which models carry a card."""
    card = getattr(comp, "model_card", None)
    if card is None:
        return None
    data = card.model_dump(exclude_none=True, exclude_defaults=True)
    return data or None


def _license_str(licenses: Any) -> str | None:
    """Flatten a CycloneDX-style licenses list to a single string (or None).

    The engine carries ``[{"license": {"id": "Apache-2.0"}}]`` /
    ``[{"license": {"name": "..."}}]`` / ``[{"expression": "..."}]`` / plain
    strings; the worker's ``license`` field is ``str | None``.
    """
    if not licenses:
        return None
    first = licenses[0]
    if isinstance(first, str):
        return first
    if isinstance(first, dict):
        lic = first.get("license")
        if isinstance(lic, dict):
            value = lic.get("id") or lic.get("name")
            if value:
                return str(value)
        if first.get("expression"):
            return str(first["expression"])
    return None


_ARTIFACT_SUFFIXES = (".bin", ".safetensors", ".gguf", ".pt", ".pth", ".onnx")
# SPDX's word for "not determined": a library whose licence the offline manifest does
# not know. Unknown / partial, which is not the same as a library with no licence.
LICENSE_UNKNOWN = "NOASSERTION"


def _finding_license(comp: AIComponent, result: ScanResult | None = None) -> str:
    """Concrete license label for a finding row."""
    props = comp.properties or {}
    if (comp.kind or "").lower() in _SERVICE_KINDS and (
        _is_local_server(comp)
        or _is_model_server(comp)
        or props.get("service:kind") == "gateway"
    ):
        # a model server or a gateway runs other makers' models: the served models'
        # shared open-weights licence, else NOASSERTION, never a provider's terms
        # (review 6062066749 of #498, m5)
        return _served_model_licence(comp, result)
    declared = _license_str(getattr(comp, "licenses", None))
    if declared and declared.strip().lower() not in ("unknown", "none", "null"):
        return declared.strip()

    name = comp.name or ""
    name_l = name.lower()
    kind = (comp.kind or "").lower()

    if "credential" in name_l or "secret" in name_l or kind in ("secret", "credential"):
        return "LicenseRef-not-applicable"

    if any(name_l.endswith(sfx) for sfx in _ARTIFACT_SUFFIXES):
        return "LicenseRef-not-declared"

    if kind == "framework":
        spdx = resolve_license(name)
        if spdx:
            return spdx
        # not resolved offline: unknown, never "not declared" (QA round 2, Q2-07)
        return LICENSE_UNKNOWN

    # Hosted services / external surfaces without a package license.
    if kind in ("service", "cloud_service", "endpoint") or _component_type(kind) == (
        "external_provider"
    ):
        text = f"{(comp.publisher or '')} {name}".lower()
        if any(
            n in text
            for n in (
                "openai",
                "bedrock",
                "azure",
                "anthropic",
                "vertex",
                "cohere",
                "mistral",
                "ollama",
                "hugging",
                "api",
            )
        ):
            return "LicenseRef-proprietary"
        return "LicenseRef-not-declared"

    spdx = resolve_license(name)
    if spdx:
        return spdx
    if kind == "model" and (comp.bom_ref or "").startswith("modelref-"):
        # a model the code references, with no licence the knowledge base knows
        # (MODEL_LICENSE_UNKNOWN): unknown, never "not declared" (nothing was read
        # that could declare one; #498 round 3, pyannote/speaker-diarization-3.1)
        return LICENSE_UNKNOWN
    return "LicenseRef-not-declared"


def _impact(flag: Flag) -> str:
    return _CODE_IMPACT.get(flag.code) or _SEVERITY_IMPACT.get(flag.severity, "Medium")


def _humanize(code: str) -> str:
    return code.replace("_", " ").title()


def _inventory_description(comp: AIComponent) -> str:
    """Finding-centric issue text for unflagged inventory rows (governance gaps)."""
    kind = (comp.kind or "").lower()
    if kind == "model":
        card = getattr(comp, "model_card", None)
        has_tech = bool(
            card
            and (getattr(card, "model_architecture", None) or getattr(card, "task", None))
        )
        if not has_tech:
            return (
                "Issue: missing model-card technical documentation "
                "(architecture/task) required for AI governance."
            )
        if not (comp.version and str(comp.version).strip()):
            return "Issue: model lacks version in the AI inventory."
        if not _license_str(getattr(comp, "licenses", None)):
            return "Issue: model lacks a declared license for integrity review."
    return f"Inventoried AI component ({comp.kind})."


def _legacy_compliance(flags: list[Flag]) -> dict[str, str]:
    """Map flagged findings to ISO 42001 / NIST controls; clean inventory -> {}."""
    if not flags:
        return {}
    codes = {f.code for f in flags}
    out: dict[str, str] = {}
    if codes & _PRIVACY_FLAG_CODES:
        out.update(_COMPLIANCE_PRIVACY)
    if codes & _SUPPLY_FLAG_CODES:
        out.update(_COMPLIANCE_SUPPLY)
    if not out:
        # Any other flag still evidences AI governance controls.
        out.update(_COMPLIANCE_SUPPLY)
    return out


def _finding_from_component(comp: AIComponent, result: ScanResult) -> dict[str, Any]:
    """Map one engine COMPONENT (the AI-asset inventory unit) to an
    AIComponentVulnerability.

    The DevSecShield dashboard treats every ``results[]`` row as an AI asset
    (``total_ai_assets = len(results)``), so the inventory unit is the component,
    not the flag. Impact + risk derive from the flags ON that component (the most
    severe wins); un-flagged components are inventoried at Low impact.
    """
    props = comp.properties or {}
    flags = result.flags_for(comp.bom_ref)
    # Finding severity = the STACKED per-component severity from the recalibrated
    # scorer (flags stack per component); fall back to the top-flag mapping, then
    # Low — so a component accumulating several flags is rated by their sum.
    stacked = (result.scores or {}).get("component_severity", {}).get(comp.bom_ref)
    if flags:
        primary = min(flags, key=lambda f: _IMPACT_RANK[_impact(f)])
        impact = stacked.capitalize() if stacked else _impact(primary)
        risk_category = _CODE_RISK.get(primary.code, _DEFAULT_RISK)
        suggested_fix = _CODE_FIX.get(primary.code, _DEFAULT_FIX)
        description = "; ".join(f.message for f in flags if f.message) or _humanize(
            primary.code
        )
    else:
        impact = stacked.capitalize() if stacked else "Low"
        risk_category = _DEFAULT_RISK
        suggested_fix = _DEFAULT_FIX
        description = _inventory_description(comp)
    license_label = _finding_license(comp, result)
    return {
        "title": comp.name,
        "description": description,
        # Stable inventory identity — FE joins posture refs → findings via bom_ref
        # (Mongo ObjectId overwrites ``id`` after persist; bom_ref stays).
        "bom_ref": comp.bom_ref,
        "impact": impact,
        "owasp_top_10": [],
        # Dict (never list) so dashboard .items() aggregation works. Flagged rows
        # get deterministic ISO 42001 / NIST maps; clean inventory stays {}.
        "compliance_controls": _legacy_compliance(flags),
        "suggested_fix": suggested_fix,
        "component_name": comp.name,
        "component_type": _component_type(comp.kind, comp, result),
        # the engine kind: a provider-served model is still a model (model counts)
        "component_kind": comp.kind,
        # a model the code uses without naming it (ChatOpenAI(), a model from
        # configuration): False; any other model True; not a model None. The views
        # count unidentified models per scan, never merged across repositories
        # (review 6062066749 of #498, m1)
        "model_identified": (
            (comp.properties or {}).get("model:identified") != "false"
            if comp.kind == "model"
            else None
        ),
        # populated model-card fields (None if absent) — the dashboard's
        # governance-readiness score credits models that carry BOTH a license + card.
        "model_card": _card_summary(comp),
        "framework": comp.name if comp.kind == "framework" else None,
        "version": comp.version,
        "source": _provider(
            comp.publisher,
            comp.name,
            comp.kind,
            location=props.get("discovery:source") or props.get("discovery:host") or "",
            props=props,
        ),
        "license": license_label,
        # "unknown" when the licence was not resolved (offline manifest only)
        "license_status": "unknown" if license_label == LICENSE_UNKNOWN else "resolved",
        "location": props.get("discovery:source") or props.get("discovery:host") or "",
        "snippet": props.get("discovery:snippet", ""),
        "risk_category": risk_category,
        "risk_score": round(
            min(
                10.0,
                max(
                    0.0,
                    {"Critical": 7.5, "High": 5.5, "Medium": 3.5, "Low": 1.2}.get(
                        impact, 1.2
                    )
                    + float(
                        (result.scores or {})
                        .get("by_component", {})
                        .get(comp.bom_ref, 0.0)
                        or 0.0
                    )
                    * 0.25,
                ),
            ),
            1,
        ),
        # OWASP-LLM categories as {LLM0x: full 2025 label}. Dashboard aggregates
        # by KEY (short code); FE resolves labels via OWASP_LLM_KEY_TO_LABEL.
        "owasp_top_10_llm": {
            code: f"{code}:2025 - {_OWASP_2025_LABELS[code]}"
            for code in sorted(_owasp_categories(comp, flags))
        },
    }


def _graph(result: ScanResult) -> dict[str, list[dict[str, str]]]:
    """Inventory + relationships for the frontend graph (edges preserved)."""
    nodes = [
        {
            "id": c.bom_ref,
            "label": c.name,
            "kind": c.kind,
            "type": _component_type(c.kind, c, result),
        }
        for c in result.components
    ]
    edges = [{"source": e.src, "target": e.dst, "rel": e.rel} for e in result.edges]
    nodes.sort(key=lambda n: n["id"])
    edges.sort(key=lambda e: (e["source"], e["rel"], e["target"]))
    return {"nodes": nodes, "edges": edges}


def _bom(result: ScanResult, fmt: str) -> dict[str, Any]:
    """Render a BOM artifact to a dict (raw, downloadable) via the reporter."""
    return json.loads(get_reporter(fmt).render(result))


def normalize(result: ScanResult, *, duration_of_scan: float) -> dict[str, Any]:
    """Normalize a scored ScanResult into the locked DevSecShield run-object.

    Pure + deterministic for a given ScanResult (``duration_of_scan`` aside).
    Assumes the compliance checks have already run (``run_native_scan`` does
    this); reads ``result.compliance`` as-is, preserving the full tri-state
    breakdown per framework ({pass, pass_with_evidence, fail, out_of_scope,
    not_bom_evidenceable, na, coverage, requirements}).
    """
    findings = [_finding_from_component(c, result) for c in _inventory(result)]
    findings.sort(
        key=lambda f: (
            _IMPACT_RANK.get(f["impact"], 9),
            f["component_name"],
            f["title"],
        )
    )
    full_graph = _graph(result)
    return {
        # --- locked contract fields ---
        "results": findings,
        "ai_bom_json": _bom(result, "cyclonedx"),
        "ai_bom_compliance": result.compliance or {},
        "duration_of_scan": duration_of_scan,
        # --- additive (downloadable artifacts + graph + scores) ---
        "ai_bom_spdx": _bom(result, "spdx"),
        "ai_bom_sarif": _bom(result, "sarif"),
        # Full inventory graph (contracts). Compact/expanded views are additive —
        # FE dependency canvas prefers ``ai_bom_graph_compact`` / ``_expanded``.
        "ai_bom_graph": full_graph,
        "ai_bom_graph_compact": compact_aibom_graph(
            full_graph,
            max_nodes=COMPACT_MAX_NODES,
            hub_cluster_models=True,
            family_group_models=True,
            collapse_orphans=True,
        ),
        "ai_bom_graph_expanded": compact_aibom_graph(
            full_graph,
            max_nodes=EXPANDED_MAX_NODES,
            hub_cluster_models=True,
            family_group_models=True,
            collapse_orphans=False,
        ),
        "ai_bom_graph_view": build_graph_view(
            full_graph, lane="aibom", max_nodes=COMPACT_MAX_NODES
        ),
        "ai_bom_scores": result.scores or {},
        # OWASP-LLM-2025 distribution {code: count} (aibom.owasp; populated on
        # every scan by the pipeline). Carried THROUGH — never flattened.
        "ai_bom_owasp": result.owasp or {},
    }


def run_native_scan(
    target: str | Path,
    *,
    level: int = 1,
    allowlist: str | Path | None = None,
    progress: ProgressCb | None = None,
    attestations: dict[str, dict[str, str]] | None = None,
) -> ScanResult:
    """Invoke the engine: scan the target, then run compliance. Lanes intact.

    Returns the scored ScanResult (scorer + checks already applied inside the
    engine). No host imports; this only orchestrates engine entry points.

    ``attestations`` is an optional ``{framework: {requirement_id: note}}`` map of
    uploaded process-evidence attestations; a matching ``not_bom_evidenceable``
    requirement flips to ``pass_with_evidence`` (the evidence-attachment path).
    """
    _report(progress, 10, "scanning repository for AI components")
    result = scan_repo(target, level=level, allowlist=allowlist)
    # the real scan time: every BOM / SPDX / SARIF of this scan carries it
    from aibom.emit.identity import utc_now

    result.generated_at = utc_now()
    _report(progress, 70, "mapping compliance frameworks")
    # tri-state compliance: pass/fail (graph) + out_of_scope (framework N/A) +
    # not_bom_evidenceable (process evidence) -> pass_with_evidence via attestations.
    _compliance.run_all(result, evidence=attestations or {})
    _report(progress, 95, "normalizing results")
    return result


def scan_to_devsecshield(
    target: str | Path,
    *,
    level: int = 1,
    allowlist: str | Path | None = None,
    progress: ProgressCb | None = None,
    attestations: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """One-call entry for the worker: scan + normalize -> locked run-object.

    ``attestations`` (optional ``{framework: {requirement_id: note}}``) flips
    matching ``not_bom_evidenceable`` requirements to ``pass_with_evidence``.
    """
    start = time.monotonic()
    result = run_native_scan(
        target,
        level=level,
        allowlist=allowlist,
        progress=progress,
        attestations=attestations,
    )
    out = normalize(result, duration_of_scan=time.monotonic() - start)
    _report(progress, 100, "scan complete")
    return out


def _report(progress: ProgressCb | None, pct: int, message: str) -> None:
    """Best-effort progress callback; never lets reporting break a scan."""
    if progress is None:
        return
    with contextlib.suppress(Exception):  # progress must never fail the scan
        progress(pct, message)


__all__ = ["normalize", "run_native_scan", "scan_to_devsecshield"]
