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
from aibom.model.component import AIComponent
from aibom.model.result import Flag, ScanResult
from aibom.owasp import OWASP_LLM_LABELS as _OWASP_2025_LABELS
from aibom.owasp import categories_for_component as _owasp_categories
from aibom.scan.pipeline import scan_repo

# --- enum mappings (values mirror worker helpers/context/enums.py) ---------- #

# component.kind -> AIComponentType value. Unknown kinds fall back to the
# closest umbrella, external_provider (a discovered external AI surface).
_KIND_TO_AI_TYPE = {
    "model": "local_model_file",
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
    "FRAMEWORK_NO_LICENSE": "license_compliance_gap",  # unresolved library license
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

ProgressCb = Callable[[int, str], None]


def _provider(
    publisher: str | None,
    name: str,
    kind: str,
    purl: str | None = None,
) -> str:
    """Infer a ModelProvider value from vendor/name/kind/purl.

    Precedence: named cloud vendor in publisher/name, then local models,
    then PyPI libraries identified by ``pkg:pypi/`` purl. Kind ``framework``
    is not a registry signal — only the purl identifies the ecosystem.
    """
    text = f"{publisher or ''} {name}".lower()
    for needle, value in (
        ("openai", "openai"),
        ("anthropic", "anthropic"),
        ("bedrock", "bedrock"),
        ("vertex", "vertex"),
        ("cohere", "cohere"),
        ("mistral", "mistral"),
        ("hugging", "huggingface"),
    ):
        if needle in text:
            return value
    if kind == "model":
        return "local"
    if (purl or "").lower().startswith("pkg:pypi/"):
        return "pypi"
    return "unknown"


def _component_type(kind: str) -> str:
    return _KIND_TO_AI_TYPE.get(kind, "external_provider")


def _is_catalog_model(comp: AIComponent) -> bool:
    """A model merely LISTED in a registry/catalog (``model:reference_type ==
    "catalog"``) — e.g. a supported-models table — rather than one the scanned code
    actually instantiates/uses. Kept in the full CycloneDX BOM (``ai_bom_json``) for
    completeness, but excluded from the risk-asset findings + dashboard graph so the
    headline model count reflects the models the application USES (not the catalog
    over-count)."""
    return (
        comp.kind == "model"
        and (comp.properties or {}).get("model:reference_type") == "catalog"
    )


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


def _impact(flag: Flag) -> str:
    return _CODE_IMPACT.get(flag.code) or _SEVERITY_IMPACT.get(flag.severity, "Medium")


def _humanize(code: str) -> str:
    return code.replace("_", " ").title()


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
        description = f"Inventoried AI component ({comp.kind})."
    return {
        "title": comp.name,
        "description": description,
        "impact": impact,
        "owasp_top_10": [],
        "compliance_controls": [],
        "suggested_fix": suggested_fix,
        "component_name": comp.name,
        "component_type": _component_type(comp.kind),
        # populated model-card fields (None if absent) — the dashboard's
        # governance-readiness score credits models that carry BOTH a license + card.
        "model_card": _card_summary(comp),
        "framework": comp.name if comp.kind == "framework" else None,
        "version": comp.version,
        "source": _provider(comp.publisher, comp.name, comp.kind, getattr(comp, "purl", None)),
        "license": _license_str(getattr(comp, "licenses", None)),
        "location": props.get("discovery:source") or props.get("discovery:host") or "",
        "snippet": props.get("discovery:snippet", ""),
        "risk_category": risk_category,
        # OWASP-LLM categories (dict {ENUM_NAME: platform_label}) so the backend
        # dashboard can aggregate them into the results-page OWASP chart. Reads
        # the component + its flags via the pure mapper — never flattened to [].
        # Real OWASP-LLM-Top-10:2025 categories (the canonical aibom.owasp mapper),
        # emitted as full "LLMxx:2025 - <meaning>" labels so the dashboard chart
        # shows the correct 2025 names (LLM08 Vector & Embedding, LLM02 Sensitive
        # Information Disclosure, LLM03 Supply Chain) regardless of the frontend's
        # legacy label map. Consistent with ScanResult.owasp (same mapper).
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
            "type": _component_type(c.kind),
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
    return {
        # --- locked contract fields ---
        "results": findings,
        "ai_bom_json": _bom(result, "cyclonedx"),
        "ai_bom_compliance": result.compliance or {},
        "duration_of_scan": duration_of_scan,
        # --- additive (downloadable artifacts + graph + scores) ---
        "ai_bom_spdx": _bom(result, "spdx"),
        "ai_bom_sarif": _bom(result, "sarif"),
        "ai_bom_graph": _graph(result),
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
