"""Which AI BOM compliance frameworks bind a team (staging QA round 2, Q2-08).

The engine's AI BOM compliance report (``scan_data["ai_bom_compliance"]``) holds every framework it knows:
CERT-In AIBOM, RBI FREE-AI, SEBI CSCRF, NIST AI RMF, EU AI Act Annex IV and the healthcare frameworks (FDA
Section 524B, HIPAA, FDA GMLP). The evidence pack's ``compliance.json`` and the PDF report show only the frameworks
that bind the team, by its regulatory profile (``regulated_entity.team_profile``, #485), the same way the CBOM board
report does, and name the others as not applicable (never silently dropped):

* CERT-In, RBI, SEBI CSCRF and NIST follow the knowledge base's clause-framework rules (``crypto_kb``
  ``applicability.clause_frameworks``): RBI binds the seven RBI-regulated entity types, SEBI CSCRF a SEBI-regulated
  team, CERT-In any Indian team, NIST AI RMF everyone (a reference);
* EU AI Act Annex IV is a reference the SOW names as an AI BOM check: always shown;
* FDA Section 524B, HIPAA and FDA GMLP bind no regulated financial entity (a bank, an NBFC …). For an "other"
  entity they are shown when the scan is in their scope (a requirement that is not out of scope), as before.

With no team profile (a team that never declared its regulated entity, or an offline render) the healthcare rule is
the scan-scope one alone and every other framework is shown; the reports say "regulated entity not set". The callers
read the profile with ``regulated_entity.declared_team_profile`` (never the NBFC default: review 6037909737 of #498,
M4).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend.utilities.cbom_sources import regulated_entity

# Carries the team's profile into the PDF payload (never rendered as text).
PROFILE_KEY = "_dss_regulatory_profile"
HEALTHCARE = ("fda_524b", "hipaa", "gmlp")
# AI BOM framework key -> the knowledge base's clause framework that states who it binds
_KB_FRAMEWORK = {"cert_in_aibom": "CERT-In", "rbi_free_ai": "RBI", "sebi_cscrf_aibom": "SEBI CSCRF",
                 "nist_rmf": "NIST"}
LABELS = {
    "cert_in_aibom": "CERT-In AIBOM",
    "rbi_free_ai": "RBI FREE-AI",
    "sebi_cscrf_aibom": "SEBI CSCRF",
    "nist_rmf": "NIST AI RMF",
    "eu_ai_act_annexIV": "EU AI Act Annex IV",
    "fda_524b": "FDA Section 524B",
    "hipaa": "HIPAA",
    "gmlp": "FDA GMLP",
}
_IN_SCOPE_VERDICTS = ("pass", "pass_with_evidence", "fail", "not_bom_evidenceable")


def _in_scan_scope(report: Mapping[str, Any]) -> bool:
    return any(int(report.get(n) or 0) for n in _IN_SCOPE_VERDICTS)


def binds(key: str, report: Mapping[str, Any], team: Mapping[str, Any] | None) -> bool:
    """Whether the framework ``key`` (its engine report ``report``) binds a team with profile ``team``."""
    if key in HEALTHCARE:
        if not _in_scan_scope(report):
            return False
        return team is None or regulated_entity.normalise(team.get("entity")) == "other"
    rule = _KB_FRAMEWORK.get(key)
    if team is None or rule is None:
        return True
    return regulated_entity.framework_binds(rule, dict(team))


def split(compliance: Mapping[str, Any], team: Mapping[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    """``(frameworks that bind, keys of those that do not)``, in the report's order; non-framework keys (the
    disclaimer) are left out of both."""
    kept: dict[str, Any] = {}
    dropped: list[str] = []
    for key, report in compliance.items():
        if not isinstance(report, Mapping):
            continue
        if binds(key, report, team):
            kept[key] = report
        else:
            dropped.append(key)
    return kept, dropped


def pack_document(compliance: Mapping[str, Any], team: Mapping[str, Any] | None) -> dict[str, Any]:
    """The evidence pack's ``compliance.json`` for an AI BOM: the binding frameworks, the disclaimer, and an
    ``applicability`` block naming the profile and the frameworks left out."""
    kept, dropped = split(compliance, team)
    doc: dict[str, Any] = dict(kept)
    if isinstance(compliance.get("disclaimer"), str):
        doc["disclaimer"] = compliance["disclaimer"]
    doc["applicability"] = {
        "regulatory_profile": dict(team) if team is not None else None,
        "basis": profile_sentence(team),
        "not_applicable": [{"framework": key, "label": LABELS.get(key, key)} for key in dropped],
    }
    return doc


UNDECLARED = "regulated entity not set"


def profile_sentence(team: Mapping[str, Any] | None) -> str:
    """"Commercial bank in India, not SEBI-regulated"; a team that declared no profile: "regulated entity not set"
    (every framework in the scan's scope is shown, review 6037909737 of #498 M4)."""
    if team is None:
        return UNDECLARED
    entity = regulated_entity.LABELS[regulated_entity.normalise(team.get("entity"))]
    flags = set(team.get("flags") or ())
    return f"{entity} in India, " + ("SEBI-regulated" if "sebi_regulated" in flags else "not SEBI-regulated")


def page_view(compliance: Any, team: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """What the results page needs to show the same frameworks as the PDF and the pack (review 6037909737 of #498,
    M3): ``{regulatory_profile, basis, binding: [keys], not_applicable: [{framework, label}]}``."""
    if not isinstance(compliance, Mapping):
        return None
    kept, dropped = split(compliance, team)
    return {
        "regulatory_profile": dict(team) if team is not None else None,
        "basis": profile_sentence(team),
        "binding": list(kept),
        "not_applicable": [{"framework": key, "label": LABELS.get(key, key)} for key in dropped],
    }


def filter_controls(controls: Any, compliance: Any, view: Mapping[str, Any] | None) -> Any:
    """The AI BOM dashboard's per-framework failure counts (keyed by a framework's title, else its key) without the
    frameworks that do not bind the team: the Compliance Controls chart shows what the matrix, the PDF and the pack
    show (review 6037909737 of #498, M3)."""
    if not isinstance(controls, Mapping) or not isinstance(compliance, Mapping) or not view:
        return controls
    names: set[str] = set()
    for entry in view.get("not_applicable") or ():
        key = entry.get("framework") if isinstance(entry, Mapping) else None
        report = compliance.get(key) if key else None
        names.add(str(key))
        if isinstance(report, Mapping) and report.get("title"):
            names.add(str(report["title"]))
    return {name: count for name, count in controls.items() if name not in names}


def is_healthcare_team(team: Mapping[str, Any] | None) -> bool:
    """Whether healthcare wording may apply to the team at all (an "other" entity); a regulated financial entity
    never gets it."""
    return team is not None and regulated_entity.normalise(team.get("entity")) == "other"


__all__ = ["HEALTHCARE", "LABELS", "PROFILE_KEY", "UNDECLARED", "binds", "filter_controls", "is_healthcare_team", "pack_document",
           "page_view", "profile_sentence", "split"]
