"""The team's regulatory profile: which RBI instrument, and which other frameworks, bind the team (SOW audit A-11).

RBI issues entity-specific directions. On 31 July 2026 it issued Cybersecurity, Technology: Risk, Resilience and
Assurance Framework Directions 2026 for seven entity types, each with its own cryptographic-controls paragraph:
commercial banks (para 140), small finance banks (para 139), payments banks (para 139), urban co-operative banks
(para 25), NBFCs (para 118, Chapter V: Middle Layer and above), All India Financial Institutions (para 135) and
credit information companies (para 135). They supersede the Master Direction on IT Governance (2023) for every entity
type it covered, so that direction is cited for nobody; an "other" entity has no RBI cryptographic clause.

The profile also records three facts a framework's scope depends on: whether the team processes payment-card data
(PCI DSS), is SEBI-regulated (SEBI CSCRF) and is a government entity (CERT-In Guidelines for Government Entities).
Jurisdiction is India: every entity type above is an Indian regulated entity. ``crypto_kb.applies`` decides, for a
clause or a framework, whether it binds the profile; every surface (run page, asset detail, OSCAL, the PDFs) passes
the profile, so they agree.

Stored in the team's CBOM settings (``CbomCollectionSettings.risk_model``, a JSON column, so no migration): the entity
under ``regulated_entity`` (NBFC when not set: the platform's first regulated client is an NBFC), the flags under
their own keys (false when not set).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

ENTITY_TYPES = ("nbfc", "bank", "sfb", "payments_bank", "ucb", "aifi", "credit_info_company", "other")
DEFAULT_ENTITY = "nbfc"
LABELS = {
    "nbfc": "NBFC",
    "bank": "Commercial bank",
    "sfb": "Small finance bank",
    "payments_bank": "Payments bank",
    "ucb": "Urban co-operative bank",
    "aifi": "All India Financial Institution",
    "credit_info_company": "Credit information company",
    "other": "Other entity",
}
SETTINGS_KEY = "regulated_entity"
# team attributes a framework's scope depends on (crypto_kb applicability "requires")
FLAGS = ("processes_card_data", "sebi_regulated", "government_entity")
FLAG_LABELS = {
    "processes_card_data": "Processes payment-card data (PCI DSS applies)",
    "sebi_regulated": "SEBI-regulated entity (SEBI CSCRF applies)",
    "government_entity": "Government entity (CERT-In Guidelines for Government Entities apply)",
}
JURISDICTION = "IN"


def normalise(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in ENTITY_TYPES else DEFAULT_ENTITY


def of_risk_model(risk_model: Mapping[str, Any] | None) -> str:
    return normalise((risk_model or {}).get(SETTINGS_KEY) if isinstance(risk_model, Mapping) else None)


def flags_of(risk_model: Mapping[str, Any] | None) -> list[str]:
    model = risk_model if isinstance(risk_model, Mapping) else {}
    return [flag for flag in FLAGS if model.get(flag) is True]


def profile(entity: str | None = None, flags: Any = ()) -> dict[str, Any]:
    """``{"jurisdiction", "entity", "flags"}``: what ``crypto_kb.applies`` reads."""
    return {"jurisdiction": JURISDICTION, "entity": normalise(entity),
            "flags": sorted({f for f in (flags or ()) if f in FLAGS})}


def profile_of(risk_model: Mapping[str, Any] | None) -> dict[str, Any]:
    return profile(of_risk_model(risk_model), flags_of(risk_model))


DEFAULT_PROFILE = profile()


def applies(clause: Mapping[str, Any], team: Mapping[str, Any] | str | None) -> bool:
    """Whether a knowledge-base clause binds the team (a profile, or an entity type alone with no flags)."""
    from backend.utilities.cbom_sources import crypto_kb

    if not isinstance(clause, Mapping):
        return True
    found = dict(team) if isinstance(team, Mapping) else profile(team)
    return crypto_kb.applies(dict(clause), found)


def framework_binds(key: str, team: Mapping[str, Any] | None) -> bool:
    """Whether a framework (a pooled code-scan framework key, or a clause framework such as "RBI") binds the team;
    a framework the knowledge base does not describe is shown (never hidden by mistake)."""
    from backend.utilities.cbom_sources import crypto_kb

    rule = crypto_kb.framework_applicability(key)
    return True if rule is None else crypto_kb.applies(rule, dict(team or DEFAULT_PROFILE))


def team_profile(session: Any, team_id: int) -> dict[str, Any]:
    """The team's profile, read without creating a settings row."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionSettings

    row = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
    return profile_of(row.risk_model if row is not None else None)


def team_entity(session: Any, team_id: int) -> str:
    return team_profile(session, team_id)["entity"]


__all__ = ["DEFAULT_ENTITY", "DEFAULT_PROFILE", "ENTITY_TYPES", "FLAGS", "FLAG_LABELS", "JURISDICTION", "LABELS",
           "SETTINGS_KEY", "applies", "flags_of", "framework_binds", "normalise", "of_risk_model", "profile",
           "profile_of", "team_entity", "team_profile"]
