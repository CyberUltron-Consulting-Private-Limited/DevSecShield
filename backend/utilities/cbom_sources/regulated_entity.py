"""The team's regulated-entity type: which RBI instrument the CBOM regulatory mapping cites.

RBI issues entity-specific directions. Since 31 July 2026 commercial banks follow the Commercial Banks
Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026 (cryptographic controls: para 140)
and NBFCs the NBFC Directions 2026 of the same name (para 118; para 155 repeals the earlier IT Framework and IT
Governance directions for NBFCs). A clause in the knowledge base that names the entity types it binds
(``applies_to``) is cited only for a team of one of those types; a clause without ``applies_to`` applies to all.

Stored in the team's CBOM settings (``CbomCollectionSettings.risk_model["regulated_entity"]``, a JSON column, so no
migration); NBFC when not set: the platform's first regulated client is an NBFC.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

ENTITY_TYPES = ("nbfc", "bank", "other")
DEFAULT_ENTITY = "nbfc"
LABELS = {"nbfc": "NBFC", "bank": "Commercial bank", "other": "Other regulated entity"}
SETTINGS_KEY = "regulated_entity"


def normalise(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in ENTITY_TYPES else DEFAULT_ENTITY


def of_risk_model(risk_model: Mapping[str, Any] | None) -> str:
    return normalise((risk_model or {}).get(SETTINGS_KEY) if isinstance(risk_model, Mapping) else None)


def applies(clause: Mapping[str, Any], entity: str | None) -> bool:
    """Whether a knowledge-base clause binds a team of this entity type."""
    scope = clause.get("applies_to") if isinstance(clause, Mapping) else None
    return not scope or normalise(entity) in scope


def team_entity(session: Any, team_id: int) -> str:
    """The team's setting, read without creating a settings row."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionSettings

    row = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
    return of_risk_model(row.risk_model if row is not None else None)


__all__ = ["DEFAULT_ENTITY", "ENTITY_TYPES", "LABELS", "SETTINGS_KEY", "applies", "normalise", "of_risk_model",
           "team_entity"]
