"""The CI/CD API key of an integration, as the UI sees it (issue #99).

The key itself is shown once (the answer of create or rotate) and stored only as its SHA-256 hash
(``auth.create_api_key``). What the read routes may show is a non-secret record kept beside it in
``integration_settings["cicd_api_key"]``: the last four characters, when it was issued and by whom. A revoked key's
column holds ``revoked:<random>``, which no hash and no caller-supplied key can equal (``auth`` refuses the prefix).

Rows created before this record existed have a hashed key and no record: they show as active with no hint.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy import Engine
from sqlmodel import Session, select

from backend.new_models import CicdIntegration, TeamMembership

REVOKED_KEY_PREFIX = "revoked:"
KEY_RECORD = "cicd_api_key"  # integration_settings entry; never holds the key or its hash


def revoked_marker() -> str:
    return REVOKED_KEY_PREFIX + secrets.token_hex(32)


def is_revoked(stored: str | None) -> bool:
    return (stored or "").startswith(REVOKED_KEY_PREFIX)


def key_record(plaintext: str, user_email: str | None) -> dict:
    return {
        "hint": plaintext[-4:],
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "issued_by": user_email,
    }


def with_key_record(settings: dict | None, record: dict | None) -> dict:
    """A copy of ``integration_settings`` with the key record set (``None`` drops it). A new dict, so SQLAlchemy sees
    the JSON column change."""
    out = dict(settings or {})
    if record is None:
        out.pop(KEY_RECORD, None)
    else:
        out[KEY_RECORD] = record
    return out


def public_settings(settings: dict | None) -> dict:
    """``integration_settings`` as the read routes return it: the key record is shown through the api_key_* fields."""
    return {k: v for k, v in (settings or {}).items() if k != KEY_RECORD}


def key_view(integration: CicdIntegration) -> dict:
    """The api_key_* fields of the list and get answers. ``api_key`` is a label (``cicd<team>-…abcd``), kept for
    older clients; nothing in it can be pasted into a pipeline."""
    if is_revoked(integration.api_key):
        return {"api_key": "", "api_key_state": "revoked", "api_key_hint": None, "api_key_issued_at": None,
                "api_key_issued_by": None}
    record = (integration.integration_settings or {}).get(KEY_RECORD) or {}
    hint = record.get("hint") if isinstance(record, dict) else None
    return {
        "api_key": f"cicd{integration.team_id}-…{hint or ''}",
        "api_key_state": "active",
        "api_key_hint": hint,
        "api_key_issued_at": record.get("issued_at") if isinstance(record, dict) else None,
        "api_key_issued_by": record.get("issued_by") if isinstance(record, dict) else None,
    }


def is_team_admin(user_id: int, team_id: int, engine: Engine) -> bool:
    with Session(engine) as session:
        membership = session.exec(
            select(TeamMembership).where(TeamMembership.user_id == user_id, TeamMembership.team_id == team_id)
        ).first()
    return membership is not None and membership.role == "admin"


def can_manage_key(integration: CicdIntegration, user_id: int, admin: bool) -> bool:
    """Rotate and revoke: the integration's owner (who already holds its key and may delete it) or a team admin."""
    return admin or integration.owner_user_id == user_id
