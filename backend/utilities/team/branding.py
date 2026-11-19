"""The team's report logo in the database: what the PDF routes load, what the branding API reads and writes.

SQL only: no network, no process, no model SDK (the CBOM deliverables router imports this module, and
tests/test_cbom_deliverables_no_llm.py guards it like the deliverables themselves).  Decoding an upload is
``logo_image.normalize_logo``'s job; this module stores and reads its result.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import Session

from backend.branding_models import TeamBranding
from backend.utilities.pdf.branding_input import ReportBranding, branding_from_png

log = logging.getLogger(__name__)

# What GET /team/{team_id}/branding reads: every column but the bytes.
METADATA_COLUMNS = (TeamBranding.logo_sha256, TeamBranding.logo_width, TeamBranding.logo_height,
                    TeamBranding.logo_bytes, TeamBranding.logo_tone, TeamBranding.updated_at)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def load_report_branding(session: Session, team_id: int) -> ReportBranding:
    """The logo a PDF export draws: one SELECT of the bytes and the tone, checked by ``branding_from_png`` (which
    recomputes the SHA-256 from the bytes).  No row: ``NO_BRANDING``.  Any failure (database, undecodable bytes):
    ``status="skipped"``, logged once; the report is then built without the logo and the route never answers 500.

    Read-only.  On PostgreSQL a failed SELECT aborts the session's transaction, so callers use a session of their
    own for the export (the PDF routes open one inside their thread function)."""
    try:
        row = session.execute(
            select(TeamBranding.logo_png, TeamBranding.logo_tone).where(TeamBranding.team_id == team_id)
        ).first()
        if row is None:
            return ReportBranding()
        png = bytes(row.logo_png) if row.logo_png is not None else None
        if not png:
            raise ValueError("empty logo")
    except Exception as exc:  # noqa: BLE001 - a broken logo never breaks a report
        log.warning("report logo skipped for team %s: %s", team_id, type(exc).__name__)
        return ReportBranding(status="skipped")
    return branding_from_png(png, tone=row.logo_tone)  # logs once itself when the bytes do not decode


def empty_metadata() -> dict[str, Any]:
    return {"logo_set": False, "sha256": None, "width": None, "height": None, "tone": None, "bytes": None,
            "updated_at": None}


def metadata_of(row: Any) -> dict[str, Any]:
    """The API's view of a row (a ``TeamBranding`` or a row of ``METADATA_COLUMNS``); never the bytes."""
    updated = row.updated_at
    return {"logo_set": True, "sha256": row.logo_sha256, "width": row.logo_width, "height": row.logo_height,
            "tone": row.logo_tone, "bytes": row.logo_bytes,
            "updated_at": updated.isoformat() + "Z" if updated is not None else None}


def branding_metadata(session: Session, team_id: int) -> dict[str, Any]:
    """GET /team/{team_id}/branding: the metadata columns only (the PNG is never loaded)."""
    row = session.execute(select(*METADATA_COLUMNS).where(TeamBranding.team_id == team_id)).first()
    return metadata_of(row) if row is not None else empty_metadata()


def logo_png(session: Session, team_id: int) -> tuple[bytes, str] | None:
    """GET /team/{team_id}/branding/logo: the stored PNG and its SHA-256, or None."""
    row = session.execute(
        select(TeamBranding.logo_png, TeamBranding.logo_sha256).where(TeamBranding.team_id == team_id)
    ).first()
    if row is None or not row.logo_png:
        return None
    return bytes(row.logo_png), row.logo_sha256


def upsert_logo(session: Session, team_id: int, logo: Any, *, user_id: int | None,
                now: dt.datetime | None = None) -> dict[str, Any]:
    """Store ``logo`` (a ``logo_image.NormalizedLogo``) as the team's logo: one INSERT ... ON CONFLICT (team_id)
    DO UPDATE on PostgreSQL and SQLite, so two first uploads racing each other both succeed (last write wins) and
    neither answers 500.  The caller holds the team row lock and commits.  Returns the new metadata."""
    values = {
        "team_id": team_id, "logo_png": logo.png, "logo_sha256": hashlib.sha256(logo.png).hexdigest(),
        "logo_width": logo.width, "logo_height": logo.height, "logo_bytes": len(logo.png),
        "logo_tone": logo.tone, "has_alpha": logo.has_alpha, "updated_at": now or _utcnow(),
        "updated_by_user_id": user_id,
    }
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        insert = postgresql_insert
    elif dialect == "sqlite":
        insert = sqlite_insert
    else:  # pragma: no cover - the app runs on PostgreSQL, the tests on SQLite
        raise RuntimeError(f"team branding: no upsert for the {dialect} dialect")
    statement = insert(TeamBranding).values(**values)
    statement = statement.on_conflict_do_update(
        index_elements=[TeamBranding.team_id],
        set_={key: statement.excluded[key] for key in values if key != "team_id"},
    )
    session.execute(statement)
    return metadata_of(TeamBranding(**values))


def delete_logo(session: Session, team_id: int) -> dict[str, Any] | None:
    """Remove the team's logo; the metadata of the row removed, or None when there was none.  The caller commits."""
    row = session.execute(select(*METADATA_COLUMNS).where(TeamBranding.team_id == team_id)).first()
    if row is None:
        return None
    session.execute(delete(TeamBranding).where(TeamBranding.team_id == team_id))
    return metadata_of(row)
