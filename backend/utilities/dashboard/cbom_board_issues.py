"""Issues of the Board / IT Strategy Committee report (SOW D14), for its trend against the previous issue (review M7c).

Each D14 download that renders is an issue of the report: one ``CbomCollectionAuditEvent`` (action
``deliverable_issued``, object ``deliverable`` / 14) records who issued which Document ID, and the headline figures it
printed. ``changed_fields`` holds them as ``name=value`` items: a Document ID, a date, a grade letter and counts, all
printed in the report itself, never a setting's value or a secret (the audit model's one documented exception to
"field names only"; a dedicated ``cbom_deliverable_issue`` table replaces it with the next migration). The row is
written through ``common.audit``, so an issue downloaded with a CBOM API key is recorded as the key's.

Two IDs per issue (PR #485 review 2 m5): ``content_id`` is the Document ID of the content alone (scans, settings,
register, day); ``document_id`` is the printed ID, whose digest also covers the previous issue's Document ID. The
previous issue of a content is fixed the first time that content is issued: the newest issue recorded before the
content's first record, with another content. So a Document ID always prints the same trend: X, then Y (trend against
X), then X again prints X's first PDF ("first issue"), never a trend against Y under X's ID. No issue recorded before:
the report says it is the first issue.

An issue is recorded once per team, report, Document ID and UTC day; on PostgreSQL concurrent downloads are serialised
by a transaction-scoped advisory lock on the team, so they never write duplicates (SQLite serialises writes itself).

What a FORMAL issue is (staging QA2 Q1-15: every download, a quick look included, became the next report's "previous
issue"). The choice, documented here and in the route (``formal_issue``):

* an explicit issue: the request says ``issue=1`` (the board pack is being issued): always recorded;
* otherwise the FIRST download of a Document ID on a UTC day, and only while its content is stable: no CBOM Sources run
  of the team is queued or running (a run that lands changes the content, so a download taken mid-run is a draft);
* a preview (``preview=1``) is never recorded, whatever else holds; a re-download of a Document ID already recorded
  that day is never recorded again (``record``).

Only formal issues are recorded, so only a formal issue can become the "previous issue" of a later one.

The renderer stays pure: the route reads ``previous`` into ``TeamCbomView.previous_issue`` before rendering and calls
``record`` after the PDF was built.
"""
from __future__ import annotations

import re
from typing import Any

ACTION = "deliverable_issued"
OBJECT_TYPE = "deliverable"
# the figures a board report issue records (board report ``issue_snapshot``); anything else is ignored on read
FIELDS = ("document_id", "content_id", "as_of", "grade", "score", "issues", "critical", "high", "quantum_vulnerable", "readiness",
          "q1", "q0", "expired")
_VALUE = {
    "document_id": re.compile(r"CBOM-D\d{2}-T\d+-\d{8}-[0-9a-f]{8}"),
    "content_id": re.compile(r"CBOM-D\d{2}-T\d+-\d{8}-[0-9a-f]{8}"),
    "as_of": re.compile(r"\d{4}-\d{2}-\d{2}"),
    "grade": re.compile(r"[A-F]|NOT ASSESSED"),
    "readiness": re.compile(r"\d{1,3}(\.\d)?"),
}
_COUNT = re.compile(r"\d{1,9}")
MAX_FIELDS = 32


def encode(snapshot: dict[str, Any]) -> list[str]:
    """``["document_id=CBOM-D14-...", "grade=C", ...]``: the known fields that have a value."""
    out = []
    for name in FIELDS:
        value = snapshot.get(name)
        if value is None or value == "":
            continue
        text = f"{value:.1f}" if isinstance(value, float) else str(value)
        if _valid(name, text):
            out.append(f"{name}={text}")
    return out


def _valid(name: str, text: str) -> bool:
    pattern = _VALUE.get(name, _COUNT)
    return bool(pattern.fullmatch(text))


def decode(items: Any) -> dict[str, Any]:
    """The recorded figures; a malformed item is dropped, never trusted."""
    out: dict[str, Any] = {}
    for item in (items if isinstance(items, list) else [])[:MAX_FIELDS]:
        name, sep, text = str(item).partition("=")
        if not sep or name not in FIELDS or not _valid(name, text):
            continue
        out[name] = float(text) if name == "readiness" else (text if name in _VALUE else int(text))
    return out


EXPLICIT = "explicit"
FIRST_DOWNLOAD = "first_download"


def formal_issue(*, explicit: bool, preview: bool, active_runs: int) -> str | None:
    """Why this download is a formal issue (``EXPLICIT`` / ``FIRST_DOWNLOAD``), or None when it is not recorded (a
    preview, or a plain download while a run can still change the content). ``record`` then keeps it to the first
    download of its Document ID that day."""
    if preview:
        return None
    if explicit:
        return EXPLICIT
    return FIRST_DOWNLOAD if active_runs <= 0 else None


_LOCK_NS = 0x5A49  # pg_advisory_xact_lock(namespace, team_id): one issue record at a time per team ("ZI")
MAX_ISSUES = 500  # issues read per lookup (one a day for well over a year)


def _rows(session: Any, team_id: int, number: int) -> list[Any]:
    """The team's newest ``MAX_ISSUES`` issue rows of deliverable ``number``, newest first."""
    from sqlmodel import col, select

    from backend.new_models import CbomCollectionAuditEvent as Event

    return list(session.exec(
        select(Event).where(Event.team_id == team_id, Event.action == ACTION, Event.object_type == OBJECT_TYPE,
                            Event.object_id == int(number))
        .order_by(col(Event.at).desc(), col(Event.id).desc()).limit(MAX_ISSUES)
    ).all())


def _content(found: dict[str, Any]) -> str | None:
    """The issue's content ID; an issue recorded before ``content_id`` existed is its own content."""
    return found.get("content_id") or found.get("document_id")


def previous(session: Any, team_id: int, number: int, content_id: str) -> dict[str, Any] | None:
    """The issue deliverable ``number``'s content ``content_id`` is compared with, or None for a first issue.

    The newest issue recorded before this content was first issued, with another content; when the content was never
    issued, the newest issue with another content. Fixed once the content is issued, so its Document ID (whose digest
    covers the previous issue's ID) and its trend never change."""
    issues = [decode(row.changed_fields) for row in reversed(_rows(session, team_id, number))]  # oldest first
    issues = [found for found in issues if found.get("document_id")]
    first = next((index for index, found in enumerate(issues) if _content(found) == content_id), len(issues))
    earlier = [found for found in issues[:first] if _content(found) != content_id]
    return earlier[-1] if earlier else None


def record(session: Any, team_id: int, number: int, snapshot: dict[str, Any], actor_id: int | None,
           now: Any = None) -> bool:
    """Record an issue unless this Document ID is already recorded for the team and report today; True when a row
    was added. Written through ``common.audit`` (an API-key caller is recorded as the key)."""
    import datetime as _dt

    from sqlalchemy import text

    from backend.utilities.cbom_sources.common import audit

    fields = encode(snapshot)
    document = snapshot.get("document_id")
    if not document or not fields:
        return False
    if session.get_bind().dialect.name == "postgresql":
        session.exec(text("SELECT pg_advisory_xact_lock(:ns, :team)").bindparams(  # type: ignore[call-overload]
            ns=_LOCK_NS, team=int(team_id)))
    day = (now or _dt.datetime.now(_dt.timezone.utc)).date()
    for row in _rows(session, team_id, number):
        at = row.at.date() if row.at is not None else None
        if at is not None and at < day:
            break
        if at == day and decode(row.changed_fields).get("document_id") == document:
            session.rollback()  # releases the advisory lock
            return False
    audit(session, team_id=team_id, actor_type="user", actor_id=actor_id, action=ACTION, object_type=OBJECT_TYPE,
          object_id=int(number), changed_fields=fields)
    session.commit()
    return True


__all__ = ["ACTION", "EXPLICIT", "FIELDS", "FIRST_DOWNLOAD", "OBJECT_TYPE", "decode", "encode", "formal_issue",
           "previous", "record"]
