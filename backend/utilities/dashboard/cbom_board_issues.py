"""Issues of the Board / IT Strategy Committee report (SOW D14), for its trend against the previous issue (review M7c).

Each D14 download that renders is an issue of the report: one ``CbomCollectionAuditEvent`` (action
``deliverable_issued``, object ``deliverable`` / 14) records who issued which Document ID, and the headline figures it
printed. ``changed_fields`` holds them as ``name=value`` items: a Document ID, a date, a grade letter and counts, all
printed in the report itself, never a setting's value or a secret. A download of the same content (the same Document
ID: same data, settings and day) is the same issue and records nothing new.

The previous issue of a report is the newest recorded issue with ANOTHER Document ID, so regenerating a document gives
the same PDF (it never compares an issue with itself). No issue recorded: the report says it is the first issue.

The renderer stays pure: the route reads ``previous`` into ``TeamCbomView.previous_issue`` before rendering and calls
``record`` after the PDF was built.
"""
from __future__ import annotations

import re
from typing import Any

ACTION = "deliverable_issued"
OBJECT_TYPE = "deliverable"
# the figures a board report issue records (board report ``issue_snapshot``); anything else is ignored on read
FIELDS = ("document_id", "as_of", "grade", "score", "issues", "critical", "high", "quantum_vulnerable", "readiness",
          "q1", "q0", "expired")
_VALUE = {
    "document_id": re.compile(r"CBOM-D\d{2}-T\d+-\d{8}-[0-9a-f]{8}"),
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


def previous(session: Any, team_id: int, number: int, document_id: str) -> dict[str, Any] | None:
    """The newest recorded issue of deliverable ``number`` for the team with another Document ID, or None."""
    from sqlmodel import col, select

    from backend.new_models import CbomCollectionAuditEvent as Event

    rows = session.exec(
        select(Event.changed_fields).where(Event.team_id == team_id, Event.action == ACTION,
                                           Event.object_type == OBJECT_TYPE, Event.object_id == int(number))
        .order_by(col(Event.at).desc(), col(Event.id).desc()).limit(50)
    ).all()
    for fields in rows:
        found = decode(fields)
        if found.get("document_id") and found["document_id"] != document_id:
            return found
    return None


def record(session: Any, team_id: int, number: int, snapshot: dict[str, Any], actor_id: int | None) -> bool:
    """Record an issue unless this Document ID is already recorded; True when a row was added."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionAuditEvent as Event

    fields = encode(snapshot)
    document = snapshot.get("document_id")
    if not document or not fields:
        return False
    seen = session.exec(
        select(Event.changed_fields).where(Event.team_id == team_id, Event.action == ACTION,
                                           Event.object_type == OBJECT_TYPE, Event.object_id == int(number))
    ).all()
    if any(decode(items).get("document_id") == document for items in seen):
        return False
    session.add(Event(team_id=team_id, actor_type="user", actor_id=actor_id, action=ACTION, object_type=OBJECT_TYPE,
                      object_id=int(number), changed_fields=fields))
    session.commit()
    return True


__all__ = ["ACTION", "FIELDS", "OBJECT_TYPE", "decode", "encode", "previous", "record"]
