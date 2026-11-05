"""Marking a stored finding fixed: one function for the manual toggle and for a re-scan that proved the fix.

``mark_finding_fixed`` sets ``finding_status = "fixed"`` (with ``fixed_at`` and, for a re-scan, the scan that proved
it) and closes the finding's Jira ticket (close-on-fixed). ``toggle_finding_state`` calls it when a user marks a
finding fixed; ``drift.on_code_scan_success`` calls it for the previous scan's findings that a later complete scan of
the same repository and branch no longer has. A finding the user marked "ignored" is left alone by the re-scan path.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Iterable

from rich.console import Console
from sqlmodel import Session, select

from backend.new_models import Team

console = Console(markup=False)


def mark_finding_fixed(collection, finding_doc: dict[str, Any], team: Team | None, *, now: _dt.datetime,
                       resolved_in_scan: int | None = None) -> bool:
    """Set the finding fixed and close its Jira ticket. Returns True when the status changed."""
    update: dict[str, Any] = {"finding_status": "fixed", "fixed_at": now}
    if resolved_in_scan is not None:
        info = finding_doc.get("info") if isinstance(finding_doc.get("info"), dict) else {}
        update["info"] = {**info, "resolved_in_scan": int(resolved_in_scan), "resolved_at": now.isoformat()}
    changed = collection.update_one({"_id": finding_doc["_id"]}, {"$set": update}).modified_count
    if team is not None:
        try:
            from backend.utilities.integrations.jira_ticketing import close_jira_issue_for_finding

            close_jira_issue_for_finding(finding_doc, team)
        except Exception as exc:  # Jira is best effort: the finding status is the record
            console.print(f"Jira close-on-fixed skipped for {finding_doc.get('_id')}: {type(exc).__name__}", style="yellow")
    return bool(changed)


def mark_code_findings_fixed(engine, *, team_id: int, scan_id: int, identities: Iterable[str], resolved_in_scan: int,
                             now: _dt.datetime, mongo_db=None) -> int:
    """Mark the findings of CBOM scan ``scan_id`` whose line-independent identity is in ``identities`` fixed. The
    identity is ``code_identity`` of the stored ``finding_data``, exactly as ``drift.code_views`` keys the scan's
    stored rows (never ``display_row``'s copy), so what drift resolves is what gets marked."""
    from backend.utilities.cbom_sources.identity import code_identity

    wanted = set(identities)
    if not wanted:
        return 0
    if mongo_db is None:
        from backend.get_db import get_mongo_client_db

        mongo_db = get_mongo_client_db()
    collection = mongo_db["scan_findings"]
    with Session(engine) as session:
        team = session.exec(select(Team).where(Team.id == team_id)).first()
    fixed = 0
    for doc in collection.find({"scan_id": scan_id}):
        if doc.get("finding_status") in ("fixed", "ignored"):
            continue
        data = doc.get("finding_data") if isinstance(doc.get("finding_data"), dict) else {}
        if code_identity(data) in wanted:
            fixed += int(mark_finding_fixed(collection, doc, team, now=now, resolved_in_scan=resolved_in_scan))
    return fixed


__all__ = ["mark_code_findings_fixed", "mark_finding_fixed"]
