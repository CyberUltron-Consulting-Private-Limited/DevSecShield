"""Deleting a collection source, the one way: a person's delete (``routers/cbom_sources.py``) and a fleet managed
source that no policy needs any more (``fleet/materialize.py``) both end here, so the two never drift.

In the caller's transaction: the source's open jobs end (pending ones refunded, claimed ones asked to stop), running
discovery sweeps that include its range stop, its runs and assets stay (unlinked, with the source's name and stable
uid kept on the jobs so its runs still compare with each other), an audit row is written, and the row goes.
"""
from __future__ import annotations

import datetime as _dt

from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource
from backend.utilities.cbom_sources import agility as AGILITY
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.common import audit


def remove_source(session: Session, source: CbomCollectionSource, team_id: int, now: _dt.datetime, *,
                  actor_type: str, actor_id: int | None, action: str = "source.delete",
                  reason: str = "Source deleted") -> None:
    J.cancel_open_jobs(session, source, now, reason=reason)
    J.stop_discoveries_using(session, source, now, "A range in this discovery was deleted")
    for job in session.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == source.id)).all():
        job.params = {**(job.params or {}), "source_name": source.name, "source_kind": source.kind,
                      "source_uid": (job.params or {}).get("source_uid") or source.source_uid}
        job.source_id = None
        session.add(job)
        job.params = {**job.params, **AGILITY.deleted_source_params(source)}  # CB-24: old runs keep their class
    session.exec(update(CbomCollectedAsset).where(CbomCollectedAsset.source_id == source.id).values(source_id=None))  # type: ignore[call-overload]
    session.flush()
    audit(session, team_id=team_id, actor_type=actor_type, actor_id=actor_id, action=action,
          object_type="source", object_id=source.id)
    session.delete(source)
