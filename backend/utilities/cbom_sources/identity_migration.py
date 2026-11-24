"""Moving the stored per-source keys when ``identity.node_identity`` changes (staging QA2 Q1-09).

The certificate identity no longer reads a cloud certificate's free-text subject, and compares a subject stored as an
attribute map as the DN it denotes. That changes ``identity.stable_key("node", source_ref, ...)`` for those rows
only (``identity.rekeyed_observations``: never a DN-text certificate off the cloud, never a non-certificate row).
Two stores hold that key, and each follows it here, in the estate store's own write (``estate.record_run``), so the
first run after the change re-keys what it reads and nothing is read as removed and added:

* ``cbomestateobservation.observation_key`` (waves and estate links look observations up by it); an observation
  keyed ``obs:<key>`` (a certificate with no cross-source key) MOVES to ``obs:<new key>`` through the store's
  existing re-keying path (``alias_to_key`` -> ``EstateWrite.rekeyed``, never a removal);
* ``cbomremediationassignment.asset_key`` (owner, status, ticket of a finding), unless the new key already has one.

The risk register and its Q0 gaps are keyed by the estate key: an ``obs:`` key that moves is in ``EstateWrite.rekeyed``,
which their hooks already read (``q0register.on_estate_write``: the old item closes as moved, never as fixed).

Drift needs no migration: both runs of a comparison are keyed from their stored rows with the current rule.
Idempotent: a key already moved maps to nothing.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

BATCH = 500


def _chunks(items: list[str], size: int = BATCH):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def remap(session: Any, team_id: int, moves: Mapping[str, Mapping[str, str]]) -> dict[str, int]:
    """``moves``: source ref -> {old key: new key}. Updates both stores in the caller's transaction; returns how
    many rows of each moved."""
    import sqlalchemy as sa

    from backend.new_models import CbomEstateObservation, CbomRemediationAssignment

    out = {"observations": 0, "assignments": 0}
    pairs = {old: new for by_ref in moves.values() for old, new in by_ref.items() if old != new}
    if not pairs:
        return out
    eo = CbomEstateObservation.__table__
    for ref, by_ref in moves.items():
        stale: list[str] = []
        for chunk in _chunks(sorted(k[:40] for k, v in by_ref.items() if k != v)):  # one read; after the first
            stale += [k for (k,) in session.execute(sa.select(eo.c.observation_key).where(  # run, nothing is left
                eo.c.team_id == team_id, eo.c.source_ref == ref, eo.c.observation_key.in_(chunk))).all()]
        for old in sorted(set(stale)):
            out["observations"] += session.execute(sa.update(eo).where(
                eo.c.team_id == team_id, eo.c.source_ref == ref, eo.c.observation_key == old)
                .values(observation_key=by_ref[old][:40])).rowcount or 0
    ra = CbomRemediationAssignment.__table__
    olds = sorted(pairs)
    held: set[str] = set()
    for chunk in _chunks(sorted(set(pairs.values()))):
        held.update(k for (k,) in session.execute(sa.select(ra.c.asset_key).where(
            ra.c.team_id == team_id, ra.c.asset_key.in_(chunk))).all())
    for chunk in _chunks(olds):
        for (key,) in session.execute(sa.select(ra.c.asset_key).where(
                ra.c.team_id == team_id, ra.c.asset_key.in_(chunk))).all():
            new = pairs[key]
            if new in held:
                continue  # the new key already has its own assignment: the newer record wins, the old one stays put
            out["assignments"] += session.execute(sa.update(ra).where(
                ra.c.team_id == team_id, ra.c.asset_key == key).values(asset_key=new)).rowcount or 0
            held.add(new)
    return out


__all__ = ["remap"]
