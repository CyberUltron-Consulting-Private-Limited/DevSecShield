"""Orphaned and unmanaged certificates of the team's estate (architecture diagram output 04; CB-38 PLAN §5.6 made
estate-wide with the CB-20 store and CB-21 asset keys).

One row per certificate asset of the estate store (``cbomestateasset``, certificate types, not removed): every source
that read it (its observations), each from its latest stored row. Flags (a certificate can carry several):

* ``unmanaged``      no observation comes from a system that manages the certificate's lifecycle: a CA connector,
                     a key manager (Vault PKI, HSM), an identity provider (its signing certificates), AWS ACM or AWS
                     Private CA (the row's ARN), or a cert-manager ``Certificate`` (``k8s_certificate``);
* ``prober_only``    every observation is a certificate a network probe read from an endpoint's chain
                     (``#chain[i]``): nothing but the wire knows it exists;
* ``orphaned``       no endpoint the team probed serves it now (no present chain observation): issued, stored or
                     held, deployed nowhere the product looked. Only judged when the team probes at least one
                     endpoint (otherwise every certificate would be "orphaned"); ACM's ``CERT_UNUSED`` (no
                     ``InUseBy``) is orphaned too;
* ``no_owner``       no observation's source names an owner or an application (the job's metadata snapshot, else
                     the source's current metadata);
* ``expired_served`` past its notAfter and still served by an endpoint the latest collection read;
* ``stale``          not seen by any source for ``stale_runs`` successful collections of that source or more (the
                     certificate stays in the estate as "not read", never confirmed removed).

Computed per request from the store (nothing stored), memoised per team on a cheap fingerprint.
"""
from __future__ import annotations

import base64
import bisect
import csv
import datetime as _dt
import io
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

import sqlalchemy as sa

UTC = _dt.timezone.utc
FLAGS = ("unmanaged", "prober_only", "orphaned", "no_owner", "expired_served", "stale")
FLAG_TEXT = {
    "unmanaged": "No managing system (CA connector, key manager, identity provider, AWS ACM / Private CA, "
                 "cert-manager) holds it",
    "prober_only": "Seen only by a network probe, on an endpoint's chain",
    "orphaned": "Served by no endpoint the team probes",
    "no_owner": "No source that read it names an owner or an application",
    "expired_served": "Expired and still served",
    "stale": "Not seen for several collections of the sources that knew it",
}
MANAGING_KINDS = frozenset({"ca_connector", "key_manager", "idp"})
MANAGING_AWS = frozenset({"acm", "acm-pca"})
STALE_RUNS = 3
MAX_LIMIT = 500
CACHE_TTL_S = 120.0
CSV_COLUMNS = ("key", "subject", "issuer", "serial", "not_after", "days_left", "flags", "sources", "owners",
               "applications", "observations", "not_seen_runs", "locations")


def _aware(moment: Any) -> _dt.datetime | None:
    if not isinstance(moment, _dt.datetime):
        return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _parse(value: Any) -> _dt.datetime | None:
    from backend.utilities.cbom_sources import classify as C

    moment = C._parse_time(value) if isinstance(value, str) else None
    return moment.replace(tzinfo=UTC) if moment is not None and moment.tzinfo is None else moment


def _served(location: str, facts: dict[str, Any]) -> bool:
    return "#chain[" in location or facts.get("chain_index") is not None


def _managing(source_kind: str | None, asset_type: str, location: str, facts: dict[str, Any]) -> bool:
    from backend.utilities.cbom_sources.agility import aws_service

    if source_kind in MANAGING_KINDS or asset_type == "k8s_certificate":
        return True
    arn = location if location.startswith("arn:") else facts.get("arn")
    return aws_service(arn) in MANAGING_AWS


@dataclass
class Cert:
    key: str
    label: str
    key_kind: str
    observations: list[dict[str, Any]] = field(default_factory=list)
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    not_after: _dt.datetime | None = None
    flags: tuple[str, ...] = ()
    not_seen_runs: int = 0
    owners: tuple[str, ...] = ()
    applications: tuple[str, ...] = ()
    latest: tuple = ()

    def public(self, today: _dt.date) -> dict[str, Any]:
        days = (self.not_after.date() - today).days if self.not_after else None
        return {
            "key": self.key, "label": self.label, "key_kind": self.key_kind, "subject": self.subject,
            "issuer": self.issuer, "serial": self.serial,
            "not_after": self.not_after.strftime("%Y-%m-%dT%H:%M:%SZ") if self.not_after else None,
            "days_left": days, "expired": days is not None and days < 0, "flags": list(self.flags),
            "not_seen_runs": self.not_seen_runs, "owners": list(self.owners), "applications": list(self.applications),
            "sources": sorted({o["source_name"] for o in self.observations}),
            "observations": [{k: o[k] for k in ("source_name", "source_kind", "location", "presence", "served",
                                                "managing", "seen_at", "not_seen_runs")}
                             for o in self.observations],
        }


@dataclass
class View:
    as_of: _dt.datetime
    state: str  # ready | pending (the store has not written every latest collection) | stale (store needs backfill)
    certs: list[Cert]
    probed: bool  # the team probes at least one endpoint: "orphaned" is judged
    stale_runs: int

    def counts(self) -> dict[str, Any]:
        by = {f: 0 for f in FLAGS}
        for c in self.certs:
            for f in c.flags:
                by[f] += 1
        return {"certificates": len(self.certs), "flagged": sum(1 for c in self.certs if c.flags), "by_flag": by}

    def select(self, *, flag: str | None = None, source: str | None = None, q: str | None = None,
               flagged_only: bool = True) -> list[Cert]:
        text = (q or "").strip().casefold()
        out = []
        for c in self.certs:
            if flag and flag not in c.flags:
                continue
            if not flag and flagged_only and not c.flags:
                continue
            if source and not any(o["source_ref"] == source or o["source_name"] == source for o in c.observations):
                continue
            if text and text not in " ".join(str(v or "") for v in (c.label, c.subject, c.issuer, c.serial)).casefold():
                continue
            out.append(c)
        return out


def _sort(c: Cert) -> tuple[str, str]:
    # soonest expiry first (expired ones on top), then the key; a certificate without notAfter last
    return (c.not_after.strftime("%Y%m%d%H%M%S") if c.not_after else "99999999999999", c.key)


def encode_after(sort_key: tuple[str, str]) -> str:
    return base64.urlsafe_b64encode(json.dumps(list(sort_key)).encode()).decode().rstrip("=")


def decode_after(text: str | None) -> tuple[str, str] | None:
    if not text:
        return None
    try:
        value = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    except Exception as exc:  # noqa: BLE001 - any malformed cursor is the client's error
        raise ValueError("after: not a cursor from this list") from exc
    if not (isinstance(value, list) and len(value) == 2 and all(isinstance(v, str) for v in value)):
        raise ValueError("after: not a cursor from this list")
    return value[0], value[1]


def page(view: View, *, flag: str | None = None, source: str | None = None, q: str | None = None,
         flagged_only: bool = True, after: str | None = None, limit: int = 100) -> dict[str, Any]:
    chosen = sorted(view.select(flag=flag, source=source, q=q, flagged_only=flagged_only), key=_sort)
    start = decode_after(after)
    rest = [c for c in chosen if _sort(c) > start] if start else chosen
    items = rest[:limit]
    today = view.as_of.date()
    return {"as_of": view.as_of.strftime("%Y-%m-%dT%H:%M:%SZ"), "state": view.state, "probed": view.probed,
            "stale_runs": view.stale_runs, "flags": {f: FLAG_TEXT[f] for f in FLAGS}, "counts": view.counts(),
            "total": len(chosen), "next": encode_after(_sort(items[-1])) if len(rest) > limit and items else None,
            "items": [c.public(today) for c in items]}


def csv_rows(view: View, **filters: Any) -> Iterator[bytes]:
    """Every row the filters select (no paging), as CSV; a cell never starts like a spreadsheet formula."""
    from backend.utilities.cbom_sources.risk_register import _csv_cell

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_COLUMNS)
    today = view.as_of.date()
    for c in sorted(view.select(**filters), key=_sort):
        p = c.public(today)
        row = {**p, "flags": " ".join(p["flags"]), "sources": "; ".join(p["sources"]),
               "owners": "; ".join(p["owners"]), "applications": "; ".join(p["applications"]),
               "observations": len(p["observations"]),
               "locations": "; ".join(sorted({o["location"] for o in p["observations"] if o["location"]}))}
        writer.writerow([_csv_cell(row.get(col)) for col in CSV_COLUMNS])
        if buf.tell() > 64_000:
            yield buf.getvalue().encode()
            buf.seek(0)
            buf.truncate()
    yield buf.getvalue().encode()


# ---------------------------------------------------------------------------------------------- the load
def build(session: Any, team_id: int, *, now: _dt.datetime | None = None, stale_runs: int = STALE_RUNS) -> View:
    from sqlmodel import select

    from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource, CbomEstateAsset,
                                    CbomEstateObservation, CbomEstateSource)
    from backend.utilities.cbom_sources import agility_rollup as ROLLUP
    from backend.utilities.cbom_sources import asset_keys as AK
    from backend.utilities.cbom_sources import estate as ESTATE

    moment = _aware(now) or _dt.datetime.now(UTC)
    state = "stale" if ESTATE.stale_status(session, team_id) else (
        "ready" if ROLLUP.store_ready(session, team_id) else "pending")
    ea, eo, es = CbomEstateAsset.__table__, CbomEstateObservation.__table__, CbomEstateSource.__table__
    cert_types = sorted(AK.CERT_TYPES)
    found = session.execute(sa.select(
        ea.c.asset_key, ea.c.label, ea.c.key_kind, eo.c.source_ref, eo.c.row_key, eo.c.presence, eo.c.location,
        eo.c.seen_job_id, eo.c.seen_attempt, eo.c.seen_at, es.c.latest_job_id, es.c.latest_attempt, es.c.latest_at,
        es.c.source_name, es.c.source_kind, es.c.source_id)
        .select_from(ea.join(eo, sa.and_(eo.c.team_id == ea.c.team_id, eo.c.asset_key == ea.c.asset_key))
                     .join(es, sa.and_(es.c.team_id == eo.c.team_id, es.c.source_ref == eo.c.source_ref)))
        .where(ea.c.team_id == team_id, ea.c.asset_type.in_(cert_types), ea.c.presence != "removed",
               eo.c.presence != "removed")).all()
    # every successful collect job per source, to count the collections since an observation was last seen
    jobs_of: dict[int, list[int]] = {}
    for source_id, job_id in session.execute(sa.select(CbomCollectionJob.source_id, CbomCollectionJob.id).where(
            CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.status == "success")).all():
        if source_id is not None:
            jobs_of.setdefault(int(source_id), []).append(int(job_id))
    for ids in jobs_of.values():
        ids.sort()
    pointers: dict[tuple[int, int], list[Any]] = {}
    for o in found:
        ptr = (o.latest_job_id, o.latest_attempt) if o.presence == "present" else (o.seen_job_id, o.seen_attempt)
        pointers.setdefault(ptr, []).append(o)
    rows: dict[tuple[int, int, str], Any] = {}
    for (job_id, attempt), items in pointers.items():
        wanted = sorted({o.row_key for o in items})
        for start in range(0, len(wanted), 500):
            for r in session.execute(sa.select(
                    CbomCollectedAsset.asset_key, CbomCollectedAsset.asset_type, CbomCollectedAsset.location,
                    CbomCollectedAsset.facts, CbomCollectedAsset.finding_codes).where(
                    CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.job_id == job_id,
                    CbomCollectedAsset.attempt == attempt,
                    CbomCollectedAsset.asset_key.in_(wanted[start:start + 500]))).all():  # type: ignore[attr-defined]
                rows[(job_id, attempt, r.asset_key)] = r
    job_ids = sorted({j for j, _a in pointers})
    jobs = {j.id: j for start in range(0, len(job_ids), 500) for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.id.in_(job_ids[start:start + 500]))).all()}  # type: ignore[union-attr]
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}

    certs: dict[str, Cert] = {}
    probed = False
    for o in found:
        ptr = (o.latest_job_id, o.latest_attempt) if o.presence == "present" else (o.seen_job_id, o.seen_attempt)
        row = rows.get((ptr[0], ptr[1], o.row_key))
        facts = row.facts if row is not None and isinstance(row.facts, dict) else {}
        location = str((row.location if row is not None else None) or o.location or "")
        a_type = str(row.asset_type if row is not None else "certificate")
        job = jobs.get(ptr[0])
        params = (job.params or {}) if job is not None else {}
        meta = params.get("metadata") if isinstance(params.get("metadata"), dict) else (
            (sources.get(o.source_id or 0).config or {}) if sources.get(o.source_id or 0) is not None else {})
        served = _served(location, facts)
        if served and o.presence == "present":
            probed = True
        ids = jobs_of.get(int(o.source_id or 0), [])
        since = 0 if o.presence == "present" else len(ids) - bisect.bisect_right(ids, int(ptr[0] or 0))
        seen = _aware(o.latest_at if o.presence == "present" else o.seen_at)
        cert = certs.setdefault(o.asset_key, Cert(key=o.asset_key, label=o.label or "", key_kind=o.key_kind))
        cert.observations.append({
            "source_ref": o.source_ref, "source_name": o.source_name or o.source_ref, "source_kind": o.source_kind,
            "location": location, "presence": o.presence, "served": served,
            "managing": _managing(o.source_kind, a_type, location, facts),
            "unused": "CERT_UNUSED" in (row.finding_codes or [] if row is not None else []),
            "seen_at": seen.strftime("%Y-%m-%dT%H:%M:%SZ") if seen else None, "not_seen_runs": since,
            "owner": str(meta.get("owner") or "").strip() if isinstance(meta, dict) else "",
            "application": str(meta.get("application") or "").strip() if isinstance(meta, dict) else ""})
        rank = (o.presence == "present", seen or _dt.datetime(1970, 1, 1, tzinfo=UTC))
        if not cert.latest or rank > cert.latest:
            leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
            cert.latest = rank
            cert.subject = facts.get("subject") or leaf.get("subject") or cert.subject
            cert.issuer = facts.get("issuer") or leaf.get("issuer") or cert.issuer
            serial = facts.get("serial") or facts.get("serial_number")
            cert.serial = str(serial) if serial else cert.serial
            cert.not_after = _parse(facts.get("not_after") or leaf.get("not_after")) or cert.not_after
    for cert in certs.values():
        obs = cert.observations
        obs.sort(key=lambda o: (o["presence"] != "present", o["source_name"].casefold(), o["location"]))
        cert.owners = tuple(sorted({o["owner"] for o in obs if o["owner"]}))
        cert.applications = tuple(sorted({o["application"] for o in obs if o["application"]}))
        cert.not_seen_runs = min(o["not_seen_runs"] for o in obs)
        served_now = any(o["served"] and o["presence"] == "present" for o in obs)
        expired = cert.not_after is not None and cert.not_after < moment
        flags = []
        if not any(o["managing"] for o in obs):
            flags.append("unmanaged")
        if all(o["served"] for o in obs):
            flags.append("prober_only")
        if (probed and not served_now) or any(o["unused"] for o in obs):
            flags.append("orphaned")
        if not cert.owners and not cert.applications:
            flags.append("no_owner")
        if expired and served_now:
            flags.append("expired_served")
        if cert.not_seen_runs >= stale_runs:
            flags.append("stale")
        cert.flags = tuple(flags)
    return View(as_of=moment, state=state, certs=list(certs.values()), probed=probed, stale_runs=stale_runs)


# ---------------------------------------------------------------------------------------------- cache
_cache: dict[tuple, tuple[float, View]] = {}
_lock = threading.Lock()


def fingerprint(session: Any, team_id: int, now: _dt.datetime, stale_runs: int) -> tuple:
    from sqlmodel import func, select

    from backend.new_models import CbomCollectionSource, CbomEstateAsset, CbomEstateSource

    store = session.exec(select(func.count(), func.max(CbomEstateSource.updated_at)).where(
        CbomEstateSource.team_id == team_id)).one()
    assets = session.exec(select(func.count(), func.max(CbomEstateAsset.updated_run_id)).where(
        CbomEstateAsset.team_id == team_id)).one()
    srcs = session.exec(select(func.count(), func.max(CbomCollectionSource.last_updated)).where(
        CbomCollectionSource.team_id == team_id)).one()
    return (team_id, tuple(store), tuple(assets), tuple(srcs), now.date().isoformat(), stale_runs)


def cached(session: Any, team_id: int, *, stale_runs: int = STALE_RUNS, now: _dt.datetime | None = None) -> View:
    moment = _aware(now) or _dt.datetime.now(UTC)
    key = fingerprint(session, team_id, moment, stale_runs)
    clock = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and clock - hit[0] < CACHE_TTL_S:
            return hit[1]
    view = build(session, team_id, now=moment, stale_runs=stale_runs)
    with _lock:
        for stale in [k for k, (at, _v) in _cache.items() if k[0] == team_id or clock - at >= CACHE_TTL_S]:
            _cache.pop(stale, None)
        while len(_cache) >= 16:
            _cache.pop(min(_cache, key=lambda k: _cache[k][0]))
        _cache[key] = (clock, view)
    return view


def clear_cache() -> None:
    with _lock:
        _cache.clear()


__all__ = ["CSV_COLUMNS", "FLAGS", "FLAG_TEXT", "MAX_LIMIT", "STALE_RUNS", "View", "build", "cached", "clear_cache",
           "csv_rows", "decode_after", "encode_after", "page"]
