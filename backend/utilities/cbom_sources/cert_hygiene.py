"""Orphaned and unmanaged certificates of the team's estate (architecture diagram output 04; CB-38 PLAN §5.6 made
estate-wide with the CB-20 store and CB-21 asset keys).

One row per certificate of ``cert_estate.unique_certificates`` (staging QA Q3-04): the list D8 prints and its CSV
holds, over the latest collection of every source that still exists (and the team's code scans), so the UI, D8 and
the CSV count the same certificates and "Seen by" never names a deleted source.  Every source that read it is an
observation, from its row in that collection. Flags (a certificate can carry several):

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
* ``stale``          kept for the API's vocabulary: a certificate no latest collection holds is in neither D8 nor this
                     list (the drift report states the removal), so no listed certificate is stale.

Computed per request from the team view (nothing stored), memoised per team on a cheap fingerprint.
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
CSV_COLUMNS = ("key", "sha256_thumbprint", "subject", "issuer", "serial", "not_after", "days_left", "flags", "sources", "owners",
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
    thumbprint: str = ""  # SHA-256 of the DER (cert_estate.thumbprint), "" when no observation recorded it
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
            "issuer": self.issuer, "serial": self.serial, "sha256_thumbprint": self.thumbprint,
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
    """The team's certificates exactly as D8 lists them (staging QA Q3-04: the UI showed 146 / 29 certificates from
    the estate store while D8 printed 155 / 33, and named deleted sources under "Seen by"): ``cert_estate.
    unique_certificates`` over the team view D8 reads (``load_core_view``), deleted sources left out, so the list,
    its counts and the D8 register are one set (Rule P)."""
    from backend.utilities.cbom_sources.cert_estate import unique_certificates
    from backend.utilities.dashboard.cbom_team_rollup import load_core_view

    moment = _aware(now) or _dt.datetime.now(UTC)
    view = load_core_view(session, team_id, now=moment)
    return from_estate(unique_certificates(view), moment, stale_runs=stale_runs)


def _codes(row: Any) -> set[str]:
    data = row if isinstance(row, dict) else {}
    return {str(c) for c in (data.get("finding_codes") or []) + (data.get("collector_codes") or [])
            if isinstance(c, str)}


def from_estate(estate: Any, moment: _dt.datetime, *, stale_runs: int = STALE_RUNS) -> View:
    """The hygiene view of one ``cert_estate.EstateResult`` (PURE).  Every observation is a row of a source's latest
    collection (a deleted source's rows are not in the estate), so ``presence`` is "present" and ``not_seen_runs`` 0:
    a certificate no latest collection holds is in neither D8 nor this list (drift reports it as removed)."""
    certs: list[Cert] = []
    probed = any(_served(str((m.row or {}).get("location") or ""), m.facts if isinstance(m.facts, dict) else {})
                 for ec in estate.certificates for m in ec.members)
    for ec in estate.certificates:
        observations: list[dict[str, Any]] = []
        placed: set[tuple[str, str]] = set()
        for member in ec.members:
            row = member.row if isinstance(member.row, dict) else {}
            facts = member.facts if isinstance(member.facts, dict) else {}
            coll = member.collection
            location = str(row.get("location") or "")
            meta = coll.metadata if isinstance(getattr(coll, "metadata", None), dict) else {}
            placed.add((coll.label, location))
            observations.append({
                "source_ref": coll.source_ref, "source_name": coll.label, "source_kind": coll.source_kind,
                "location": location, "presence": "present", "served": _served(location, facts),
                "managing": _managing(coll.source_kind, str(member.node_type or ""), location, facts),
                "unused": "CERT_UNUSED" in _codes(row),
                "seen_at": _aware(coll.observed_at).strftime("%Y-%m-%dT%H:%M:%SZ") if _aware(coll.observed_at) else None,
                "not_seen_runs": 0, "owner": str(meta.get("owner") or "").strip(),
                "application": str(meta.get("application") or "").strip()})
        seen = _aware(ec.cert.last_seen)
        for sighting in ec.sightings:  # a code scan's sightings (and a merged certificate's earlier code locations)
            if (sighting.source, sighting.location) in placed or sighting.source_ref:
                continue
            placed.add((sighting.source, sighting.location))
            observations.append({
                "source_ref": sighting.source, "source_name": sighting.source, "source_kind": "code_scan",
                "location": sighting.location, "presence": "present", "served": False, "managing": False,
                "unused": False, "seen_at": seen.strftime("%Y-%m-%dT%H:%M:%SZ") if seen else None,
                "not_seen_runs": 0, "owner": "", "application": ""})
        cert = Cert(key=ec.key, label=ec.subject or ec.cert.name or ec.key,
                    key_kind="sha256" if ec.thumbprint else "identity", observations=observations,
                    subject=ec.subject or None, issuer=ec.issuer or None, serial=ec.serial or None,
                    thumbprint=ec.thumbprint, not_after=_parse(ec.not_after))
        certs.append(cert)
        obs = cert.observations
        obs.sort(key=lambda o: (o["source_name"].casefold(), o["location"]))
        cert.owners = tuple(sorted({o["owner"] for o in obs if o["owner"]} | set(ec.owners)))
        cert.applications = tuple(sorted({o["application"] for o in obs if o["application"]}))
        served_now = any(o["served"] for o in obs)
        expired = cert.not_after is not None and cert.not_after < moment
        flags = []
        if not any(o["managing"] for o in obs):
            flags.append("unmanaged")
        if obs and all(o["served"] for o in obs):
            flags.append("prober_only")
        if (probed and not served_now) or any(o["unused"] for o in obs):
            flags.append("orphaned")
        if not cert.owners and not cert.applications:
            flags.append("no_owner")
        if expired and served_now:
            flags.append("expired_served")
        cert.flags = tuple(flags)
    return View(as_of=moment, state="ready", certs=certs, probed=probed, stale_runs=stale_runs)


# ---------------------------------------------------------------------------------------------- cache
_cache: dict[tuple, tuple[float, View]] = {}
_lock = threading.Lock()


def fingerprint(session: Any, team_id: int, now: _dt.datetime, stale_runs: int) -> tuple:
    """What the list is computed from: the team's finished collect jobs, its CBOM code scans and its sources (a new
    collection, a re-scan, a deleted or edited source is a new key), the UTC day (expiry) and ``stale_runs``."""
    from sqlmodel import func, select

    from backend.new_models import CbomCollectionJob, CbomCollectionSource, Scan

    jobs = session.exec(select(func.count(), func.max(CbomCollectionJob.id), func.max(CbomCollectionJob.finished_at))
                        .where(CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect",
                               CbomCollectionJob.status == "success")).one()
    scans = session.exec(select(func.count(), func.max(Scan.last_updated)).where(
        Scan.team_id == team_id, Scan.scan_type == "cbom")).one()
    srcs = session.exec(select(func.count(), func.max(CbomCollectionSource.last_updated)).where(
        CbomCollectionSource.team_id == team_id)).one()
    return (team_id, tuple(jobs), tuple(scans), tuple(srcs), now.date().isoformat(), stale_runs)


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
           "csv_rows", "decode_after", "encode_after", "from_estate", "page"]
