"""Crypto-agility baseline at system and enterprise level (CB-25 PR-A; diagram output 03, "Asset, system and
enterprise agility by fix class").

What is counted (the team's current estate, computed per request, nothing stored):

* every asset of each source's latest successful collection (``collections_view.load_sources_result``: the same rows
  the CBOM dashboard and the team PDFs read);
* every row of each code source's (repository@branch, upload) latest successful code scan with results;
* the evidence items that carry a class (CB-24 §4: an answered HSM firmware area is hardware-fixed; an answered
  third-party area and each third-party vendor are vendor-fixed). An unanswered one is "not assessed", counted apart.

One asset per cross-source identity: every Sources observation is correlated with ``asset_keys.correlate_detail``
(a certificate by serial / fingerprint / thumbprint / DNs, an endpoint by host:port, a cloud resource by its id), a
code-scan certificate joins the Sources certificate it shares a link key with (``collections_view.resolve``'s rule),
and anything without a cross-source key is identified within its own source. An asset seen several times takes the
**hardest** class across its observations (the asset rule over the union of their codes), and counts in the system of
its latest observation, so the per-system counts always add up to the enterprise counts.

System (owner default, CB-24 §6.1): the job snapshot's ``application``, else the source; a code scan's repository; the
evidence items' "Third parties" and "Key management (evidence)". Headline: the self-fixable share (configurable +
code-fixed over the assets with one of the four classes). Every count is also given without the post-quantum codes.

Where the Sources observations come from: the estate store (CB-20, ``estate``: the store's asset keys, each
observation's latest stored row; faster at scale) once it has written every source's latest successful collection
and the team's store is not stale; else ``collections_view`` (a run's store write waits for its drift recording, and
a team whose runs predate the store waits for ``estate backfill``). The response says which (``inputs.read_from``).
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from backend.utilities.cbom_sources import agility as AG

UTC = _dt.timezone.utc
METHOD = "asset_keys"  # one asset per cross-source identity (CB-21 correlate)
MAX_LIMIT = 500
KINDS = ("application", "source", "repository", "evidence")
EVIDENCE_SYSTEMS = {"vendor": ("evidence:third_parties", "Third parties"),
                    "hsm": ("evidence:key_management", "Key management (evidence)")}
CACHE_TTL_S = 120.0
CACHE_TEAMS = 8


@dataclass
class Subject:
    """One agility subject (an asset, or an evidence item) and the observations that make it."""

    key: str
    evals: list[tuple] = field(default_factory=list)  # agility._evaluate results, one per observation
    seen_at: tuple = ()  # the latest observation's (time, tie-break): its system and its name win
    system: tuple[str, str, str] = ("", "", "")  # (key, label, kind)
    name: str = ""
    type: str = ""
    location: str = ""
    origin: str = ""
    sources: set[str] = field(default_factory=set)
    fix_class: str = "none"
    floor: str | None = None
    excl_pq: str = "none"
    reasons: tuple[str, ...] = ()
    per: tuple = ()
    observations: int = 0
    codes: tuple[str, ...] | None = None  # the deciding codes when they come stored (estate store), not from ``per``

    def observe(self, ev: tuple, at: tuple, system: tuple[str, str, str], name: str, a_type: str, location: str,
                origin: str, source_label: str) -> None:
        self.evals.append(ev)
        self.sources.add(source_label)
        if not self.seen_at or at > self.seen_at:
            self.seen_at, self.system, self.name, self.type, self.location, self.origin = (
                at, system, name, a_type, location, origin)

    def finish(self) -> None:
        if len(self.evals) == 1:
            whole, per, excl, reasons = self.evals[0]
        else:  # hardest across its observations: the asset rule over every code any observation has
            per = tuple(p for ev in self.evals for p in ev[1])
            whole = AG.asset_class(list(per))
            excl = AG.asset_class([p for p in per if p["code"] not in AG.PQ_CODES])["fix_class"]
            reasons = tuple(dict.fromkeys(p["unknown_reason"] for p in per if p["unknown_reason"])) \
                if whole["fix_class"] == "unknown" else ()
        self.fix_class, self.floor, self.excl_pq, self.reasons = whole["fix_class"], whole["floor"], excl, reasons
        self.per = per  # memoised and shared between assets: a reference, not a copy
        self.evals = []

    @property
    def deciding(self) -> tuple[str, ...]:
        """The codes that put the asset in its class (the drill-down's "why")."""
        if self.codes is not None:
            return self.codes
        target = self.fix_class if self.fix_class in AG.RANK else None
        return tuple(dict.fromkeys(p["code"] for p in self.per if target and p["class"] == target))


@dataclass
class Rollup:
    """The roll-up. From ``collections_view``: every subject in ``subjects``. From the estate store: the store's
    assets as ``groups`` (one GROUP BY row: system, class, class without PQ codes, unknown reasons, count) and only
    the code-scan, evidence and merged subjects in ``subjects``; ``merged`` holds the store assets a code scan
    joined (counted in ``subjects``, so taken out of the groups and of the store's drill-down pages)."""

    as_of: str
    subjects: list[Subject]
    observations: int
    not_correlated: int
    not_assessed: int
    inputs: dict[str, Any]
    groups: list[tuple] = field(default_factory=list)
    team_id: int | None = None  # set when the store backs the roll-up (its drill-down pages are read from it)
    merged: frozenset[str] = frozenset()

    # ------------------------------------------------------------------ enterprise
    def _tally(self) -> tuple[Counter, Counter, Counter, dict[str, dict[str, Any]]]:
        counts: Counter = Counter()
        excl: Counter = Counter()
        reasons: Counter = Counter()
        systems: dict[str, dict[str, Any]] = {}

        def add(system: tuple, cls: str, x: str, why: Iterable[str], n: int) -> None:
            counts[cls] += n
            excl[x] += n
            for r in why:
                reasons[r] += n
            item = systems.setdefault(system[0], {"key": system[0], "label": system[1], "kind": system[2],
                                                  "c": Counter(), "x": Counter()})
            item["c"][cls] += n
            item["x"][x] += n

        for key, label, kind, cls, x, why, n in self.groups:
            add((key, label, kind), cls, x, why, n)
        for sub in self.subjects:
            add(sub.system, sub.fix_class, sub.excl_pq, sub.reasons, 1)
        return counts, excl, reasons, systems

    @property
    def assets(self) -> int:
        return sum(n for *_rest, n in self.groups) + len(self.subjects)

    def counts(self, excl_pq: bool = False) -> dict[str, int]:
        c = self._tally()[1 if excl_pq else 0]
        return {v: c.get(v, 0) for v in AG.VALUES}

    def unknown_reasons(self) -> dict[str, int]:
        return dict(sorted(self._tally()[2].items()))

    def systems(self) -> list[dict[str, Any]]:
        out = []
        for item in self._tally()[3].values():
            counts = {v: item["c"].get(v, 0) for v in AG.VALUES}
            excl = {v: item["x"].get(v, 0) for v in AG.VALUES}
            out.append({"key": item["key"], "label": item["label"], "kind": item["kind"],
                        "assets": sum(counts.values()), "hardest": _hardest(counts), "counts": counts,
                        "counts_excl_pq": excl, "self_fixable_pct": AG.self_fixable_pct(counts),
                        "self_fixable_pct_excl_pq": AG.self_fixable_pct(excl), "unknown": counts["unknown"]})
        out.sort(key=_system_sort)
        return out

    def summary(self, *, after: str | None = None, limit: int = 100, fix_class: str | None = None,
                kind: str | None = None) -> dict[str, Any]:
        counts, excl = self.counts(), self.counts(True)
        systems = self.systems()
        listed = [s for s in systems if (not kind or s["kind"] == kind) and (not fix_class or s["counts"][fix_class])]
        page, next_cursor = _keyset(listed, after, limit, _system_sort)
        assets = self.assets
        return {
            "as_of": self.as_of, "scope": "current estate", "model": AG.MODEL, "agility_version": AG.version(),
            "assets": assets, "counts": counts, "counts_excl_pq": excl,
            "self_fixable_pct": AG.self_fixable_pct(counts), "self_fixable_pct_excl_pq": AG.self_fixable_pct(excl),
            "hardest": _hardest(counts), "unknown_reasons": self.unknown_reasons(), "not_assessed": self.not_assessed,
            "dedupe": {"method": METHOD, "key_version": _key_version(), "observations": self.observations,
                       "merged": self.observations - (assets - self.inputs.get("evidence_items", 0)),
                       "not_correlated": self.not_correlated},
            "inputs": dict(self.inputs),
            "systems_total": len(systems),
            "systems": {"items": page, "next": next_cursor, "matched": len(listed)},
        }

    # ------------------------------------------------------------------ drill-down
    def subjects_page(self, *, fix_class: str | None = None, system: str | None = None, excl_pq: bool = False,
                      after: str | None = None, limit: int = 100, session: Any = None) -> dict[str, Any]:
        def wanted(s: Subject) -> bool:
            return (not fix_class or (s.excl_pq if excl_pq else s.fix_class) == fix_class) and \
                (not system or s.system[0] == system)

        chosen = sorted((s for s in self.subjects if wanted(s)), key=_subject_sort)
        head = {"as_of": self.as_of, "view": "excl_pq" if excl_pq else "all", "fix_class": fix_class,
                "system": system}
        if self.team_id is None or session is None:
            page, next_cursor = _keyset(chosen, after, limit, _subject_sort)
            return {**head, "total": len(chosen), "next": next_cursor, "items": [_public(s) for s in page]}
        # the store's assets first (keyset on the asset key, in SQL), then the code-scan, evidence and merged subjects
        start = decode_cursor(after)
        stored, total = _store_page(session, self.team_id, fix_class=fix_class, system=system, excl_pq=excl_pq,
                                    after=str(start[1]) if start and start[0] == "s" else None,
                                    skip_store=bool(start and start[0] == "p"), limit=limit, merged=self.merged)
        items = [*stored]
        next_cursor = None
        if len(items) > limit:
            items = items[:limit]
            next_cursor = _cursor(("s", items[-1]["key"]))
        else:
            rest = chosen
            if start and start[0] == "p":
                rest = [s for s in chosen if _comparable(_subject_sort(s)) > _comparable(tuple(start[1:]))]
            room = limit - len(items)
            items += [_public(s) for s in rest[:room]]
            if len(rest) > room:
                last = rest[room - 1] if room else None
                next_cursor = _cursor(("p", *_subject_sort(last))) if last else _cursor(("s", items[-1]["key"]))
        return {**head, "total": total + len(chosen), "next": next_cursor, "items": items}


def _store_page(session: Any, team_id: int, *, fix_class: str | None, system: str | None, excl_pq: bool,
                after: str | None, skip_store: bool, limit: int, merged: frozenset[str]) -> tuple[list[dict], int]:
    """One keyset page of the store's assets (``limit + 1`` rows, so the caller knows if more follow) and how many
    match; the assets a code scan joined are left out (they are subjects of their own)."""
    import sqlalchemy as sa

    from backend.new_models import CbomEstateAsset, CbomEstateObservation, CbomEstateSource

    ea, eo, es = CbomEstateAsset.__table__, CbomEstateObservation.__table__, CbomEstateSource.__table__
    cls_col = ea.c.fix_class_excl_pq if excl_pq else ea.c.fix_class
    conds = [ea.c.team_id == team_id, ea.c.presence != "removed", ea.c.fix_class.is_not(None)]
    if fix_class:
        conds.append(cls_col == fix_class)
    if system:
        conds.append(ea.c.system_key == system)
    total = int(session.execute(sa.select(sa.func.count()).select_from(ea).where(*conds)).scalar() or 0)
    if merged:  # few: the store assets a code-scan certificate joined
        total -= int(session.execute(sa.select(sa.func.count()).select_from(ea).where(
            *conds, ea.c.asset_key.in_(sorted(merged)))).scalar() or 0)
    if skip_store:
        return [], total
    page_conds = [*conds] + ([ea.c.asset_key > after] if after else [])
    rows = session.execute(sa.select(
        ea.c.asset_key, ea.c.label, ea.c.asset_type, ea.c.fix_class, ea.c.fix_floor, ea.c.fix_class_excl_pq,
        ea.c.fix_codes, ea.c.fix_reasons, ea.c.system_key, ea.c.system_label, ea.c.system_kind, ea.c.fix_observations)
        .where(*page_conds).order_by(ea.c.asset_key).limit(limit + 1 + len(merged))).all()
    rows = [r for r in rows if r.asset_key not in merged][:limit + 1]
    where: dict[str, tuple[str, set[str]]] = {}
    if rows:
        for o in session.execute(sa.select(eo.c.asset_key, eo.c.location, eo.c.fix_at, es.c.source_name,
                                           eo.c.source_ref).select_from(eo.outerjoin(es, sa.and_(
                es.c.team_id == eo.c.team_id, es.c.source_ref == eo.c.source_ref))).where(
                eo.c.team_id == team_id, eo.c.presence != "removed",
                eo.c.asset_key.in_([r.asset_key for r in rows])).order_by(eo.c.fix_at)).all():
            loc, names = where.get(o.asset_key, ("", set()))
            names.add(o.source_name or o.source_ref)
            where[o.asset_key] = (o.location or loc, names)  # the latest observation's place
    split = lambda text: [v for v in (text or "").split(",") if v]  # noqa: E731
    return [{"key": r.asset_key, "name": r.label or r.asset_type, "type": r.asset_type,
             "location": where.get(r.asset_key, ("", set()))[0], "origin": "sources_run", "fix_class": r.fix_class,
             "fix_class_floor": r.fix_floor, "fix_class_excl_pq": r.fix_class_excl_pq,
             "deciding_codes": split(r.fix_codes), "unknown_reasons": split(r.fix_reasons),
             "observations": r.fix_observations or 0,
             "sources": sorted(where.get(r.asset_key, ("", set()))[1])[:10],
             "system": {"key": r.system_key, "label": r.system_label, "kind": r.system_kind}} for r in rows], total


# ---------------------------------------------------------------------------------------------- helpers
def _hardest(counts: dict[str, int]) -> str | None:
    return max((c for c in AG.CLASSES if counts.get(c)), key=AG.RANK.__getitem__, default=None)


def _system_sort(s: Any) -> tuple:
    return (-s["assets"], s["label"].casefold(), s["key"])


def _subject_sort(s: Any) -> tuple:
    return (s.name.casefold(), s.key)


def _key_version() -> str:
    from backend.utilities.cbom_sources import asset_keys as AK

    return AK.KEY_VERSION


def _cursor(sort_key: tuple) -> str:
    return base64.urlsafe_b64encode(json.dumps(list(sort_key), separators=(",", ":")).encode()).decode().rstrip("=")


def decode_cursor(text: str | None) -> tuple | None:
    """The sort key a cursor names; ValueError when it is not one of ours."""
    if not text:
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        value = json.loads(raw)
    except Exception as exc:  # noqa: BLE001 - any malformed cursor is the client's error
        raise ValueError("after: not a cursor from this list") from exc
    if not isinstance(value, list) or not 2 <= len(value) <= 3 or not all(isinstance(v, (str, int)) for v in value):
        raise ValueError("after: not a cursor from this list")
    return tuple(value)


def _keyset(items: list, after: str | None, limit: int, sort: Any) -> tuple[list, str | None]:
    """Items strictly after the cursor (the sort key of the last item of the previous page), then ``limit`` of them."""
    start = decode_cursor(after)
    if start is not None:
        items = [i for i in items if _comparable(sort(i)) > _comparable(start)]
    page = items[:limit]
    return page, (_cursor(sort(page[-1])) if len(items) > limit and page else None)


def _comparable(key: tuple) -> tuple:
    # a cursor someone edited may mix types; compare as (type order, value) so it never raises
    return tuple((0, v) if isinstance(v, int) else (1, str(v)) for v in key)


def _public(s: Subject) -> dict[str, Any]:
    key, label, kind = s.system
    return {"key": s.key, "name": s.name, "type": s.type, "location": s.location, "origin": s.origin,
            "fix_class": s.fix_class, "fix_class_floor": s.floor, "fix_class_excl_pq": s.excl_pq,
            "deciding_codes": list(s.deciding), "unknown_reasons": list(s.reasons),
            "observations": s.observations,
            "sources": sorted(s.sources)[:10], "system": {"key": key, "label": label, "kind": kind}}


def _aware(moment: Any) -> _dt.datetime:
    if not isinstance(moment, _dt.datetime):
        return _dt.datetime(1970, 1, 1, tzinfo=UTC)
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


# ---------------------------------------------------------------------------------------------- the load
def latest_code_scans(session: Any, team_id: int) -> list[Any]:
    """Each code source's newest successful CBOM scan (``identity.code_source_ref``: repository@branch, upload)."""
    from sqlmodel import col, select

    from backend.new_models import Scan
    from backend.utilities.cbom_sources import identity as ID

    heads = session.exec(select(Scan.id, Scan.title, Scan.created_at, Scan.scan_metadata).where(
        Scan.team_id == team_id, Scan.scan_type == "cbom", Scan.scan_status == "success")
        .order_by(col(Scan.created_at).desc(), col(Scan.id).desc())).all()
    chosen: dict[str, tuple] = {}
    for scan_id, title, created, meta in heads:
        key, label = ID.code_source_ref(meta, title or "", scan_id)
        chosen.setdefault(key, (scan_id, key, label, _aware(created)))
    return list(chosen.values())


@dataclass
class _Obs:
    """One Sources observation, whatever read it: its asset key, class result, system and how it is shown."""

    key: str
    ev: tuple
    at: tuple
    system: tuple[str, str, str]
    name: str
    type: str
    location: str
    source: str


@dataclass
class _SourcesSide:
    read_from: str  # "estate_store" | "collections_view"
    observations: list[_Obs]
    aliases: dict[str, str]  # a certificate link key -> the asset key it names (code certificates join through it)
    not_correlated: int
    collections: int


def _alias(aliases: dict[str, str], ambiguous: set[str], link: str, key: str) -> None:
    if aliases.setdefault(link, key) != key:
        ambiguous.add(link)


def _from_view(session: Any, team_id: int, found: Any) -> _SourcesSide:
    """Sources from ``collections_view.load_sources_result`` (each source's latest successful collection)."""
    from backend.utilities.cbom_sources import agility_store as STORE
    from backend.utilities.cbom_sources import asset_keys as AK

    contexts = STORE.Contexts(session, team_id, (item.collection.job_id for item in found.rows))
    kb = AG.crypto_kb.version()
    out: list[_Obs] = []
    aliases: dict[str, str] = {}
    ambiguous: set[str] = set()
    not_correlated = 0
    for item in found.rows:
        col, row = item.collection, item.row
        ctx_key, system = contexts.of(col.job_id, col.source_ref, col.source_name)
        if item.node_type in AK.CERT_TYPES or row.get("algorithm_type") == "certificate":
            # load_sources_result already correlated the certificates (link_certificates: asset_keys.correlate_detail)
            key = item.identity
            if key.startswith("node|"):
                not_correlated += 1  # a certificate with nothing identifying: counted within its own source
            for link in item.aliases:
                _alias(aliases, ambiguous, link, key)
        else:  # an endpoint (host:port; a private address only within its source) or a cloud resource id
            found_key = AK.asset_key(AK.Observation(
                kind=str(item.node_type or ""), facts=item.facts if isinstance(item.facts, dict) else {},
                location=str(row.get("location") or ""), target=str(item.target or ""), scope=col.source_ref))
            key = found_key if isinstance(found_key, str) else item.identity
        a_type = str(item.node_type or "")
        ev = STORE.evaluate_node(kb, ctx_key, a_type, row.get("collector_codes") or [], item.facts, row.get("location"))
        out.append(_Obs(key, ev, (col.observed_at, 0, col.job_id), system, str(row.get("title") or a_type), a_type,
                        str(row.get("location") or ""), col.source_name))
    for link in ambiguous:
        aliases.pop(link, None)
    return _SourcesSide("collections_view", out, aliases, not_correlated, len(found.collections))


def store_ready(session: Any, team_id: int, latest: list[Any] | None = None) -> bool:
    """True when the estate store (CB-20) can stand for ``collections_view``: the team's store is not stale and it has
    written every source's latest successful collection (the store is written when drift is recorded for the run, a
    scheduler tick after the run finishes; a team whose runs predate the store waits for ``estate backfill``)."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionSource, CbomEstateSource
    from backend.utilities.cbom_sources import collections_view as CV
    from backend.utilities.cbom_sources import estate as ESTATE
    from backend.utilities.cbom_sources import identity as ID

    if ESTATE.stale_status(session, team_id) is not None:
        return False
    jobs = latest if latest is not None else CV.latest_jobs(session, team_id)
    if not jobs:
        return True
    srcs = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    written = {r.source_ref: r.latest_job_id for r in session.exec(select(CbomEstateSource).where(
        CbomEstateSource.team_id == team_id)).all()}
    return all((written.get(ID.job_source_ref(j, srcs.get(j.source_id or 0))) or 0) >= j.id for j in jobs)


USE_STORE = True  # CB-20 merged (#167): read the estate store when it is ready, else collections_view


def _code_side(session: Any, team_id: int, subject: Any, lookup: Any) -> tuple[int, int]:
    """Each code source's latest successful scan into ``subject(key)``; a certificate row's match token goes through
    ``lookup(parts) -> key | None`` (the Sources certificate it names). Returns (scans, rows)."""
    from sqlmodel import select

    from backend.new_models import Scan
    from backend.utilities.cbom_sources import collections_view as CV
    from backend.utilities.cbom_sources import identity as ID

    code_scans = latest_code_scans(session, team_id)
    loaded = []
    for scan_id, skey, label, created in code_scans:
        data = session.exec(select(Scan.scan_data).where(Scan.id == scan_id, Scan.team_id == team_id)).first()
        data = data if isinstance(data, dict) else {}
        rows = [r for r in (data.get("results") or []) if isinstance(r, dict)]
        cert_ids = CV.code_cert_identities(data)
        loaded.append((scan_id, skey, label, created, [(r, CV.code_row_identity(r, cert_ids)) for r in rows]))
    resolved = lookup({p for *_x, rows in loaded for _r, t in rows if t for p in t.split("+")})
    count = 0
    for scan_id, skey, label, created, rows in loaded:
        system = (f"repository:{skey}", label, "repository")
        for row, token in rows:
            if token:
                parts = token.split("+")
                key = next((resolved[p] for p in parts if p in resolved), parts[0])
            else:
                key = f"code|{skey}|{ID.code_identity(row)}"
            count += 1
            subject(key).observe(AG.classify_code_row(row), (created, 1, scan_id), system,
                                 str(row.get("title") or row.get("algorithm_name") or row.get("asset_type") or ""),
                                 str(row.get("asset_type") or row.get("algorithm_type") or ""),
                                 str(row.get("location") or ""), CV.ORIGIN_CODE, label)
    return len(code_scans), count


def _evidence_side(session: Any, team_id: int, subject: Any) -> tuple[int, int]:
    """The evidence items with a class into ``subject(key)``. Returns (items, areas not assessed)."""
    from sqlmodel import select

    from backend.new_models import CbomEvidenceArea, CbomEvidenceVendor

    not_assessed = items = 0
    for area in session.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.team_id == team_id)).all():
        fields = AG.evidence_area_fields(area.area_key, area.answers)
        if fields["not_assessed"]:
            not_assessed += 1
        if not fields["fix_class"]:
            continue
        which = "hsm" if fields["fix_class"] == "hardware-fixed" else "vendor"
        items += 1
        _evidence(subject(f"evidence|area|{area.area_key}"), fields["fix_class"], EVIDENCE_SYSTEMS[which],
                  f"Evidence area: {area.area_key.replace('_', ' ')}", area.last_updated)
    for vendor in session.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.team_id == team_id)).all():
        items += 1
        _evidence(subject(f"evidence|vendor|{vendor.id}"), AG.evidence_vendor_fields()["fix_class"],
                  EVIDENCE_SYSTEMS["vendor"], vendor.name, vendor.created_at)
    return items, not_assessed


def build(session: Any, team_id: int, *, now: _dt.datetime | None = None, sources: Any = None) -> Rollup:
    """The team's agility roll-up. ``sources``: a ``collections_view.SourcesResult`` already loaded for this request
    (then it is used as is); otherwise the estate store when ``store_ready`` (``build_store``: a GROUP BY), else
    ``collections_view``."""
    from backend.utilities.cbom_sources import collections_view as CV

    moment = _aware(now or _dt.datetime.now(UTC))
    if sources is None and USE_STORE and store_ready(session, team_id):
        return build_store(session, team_id, now=moment)
    side = _from_view(session, team_id, sources if sources is not None
                      else CV.load_sources_result(session, team_id, moment))
    subjects: dict[str, Subject] = {}

    def subject(key: str) -> Subject:
        item = subjects.get(key)
        if item is None:
            item = subjects[key] = Subject(key=key)
        return item

    for o in side.observations:
        subject(o.key).observe(o.ev, o.at, o.system, o.name, o.type, o.location, CV.ORIGIN_SOURCES, o.source)
    aliases = side.aliases
    scans, code_rows = _code_side(session, team_id, subject, lambda parts: {p: aliases[p] for p in parts
                                                                             if p in aliases})
    evidence_items, not_assessed = _evidence_side(session, team_id, subject)
    for item in subjects.values():
        item.observations = len(item.evals)
        item.finish()
    return Rollup(as_of=moment.strftime("%Y-%m-%dT%H:%M:%SZ"), subjects=list(subjects.values()),
                  observations=len(side.observations) + code_rows, not_correlated=side.not_correlated,
                  not_assessed=not_assessed,
                  inputs={"collections": side.collections, "code_scans": scans, "evidence_items": evidence_items,
                          "read_from": side.read_from})


def build_store(session: Any, team_id: int, *, now: _dt.datetime | None = None, healed: bool = False) -> Rollup:
    """The roll-up over the estate store: heal any stale stored class (``agility_store.heal``; the caller commits),
    then ONE ``GROUP BY system_key, fix_class, fix_class_excl_pq, fix_reasons`` over the team's assets, plus the
    code scans and evidence items. A code-scan certificate that names a stored certificate (its CN + dates link
    keys, stored on the observation) merges with it: that asset leaves its group and is a subject of its own."""
    import sqlalchemy as sa

    from backend.new_models import CbomEstateAsset, CbomEstateObservation, CbomEstateSource
    from backend.utilities.cbom_sources import agility_store as STORE

    moment = _aware(now or _dt.datetime.now(UTC))
    if not healed:
        STORE.heal(session, team_id, moment)
    ea, eo, es = CbomEstateAsset.__table__, CbomEstateObservation.__table__, CbomEstateSource.__table__
    live = (ea.c.team_id == team_id, ea.c.presence != "removed", ea.c.fix_class.is_not(None))
    raw = session.execute(sa.select(
        ea.c.system_key, sa.func.max(ea.c.system_label), sa.func.max(ea.c.system_kind), ea.c.fix_class,
        ea.c.fix_class_excl_pq, ea.c.fix_reasons, sa.func.count()).where(*live).group_by(
        ea.c.system_key, ea.c.fix_class, ea.c.fix_class_excl_pq, ea.c.fix_reasons)).all()
    groups: dict[tuple, int] = {}
    labels: dict[str, tuple[str, str]] = {}
    for key, label, kind, cls, excl, reasons, n in raw:
        labels[key or ""] = (label or "", kind or "")
        groups[(key or "", cls, excl or "none", tuple(v for v in (reasons or "").split(",") if v))] = int(n)
    observations = int(session.execute(sa.select(sa.func.count()).select_from(eo).where(
        eo.c.team_id == team_id, eo.c.presence != "removed")).scalar() or 0)
    not_correlated = int(session.execute(sa.select(sa.func.count()).select_from(ea).where(
        ea.c.team_id == team_id, ea.c.key_kind == "not_correlated", ea.c.presence != "removed")).scalar() or 0)
    collections = int(session.execute(sa.select(sa.func.count()).select_from(es).where(
        es.c.team_id == team_id)).scalar() or 0)

    subjects: dict[str, Subject] = {}

    def subject(key: str) -> Subject:
        item = subjects.get(key)
        if item is None:
            item = subjects[key] = Subject(key=key)
        return item

    def lookup(parts: set[str]) -> dict[str, str]:
        found: dict[str, set[str]] = {}
        ordered = sorted(parts)
        for start in range(0, len(ordered), 500):
            chunk = ordered[start:start + 500]
            for key, cnb, cn in session.execute(sa.select(eo.c.asset_key, eo.c.cert_cnb_key, eo.c.cert_cn_key).where(
                    eo.c.team_id == team_id, eo.c.presence != "removed",
                    sa.or_(eo.c.cert_cnb_key.in_(chunk), eo.c.cert_cn_key.in_(chunk)))).all():
                for link in (cnb, cn):
                    if link in parts:
                        found.setdefault(link, set()).add(key)
        return {link: next(iter(keys)) for link, keys in found.items() if len(keys) == 1}  # ambiguous: no join

    scans, code_rows = _code_side(session, team_id, subject, lookup)
    evidence_items, not_assessed = _evidence_side(session, team_id, subject)
    stored_keys = sorted(k for k in subjects if not k.startswith(("code|", "evidence|")))
    merged: set[str] = set()
    for start in range(0, len(stored_keys), 500):
        for r in session.execute(sa.select(
                ea.c.asset_key, ea.c.label, ea.c.asset_type, ea.c.fix_class, ea.c.fix_class_excl_pq, ea.c.fix_floor,
                ea.c.fix_reasons, ea.c.fix_codes, ea.c.fix_at, ea.c.system_key, ea.c.system_label, ea.c.system_kind,
                ea.c.fix_observations).where(*live, ea.c.asset_key.in_(stored_keys[start:start + 500]))).all():
            sub = subjects[r.asset_key]
            sub.observations = len(sub.evals)
            sub.finish()
            code = STORE.Part(sub.fix_class, sub.excl_pq, sub.floor, tuple(sub.reasons), sub.deciding, sub.seen_at,
                              sub.system)
            split = tuple(v for v in (r.fix_reasons or "").split(",") if v)
            store = STORE.Part(r.fix_class, r.fix_class_excl_pq or "none", r.fix_floor, split,
                               tuple(v for v in (r.fix_codes or "").split(",") if v),
                               (_aware(r.fix_at), 0), (r.system_key or "", r.system_label or "", r.system_kind or ""))
            both = STORE.combine([store, code])
            group = (r.system_key or "", r.fix_class, r.fix_class_excl_pq or "none", split)
            groups[group] -= 1
            merged.add(r.asset_key)
            sub.fix_class, sub.excl_pq, sub.floor, sub.reasons, sub.codes = (
                both.fix_class, both.excl_pq, both.floor, both.reasons, both.codes)
            sub.system = both.system
            if store.at >= code.at:
                sub.name, sub.type, sub.origin = r.label or r.asset_type, r.asset_type, "sources_run"
            sub.observations += int(r.fix_observations or 0)
            sub.evals = []
    for item in subjects.values():
        if item.evals:
            item.observations = len(item.evals)
            item.finish()
    return Rollup(as_of=moment.strftime("%Y-%m-%dT%H:%M:%SZ"), subjects=list(subjects.values()),
                  observations=observations + code_rows, not_correlated=not_correlated, not_assessed=not_assessed,
                  inputs={"collections": collections, "code_scans": scans, "evidence_items": evidence_items,
                          "read_from": "estate_store"},
                  groups=[(key, *labels.get(key, ("", "")), cls, excl, reasons, n)
                          for (key, cls, excl, reasons), n in groups.items() if n > 0],
                  team_id=team_id, merged=frozenset(merged))


def _evidence(item: Subject, cls: str, system: tuple[str, str], name: str, at: Any) -> None:
    per = ({"code": "EVIDENCE", "class": cls, "floor": None, "capability": False, "rule": "EVIDENCE",
            "basis": "evidence item", "fact": None, "confidence": "observed", "unknown_reason": None},)
    whole = {"fix_class": cls, "floor": None, "confidence": "observed"}
    item.observe((whole, per, cls, ()), (_aware(at), 2, 0), (system[0], system[1], "evidence"), name, "evidence",
                 "", "evidence", system[1])


# ---------------------------------------------------------------------------------------------- per-request cache
_cache: dict[tuple, tuple[float, Rollup]] = {}
_lock = threading.Lock()


def fingerprint(session: Any, team_id: int, now: _dt.datetime) -> tuple:
    """What the roll-up depends on, read without loading any asset: the latest collection of each source, the
    latest code scan of each code source, the sources' and evidence's versions, the day (expiry is judged today)
    and the knowledge base in force."""
    from sqlalchemy import func
    from sqlmodel import select

    from backend.new_models import CbomCollectionSource, CbomEstateSource, CbomEvidenceArea, CbomEvidenceVendor
    from backend.utilities.cbom_sources import collections_view as CV
    from backend.utilities.cbom_sources import crypto_kb

    jobs = tuple(sorted((j.id, j.attempts) for j in CV.latest_jobs(session, team_id)))
    scans = tuple(sorted(s[0] for s in latest_code_scans(session, team_id)))
    srcs = session.exec(select(func.count(), func.max(CbomCollectionSource.last_updated)).where(
        CbomCollectionSource.team_id == team_id)).one()
    areas = session.exec(select(func.count(), func.max(CbomEvidenceArea.last_updated)).where(
        CbomEvidenceArea.team_id == team_id)).one()
    vendors = session.exec(select(func.count(), func.max(CbomEvidenceVendor.last_updated)).where(
        CbomEvidenceVendor.team_id == team_id)).one()
    store = session.exec(select(func.count(), func.max(CbomEstateSource.updated_at)).where(
        CbomEstateSource.team_id == team_id)).one()  # the store catching up (drift recorded, a backfill) refreshes it
    return (team_id, jobs, scans, tuple(srcs), tuple(areas), tuple(vendors), tuple(store), now.date().isoformat(),
            crypto_kb.version(), AG.version(), USE_STORE)


def cached(session: Any, team_id: int, *, now: _dt.datetime | None = None) -> Rollup:
    """``build`` memoised per team on ``fingerprint`` for ``CACHE_TTL_S`` (paging the drill-down never reloads the
    estate; any new collection, scan, metadata or evidence edit changes the fingerprint)."""
    moment = _aware(now or _dt.datetime.now(UTC))
    key = fingerprint(session, team_id, moment)
    clock = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit is not None and clock - hit[0] < CACHE_TTL_S:
            return hit[1]
    result = build(session, team_id, now=moment)
    with _lock:
        for stale in [k for k, (at, _r) in _cache.items() if k[0] == team_id or clock - at >= CACHE_TTL_S]:
            _cache.pop(stale, None)
        while len(_cache) >= CACHE_TEAMS:
            _cache.pop(min(_cache, key=lambda k: _cache[k][0]))
        _cache[key] = (clock, result)
    return result


def clear_cache() -> None:
    with _lock:
        _cache.clear()


__all__ = ["CACHE_TTL_S", "KINDS", "MAX_LIMIT", "METHOD", "Rollup", "Subject", "build", "cached", "clear_cache",
           "decode_cursor", "fingerprint", "latest_code_scans", "store_ready"]
