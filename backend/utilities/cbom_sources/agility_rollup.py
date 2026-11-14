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

The estate store (CB-20, PR #167) replaces the load in PR-B; until then this reads ``collections_view``.
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

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
        target = self.fix_class if self.fix_class in AG.RANK else None
        return tuple(dict.fromkeys(p["code"] for p in self.per if target and p["class"] == target))


@dataclass
class Rollup:
    as_of: str
    subjects: list[Subject]
    observations: int
    not_correlated: int
    not_assessed: int
    inputs: dict[str, int]

    # ------------------------------------------------------------------ enterprise
    def counts(self, excl_pq: bool = False) -> dict[str, int]:
        c = Counter(s.excl_pq if excl_pq else s.fix_class for s in self.subjects)
        return {v: c.get(v, 0) for v in AG.VALUES}

    def unknown_reasons(self) -> dict[str, int]:
        c: Counter = Counter()
        for s in self.subjects:
            c.update(s.reasons)
        return dict(sorted(c.items()))

    def systems(self) -> list[dict[str, Any]]:
        acc: dict[str, dict[str, Any]] = {}
        for s in self.subjects:
            key, label, kind = s.system
            item = acc.setdefault(key, {"key": key, "label": label, "kind": kind, "c": Counter(), "x": Counter()})
            item["c"][s.fix_class] += 1
            item["x"][s.excl_pq] += 1
        out = []
        for item in acc.values():
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
        return {
            "as_of": self.as_of, "scope": "current estate", "model": AG.MODEL, "agility_version": AG.version(),
            "assets": len(self.subjects), "counts": counts, "counts_excl_pq": excl,
            "self_fixable_pct": AG.self_fixable_pct(counts), "self_fixable_pct_excl_pq": AG.self_fixable_pct(excl),
            "hardest": _hardest(counts), "unknown_reasons": self.unknown_reasons(), "not_assessed": self.not_assessed,
            "dedupe": {"method": METHOD, "key_version": _key_version(), "observations": self.observations,
                       "merged": self.observations - (len(self.subjects) - self.inputs.get("evidence_items", 0)),
                       "not_correlated": self.not_correlated},
            "inputs": dict(self.inputs),
            "systems_total": len(systems),
            "systems": {"items": page, "next": next_cursor, "matched": len(listed)},
        }

    # ------------------------------------------------------------------ drill-down
    def subjects_page(self, *, fix_class: str | None = None, system: str | None = None, excl_pq: bool = False,
                      after: str | None = None, limit: int = 100) -> dict[str, Any]:
        chosen = [s for s in self.subjects
                  if (not fix_class or (s.excl_pq if excl_pq else s.fix_class) == fix_class)
                  and (not system or s.system[0] == system)]
        chosen.sort(key=_subject_sort)
        page, next_cursor = _keyset(chosen, after, limit, _subject_sort)
        return {"as_of": self.as_of, "view": "excl_pq" if excl_pq else "all", "fix_class": fix_class,
                "system": system, "total": len(chosen), "next": next_cursor,
                "items": [_public(s) for s in page]}


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


def build(session: Any, team_id: int, *, now: _dt.datetime | None = None, sources: Any = None) -> Rollup:
    """The team's agility roll-up. ``sources``: a ``collections_view.SourcesResult`` already loaded for this request."""
    from sqlmodel import select

    from backend.new_models import (CbomCollectionJob, CbomCollectionSource, CbomEvidenceArea, CbomEvidenceVendor,
                                    Scan)
    from backend.utilities.cbom_sources import asset_keys as AK
    from backend.utilities.cbom_sources import collections_view as CV
    from backend.utilities.cbom_sources import identity as ID

    moment = _aware(now or _dt.datetime.now(UTC))
    found = sources if sources is not None else CV.load_sources_result(session, team_id, moment)
    subjects: dict[str, Subject] = {}

    def subject(key: str) -> Subject:
        item = subjects.get(key)
        if item is None:
            item = subjects[key] = Subject(key=key)
        return item

    # 1. Sources: one key per cross-source identity (certificates, endpoints, cloud resources), class per observation
    job_ids = sorted({item.collection.job_id for item in found.rows})
    jobs = {j.id: j for start in range(0, len(job_ids), 500) for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.id.in_(job_ids[start:start + 500]))).all()}  # type: ignore[union-attr]
    srcs = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    contexts: dict[int, tuple[tuple, tuple[str, str, str]]] = {}
    kb = AG.crypto_kb.version()
    aliases: dict[str, str] = {}
    ambiguous: set[str] = set()
    not_correlated = 0
    for item in found.rows:
        col = item.collection
        if col.job_id not in contexts:
            job = jobs.get(col.job_id)
            source = srcs.get(getattr(job, "source_id", None) or 0)
            ctx = AG.node_context(job, source)
            (kind, skey), label = AG.system_of(job, source, ctx)
            if kind == "source":  # the source uid collections_view uses (snapshot first)
                skey, label = col.source_ref, col.source_name
            contexts[col.job_id] = (AG._ctx_key(ctx), (f"{kind}:{skey}", label, kind))
        ctx_key, system = contexts[col.job_id]
        row = item.row
        if item.node_type in AK.CERT_TYPES or row.get("algorithm_type") == "certificate":
            # load_sources_result already correlated the certificates (link_certificates: asset_keys.correlate_detail)
            key = item.identity
            if key.startswith("node|"):
                not_correlated += 1  # a certificate with nothing identifying: counted within its own source
            for alias in item.aliases:
                if aliases.setdefault(alias, key) != key:
                    ambiguous.add(alias)
        else:  # an endpoint (host:port, a private address scoped to its source) or a cloud resource id
            found_key = AK.asset_key(AK.Observation(
                kind=str(item.node_type or ""), facts=item.facts if isinstance(item.facts, dict) else {},
                location=str(row.get("location") or ""), target=str(item.target or ""), scope=col.source_ref))
            key = found_key if isinstance(found_key, str) else item.identity
        codes = row.get("collector_codes") or []
        a_type = str(item.node_type or "")
        facts = item.facts if isinstance(item.facts, dict) else {}
        # agility.RunAgility's path: the job context's memo key computed once per job
        ev = AG._evaluate(kb, "node", a_type, AG._codes(codes), AG._deciding(a_type, facts, row.get("location")),
                          ctx_key)
        subject(key).observe(ev, (col.observed_at, 0, col.job_id), system, str(row.get("title") or item.node_type),
                             item.node_type, str(row.get("location") or ""), CV.ORIGIN_SOURCES, col.source_name)
    for alias in ambiguous:
        aliases.pop(alias, None)

    # 2. code scans: each code source's latest successful scan; a certificate joins the Sources one it shares a key with
    code_scans = latest_code_scans(session, team_id)
    observations = len(found.rows)
    for scan_id, skey, label, created in code_scans:
        data = session.exec(select(Scan.scan_data).where(Scan.id == scan_id, Scan.team_id == team_id)).first()
        data = data if isinstance(data, dict) else {}
        rows = [r for r in (data.get("results") or []) if isinstance(r, dict)]
        cert_ids = CV.code_cert_identities(data)
        system = (f"repository:{skey}", label, "repository")
        for row in rows:
            token = CV.code_row_identity(row, cert_ids)
            if token:
                key = next((aliases[p] for p in token.split("+") if p in aliases), token.split("+")[0])
            else:
                key = f"code|{skey}|{ID.code_identity(row)}"
            observations += 1
            subject(key).observe(AG.classify_code_row(row), (created, 1, scan_id), system,
                                 str(row.get("title") or row.get("algorithm_name") or row.get("asset_type") or ""),
                                 str(row.get("asset_type") or row.get("algorithm_type") or ""),
                                 str(row.get("location") or ""), CV.ORIGIN_CODE, label)

    # 3. evidence items with a class
    not_assessed = evidence_items = 0
    for area in session.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.team_id == team_id)).all():
        fields = AG.evidence_area_fields(area.area_key, area.answers)
        if fields["not_assessed"]:
            not_assessed += 1
        if not fields["fix_class"]:
            continue
        which = "hsm" if fields["fix_class"] == "hardware-fixed" else "vendor"
        evidence_items += 1
        _evidence(subject(f"evidence|area|{area.area_key}"), fields["fix_class"], EVIDENCE_SYSTEMS[which],
                  f"Evidence area: {area.area_key.replace('_', ' ')}", area.last_updated)
    for vendor in session.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.team_id == team_id)).all():
        evidence_items += 1
        _evidence(subject(f"evidence|vendor|{vendor.id}"), AG.evidence_vendor_fields()["fix_class"],
                  EVIDENCE_SYSTEMS["vendor"], vendor.name, vendor.created_at)

    for item in subjects.values():
        item.observations = len(item.evals)
        item.finish()
    return Rollup(as_of=moment.strftime("%Y-%m-%dT%H:%M:%SZ"), subjects=list(subjects.values()),
                  observations=observations, not_correlated=not_correlated, not_assessed=not_assessed,
                  inputs={"collections": len(found.collections), "code_scans": len(code_scans),
                          "evidence_items": evidence_items})


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

    from backend.new_models import CbomCollectionSource, CbomEvidenceArea, CbomEvidenceVendor
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
    return (team_id, jobs, scans, tuple(srcs), tuple(areas), tuple(vendors), now.date().isoformat(),
            crypto_kb.version(), AG.version())


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
           "decode_cursor", "fingerprint", "latest_code_scans"]
