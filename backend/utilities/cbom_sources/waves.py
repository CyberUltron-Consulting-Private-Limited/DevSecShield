"""Remediation waves with owners: a suggested wave per asset, the team's assignments, and the roadmap's rows.

Suggested wave (the user may override it per asset): the first of ``WAVE_RULES`` the asset meets.
  1. Critical / High weakness on an internet-facing or in-transit asset, or any harvest-now-decrypt-later asset
     (quantum-vulnerable key exchange in transit)
  2. other Critical / High weakness
  3. any other weakness, whatever its impact (Medium, Low, Info or none recorded)
  4. quantum-vulnerable inventory with no other weakness (plan the post-quantum migration)
  none: no weakness and not quantum-vulnerable (nothing to remediate)

Assignments (``CbomRemediationAssignment``) are keyed by the asset's STABLE identity (``identity.stable_key``), never by
a row id or inside ``scan_data``, so a plan made on one run still applies to the same asset in every later run or scan.
"""
from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Literal

import sqlalchemy as sa
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomEstateAsset,
    CbomEstateObservation,
    CbomRemediationAssignment,
    CbomScanNode,
    Scan,
)
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources import pqc_targets as PQT
from backend.utilities.cbom_sources.cbom_metrics import code_row_quantum_vulnerable
from backend.utilities.cbom_sources.cbom_rows import display_row, is_finding
from backend.utilities.cbom_sources.common import iso_z

WAVES = (1, 2, 3, 4)
STATUSES = ("open", "in_progress", "done", "accepted_risk")
WAVE_LABEL = PQT.WAVE_LABEL


@dataclass(frozen=True)
class WaveRule:
    """One rule of ``suggested_wave``: the first rule an asset meets gives its wave. ``text`` is the rule in words: the
    results page's wave legend is built from these texts (``WAVE_RULE``), so the legend and the code cannot drift."""
    key: str
    wave: int
    text: str
    test: Callable[[SimpleNamespace], bool]


# ``weakness``: a finding other than the bare quantum verdict (QUANTUM_VULNERABLE) and coverage notes; ``hndl``: a
# quantum-vulnerable key exchange in transit (posture.hndl), harvest now, decrypt later.
WAVE_RULES: tuple[WaveRule, ...] = (
    WaveRule("exposed", 1, "a Critical or High weakness on an internet-facing or in-transit (HNDL) asset",
             lambda a: a.weakness and a.severe and (a.internet or a.hndl)),
    WaveRule("hndl", 1, "any quantum-vulnerable key exchange in transit (harvest now, decrypt later: traffic recorded "
                        "today can be decrypted later)",
             lambda a: a.hndl and a.quantum_vulnerable),
    WaveRule("severe", 2, "any other Critical or High weakness", lambda a: a.weakness and a.severe),
    WaveRule("weakness", 3, "any other weakness, whatever its impact (Medium, Low, Info or none recorded)",
             lambda a: a.weakness),
    WaveRule("quantum", 4, "a quantum-vulnerable asset with no other weakness: plan its post-quantum migration",
             lambda a: bool(a.quantum_vulnerable)),
)


def _rule_text(wave: int) -> str:
    text = ", or ".join(r.text for r in WAVE_RULES if r.wave == wave)
    return "Urgent: " + text if wave == 1 else text[:1].upper() + text[1:]


# What puts an asset in each wave, in words (the results page's legend, issue #271), built from WAVE_RULES. A wave no
# asset meets is simply not listed.
WAVE_RULE: dict[int | str, str] = {**{w: _rule_text(w) for w in WAVES},
                                   "none": "No weakness and not quantum-vulnerable: nothing to remediate"}
MAX_ITEMS = 2_000  # per bulk request
ROADMAP_NODE_CAP = 2_000
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def matching_rule(impact: str | None, codes: Iterable[str], quantum_vulnerable: bool | None, *,
                  internet: bool = False, hndl: bool = False) -> WaveRule | None:
    """The first of ``WAVE_RULES`` the asset meets; None: nothing to remediate."""
    facts = SimpleNamespace(
        weakness=any(c and c != "QUANTUM_VULNERABLE" and not c.startswith("COVERAGE_") for c in codes),
        severe=impact in ("Critical", "High"), quantum_vulnerable=quantum_vulnerable, internet=internet, hndl=hndl)
    return next((r for r in WAVE_RULES if r.test(facts)), None)


def suggested_wave(impact: str | None, codes: Iterable[str], quantum_vulnerable: bool | None, *,
                   internet: bool = False, hndl: bool = False) -> int | None:
    rule = matching_rule(impact, codes, quantum_vulnerable, internet=internet, hndl=hndl)
    return rule.wave if rule else None


def public_assignment(a: CbomRemediationAssignment | None) -> dict[str, Any] | None:
    if a is None:
        return None
    return {"wave": a.wave, "owner": a.owner, "target_date": a.target_date, "status": a.status, "note": a.note,
            "row_version": a.row_version, "last_updated": iso_z(a.last_updated),
            "ticket_key": a.ticket_key, "ticket_url": a.ticket_url, "done_at": iso_z(a.done_at)}


def _assignments(session: Session, team_id: int, keys: Iterable[str]) -> dict[str, CbomRemediationAssignment]:
    wanted = list(dict.fromkeys(keys))
    out: dict[str, CbomRemediationAssignment] = {}
    for start in range(0, len(wanted), 500):
        for a in session.exec(select(CbomRemediationAssignment).where(
                CbomRemediationAssignment.team_id == team_id,
                CbomRemediationAssignment.asset_key.in_(wanted[start:start + 500]))).all():  # type: ignore[attr-defined]
            out[a.asset_key] = a
    return out


def fix_windows(session: Session, team_id: int) -> dict[int, int]:
    """The team's days-to-fix per wave for classical weaknesses (``risk_model`` wave1..3_fix_days, else the KB's)."""
    from backend.new_models import CbomCollectionSettings

    settings = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
    return PQT.fix_windows((settings.risk_model if settings is not None else None) or {})


def _today() -> _dt.date:
    """The as-of day of the wave API (one clock read; tests freeze it)."""
    return _dt.datetime.now(_dt.timezone.utc).date()


_CLOSED_STATUSES = ("done", "accepted_risk")


def _with_assignment(items: list[dict[str, Any]], found: dict[str, CbomRemediationAssignment],
                     windows: dict[int, int] | None = None, as_of: _dt.date | None = None) -> list[dict[str, Any]]:
    """Each item's plan and dates. An item carries ``first_seen_on`` (YYYY-MM-DD, when the asset was first found; None
    when unknown) and ``disallowed`` (``qgrade.disallowed_now``) from its loader."""
    as_of = as_of or _today()
    for item in items:
        a = found.get(item["asset_key"])
        item["assignment"] = public_assignment(a)
        item["wave"] = a.wave if a is not None and a.wave is not None else item["suggested_wave"]
        item["wave_source"] = "assigned" if a is not None and a.wave is not None else "suggested"
        # D13: the proposed dates unless the team set one: a classical weakness of waves 1-3 is due within the wave's
        # window from when the asset was FIRST FOUND (never from the day of the request, so the date is fixed and can
        # become overdue); the post-quantum migration by the wave's IR 8547 / CNSA 2.0 milestone
        dates = PQT.proposed_dates(item["wave"], item.get("finding_codes") or (), item.get("quantum_vulnerable"),
                                   as_of, windows, found_on=item.get("first_seen_on"),
                                   disallowed=item.get("disallowed")) if item["wave"] else {}
        item["proposed_date"] = dates.get("date")
        item["proposed_date_kind"] = dates.get("kind")  # fix | pq
        item["fix_by"] = dates.get("fix_by")
        item["pq_by"] = dates.get("pq_by")
        item["found_on"] = dates.get("found_on")  # the day fix_by counts from
        item["found_basis"] = dates.get("found_basis")  # first_seen | as_of (first observation unknown)
        item["fix_basis"] = dates.get("fix_basis")  # disallowed | classical (PQT.FIX_BASIS_TEXT)
        due = (a.target_date if a is not None and a.target_date else None) or item["proposed_date"]
        open_ = a is None or a.status not in _CLOSED_STATUSES
        item["due_date"] = due  # the assigned target date, else the proposed one
        item["overdue"] = bool(due) and open_ and as_of.isoformat() > str(due)
    return items


def _day(value: Any) -> str | None:
    if isinstance(value, _dt.datetime):
        return value.date().isoformat()
    if isinstance(value, _dt.date):
        return value.isoformat()
    return None


def _earliest(a: str | None, b: str | None) -> str | None:
    return min(x for x in (a, b) if x) if (a or b) else None


def node_first_seen(session: Session, team_id: int, refs_keys: Iterable[tuple[str, str]]) -> dict[str, str]:
    """observation key -> the day its estate asset was first found (``CbomEstateAsset.first_seen_at``; the estate
    asset is cross-source, so a certificate first seen by another source counts from then). Keys the estate has not
    recorded are left out (the caller falls back).

    One query per source through the ``(team_id, source_ref, asset_key)`` observation index joined to the estate
    asset's unique ``(team_id, asset_key)``: ``observation_key`` has no index, so a page of keys (``IN``) is filtered
    inside the source's range and a whole run reads the range once (50k keys: one pass, not one scan per batch)."""
    wanted: dict[str, set[str]] = {}
    for ref, key in refs_keys:
        wanted.setdefault(ref, set()).add(key)
    out: dict[str, str] = {}
    for ref, keys in wanted.items():
        query = select(CbomEstateObservation.observation_key, CbomEstateAsset.first_seen_at).join(
            CbomEstateAsset, sa.and_(CbomEstateAsset.team_id == CbomEstateObservation.team_id,
                                     CbomEstateAsset.asset_key == CbomEstateObservation.asset_key)).where(
            CbomEstateObservation.team_id == team_id, CbomEstateObservation.source_ref == ref)
        if len(keys) <= 500:
            query = query.where(CbomEstateObservation.observation_key.in_(sorted(keys)))  # type: ignore[attr-defined]
        for okey, at in session.exec(query).all():
            day = _day(at)
            if okey in keys and day:
                out[okey] = _earliest(out.get(okey), day) or day
    return out


def code_disallowed(asset_type: Any, algorithm: Any, key_size: Any) -> bool:
    """NIST disallows the code row's algorithm or key size today (``qgrade.disallowed_now``, as D12 grades it)."""
    from backend.utilities.cbom_sources import qgrade as QG

    try:
        size = int(str(key_size).strip()) if key_size not in (None, "") else None
    except ValueError:
        size = None
    return QG.disallowed_now(SimpleNamespace(asset_type=str(asset_type or "algorithm"), algorithm=algorithm,
                                            key_size=size, facts={}))


def code_first_seen(session: Session, team_id: int, ref: str, keys: Iterable[str]) -> dict[str, str]:
    """stable key -> the day of the earliest INCLUDED scan of source ``ref`` that carries it (the team roll-up's
    ``AssetAgg.first_seen``: successful CBOM scans, the newest ``HISTORY_WINDOW`` of the team), oldest scan first and
    stopping once every key is found."""
    from backend.utilities.dashboard.cbom_team_rollup import HISTORY_WINDOW, _status_exclusion, source_key_for

    remaining = set(keys)
    if not remaining:
        return {}
    heads = session.exec(select(Scan.id, Scan.created_at, Scan.scan_status, Scan.scan_metadata, Scan.title).where(
        Scan.team_id == team_id, Scan.scan_type == "cbom").order_by(
        Scan.created_at.desc(), Scan.id.desc())).all()  # type: ignore[union-attr]
    eligible = [h for h in heads if _status_exclusion(h[2]) is None][:HISTORY_WINDOW]
    same = [(sid, created) for sid, created, _st, meta, title in eligible
            if source_key_for(meta if isinstance(meta, dict) else {}, str(title or "").strip(), sid or 0)[0] == ref]
    same.sort(key=lambda h: (h[1] or _dt.datetime.min, h[0]))
    out: dict[str, str] = {}
    for start in range(0, len(same), 10):
        batch = same[start:start + 10]
        blobs = dict(session.exec(select(Scan.id, Scan.scan_data).where(
            Scan.id.in_([b[0] for b in batch]))).all())  # type: ignore[union-attr]
        for sid, created in batch:
            data = blobs.get(sid)
            rows = data.get("results") if isinstance(data, dict) else None
            for raw in rows if isinstance(rows, list) else ():
                if not isinstance(raw, dict):
                    continue
                key = ID.stable_key("code", ref, ID.code_identity(raw))
                if key in remaining:
                    remaining.discard(key)
                    out[key] = _day(created) or ""
            if not remaining:
                return {k: v for k, v in out.items() if v}
    return {k: v for k, v in out.items() if v}


def target_fields(asset_type: Any, algorithm: Any, facts: Any, primitive: Any = None) -> dict[str, Any]:
    """The asset's NIST post-quantum target (``pqc_targets``), as every surface prints it."""
    t = PQT.asset_target(asset_type, algorithm, facts, primitive)
    return {"pq_usage": t["usage"] if t else None, "pq_target": t["target_text"] if t else None,
            "pq_target_cnsa": t["cnsa_target"] if t else None, "pq_reference": t["reference"] if t else None}


# ----------------------------------------------------------------------------- node runs
def node_items(session: Session, team_id: int, run: CbomCollectionRun, *,
               asset_ids: Iterable[int] | None = None, as_of: _dt.date | None = None) -> list[dict[str, Any]]:
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.cbom_sources.posture import (
        asset_exposure,
        hndl,
        job_metadata,
    )

    jobs = {j.id: j for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.run_id == run.id)).all()}
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    query = select(CbomCollectedAsset).where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id)
    if asset_ids is not None:
        query = query.where(CbomCollectedAsset.id.in_(list(asset_ids)))  # type: ignore[union-attr]
    else:
        # the whole run: one item per resource, the rows the run's assets API lists (review 6039899144 B1: the waves
        # and the run's tickets planned both jobs' rows, 458 for 229).  Ids a caller names are its own choice.
        from backend.utilities.cbom_sources import resource_identity as RI

        query = query.where(RI.kept_clause(RI.run_fold(session, team_id, int(run.id or 0))))
    from backend.utilities.cbom_sources.classify import shown

    items = []
    now = _dt.datetime.utcnow()
    for row in session.exec(query.order_by(CbomCollectedAsset.id)).all():
        if row.asset_type == "coverage":
            continue
        view = shown(row, now)  # date-based findings (certificate expiry, library end of life) judged today
        job = jobs.get(row.job_id)
        src = sources.get((job.source_id if job else None) or 0)
        ref = ID.job_source_ref(job, src) if job else f"source-{row.source_id}"
        meta = job_metadata(job.params if job else None, src, nodes.get((job.node_id if job else None) or 0))
        exposure, _basis = asset_exposure(row.facts, row.target, row.location, override=meta["exposure"],
                                          node_segment=meta["segment"])
        codes = view["finding_codes"]
        in_transit = hndl(row.asset_type, row.quantum_vulnerable)
        snap = (job.params or {}).get("metadata") if job else None
        owner = (snap.get("owner") if isinstance(snap, dict) else None) or ((src.config or {}).get("owner") if src else None)
        items.append({
            "asset_id": row.id, "asset_key": ID.stable_key("node", ref, ID.node_identity(row)), "scope": "node",
            "source_ref": ref, "source_name": ID.job_source_name(job, src) if job else None,
            "label": ID.node_label(row), "type": row.asset_type, "impact": view["impact"], "finding_codes": codes,
            "quantum_vulnerable": row.quantum_vulnerable, "exposure": exposure, "hndl": in_transit,
            "owner_hint": owner, **target_fields(row.asset_type, row.algorithm, row.facts),
            "suggested_wave": suggested_wave(view["impact"], codes, row.quantum_vulnerable,
                                             internet=exposure == "internet", hndl=in_transit),
            # when it was first found: the estate's first_seen_at (below), else this collection
            "first_seen_on": _day(row.created_at),
            "disallowed": QG.disallowed_now(row) if PQT.classical_weakness(codes) else False,
        })
    first = node_first_seen(session, team_id, ((i["source_ref"], i["asset_key"]) for i in items))
    for item in items:
        item["first_seen_on"] = _earliest(first.get(item["asset_key"]), item["first_seen_on"])
    return _with_assignment(items, _assignments(session, team_id, (i["asset_key"] for i in items)),
                            fix_windows(session, team_id), as_of)


# ----------------------------------------------------------------------------- code scans
def code_items(session: Session, team_id: int, scan: Scan, *, as_of: _dt.date | None = None) -> list[dict[str, Any]]:
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    rows = data.get("results") if isinstance(data.get("results"), list) else []
    ref, label = ID.code_source_ref(scan.scan_metadata, scan.title, scan.id or 0)
    seen: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            continue
        row = display_row(raw)
        key = ID.stable_key("code", ref, ID.code_identity(raw))  # the stored row, as drift and the roll-up key it
        finding = is_finding(row)
        codes = [c for c in row.get("finding_codes") or [] if isinstance(c, str)] or (["FINDING"] if finding else [])
        qv = code_row_quantum_vulnerable(row)
        impact = str(row.get("impact") or "Low") if finding else None
        item = seen.get(key)
        if item is None:
            seen[key] = {"row_index": index, "bom_ref": row.get("bom_ref"), "asset_key": key, "scope": "code",
                         "source_ref": ref, "source_name": label, "label": ID.code_label(row),
                         "type": row.get("asset_type") or row.get("algorithm_type"), "impact": impact,
                         "finding_codes": codes, "quantum_vulnerable": qv, "exposure": "unknown", "hndl": False,
                         "owner_hint": row.get("owner") or row.get("owner_hint"),
                         **target_fields(row.get("asset_type") or "algorithm",
                                         row.get("title") or row.get("algorithm_name"), None,
                                         row.get("primitive") or row.get("algorithm_type")),
                         "_probe": (row.get("asset_type") or row.get("algorithm_type"),
                                    row.get("title") or row.get("algorithm_name"), row.get("key_size"))}
        else:  # the same asset on several lines: one plan
            item["finding_codes"] = sorted(set(item["finding_codes"]) | set(codes))
            item["quantum_vulnerable"] = item["quantum_vulnerable"] or qv
    items = list(seen.values())
    first = code_first_seen(session, team_id, ref, (i["asset_key"] for i in items))
    this_scan = _day(scan.created_at)
    for item in items:
        item["suggested_wave"] = suggested_wave(item["impact"], item["finding_codes"], item["quantum_vulnerable"])
        # when it was first found: the earliest included scan with this key, else this scan (an excluded one)
        item["first_seen_on"] = first.get(item["asset_key"]) or this_scan
        probe = item.pop("_probe")
        item["disallowed"] = code_disallowed(*probe) if PQT.classical_weakness(item["finding_codes"]) else False
    return _with_assignment(items, _assignments(session, team_id, (i["asset_key"] for i in items)),
                            fix_windows(session, team_id), as_of)


# ----------------------------------------------------------------------------- write
class AssignmentItem(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    asset_key: str = Field(min_length=40, max_length=40)
    wave: int | None = Field(default=None, ge=1, le=4)
    owner: str | None = Field(default=None, max_length=128)
    target_date: str | None = Field(default=None, max_length=10)
    status: Literal["open", "in_progress", "done", "accepted_risk"] | None = None
    note: str | None = Field(default=None, max_length=500)

    @field_validator("asset_key")
    @classmethod
    def _hex(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{40}", v):
            raise ValueError("asset_key: not an asset key")
        return v

    @field_validator("target_date")
    @classmethod
    def _date(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        if not _DATE.match(v):
            raise ValueError("target_date: use YYYY-MM-DD")
        try:
            _dt.date.fromisoformat(v)
        except ValueError as exc:
            raise ValueError("target_date: not a calendar date") from exc
        return v

    @field_validator("owner", "note")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        if v is None:
            return None
        text = "".join(ch for ch in v if ch >= " " and ch != "\x7f").strip()
        return text or None


class AssignmentBulk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: int | None = Field(default=None, ge=1)
    scan_id: int | None = Field(default=None, ge=1)
    items: list[AssignmentItem] = Field(min_length=1, max_length=MAX_ITEMS)


def upsert(session: Session, team_id: int, user_id: int, body: AssignmentBulk, now: _dt.datetime) -> dict[str, Any]:
    """Apply the fields each item names (others keep their value). Every key must belong to the run or scan the
    request names, so labels and sources come from the server, never from the browser."""
    if (body.run_id is None) == (body.scan_id is None):
        raise HTTPException(status_code=400, detail="Name exactly one of run_id or scan_id")
    if body.run_id is not None:
        run = session.get(CbomCollectionRun, body.run_id)
        if run is None or run.team_id != team_id:
            raise HTTPException(status_code=404, detail="Run not found")
        known = {i["asset_key"]: i for i in node_items(session, team_id, run)}
    else:
        scan = session.get(Scan, body.scan_id)
        if scan is None or scan.team_id != team_id or scan.scan_type != "cbom":
            raise HTTPException(status_code=404, detail="Scan not found")
        known = {i["asset_key"]: i for i in code_items(session, team_id, scan)}
    unknown = [i.asset_key for i in body.items if i.asset_key not in known]
    if unknown:
        raise HTTPException(status_code=400, detail=f"items: {len(unknown)} asset(s) are not in this run or scan")
    existing = _assignments(session, team_id, (i.asset_key for i in body.items))
    changed = 0
    for item in body.items:
        fields = {k: getattr(item, k) for k in item.model_fields_set if k != "asset_key"}
        info = known[item.asset_key]
        row = existing.get(item.asset_key)
        if row is None:
            row = CbomRemediationAssignment(team_id=team_id, asset_key=item.asset_key, scope=info["scope"],
                                            source_ref=str(info["source_ref"])[:255], created_at=now)
            existing[item.asset_key] = row
        elif not fields:
            continue
        was_done = row.status == "done" and row.id is not None
        for key, value in fields.items():
            setattr(row, key, value if key != "status" or value is not None else "open")
        if row.status == "done" and (not was_done or row.done_at is None):
            row.done_at = now  # remediation metrics (CB-38 PR-4): when it became done
        elif row.status != "done":
            row.done_at = None
        row.label = str(info.get("label") or "")[:255] or None
        row.updated_by_user_id, row.last_updated = user_id, now
        row.row_version = (row.row_version or 0) + 1 if row.id is not None else 1
        session.add(row)
        changed += 1
    return {"updated": changed}


# ----------------------------------------------------------------------------- roadmap
def _kex_group(facts: Any) -> str | None:
    facts = facts if isinstance(facts, dict) else {}
    for key in ("negotiated_group", "group", "kex"):
        value = facts.get(key)
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value[:3])
        if isinstance(value, str) and value.strip() and value != "<NULL>":
            return value.strip()[:64]
    return None


def code_asset_key(asset: Any) -> str:
    return ID.stable_key("code", asset.source_key, ID.asset_agg_identity(asset))


def roadmap_extras(session: Session, team_id: int, view: Any = None) -> dict[str, Any]:
    """What the PQC roadmap needs beyond the code-scan roll-up: the plan of every current roll-up asset
    (``code_plans``, keyed by ``cbom_team_rollup.plan_key``: assigned fields and the suggested wave), and the
    quantum-vulnerable assets of each source's latest complete collection (scan nodes and the cloud worker)."""
    from backend.utilities.dashboard.cbom_team_rollup import plan_key

    as_of = getattr(view, "as_of", None)

    assignments = {a.asset_key: public_assignment(a) for a in session.exec(select(CbomRemediationAssignment).where(
        CbomRemediationAssignment.team_id == team_id).limit(50_000)).all()}
    code_plans: dict[str, Any] = {}
    # when each code asset was first found: the earliest included scan with its stable key (the roll-up's first_seen
    # over every AssetAgg of the key, current or not), as the wave API's ``code_first_seen``
    first_code: dict[str, str] = {}
    for asset in (getattr(view, "assets", None) or ())[:50_000]:
        if asset.source_key.startswith("sources:"):
            continue
        day = _day(getattr(asset, "first_seen", None))
        if day:
            key = code_asset_key(asset)
            first_code[key] = _earliest(first_code.get(key), day) or day
    for asset in (getattr(view, "assets", None) or ())[:50_000]:
        if not asset.current or asset.source_key.startswith("sources:"):  # Sources assets: node_rows below
            continue
        code_plans[plan_key(asset)] = {
            "assigned": assignments.get(code_asset_key(asset)) or {},
            "suggested": suggested_wave(asset.impact, asset.finding_codes, asset.quantum_vulnerable),
            "finding_codes": list(asset.finding_codes or ()), "quantum_vulnerable": asset.quantum_vulnerable,
            "first_seen_on": first_code.get(code_asset_key(asset)),
            "disallowed": (code_disallowed(asset.asset_type, asset.title, asset.key_size)
                           if PQT.classical_weakness(asset.finding_codes or ()) else False)}
    # the same collections every CBOM view counts: each source's latest completed collection (collections_view)
    from backend.utilities.cbom_sources.collections_view import latest_jobs

    node_rows: list[dict[str, Any]] = []
    runs: dict[int, CbomCollectionRun] = {}
    for job in latest_jobs(session, team_id):
        if job.run_id is None or len(node_rows) >= ROADMAP_NODE_CAP:
            continue
        run = runs.get(job.run_id) or session.get(CbomCollectionRun, job.run_id)
        if run is None:
            continue
        runs[run.id] = run
        ids = [r for r in session.exec(select(CbomCollectedAsset.id).where(
            CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == job.attempts,
            CbomCollectedAsset.quantum_vulnerable == True)).all()]  # noqa: E712
        if not ids:
            continue
        for item in node_items(session, team_id, run, asset_ids=ids, as_of=as_of):
            row = session.get(CbomCollectedAsset, item["asset_id"])
            node_rows.append({**item, "algorithm": row.algorithm if row else None,
                              "key_size": row.key_size if row else None, "target": row.target if row else None,
                              "location": row.location if row else None, "run_id": run.id,
                              # the key-exchange group an endpoint negotiated (the part a quantum computer breaks)
                              "kex_group": _kex_group(row.facts) if row else None,
                              "collected_at": iso_z(row.created_at) if row else None})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    node_rows.sort(key=lambda r: (r["wave"] or 9, order.get(r["impact"] or "", 8), str(r["source_name"]), r["label"]))
    return {"code_plans": code_plans, "node_rows": node_rows[:ROADMAP_NODE_CAP],
            "node_rows_omitted": max(len(node_rows) - ROADMAP_NODE_CAP, 0),
            # the days-to-fix per wave the PDF dates classical weaknesses with, from when each asset was first found
            "fix_windows": fix_windows(session, team_id)}


__all__ = ["AssignmentBulk", "STATUSES", "WAVES", "WAVE_LABEL", "WAVE_RULE", "WAVE_RULES", "WaveRule", "code_asset_key",
           "code_disallowed", "code_first_seen", "code_items", "fix_windows", "node_first_seen", "node_items", "matching_rule", "roadmap_extras", "suggested_wave", "upsert"]
