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

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
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


def _with_assignment(items: list[dict[str, Any]], found: dict[str, CbomRemediationAssignment]) -> list[dict[str, Any]]:
    for item in items:
        a = found.get(item["asset_key"])
        item["assignment"] = public_assignment(a)
        item["wave"] = a.wave if a is not None and a.wave is not None else item["suggested_wave"]
        item["wave_source"] = "assigned" if a is not None and a.wave is not None else "suggested"
        # D13: the wave's proposed completion date (NIST IR 8547 / CNSA 2.0 milestones, crypto KB) unless the team set one
        milestone = PQT.wave_milestone(item["wave"]) if item["wave"] else None
        item["proposed_date"] = milestone["date"] if milestone else None
    return items


def target_fields(asset_type: Any, algorithm: Any, facts: Any, primitive: Any = None) -> dict[str, Any]:
    """The asset's NIST post-quantum target (``pqc_targets``), as every surface prints it."""
    t = PQT.asset_target(asset_type, algorithm, facts, primitive)
    return {"pq_usage": t["usage"] if t else None, "pq_target": t["target_text"] if t else None,
            "pq_target_cnsa": t["cnsa_target"] if t else None, "pq_reference": t["reference"] if t else None}


# ----------------------------------------------------------------------------- node runs
def node_items(session: Session, team_id: int, run: CbomCollectionRun, *,
               asset_ids: Iterable[int] | None = None) -> list[dict[str, Any]]:
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
        })
    return _with_assignment(items, _assignments(session, team_id, (i["asset_key"] for i in items)))


# ----------------------------------------------------------------------------- code scans
def code_items(session: Session, team_id: int, scan: Scan) -> list[dict[str, Any]]:
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
                                         row.get("primitive") or row.get("algorithm_type"))}
        else:  # the same asset on several lines: one plan
            item["finding_codes"] = sorted(set(item["finding_codes"]) | set(codes))
            item["quantum_vulnerable"] = item["quantum_vulnerable"] or qv
    items = list(seen.values())
    for item in items:
        item["suggested_wave"] = suggested_wave(item["impact"], item["finding_codes"], item["quantum_vulnerable"])
    return _with_assignment(items, _assignments(session, team_id, (i["asset_key"] for i in items)))


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

    assignments = {a.asset_key: public_assignment(a) for a in session.exec(select(CbomRemediationAssignment).where(
        CbomRemediationAssignment.team_id == team_id).limit(50_000)).all()}
    code_plans: dict[str, Any] = {}
    for asset in (getattr(view, "assets", None) or ())[:50_000]:
        if not asset.current or asset.source_key.startswith("sources:"):  # Sources assets: node_rows below
            continue
        code_plans[plan_key(asset)] = {
            "assigned": assignments.get(code_asset_key(asset)) or {},
            "suggested": suggested_wave(asset.impact, asset.finding_codes, asset.quantum_vulnerable)}
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
        for item in node_items(session, team_id, run, asset_ids=ids):
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
            "node_rows_omitted": max(len(node_rows) - ROADMAP_NODE_CAP, 0)}


__all__ = ["AssignmentBulk", "STATUSES", "WAVES", "WAVE_LABEL", "WAVE_RULE", "WAVE_RULES", "WaveRule", "code_asset_key",
           "code_items", "node_items", "matching_rule", "roadmap_extras", "suggested_wave", "upsert"]
