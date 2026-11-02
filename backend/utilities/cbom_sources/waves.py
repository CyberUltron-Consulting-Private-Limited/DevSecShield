"""Remediation waves with owners: a suggested wave per asset, the team's assignments, and the roadmap's rows.

Suggested wave (the user may override it per asset):
  1. Critical / High with internet exposure, or harvest-now-decrypt-later (quantum-vulnerable key exchange in transit)
  2. other Critical / High
  3. Medium and Low findings
  4. quantum-vulnerable inventory with no other weakness (plan the post-quantum migration)
  none: clean inventory (nothing to remediate)

Assignments (``CbomRemediationAssignment``) are keyed by the asset's STABLE identity (``identity.stable_key``), never by
a row id or inside ``scan_data``, so a plan made on one run still applies to the same asset in every later run or scan.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Iterable, Literal

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
from backend.utilities.cbom_sources.cbom_metrics import code_row_quantum_vulnerable
from backend.utilities.cbom_sources.cbom_rows import display_row, is_finding
from backend.utilities.cbom_sources.common import iso_z

WAVES = (1, 2, 3, 4)
STATUSES = ("open", "in_progress", "done", "accepted_risk")
WAVE_LABEL = {1: "Wave 1: urgent (exposed or HNDL)", 2: "Wave 2: high", 3: "Wave 3: medium and low",
              4: "Wave 4: post-quantum migration"}
MAX_ITEMS = 2_000  # per bulk request
ROADMAP_NODE_CAP = 2_000
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def suggested_wave(impact: str | None, codes: Iterable[str], quantum_vulnerable: bool | None, *,
                   internet: bool = False, hndl: bool = False) -> int | None:
    weakness = [c for c in codes if c and c != "QUANTUM_VULNERABLE" and not c.startswith("COVERAGE_")]
    severe = impact in ("Critical", "High")
    if weakness and severe and (internet or hndl):
        return 1
    if hndl and quantum_vulnerable:
        return 1
    if weakness and severe:
        return 2
    if weakness:
        return 3
    if quantum_vulnerable:
        return 4
    return None


def public_assignment(a: CbomRemediationAssignment | None) -> dict[str, Any] | None:
    if a is None:
        return None
    return {"wave": a.wave, "owner": a.owner, "target_date": a.target_date, "status": a.status, "note": a.note,
            "row_version": a.row_version, "last_updated": iso_z(a.last_updated)}


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
    return items


# ----------------------------------------------------------------------------- node runs
def node_items(session: Session, team_id: int, run: CbomCollectionRun, *,
               asset_ids: Iterable[int] | None = None) -> list[dict[str, Any]]:
    from backend.utilities.cbom_sources.posture import asset_exposure, hndl, job_metadata

    jobs = {j.id: j for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.run_id == run.id)).all()}
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    query = select(CbomCollectedAsset).where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id)
    if asset_ids is not None:
        query = query.where(CbomCollectedAsset.id.in_(list(asset_ids)))  # type: ignore[union-attr]
    items = []
    for row in session.exec(query.order_by(CbomCollectedAsset.id)).all():
        if row.asset_type == "coverage":
            continue
        job = jobs.get(row.job_id)
        src = sources.get((job.source_id if job else None) or 0)
        ref = ID.job_source_ref(job, src) if job else f"source-{row.source_id}"
        meta = job_metadata(job.params if job else None, src, nodes.get((job.node_id if job else None) or 0))
        exposure, _basis = asset_exposure(row.facts, row.target, row.location, override=meta["exposure"],
                                          node_segment=meta["segment"])
        codes = [c for c in row.finding_codes or [] if isinstance(c, str)]
        in_transit = hndl(row.asset_type, row.quantum_vulnerable)
        snap = (job.params or {}).get("metadata") if job else None
        owner = (snap.get("owner") if isinstance(snap, dict) else None) or ((src.config or {}).get("owner") if src else None)
        items.append({
            "asset_id": row.id, "asset_key": ID.stable_key("node", ref, ID.node_identity(row)), "scope": "node",
            "source_ref": ref, "source_name": ID.job_source_name(job, src) if job else None,
            "label": ID.node_label(row), "type": row.asset_type, "impact": row.impact, "finding_codes": codes,
            "quantum_vulnerable": row.quantum_vulnerable, "exposure": exposure, "hndl": in_transit,
            "owner_hint": owner,
            "suggested_wave": suggested_wave(row.impact, codes, row.quantum_vulnerable,
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
        key = ID.stable_key("code", ref, ID.code_identity(row))
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
                         "owner_hint": row.get("owner") or row.get("owner_hint")}
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
        for key, value in fields.items():
            setattr(row, key, value if key != "status" or value is not None else "open")
        row.label = str(info.get("label") or "")[:255] or None
        row.updated_by_user_id, row.last_updated = user_id, now
        row.row_version = (row.row_version or 0) + 1 if row.id is not None else 1
        session.add(row)
        changed += 1
    return {"updated": changed}


# ----------------------------------------------------------------------------- roadmap
def code_asset_key(asset: Any) -> str:
    return ID.stable_key("code", asset.source_key, ID.asset_agg_identity(asset))


def roadmap_extras(session: Session, team_id: int, view: Any = None) -> dict[str, Any]:
    """What the PQC roadmap needs beyond the code-scan roll-up: the plan of every current roll-up asset
    (``code_plans``, keyed by ``cbom_team_rollup.plan_key``: assigned fields and the suggested wave), and the
    quantum-vulnerable assets of each source's latest complete collection (scan nodes and the cloud worker)."""
    from backend.utilities.cbom_sources.drift import job_comparable
    from backend.utilities.dashboard.cbom_team_rollup import plan_key

    assignments = {a.asset_key: public_assignment(a) for a in session.exec(select(CbomRemediationAssignment).where(
        CbomRemediationAssignment.team_id == team_id).limit(50_000)).all()}
    code_plans: dict[str, Any] = {}
    for asset in (getattr(view, "assets", None) or ())[:50_000]:
        if not asset.current:
            continue
        code_plans[plan_key(asset)] = {
            "assigned": assignments.get(code_asset_key(asset)) or {},
            "suggested": suggested_wave(asset.impact, asset.finding_codes, asset.quantum_vulnerable)}
    latest: dict[str, CbomCollectionJob] = {}
    for job in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.status == "success").order_by(CbomCollectionJob.id.desc()).limit(2_000)).all():  # type: ignore[union-attr]
        if not job_comparable(job)[0]:
            continue
        ref = ID.job_source_ref(job, session.get(CbomCollectionSource, job.source_id) if job.source_id else None)
        latest.setdefault(ref, job)
    node_rows: list[dict[str, Any]] = []
    runs: dict[int, CbomCollectionRun] = {}
    for ref, job in latest.items():
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
                              "collected_at": iso_z(row.created_at) if row else None})
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    node_rows.sort(key=lambda r: (r["wave"] or 9, order.get(r["impact"] or "", 8), str(r["source_name"]), r["label"]))
    return {"code_plans": code_plans, "node_rows": node_rows[:ROADMAP_NODE_CAP],
            "node_rows_omitted": max(len(node_rows) - ROADMAP_NODE_CAP, 0)}


__all__ = ["AssignmentBulk", "STATUSES", "WAVES", "WAVE_LABEL", "code_asset_key", "code_items", "node_items",
           "roadmap_extras", "suggested_wave", "upsert"]
