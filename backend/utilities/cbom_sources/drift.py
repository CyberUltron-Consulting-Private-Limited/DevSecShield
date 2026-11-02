"""Diff, drift and proof that fixes landed: one comparison for collection runs and for code scans.

Rules (WP10 / plan C2):

* Only COMPLETE collections are compared: a collect job that succeeded with outcome ``ok``. A partial, failed,
  cancelled or truncated job is "not compared" with its reason, never a list of removals.
* Identity is stable (``identity``): source uid + asset key; certificates by (target, location, subject, issuer), so a
  renewal is "changed (renewed)"; code-scan rows by a line-independent key within ``repository@branch``.
* Version-aware: a run records the knowledge-base and classifier versions that judged it. When the two sides differ,
  both sides are RE-CLASSIFIED with the current rules (the classifier is deterministic and every input is stored), so
  the lists show what changed in the estate; what changed only because a rule changed is listed apart as
  ``rule_changes`` ("rule change"). Code scans cannot be re-judged (the engine ran in the worker), so a different
  engine version labels every finding change "rule change possible".
* A finding (identity + code) missing from a later complete collection of the same source is RESOLVED in that run or
  scan. The drift events are the one record of it: the run's "Changes", the integrations, and for code scans the
  Mongo finding status and the Jira close-on-fixed (``finding_state.mark_finding_fixed``, shared with the manual
  "fixed" toggle) all read the same comparison.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomDriftEvent,
    Scan,
)
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources.cbom_metrics import code_row_quantum_vulnerable, quantum_readiness_pct
from backend.utilities.cbom_sources.cbom_rows import display_row, is_finding
from backend.utilities.cbom_sources.common import iso_z, log

LIST_CAP = 500  # per list in an API diff
EVENT_CAP = 5_000  # drift events recorded per run or scan
EXPIRING_DAYS = 30
FINISHED = ("done", "partial", "failed", "cancelled")
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_FIELDS = ("algorithm", "key_size", "protocol", "impact", "quantum_vulnerable", "fingerprint", "not_after")
EVENT_KINDS = ("opened", "resolved", "new_asset", "removed_asset", "cert_renewed", "cert_expiring",
               "schedule_skipped")


@dataclass
class View:
    identity: str
    key: str
    label: str
    asset_type: str
    codes: frozenset[str]
    impact: str | None
    quantum_vulnerable: bool | None
    finding: bool
    judged: bool  # has a quantum verdict (readiness denominator)
    algorithm: str | None = None
    key_size: Any = None
    protocol: str | None = None
    fingerprint: str | None = None
    not_after: str | None = None
    certificate: bool = False
    asset_id: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"key": self.key, "label": self.label, "type": self.asset_type, "impact": self.impact,
                "finding_codes": sorted(self.codes), "quantum_vulnerable": self.quantum_vulnerable,
                "asset_id": self.asset_id, **self.extra}


def _worse(a: str | None, b: str | None) -> str | None:
    return min((x for x in (a, b) if x), key=lambda x: _IMPACT_RANK.get(x, 9), default=None)


def _merge(table: dict[str, View], view: View) -> None:
    old = table.get(view.identity)
    if old is None:
        table[view.identity] = view
        return
    old.codes = old.codes | view.codes
    old.impact = _worse(old.impact, view.impact)
    old.finding = old.finding or view.finding
    if old.quantum_vulnerable is not True and view.quantum_vulnerable is not None:
        old.quantum_vulnerable = view.quantum_vulnerable if old.quantum_vulnerable is None else (
            old.quantum_vulnerable or view.quantum_vulnerable)
    old.judged = old.judged or view.judged
    old.extra["occurrences"] = int(old.extra.get("occurrences", 1)) + int(view.extra.get("occurrences", 1))


# ----------------------------------------------------------------------------- views
def node_views(rows: Iterable[CbomCollectedAsset], source_ref: str, *, reclassify: bool) -> dict[str, View]:
    """Views of one collect job's assets; ``reclassify`` re-judges them with the current classifier (as of each
    asset's own collection time, so certificate expiry is still "as of the run")."""
    from backend.utilities.cbom_sources.classify import classify
    from backend.utilities.cbom_sources.posture import pqc_class

    out: dict[str, View] = {}
    for row in rows:
        if row.asset_type == "coverage":
            continue
        codes, impact, qv = list(row.finding_codes or []), row.impact, row.quantum_vulnerable
        if reclassify:
            try:
                verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts or {},
                                   row.created_at)
                codes, impact, qv = verdict["finding_codes"], verdict["impact"], verdict["quantum_vulnerable"]
            except Exception:  # an asset the current rules cannot read keeps its stored verdict
                pass
        clean = frozenset(c for c in codes if isinstance(c, str) and c and not c.startswith("COVERAGE_"))
        facts = row.facts or {}
        ident = ID.node_identity(row)
        cls = pqc_class(row.asset_type, qv, sorted(clean), facts)
        cert = ID.is_certificate(row)
        _merge(out, View(
            identity=ident, key=ID.stable_key("node", source_ref, ident), label=ID.node_label(row),
            asset_type=row.asset_type, codes=clean, impact=impact if clean or impact else None,
            quantum_vulnerable=qv, finding=bool(clean), judged=cls != "not-applicable",
            algorithm=row.algorithm, key_size=row.key_size, protocol=row.protocol,
            fingerprint=(str(facts.get("fingerprint_sha256")) if cert and facts.get("fingerprint_sha256") else None),
            not_after=(str(facts.get("not_after")) if cert and facts.get("not_after") else None),
            certificate=cert, asset_id=row.id,
            extra={"target": row.target, "location": row.location, "pqc_class": cls},
        ))
    return out


def code_views(rows: Iterable[Any], source_ref: str) -> dict[str, View]:
    out: dict[str, View] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = display_row(raw)
        finding = is_finding(row)
        if "finding_codes" in row:
            codes = frozenset(c for c in row.get("finding_codes") or [] if isinstance(c, str) and c)
        else:
            codes = frozenset({"FINDING"}) if finding else frozenset()  # legacy rows: one finding, no code
        if finding and not codes:
            codes = frozenset({"WEAK_OR_QUANTUM_VULNERABLE"})
        qv = code_row_quantum_vulnerable(row)
        ident = ID.code_identity(row)
        cert = str(row.get("asset_type") or row.get("algorithm_type") or "") == "certificate"
        _merge(out, View(
            identity=ident, key=ID.stable_key("code", source_ref, ident), label=ID.code_label(row),
            asset_type=str(row.get("asset_type") or row.get("algorithm_type") or "other"), codes=codes,
            impact=(str(row.get("impact") or "Low") if finding else None), quantum_vulnerable=qv, finding=finding,
            judged=qv is not None, algorithm=row.get("algorithm_name") or row.get("title"),
            key_size=row.get("key_size"), protocol=row.get("protocol_version"),
            not_after=(str(row.get("not_valid_after")) if cert and row.get("not_valid_after") else None),
            certificate=cert,
            extra={"location": row.get("location"), "bom_ref": row.get("bom_ref"),
                   "occurrences": int(row.get("occurrence_count") or 1)},
        ))
    return out


def readiness(views: Mapping[str, View]) -> float | None:
    judged = [v for v in views.values() if v.judged]
    return quantum_readiness_pct(sum(1 for v in judged if v.quantum_vulnerable is True), len(judged))


# ----------------------------------------------------------------------------- compare
def compare(before: Mapping[str, View], after: Mapping[str, View]) -> dict[str, list[dict[str, Any]]]:
    """added / removed / changed assets and opened / resolved findings (identity + code)."""
    added = [after[i] for i in sorted(after) if i not in before]
    removed = [before[i] for i in sorted(before) if i not in after]
    changed: list[dict[str, Any]] = []
    opened: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    for ident in sorted(before.keys() & after.keys()):
        b, a = before[ident], after[ident]
        fields = {f: [getattr(b, f), getattr(a, f)] for f in _FIELDS if getattr(b, f) != getattr(a, f)}
        if b.codes != a.codes:
            fields["finding_codes"] = [sorted(b.codes), sorted(a.codes)]
        renewed = a.certificate and bool(
            (b.fingerprint and a.fingerprint and b.fingerprint != a.fingerprint)
            or (b.not_after and a.not_after and a.not_after > b.not_after))
        if fields:
            changed.append({**a.public(), "changes": fields, "renewed": renewed})
        for code in sorted(a.codes - b.codes):
            opened.append({**a.public(), "code": code})
        for code in sorted(b.codes - a.codes):
            resolved.append({**b.public(), "code": code, "asset_removed": False})
    for view in added:
        for code in sorted(view.codes):
            opened.append({**view.public(), "code": code, "new_asset": True})
    for view in removed:
        for code in sorted(view.codes):
            resolved.append({**view.public(), "code": code, "asset_removed": True})
    return {"added": [v.public() for v in added], "removed": [v.public() for v in removed], "changed": changed,
            "opened": opened, "resolved": resolved}


def _finding_pairs(diff: Mapping[str, list[dict[str, Any]]]) -> set[tuple[str, str, str]]:
    return ({("opened", d["key"], d["code"]) for d in diff["opened"]}
            | {("resolved", d["key"], d["code"]) for d in diff["resolved"]})


def rule_only_changes(stored: Mapping[str, list[dict[str, Any]]], current: Mapping[str, list[dict[str, Any]]]
                      ) -> list[dict[str, Any]]:
    """Finding changes that appear with the verdicts as stored but not when both sides are judged by the current
    rules (or the other way round): a rule changed, the estate did not."""
    s, c = _finding_pairs(stored), _finding_pairs(current)
    lookup = {(k, d["key"], d["code"]): d for k in ("opened", "resolved") for d in stored[k]}
    lookup.update({(k, d["key"], d["code"]): d for k in ("opened", "resolved") for d in current[k]})
    out = []
    for item in sorted(s ^ c):
        d = lookup[item]
        out.append({"key": d["key"], "label": d["label"], "code": d["code"], "direction": item[0],
                    "label_change": "rule change",
                    "seen_with": "stored verdicts" if item in s else "current rules"})
    return out


def _cap(items: list[Any]) -> tuple[list[Any], bool]:
    return items[:LIST_CAP], len(items) > LIST_CAP


# ----------------------------------------------------------------------------- collection runs
def job_comparable(job: CbomCollectionJob) -> tuple[bool, str | None]:
    if job.kind != "collect":
        return False, "not a collection job"
    if job.status != "success":
        return False, f"collection {job.status}"
    if (job.result or {}).get("truncated"):
        return False, "collection truncated at the asset limit"
    if job.outcome != "ok":
        return False, f"collection {job.outcome or 'incomplete'} (some targets were not read)"
    return True, None


def _versions(run: CbomCollectionRun | None) -> dict[str, Any]:
    if run is None:
        return {}
    return {"kb_version": run.kb_version, "classifier_version": run.classifier_version,
            "engine_version": run.engine_version}


def rules_differ(a: CbomCollectionRun | None, b: CbomCollectionRun | None) -> bool:
    """The knowledge base or the classifier that judged the two runs differ (unknown counts as different)."""
    va, vb = _versions(a), _versions(b)
    return any(va.get(k) is None or va.get(k) != vb.get(k) for k in ("kb_version", "classifier_version"))


def _job_assets(session: Session, job: CbomCollectionJob) -> list[CbomCollectedAsset]:
    return list(session.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == job.team_id, CbomCollectedAsset.job_id == job.id,
        CbomCollectedAsset.attempt == job.attempts)).all())


def _run_jobs(session: Session, run: CbomCollectionRun) -> list[CbomCollectionJob]:
    return list(session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == run.team_id, CbomCollectionJob.run_id == run.id,
        CbomCollectionJob.kind == "collect").order_by(CbomCollectionJob.id)).all())


def _sources(session: Session, team_id: int) -> dict[int, CbomCollectionSource]:
    return {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}


def previous_comparable_run(session: Session, run: CbomCollectionRun) -> CbomCollectionRun | None:
    """The newest earlier run of the team with a complete collection of at least one source this run collected
    completely."""
    sources = _sources(session, run.team_id)
    mine = {ID.job_source_ref(j, sources.get(j.source_id or 0)) for j in _run_jobs(session, run)
            if job_comparable(j)[0]}
    if not mine:
        return None
    earlier = session.exec(select(CbomCollectionRun).where(
        CbomCollectionRun.team_id == run.team_id, CbomCollectionRun.id < run.id)
        .order_by(CbomCollectionRun.id.desc()).limit(50)).all()  # type: ignore[union-attr]
    for other in earlier:
        refs = {ID.job_source_ref(j, sources.get(j.source_id or 0)) for j in _run_jobs(session, other)
                if job_comparable(j)[0]}
        if refs & mine:
            return other
    return None


def run_diff(session: Session, run: CbomCollectionRun, base: CbomCollectionRun) -> dict[str, Any]:
    """Compare ``base`` (before) with ``run`` (after), source by source; only sources complete in both are compared."""
    sources = _sources(session, run.team_id)
    reclassify = rules_differ(base, run)
    sides: dict[str, dict[str, CbomCollectionJob]] = {"before": {}, "after": {}}
    names: dict[str, str] = {}
    for side, which in (("before", base), ("after", run)):
        for job in _run_jobs(session, which):
            src = sources.get(job.source_id or 0)
            ref = ID.job_source_ref(job, src)
            names.setdefault(ref, ID.job_source_name(job, src))
            sides[side][ref] = job
    per_source: list[dict[str, Any]] = []
    totals: dict[str, list[Any]] = {k: [] for k in ("added", "removed", "changed", "opened", "resolved")}
    rule_changes: list[dict[str, Any]] = []
    before_all: dict[str, View] = {}
    after_all: dict[str, View] = {}
    for ref in sorted(set(sides["before"]) | set(sides["after"]), key=lambda r: names.get(r, r)):
        b_job, a_job = sides["before"].get(ref), sides["after"].get(ref)
        entry: dict[str, Any] = {"source_ref": ref, "name": names.get(ref), "status": "not_compared", "reason": None}
        if b_job is None or a_job is None:
            entry["reason"] = f"not collected in run #{(base if b_job is None else run).id}"
            per_source.append(entry)
            continue
        ok_b, why_b = job_comparable(b_job)
        ok_a, why_a = job_comparable(a_job)
        if not (ok_b and ok_a):
            entry["reason"] = (f"run #{base.id}: {why_b}" if not ok_b else f"run #{run.id}: {why_a}")
            per_source.append(entry)
            continue
        b_rows, a_rows = _job_assets(session, b_job), _job_assets(session, a_job)
        before = node_views(b_rows, ref, reclassify=reclassify)
        after = node_views(a_rows, ref, reclassify=reclassify)
        diff = compare(before, after)
        if reclassify:
            stored = compare(node_views(b_rows, ref, reclassify=False), node_views(a_rows, ref, reclassify=False))
            rule_changes += [{**r, "source_name": names.get(ref)} for r in rule_only_changes(stored, diff)]
        for k in totals:
            totals[k] += [{**d, "source_name": names.get(ref)} for d in diff[k]]
        before_all.update({f"{ref}|{i}": v for i, v in before.items()})
        after_all.update({f"{ref}|{i}": v for i, v in after.items()})
        entry.update(status="compared", reason=None, counts={k: len(v) for k, v in diff.items()},
                     before_job_id=b_job.id, after_job_id=a_job.id)
        per_source.append(entry)
    out: dict[str, Any] = {"run_id": run.id, "against_run_id": base.id,
                           "versions": {"before": _versions(base), "after": _versions(run),
                                        "rules_changed": reclassify, "reclassified": reclassify},
                           "sources": per_source}
    truncated = False
    for k, items in totals.items():
        out[k], cut = _cap(items)
        truncated = truncated or cut
    out["rule_changes"], cut = _cap(rule_changes)
    out["counts"] = {**{k: len(v) for k, v in totals.items()}, "rule_changes": len(rule_changes),
                     "compared_sources": sum(1 for s in per_source if s["status"] == "compared"),
                     "not_compared_sources": sum(1 for s in per_source if s["status"] != "compared")}
    rb, ra = readiness(before_all), readiness(after_all)
    out["readiness"] = {"before": rb, "after": ra,
                        "delta": None if rb is None or ra is None else round(ra - rb, 1),
                        "scope": "compared sources only"}
    out["truncated"] = truncated or cut
    return out


# ----------------------------------------------------------------------------- events
def dedupe(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()


def insert_events(session: Session, rows: list[dict[str, Any]]) -> int:
    """INSERT ... ON CONFLICT (team_id, dedupe_key) DO NOTHING: recording the same change twice stores it once."""
    if not rows:
        return 0
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    total = 0
    for start in range(0, len(rows), 500):
        stmt = dialect_insert(CbomDriftEvent.__table__).values(rows[start:start + 500]).on_conflict_do_nothing(
            index_elements=["team_id", "dedupe_key"])
        total += int(session.exec(stmt).rowcount or 0)  # type: ignore[call-overload]
    return total


def _event(team_id: int, now: _dt.datetime, kind: str, item: Mapping[str, Any] | None, *, scope: str,
           source_ref: str, source_name: str | None, key_parts: tuple[Any, ...], **links: Any) -> dict[str, Any]:
    item = item or {}
    detail = {k: v for k, v in item.items() if k in ("finding_codes", "type", "location", "target", "changes",
                                                       "asset_removed", "new_asset", "not_after", "asset_id",
                                                       "bom_ref", "rule_change", "reason", "cause")}
    return {"team_id": team_id, "at": now, "scope": scope, "kind": kind,
            "run_id": links.get("run_id"), "baseline_run_id": links.get("baseline_run_id"),
            "scan_id": links.get("scan_id"), "baseline_scan_id": links.get("baseline_scan_id"),
            "source_ref": (source_ref or "")[:255], "source_name": (source_name or None) and source_name[:255],
            "asset_key": item.get("key"), "asset_label": (item.get("label") or None) and str(item["label"])[:255],
            "code": (item.get("code") or None) and str(item["code"])[:48], "severity": item.get("impact"),
            "detail": detail, "dedupe_key": dedupe(scope, *key_parts), "forwarded_at": None}


def diff_events(team_id: int, now: _dt.datetime, diff: Mapping[str, list[dict[str, Any]]], *, scope: str,
                source_ref: str, source_name: str | None, anchor: str, cause: str | None = None,
                **links: Any) -> list[dict[str, Any]]:
    """Events for one source's comparison. ``anchor`` ("run:12" / "scan:40") makes them idempotent per run."""
    out: list[dict[str, Any]] = []

    def add(kind: str, item: Mapping[str, Any], *extra: Any) -> None:
        payload = {**item, "cause": cause} if cause else dict(item)
        out.append(_event(team_id, now, kind, payload, scope=scope, source_ref=source_ref, source_name=source_name,
                          key_parts=(anchor, kind, item.get("key"), *extra), **links))

    for item in diff["added"]:
        add("new_asset", item)
    for item in diff["removed"]:
        add("removed_asset", item)
    for item in diff["changed"]:
        if item.get("renewed"):
            add("cert_renewed", item)
    for item in diff["opened"]:
        add("opened", item, item["code"])
    for item in diff["resolved"]:
        add("resolved", item, item["code"])
    return out


def _expiring(team_id: int, now: _dt.datetime, views: Mapping[str, View], *, scope: str, source_ref: str,
              source_name: str | None, **links: Any) -> list[dict[str, Any]]:
    """Certificates that expire within EXPIRING_DAYS: once per certificate and expiry date (not once per run)."""
    out = []
    horizon = now + _dt.timedelta(days=EXPIRING_DAYS)
    for view in views.values():
        when = parse_time(view.not_after)
        if not view.certificate or when is None or not (now <= when <= horizon):
            continue
        item = {**view.public(), "not_after": view.not_after}
        out.append(_event(team_id, now, "cert_expiring", item, scope=scope, source_ref=source_ref,
                          source_name=source_name, key_parts=("expiring", view.key, view.not_after), **links))
    return out


def parse_time(value: Any) -> _dt.datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        moment = _dt.datetime.fromisoformat(text)
    except ValueError:
        try:
            moment = _dt.datetime.strptime(str(value).strip(), "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return moment


def _baseline_job(session: Session, job: CbomCollectionJob, ref: str,
                  sources: Mapping[int, CbomCollectionSource]) -> CbomCollectionJob | None:
    if job.source_id is None:
        return None
    for other in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == job.team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.source_id == job.source_id, CbomCollectionJob.status == "success",
            CbomCollectionJob.id < job.id).order_by(CbomCollectionJob.id.desc()).limit(20)).all():  # type: ignore[union-attr]
        if job_comparable(other)[0] and ID.job_source_ref(other, sources.get(other.source_id or 0)) == ref:
            return other
    return None


def record_run_drift(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> int | None:
    """Record the drift events of a FINISHED run, once (``drift_at`` compare-and-set). The caller commits.
    Returns events stored, or None when the run is not finished or another caller recorded it."""
    if run.status not in FINISHED or run.finished_at is None or run.drift_at is not None:
        return None
    won = session.exec(update(CbomCollectionRun).where(
        CbomCollectionRun.id == run.id, CbomCollectionRun.drift_at.is_(None))  # type: ignore[union-attr]
        .values(drift_at=now)).rowcount == 1
    if not won:
        return None
    sources = _sources(session, run.team_id)
    rows: list[dict[str, Any]] = []
    for job in _run_jobs(session, run):
        if not job_comparable(job)[0]:
            continue
        src = sources.get(job.source_id or 0)
        ref, name = ID.job_source_ref(job, src), ID.job_source_name(job, src)
        base = _baseline_job(session, job, ref, sources)
        base_run = session.get(CbomCollectionRun, base.run_id) if base is not None and base.run_id else None
        reclassify = base is not None and rules_differ(base_run, run)
        a_rows = _job_assets(session, job)
        after = node_views(a_rows, ref, reclassify=reclassify)
        rows += _expiring(run.team_id, now, after, scope="node", source_ref=ref, source_name=name, run_id=run.id)
        if base is None:
            continue
        diff = compare(node_views(_job_assets(session, base), ref, reclassify=reclassify), after)
        rows += diff_events(run.team_id, now, diff, scope="node", source_ref=ref, source_name=name,
                            anchor=f"run:{run.id}", cause="re-judged with the current rules" if reclassify else None,
                            run_id=run.id, baseline_run_id=base.run_id)
    stored = insert_events(session, rows[:EVENT_CAP])
    log("drift recorded", team=run.team_id, run=run.id, events=stored, truncated=len(rows) > EVENT_CAP or None)
    return stored


def record_pending_drift(engine, now: _dt.datetime, *, limit: int = 20) -> int:
    """Scheduler tick: record drift for finished runs that have none yet (each in its own transaction)."""
    with Session(engine) as session:
        ids = session.exec(select(CbomCollectionRun.id).where(
            CbomCollectionRun.drift_at.is_(None), CbomCollectionRun.finished_at.is_not(None),  # type: ignore[union-attr]
            CbomCollectionRun.status.in_(FINISHED)).order_by(CbomCollectionRun.id).limit(limit)).all()  # type: ignore[attr-defined]
    done = 0
    for run_id in ids:
        with Session(engine) as session:
            try:
                run = session.get(CbomCollectionRun, run_id)
                if run is not None and record_run_drift(session, run, now) is not None:
                    done += 1
                session.commit()
            except Exception as exc:
                session.rollback()
                log("drift FAILED", run=run_id, error=type(exc).__name__)
    return done


def public_event(e: CbomDriftEvent) -> dict[str, Any]:
    return {"id": e.id, "at": iso_z(e.at), "scope": e.scope, "kind": e.kind, "run_id": e.run_id,
            "baseline_run_id": e.baseline_run_id, "scan_id": e.scan_id, "baseline_scan_id": e.baseline_scan_id,
            "source_ref": e.source_ref, "source_name": e.source_name, "asset_key": e.asset_key,
            "asset_label": e.asset_label, "code": e.code, "severity": e.severity, "detail": e.detail or {}}


# ----------------------------------------------------------------------------- code scans
def _code_rows(scan: Scan) -> list[Any]:
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    rows = data.get("results")
    return rows if isinstance(rows, list) else []


def _tool_version(scan: Scan) -> str | None:
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    meta = ((data.get("cbom_json") or {}).get("metadata") or {}) if isinstance(data.get("cbom_json"), dict) else {}
    tools = meta.get("tools")
    items = tools.get("components") if isinstance(tools, dict) else tools
    if isinstance(items, list) and items and isinstance(items[0], dict):
        return f"{items[0].get('name')}@{items[0].get('version')}"
    return None


def code_source(scan: Scan) -> tuple[str, str]:
    return ID.code_source_ref(scan.scan_metadata, scan.title, scan.id or 0)


def previous_code_scan(session: Session, scan: Scan) -> Scan | None:
    """The newest earlier successful CBOM scan of the same repository and branch (or the same zip / file title).
    Scans with no stable source (``scan:<id>``) have no previous scan."""
    key, _label = code_source(scan)
    if key.startswith("scan:"):
        return None
    heads = session.exec(select(Scan.id, Scan.scan_metadata, Scan.title).where(
        Scan.team_id == scan.team_id, Scan.scan_type == "cbom", Scan.scan_status == "success",
        Scan.id != scan.id, Scan.created_at <= scan.created_at)
        .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(200)).all()  # type: ignore[union-attr]
    for scan_id, meta, title in heads:
        if ID.code_source_ref(meta, title, scan_id)[0] == key:
            return session.get(Scan, scan_id)
    return None


def code_scan_diff(scan: Scan, base: Scan) -> dict[str, Any]:
    key, label = code_source(scan)
    before, after = code_views(_code_rows(base), key), code_views(_code_rows(scan), key)
    diff = compare(before, after)
    tb, ta = _tool_version(base), _tool_version(scan)
    rules_changed = tb != ta
    if rules_changed:
        for k in ("opened", "resolved"):
            for item in diff[k]:
                item["rule_change"] = "possible: the scans were made by different engine versions"
    out: dict[str, Any] = {"scan_id": scan.id, "against_scan_id": base.id, "source": label, "source_ref": key,
                           "versions": {"before": tb, "after": ta, "rules_changed": rules_changed,
                                        "reclassified": False}}
    truncated = False
    for k, items in diff.items():
        out[k], cut = _cap(items)
        truncated = truncated or cut
    rb, ra = readiness(before), readiness(after)
    out["counts"] = {k: len(v) for k, v in diff.items()}
    out["readiness"] = {"before": rb, "after": ra, "delta": None if rb is None or ra is None else round(ra - rb, 1)}
    out["truncated"] = truncated
    out["_views"] = (before, after)
    return out


def record_code_scan_drift(session: Session, scan: Scan, now: _dt.datetime) -> tuple[dict[str, Any] | None, int]:
    """Events for a successful code scan against the previous scan of the same source. The caller commits."""
    base = previous_code_scan(session, scan)
    if base is None:
        return None, 0
    diff = code_scan_diff(scan, base)
    key, label = code_source(scan)
    before, after = diff["_views"]
    full = compare(before, after)
    rows = diff_events(scan.team_id, now, full, scope="code", source_ref=key, source_name=label,
                       anchor=f"scan:{scan.id}", cause=("engine version changed" if diff["versions"]["rules_changed"]
                                                        else None),
                       scan_id=scan.id, baseline_scan_id=base.id)
    rows += _expiring(scan.team_id, now, after, scope="code", source_ref=key, source_name=label, scan_id=scan.id)
    return diff, insert_events(session, rows[:EVENT_CAP])


def fixed_identities(diff: Mapping[str, Any]) -> set[str]:
    """Identities whose every finding was resolved: the asset is gone, or still listed but no longer a finding."""
    before, after = diff["_views"]
    return {ident for ident, view in before.items()
            if view.finding and (ident not in after or not after[ident].finding)}


def on_code_scan_success(scan_id: int, engine, now: _dt.datetime | None = None) -> dict[str, int]:
    """After a CBOM code scan's results were ingested (once): drift events, and the previous scan's findings that are
    gone marked fixed in Mongo with their Jira tickets closed (the same helper as the manual "fixed" toggle)."""
    from backend.utilities.cbom_sources.common import utcnow

    now = now or utcnow()
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.scan_type != "cbom" or scan.scan_status != "success":
            return {"events": 0, "fixed": 0}
        diff, stored = record_code_scan_drift(session, scan, now)
        session.commit()
        if diff is None:
            return {"events": 0, "fixed": 0}
        gone = fixed_identities(diff)
        base_id, team_id = diff["against_scan_id"], scan.team_id
    fixed = 0
    if gone:
        from backend.utilities.db.finding_state import mark_code_findings_fixed

        fixed = mark_code_findings_fixed(engine, team_id=team_id, scan_id=base_id, identities=gone,
                                         resolved_in_scan=scan_id, now=now)
    log("code drift recorded", team=team_id, scan=scan_id, against=base_id, events=stored, fixed=fixed)
    return {"events": stored, "fixed": fixed}
