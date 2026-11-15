"""The cross-repository roll-up: the same issue in many repositories is ONE finding with a repository count.

Each finding a repository scan stored gets a location-free fingerprint per product:

    sbom_sca  package (dependency) + the sorted CVEs, or the title when there are none
    sast      the normalised title
    iac       the normalised title + category
    cbom      asset type + algorithm (or title) + the sorted finding codes (findings only: cbom_rows.is_finding)
    ai_bom    component + provider + version

``fold_scan`` replaces one repository's occurrences for one product with those of its latest successful scan (so a
fixed issue drops off that repository), then recounts the touched findings; a finding left in no repository gets
``resolved_at`` (and loses it when it comes back). Findings are read from ``Scan.scan_data`` with the same per-type
shapes ``celery/create_findings.py`` writes to Mongo, so the roll-up needs no Mongo round trip. SAST titles come from
a language model and vary between repositories more than package or rule identities do, so SAST de-duplicates less.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections.abc import Iterator
from typing import Any

from sqlalchemy import delete, func
from sqlmodel import Session, select

from backend.utilities.scm.models import ScmFinding, ScmFindingOccurrence

SEVERITIES = ("critical", "high", "medium", "low", "info")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_SPACE = re.compile(r"\s+")
MAX_LOCATIONS = 5


def _norm(value: Any) -> str:
    return _SPACE.sub(" ", str(value or "").strip().lower())


def severity_of(fd: dict[str, Any]) -> str:
    value = _norm(fd.get("impact") or fd.get("severity") or "low")
    return value if value in _RANK else ("info" if value in ("informational", "none") else "low")


def iter_findings(product: str, scan_data: Any) -> Iterator[dict[str, Any]]:
    results = scan_data.get("results") if isinstance(scan_data, dict) else None
    if not isinstance(results, list):
        return
    if product == "sast":
        for item in results:
            if not isinstance(item, dict):
                continue
            for vuln in item.get("vulnerabilities") or []:
                if isinstance(vuln, dict):
                    yield {**vuln, "logical_component_title": item.get("logical_component_title")}
    elif product == "sbom_sca":
        from backend.utilities.celery.sbom_finding_normalize import normalize_sbom_finding_data

        for row in results:
            if isinstance(row, dict):
                yield normalize_sbom_finding_data(row)
    elif product == "cbom":
        from backend.utilities.cbom_sources.cbom_rows import is_finding

        for row in results:
            if isinstance(row, dict) and is_finding(row):
                yield row
    else:
        for row in results:
            if isinstance(row, dict):
                yield row


def describe(product: str, fd: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """(fingerprint, title, key fields) of one finding."""
    title = str(fd.get("title") or "").strip()
    if product == "sbom_sca":
        dep = str(fd.get("dependency") or "").strip()
        cves = sorted({str(c).upper() for c in (fd.get("cves") or []) if c})
        key = ["sbom_sca", _norm(dep), ",".join(cves) if cves else _norm(title)]
        shown = f"{title} ({dep})" if dep and dep not in title else (title or dep or "Untitled finding")
        fields = {"dependency": dep, "cves": cves}
    elif product == "iac":
        key = ["iac", _norm(title), _norm(fd.get("category"))]
        shown, fields = title or "Untitled finding", {"category": fd.get("category")}
    elif product == "cbom":
        algorithm = str(fd.get("algorithm_name") or "").strip()
        codes = sorted({str(c) for c in (fd.get("finding_codes") or []) if c})
        key = ["cbom", _norm(fd.get("asset_type")), _norm(algorithm or title), ",".join(codes)]
        shown = title or algorithm or "Untitled finding"
        fields = {"asset_type": fd.get("asset_type"), "algorithm": algorithm, "finding_codes": codes}
    elif product == "ai_bom":
        from backend.utilities.dashboard.aibom_provider import resolve_aibom_provider

        component = str(fd.get("component_name") or title).strip()
        provider = resolve_aibom_provider(fd)
        key = ["ai_bom", _norm(component), _norm(provider), _norm(fd.get("version"))]
        shown = title or component or "Untitled finding"
        fields = {"component": component, "provider": provider, "version": fd.get("version")}
    else:  # sast
        key = [product, _norm(title)]
        shown, fields = title or "Untitled finding", {"owasp_top_10": list(fd.get("owasp_top_10") or [])[:5]}
    digest = hashlib.sha256("\x1f".join(key).encode("utf-8")).hexdigest()
    return digest, shown[:255], fields


def _location(fd: dict[str, Any]) -> str:
    where = fd.get("location") or fd.get("dependency") or fd.get("resource") or fd.get("logical_component_title") or ""
    return str(where)[:200]


def fold_scan(session: Session, *, team_id: int, repo_id: int, product: str, scan_id: int | None, scan_data: Any,
              now: dt.datetime) -> int:
    """Make this repository's occurrences for ``product`` those of this scan. Returns the number of findings read."""
    grouped: dict[str, dict[str, Any]] = {}
    total = 0
    for fd in iter_findings(product, scan_data):
        total += 1
        fp, title, fields = describe(product, fd)
        entry = grouped.setdefault(fp, {"title": title, "fields": fields, "severity": severity_of(fd), "count": 0,
                                        "locations": []})
        entry["count"] += 1
        if _RANK[severity_of(fd)] < _RANK[entry["severity"]]:
            entry["severity"] = severity_of(fd)
        loc = _location(fd)
        if loc and loc not in entry["locations"] and len(entry["locations"]) < MAX_LOCATIONS:
            entry["locations"].append(loc)

    findings: dict[str, ScmFinding] = {}
    fps = list(grouped)
    for i in range(0, len(fps), 500):
        for row in session.exec(select(ScmFinding).where(ScmFinding.team_id == team_id, ScmFinding.product == product,
                                                         ScmFinding.fingerprint.in_(fps[i:i + 500]))).all():  # type: ignore[union-attr]
            findings[row.fingerprint] = row
    for fp, entry in grouped.items():
        row = findings.get(fp)
        if row is None:
            row = ScmFinding(team_id=team_id, product=product, fingerprint=fp, title=entry["title"],
                             severity=entry["severity"], key_fields=entry["fields"], first_seen_at=now,
                             last_seen_at=now)
            session.add(row)
            findings[fp] = row
        else:
            row.last_seen_at = now
            if _RANK[entry["severity"]] < _RANK.get(row.severity, 9):
                row.severity = entry["severity"]
            session.add(row)
    session.flush()

    previous = session.exec(select(ScmFindingOccurrence).where(ScmFindingOccurrence.repo_id == repo_id,
                                                               ScmFindingOccurrence.product == product)).all()
    touched = {occ.finding_id for occ in previous}
    by_finding = {occ.finding_id: occ for occ in previous}
    keep: set[int] = set()
    for fp, entry in grouped.items():
        fid = findings[fp].id
        keep.add(fid)
        touched.add(fid)
        occ = by_finding.get(fid)
        if occ is None:
            occ = ScmFindingOccurrence(team_id=team_id, finding_id=fid, repo_id=repo_id, product=product)
        occ.scan_id, occ.count, occ.locations, occ.last_seen_at = scan_id, entry["count"], entry["locations"], now
        session.add(occ)
    stale = [occ.id for occ in previous if occ.finding_id not in keep]
    if stale:
        session.exec(delete(ScmFindingOccurrence).where(ScmFindingOccurrence.id.in_(stale)))  # type: ignore[union-attr]
    session.flush()
    _recount(session, touched, now)
    return total


def _recount(session: Session, finding_ids: set[int], now: dt.datetime) -> None:
    ids = sorted(finding_ids)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        counts = {fid: (repos, occurrences or 0) for fid, repos, occurrences in session.exec(
            select(ScmFindingOccurrence.finding_id, func.count(), func.sum(ScmFindingOccurrence.count))
            .where(ScmFindingOccurrence.finding_id.in_(chunk))  # type: ignore[union-attr]
            .group_by(ScmFindingOccurrence.finding_id)).all()}
        for row in session.exec(select(ScmFinding).where(ScmFinding.id.in_(chunk))).all():  # type: ignore[union-attr]
            repos, occurrences = counts.get(row.id, (0, 0))
            row.repo_count, row.occurrence_count = int(repos), int(occurrences)
            row.resolved_at = (row.resolved_at or now) if repos == 0 else None
            session.add(row)


def forget_repo(session: Session, repo_id: int, now: dt.datetime) -> None:
    """Drop a repository from the roll-up (it was removed from the inventory or excluded)."""
    previous = session.exec(select(ScmFindingOccurrence).where(ScmFindingOccurrence.repo_id == repo_id)).all()
    touched = {occ.finding_id for occ in previous}
    for occ in previous:
        session.delete(occ)
    session.flush()
    _recount(session, touched, now)


__all__ = ["SEVERITIES", "describe", "fold_scan", "forget_repo", "iter_findings", "severity_of"]
