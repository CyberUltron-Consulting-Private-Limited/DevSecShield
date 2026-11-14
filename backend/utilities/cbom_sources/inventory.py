"""Read side of collected assets: the paged table, its facets, and the CycloneDX 1.6 export.

The table, the counts on the run and the export are built from the same query over
``cbomcollectedasset`` so they can never disagree.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import uuid
from typing import Any, BinaryIO, Callable, Iterator

from sqlalchemy import and_, func, or_
from sqlmodel import Session, select

from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSettings,
                                 CbomCollectionSource)
from backend.utilities.build_info import build_sha, build_version
from backend.utilities.cbom_sources import agility as AGILITY
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import qgrade as QG
from backend.utilities.cbom_sources.classify import DATED_TYPES, classify, shown
from backend.utilities.cbom_sources.common import iso_z
# CB-06: per-component provenance, PQC class and algorithm families for the export
from backend.utilities.cbom_sources import provenance as PROV
from backend.utilities.cbom_sources.classify import family, quantum_vulnerable
from backend.utilities.cbom_sources.posture import pqc_class
from backend.utilities.cbom_sources import tls_suites

EXPORT_CAP = 50_000
# serialNumber = uuid5(this namespace, "<run id>:<KB version>"): the same run exported with the same knowledge base is
# the same BOM (same serial); a newer KB re-judges the findings, so it is a new serial.
_SERIAL_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/cbom/sources/run")


def export_serial(run_id: int, kb_version: str, judged_on: str | None = None, *, grade_model_version: str | None = None,
                  grade_inputs_digest: str | None = None, agility_version: str | None = None) -> str:
    """``judged_on``: the day a date-based rule (certificate expiry, library end of life) changed a finding since the
    run; the export then differs from the run's own record, so it gets its own serial. The quantum risk grade model
    version and its inputs digest (CB-19 cx3 ST-A) and the agility version (CB-24) are in the key too: an export whose
    grade or fix-class content differs never reuses a serial."""
    key = f"{run_id}:{kb_version}" + (f":{judged_on}" if judged_on else "")
    if grade_model_version is not None or grade_inputs_digest is not None:
        key += f":qg={grade_model_version}:gi={grade_inputs_digest}"
    if agility_version is not None:
        key += f":fx={agility_version}"
    return f"urn:uuid:{uuid.uuid5(_SERIAL_NS, key)}"
_IMPACT_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _now() -> _dt.datetime:
    return _dt.datetime.utcnow()  # naive UTC, as the stored collection times


def changed_today(session: Session, scope, now: _dt.datetime) -> dict[int, dict[str, Any]]:
    """Today's view (``classify.shown``) of every asset in ``scope`` whose date-based rule judges it differently
    than its run did, by asset id. Only certificate and library rows can change, so only they are read."""
    rows = session.exec(scope.where(CbomCollectedAsset.asset_type.in_(sorted(DATED_TYPES)))).all()  # type: ignore[union-attr]
    views = {row.id: shown(row, now) for row in rows}
    return {aid: view for aid, view in views.items() if view["as_of_run"]}


def _filtered(query, *, asset_type: str | None, impact: str | None, quantum: bool | None, text: str | None,
              source_id: int | None, changed: dict[int, dict[str, Any]] | None = None):
    changed = changed or {}
    if asset_type:
        query = query.where(CbomCollectedAsset.asset_type == asset_type)
    if impact:
        stored = (CbomCollectedAsset.impact.is_(None) if impact == "none"  # type: ignore[union-attr]
                  else CbomCollectedAsset.impact == impact)
        if changed:  # a row a date-based rule changed is filtered by today's impact, not the run's
            today = [aid for aid, view in changed.items() if (view["impact"] or "none") == impact]
            stored = and_(stored, CbomCollectedAsset.id.notin_(list(changed)))  # type: ignore[union-attr]
            if today:
                stored = or_(stored, CbomCollectedAsset.id.in_(today))  # type: ignore[union-attr]
        query = query.where(stored)
    if quantum is not None:
        query = query.where(CbomCollectedAsset.quantum_vulnerable == quantum)
    if source_id:
        query = query.where(CbomCollectedAsset.source_id == source_id)
    if text:
        like = f"%{text.lower()}%"
        match = or_(func.lower(CbomCollectedAsset.location).like(like),
                    func.lower(func.coalesce(CbomCollectedAsset.name, "")).like(like),
                    func.lower(func.coalesce(CbomCollectedAsset.finding, "")).like(like),
                    func.lower(func.coalesce(CbomCollectedAsset.algorithm, "")).like(like))
        today = [aid for aid, view in changed.items() if text.lower() in str(view["finding"] or "").lower()]
        query = query.where(or_(match, CbomCollectedAsset.id.in_(today)) if today else match)  # type: ignore[union-attr]
    return query


def public_asset(row: CbomCollectedAsset, source_names: dict[int, str], job_names: dict[int, str] | None = None,
                 view: dict[str, Any] | None = None, grade: dict[str, Any] | None = None) -> dict[str, Any]:
    """One asset as the list shows it: findings judged today (``classify.shown``); ``as_of_run`` holds the run's own
    verdict when a date-based rule changed it since; ``q_grade`` / ``q_label`` / ``q_reason`` / ``q_item_key`` the
    quantum risk grade (``qgrade``; null when the asset has no grade)."""
    view = view or shown(row)
    grade = grade or {}
    return {
        "id": row.id, "type": row.asset_type, "cdx_type": row.cdx_type, "job_id": row.job_id,
        "source_id": row.source_id,
        "source_name": source_names.get(row.source_id or 0) or (job_names or {}).get(row.job_id),
        "target": row.target, "location": row.location, "name": row.name, "algorithm": row.algorithm,
        "key_size": row.key_size, "protocol": row.protocol, "quantum_vulnerable": row.quantum_vulnerable,
        "impact": view["impact"], "finding": view["finding"], "finding_codes": view["finding_codes"],
        "as_of_run": view["as_of_run"],
        "q_grade": grade.get("q_grade"), "q_label": grade.get("q_label"), "q_reason": grade.get("q_reason"),
        "q_item_key": grade.get("q_item_key"),
        "facts": row.facts or {},
    }


def _source_names(session: Session, team_id: int, jobs: list[CbomCollectionJob]) -> dict[int, str]:
    names = {s.id: s.name for s in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all()}
    for job in jobs:  # deleted sources keep their name on the job
        if job.source_id and job.source_id not in names and (job.params or {}).get("source_name"):
            names[job.source_id] = job.params["source_name"]
    return names


def list_assets(session: Session, *, team_id: int, run_id: int | None = None, job_id: int | None = None,
                refine: Any = None,  # (query, changed_today) -> query
                asset_type: str | None = None, impact: str | None = None, quantum: bool | None = None,
                text: str | None = None, source_id: int | None = None, page: int = 1, page_size: int = 50,
                now: _dt.datetime | None = None, risk_model: dict[str, Any] | None = None) -> dict[str, Any]:
    now = now or _now()
    base = select(CbomCollectedAsset).where(CbomCollectedAsset.team_id == team_id)
    if run_id is not None:
        base = base.where(CbomCollectedAsset.run_id == run_id)
    if job_id is not None:
        base = base.where(CbomCollectedAsset.job_id == job_id)
    changed = changed_today(session, base, now)
    filtered = _filtered(base, asset_type=asset_type, impact=impact, quantum=quantum, text=text, source_id=source_id,
                         changed=changed)
    if refine is not None:  # CB-38: a caller's extra filter (run_assets: findings view, status), given today's view
        filtered = refine(filtered, changed)
    total = int(session.exec(select(func.count()).select_from(filtered.subquery())).one())
    rows = session.exec(filtered.order_by(CbomCollectedAsset.id).offset((page - 1) * page_size).limit(page_size)).all()
    views = {row.id: changed.get(row.id) or shown(row, now) for row in rows}
    rows = sorted(rows, key=lambda r: (_IMPACT_ORDER.get(views[r.id]["impact"] or "", 9), r.id or 0))

    # facets are over the whole run/job, not the filtered page, so the filter chips always add up
    scope = select(CbomCollectedAsset.asset_type, CbomCollectedAsset.impact, CbomCollectedAsset.quantum_vulnerable,
                   func.count()).where(CbomCollectedAsset.team_id == team_id)
    if run_id is not None:
        scope = scope.where(CbomCollectedAsset.run_id == run_id)
    if job_id is not None:
        scope = scope.where(CbomCollectedAsset.job_id == job_id)
    by_type: dict[str, int] = {}
    by_impact: dict[str, int] = {}
    quantum_count = 0
    all_total = 0
    for a_type, a_impact, a_qv, count in session.exec(scope.group_by(
            CbomCollectedAsset.asset_type, CbomCollectedAsset.impact, CbomCollectedAsset.quantum_vulnerable)).all():
        all_total += count
        by_type[a_type] = by_type.get(a_type, 0) + count
        by_impact[a_impact or "none"] = by_impact.get(a_impact or "none", 0) + count
        if a_qv:
            quantum_count += count
    for view in changed.values():  # the impact chips count today's verdicts, as the list shows them
        before, after = view["as_of_run"]["impact"] or "none", view["impact"] or "none"
        by_impact[before] = by_impact.get(before, 0) - 1
        by_impact[after] = by_impact.get(after, 0) + 1
    by_impact = {k: v for k, v in by_impact.items() if v > 0}
    jobs = session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id,
        (CbomCollectionJob.run_id == run_id) if run_id is not None else (CbomCollectionJob.id == job_id))).all()
    names = _source_names(session, team_id, list(jobs))
    job_names = {j.id: names.get(j.source_id or 0) or (j.params or {}).get("source_name") for j in jobs}
    grading = QG.load_context(session, team_id=team_id, run_id=run_id, job_id=job_id, risk_model=risk_model)
    grades = {r.id: grading.grade_row(r, views[r.id]["finding_codes"], explain=False).fields() for r in rows}
    return {
        "total": total, "all_total": all_total, "page": page, "page_size": page_size,
        "items": AGILITY.annotate_assets(session, team_id, jobs,  # CB-24: fix class per asset
                                         [public_asset(r, names, job_names, views[r.id], grades[r.id]) for r in rows]),
        "grade_model_version": QG.GRADE_MODEL_VERSION, "grade_inputs": grading.inputs(),
        "facets": {"type": by_type, "impact": by_impact, "quantum_vulnerable": quantum_count},
        "targets": [_job_targets(job, names) for job in jobs],
    }


def _job_targets(job: CbomCollectionJob, names: dict[int, str]) -> dict[str, Any]:
    result = job.result if isinstance(job.result, dict) else {}
    targets = result.get("targets") if isinstance(result.get("targets"), list) else []
    return {
        "job_id": job.id, "source_id": job.source_id, "source_name": names.get(job.source_id or 0) or (job.params or {}).get("source_name"),
        "status": job.status, "outcome": job.outcome, "attempt": job.attempts, "asset_count": job.asset_count,
        "counts": result.get("counts") if isinstance(result.get("counts"), dict) else None,
        "summary": result.get("summary"), "truncated": bool(result.get("truncated")),
        "asset_mismatch": result.get("asset_mismatch"), "error": job.error,
        "targets": [t for t in targets[:1000] if isinstance(t, dict)],
        "duration_s": result.get("duration_s"),
    }


# ----------------------------------------------------------------------------- CycloneDX 1.6
_REL_TYPE = {"private_key": "private-key", "public_key": "public-key", "ssh_host_key": "public-key",
             "signing_key": "public-key", "kms_key": "key", "cloud_secret": "secret-key", "host_secret": "secret-key", "keystore": "key",
             "k8s_certificate": "key", "managed_key": "key"}


# CycloneDX 1.6 enums (cryptoProperties): values outside them make the document invalid
_CDX_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree",
                   "kem", "ae", "combiner", "other", "unknown"}
_CDX_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}
_KEY_STATE = {"Enabled": "active", "Disabled": "suspended", "PendingDeletion": "deactivated",
              "PendingImport": "pre-activation", "Unavailable": "suspended", "active": "active",
              # KMIP states (managed_key facts from KMIP servers)
              "Pre-Active": "pre-activation", "Active": "active", "Deactivated": "deactivated",
              "Compromised": "compromised", "Destroyed": "destroyed", "Destroyed Compromised": "compromised"}
_SEVERITY = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}


def _rank(impact: str) -> int:
    order = list(_SEVERITY)
    value = str(impact or "").capitalize()
    return order.index(value) if value in order else len(order)


def _code_impacts(row: CbomCollectedAsset) -> dict[str, str | None]:
    """The impact the classifier gives each code on this asset (re-run on the stored facts; it is deterministic)."""
    try:
        return classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts or {}, row.created_at)["impacts"]
    except Exception:
        return {}


def vulnerabilities(rows: list[CbomCollectedAsset], views: dict[int, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """CycloneDX vulnerabilities with VEX analysis.

    One entry per finding code (the weak setting was observed on the listed assets, so the analysis state is
    "exploitable", CERT-In's "Affected"), and one per CVE matched from that evidence or from a library version
    ("in_triage": a version or configuration match is not proof; distribution back-ports are not checked)."""
    by_code: dict[str, list[CbomCollectedAsset]] = {}
    code_impacts: dict[str, list[str]] = {}
    by_cve: dict[str, dict[str, Any]] = {}
    views = views or {}
    for row in rows:
        view = views.get(row.id) or shown(row)
        own = view["impacts"] or _code_impacts(row)
        for code in view["finding_codes"]:
            if isinstance(code, str) and crypto_kb.entry("node", code):
                by_code.setdefault(code, []).append(row)
                impact = own.get(code) or (crypto_kb.entry("node", code) or {}).get("default_impact")
                if impact:
                    code_impacts.setdefault(code, []).append(impact)
                for cve in crypto_kb.cves_for("node", code, view["finding"] or ""):
                    if code == "LIB_KNOWN_CVE":
                        continue
                    hit = by_cve.setdefault(cve["id"], {"cve": cve, "rows": [], "why": set()})
                    hit["rows"].append(row)
                    hit["why"].add(f"{code} ({cve.get('matched_on')})")
        facts = row.facts or {}
        if "LIB_KNOWN_CVE" in view["finding_codes"] and facts.get("version"):
            status = crypto_kb.library_status(str(facts.get("name") or facts.get("package") or ""), str(facts["version"]))
            for cid in (status or {}).get("cves") or []:
                hit = by_cve.setdefault(cid, {"cve": crypto_kb.cve(cid) or {"id": cid}, "rows": [], "why": set()})
                hit["rows"].append(row)
                hit["why"].add(f"{status['package']} {status['upstream_version']} is in the affected range")
    out: list[dict[str, Any]] = []
    for code, hits in sorted(by_code.items()):
        e = crypto_kb.entry("node", code) or {}
        # the severity of THIS finding (worst across the assets that have it), not the worst finding on those assets
        worst = min(code_impacts.get(code) or [], key=_rank, default=None)
        out.append({
            "bom-ref": f"zs-vuln-{code.lower()}", "id": f"ZS-CBOM-{code}",
            "source": {"name": "ZeroShield crypto knowledge base", "url": "https://cwe.mitre.org/"},
            "ratings": [{"severity": _SEVERITY.get(str(worst or "").capitalize(), "info"), "method": "other"}],
            "cwes": [int(c[4:]) for c in e.get("cwe") or []],
            "description": e.get("description"), "detail": e.get("attack"),
            "recommendation": (e.get("remediation") or {}).get("summary"),
            "analysis": {"state": "exploitable", "detail": "Observed directly by the collector on each affected asset."},
            "affects": [{"ref": f"zs-asset-{rid}"} for rid in list(dict.fromkeys(h.id for h in hits))[:5000]],
            "properties": [{"name": "zs:kb_version", "value": crypto_kb.version()}],
        })
    for cid, hit in sorted(by_cve.items()):
        cve = hit["cve"]
        cvss = cve.get("cvss") or {}
        rating = {"method": "CVSSv31" if cvss.get("version") == "3.1" else "CVSSv3" if cvss.get("version") == "3.0" else "other"}
        if cvss.get("score") is not None:
            rating.update({"score": cvss["score"], "severity": str(cvss.get("severity") or "unknown").lower(),
                           "vector": cvss.get("vector")})
        out.append({
            "bom-ref": f"zs-vuln-{cid.lower()}", "id": cid,
            "source": {"name": "NVD", "url": cve.get("url") or f"https://nvd.nist.gov/vuln/detail/{cid}"},
            "ratings": [{k: v for k, v in rating.items() if v is not None}],
            "cwes": [int(c[4:]) for c in cve.get("cwe") or [] if c[4:].isdigit()],
            "description": cve.get("summary") or f"{cid}: see the NVD record (not in the offline knowledge base).",
            "analysis": {"state": "in_triage",
                         "detail": "Matched on: " + "; ".join(sorted(hit["why"]))[:900] +
                                   ". A version or configuration match is not proof of exposure."},
            "affects": [{"ref": f"zs-asset-{rid}"} for rid in list(dict.fromkeys(r.id for r in hit["rows"]))[:5000]],
        })
    return out


def ct_properties(facts: dict[str, Any]) -> list[dict[str, str]]:
    """What a certificate found in Certificate Transparency logs (ct_collect) adds to its component.  ``zs:collector``
    (``ct``), ``zs:method`` and the rest of the provenance come from provenance.py like every other row's (one emitter,
    CB-06); ``zs:source`` keeps meaning the source's name."""
    out: list[dict[str, str]] = []
    for prop, key in (("zs:ct_provider", "ct_provider"), ("zs:ct_entry_id", "ct_provider_id"), ("zs:ct_detail", "ct_detail"),
                      ("zs:tbs_sha256", "tbs_sha256"), ("zs:fingerprint_sha256", "fingerprint_sha256"),
                      ("zs:precert_sha256", "precert_sha256"), ("zs:serial", "serial")):
        if facts.get(key):
            out.append({"name": prop, "value": str(facts[key])[:255]})
    for domain in (facts.get("matched_domains") or [])[:20]:
        out.append({"name": "zs:ct_matched_domain", "value": str(domain)[:253]})
    if facts.get("revoked") is not None:
        out.append({"name": "zs:revoked", "value": str(bool(facts["revoked"])).lower()})
    return out


# ----------------------------------------------------------------------------- what each component carries (CB-06)
COVERAGE = "coverage"  # a coverage row says what was NOT read: a gap of the document, never a cryptographic asset
COVERAGE_GAP_CAP = 5_000
_LIST_CAP = 200
_OID = re.compile(r"^[0-2](\.[0-9]{1,20}){1,40}$")
# RFC 3339 date-time with upper-case T/Z (what both the JSON schema's date-time and the XSD's xs:dateTime accept)
_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,12})?(Z|[+-](\d{2}):(\d{2}))$")
# facts CB-04 adds to the collectors' output (KF-9 extended), exported as zs:<name> whenever a collector wrote them
_IDENTITY_FACTS = ("key_alg_oid", "sig_alg_oid", "parameter_set", "nist_category", "algorithm_unknown")


def _text(value: Any, limit: int = 128) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = (str(value).lower() if isinstance(value, bool) else str(value)).strip()[:limit]
    return text or None


def _first(facts: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        text = _text(facts.get(key))
        if text:
            return text
    return None


def _names(*values: Any) -> list[str]:
    """Names from lists or comma-separated strings, in order, each once (at most ``_LIST_CAP``)."""
    out: list[str] = []
    for value in values:
        items = value.split(",") if isinstance(value, str) else value if isinstance(value, (list, tuple)) else []
        for item in items:
            text = _text(item)
            if text and text not in out and len(out) < _LIST_CAP:
                out.append(text)
    return out


def _date_time(value: Any) -> str | None:
    """A certificate date as an RFC 3339 date-time (CycloneDX ``notValidBefore/After``): kept as collected when it is
    one; another readable time is written in UTC with Z (a time without an offset is UTC, as everywhere here);
    anything else is left out, so one odd value from a collector never makes the whole document invalid."""
    text = _text(value, 64)
    if not text:
        return None
    text = text.upper()
    match = _DATE_TIME.match(text)
    if match:
        try:
            _dt.datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
        if match.group(3) is not None:
            hours, minutes = int(match.group(3)), int(match.group(4))
            if hours > 14 or minutes > 59 or (hours == 14 and minutes):
                return None  # xs:dateTime offsets stop at 14:00 (RFC 3339 allows +14:30, the XSD does not)
        return text
    try:
        moment = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return iso_z(moment)


def _protocol_versions(row: CbomCollectedAsset, facts: dict[str, Any]) -> list[str]:
    """The versions the server accepted, read as the classifier reads them (``classify._normalise``): its own list,
    else the version probes that succeeded (``versions``: {"TLSv1.2": true, "TLSv1.1": null ...}; null = not read),
    else the SSH banner (RFC 4253 4.2: "SSH-2.0-" and the compatibility "SSH-1.99-" are protocol 2), else the
    negotiated version, else the stored protocol."""
    listed = _names(facts.get("protocols") or facts.get("accepted_versions"))
    if listed:
        return listed
    versions = facts.get("versions")
    if isinstance(versions, dict):
        return _names([name for name, offered in versions.items() if offered is True])
    if isinstance(versions, (list, tuple)) and versions:
        return _names(versions)
    banner = str(facts.get("banner") or "")
    if banner.startswith(("SSH-2.0-", "SSH-1.99-")):
        return ["SSHv2"]
    if banner.startswith("SSH-1."):
        return ["SSHv1"]
    return _names(facts.get("negotiated_version")) or _names(row.protocol)


def _named(values: list[str]) -> list[str]:
    """``values`` without the sentinels tools print for "none" (``<NULL>``, ``(NONE)`` ...)."""
    return [v for v in values if not tls_suites.is_sentinel(v)]


def _database_suites(facts: dict[str, Any]) -> list[Any]:
    """Suites of the database collector's own connection and of the live connections it saw (PostgreSQL
    ``pg_stat_ssl``: {"version", "cipher"}; MySQL status variables: {"Ssl_cipher"} / {"variable", "value"})."""
    own = facts.get("own_connection")
    out: list[Any] = []
    if isinstance(own, dict):
        out += [own.get("cipher"), own.get("Ssl_cipher")]
    live = facts.get("live_connections")
    for conn in live if isinstance(live, list) else []:
        if isinstance(conn, dict):
            out.append(conn.get("cipher"))
            if conn.get("variable") == "Ssl_cipher":
                out.append(conn.get("value"))
    return out


def _cipher_suites(facts: dict[str, Any], tls: bool) -> list[dict[str, Any]]:
    """Every suite the collector saw the server accept: its own list (a list, or sshd's comma-separated string), else
    the negotiated suite, the suites the weak-class probes found accepted (``weak_ciphers_accepted``) and the
    database connections' suites. TLS suites are listed once each by their IANA name with their code
    (``tls_suites``): one suite stored under its OpenSSL and its IANA name is one suite."""
    names = _names(facts.get("ciphers"))
    if not names:
        weak = facts.get("weak_ciphers_accepted")
        extra = [v for v in weak.values() if isinstance(v, (list, tuple))] if isinstance(weak, dict) else []
        names = _names(facts.get("cipher") or facts.get("negotiated_cipher"), *extra, _database_suites(facts))
    if not tls:
        return [{"name": name} for name in names]
    out: dict[str, dict[str, Any]] = {}
    for name in _named(names):
        iana, code = tls_suites.canonical(name)
        if iana not in out:
            out[iana] = {"name": iana, **({"identifiers": tls_suites.identifiers(code)} if code else {})}
    return list(out.values())


def _key_primitive(algorithm: str) -> str:
    """CycloneDX primitive of a certificate's subject key algorithm, by family (unknown when the family does not say)."""
    fam = family(algorithm)
    if fam == "RSA":
        return "pke"
    if fam in ("EC", "ECDSA", "ED25519", "ED448", "EDDSA", "DSA", "SM2"):
        return "signature"
    if fam in ("X25519", "X448", "ECDH", "DH"):
        return "key-agree"
    return "unknown"


def _algorithm(ref: str, name: str, primitive: str, *, oid: str | None = None, curve: str | None = None,
               parameter: str | None = None) -> dict[str, Any]:
    props = {k: v for k, v in {"primitive": primitive, "parameterSetIdentifier": parameter, "curve": curve,
                               # 0: a quantum computer breaks it (CycloneDX allows the level only on algorithms)
                               "nistQuantumSecurityLevel": 0 if quantum_vulnerable(name) is True else None,
                               }.items() if v is not None}
    crypto: dict[str, Any] = {"assetType": "algorithm", "algorithmProperties": props}
    oid = oid or (name if _OID.match(name) else None)
    if oid and _OID.match(oid):
        crypto["oid"] = oid
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": name[:255], "cryptoProperties": crypto}


class CertificateParts:
    """One export's certificate parts: the signature algorithms, public keys and key algorithms its certificates
    reference (CycloneDX 1.6 ``signatureAlgorithmRef`` / ``subjectPublicKeyRef`` / ``algorithmRef``), one component per
    distinct content, shared by bom-ref by every certificate that has it. An estate's certificates share a handful of
    (signature algorithm, key algorithm, size, curve) tuples, so 50,000 certificates need a few dozen parts, not
    150,000 nested copies (review 5879114669: 2.2 GB to write such an export as XML).

    The parts are top-level components after the assets, with bom-refs ``zs-signature-algorithm-<hash>``,
    ``zs-public-key-<hash>`` and ``zs-public-key-algorithm-<hash>`` (a hash of the content: the same content has the
    same ref in every export) and one property, ``zs:part_of`` = ``certificate``: they describe parts of
    certificates, not assets of their own (no ``zs-asset-`` ref, no provenance, not in ``zs:asset_count``)."""

    PART_OF = {"name": "zs:part_of", "value": "certificate"}

    def __init__(self) -> None:
        self._by_key: dict[tuple, str] = {}
        self._refs: set[str] = set()
        self._components: list[dict[str, Any]] = []

    def ref(self, kind: str, key: tuple, build) -> str:
        """The bom-ref of the ``kind`` part with content ``key``; ``build(ref)`` makes its component the first time."""
        full = (kind, *key)
        ref = self._by_key.get(full)
        if ref is None:
            digest = hashlib.sha256(json.dumps(full, default=str).encode()).hexdigest()[:16]
            ref = f"zs-{kind}-{digest}"
            while ref in self._refs:  # a 64-bit prefix collision: never in practice, still never a shared ref
                ref += "x"
            self._refs.add(ref)
            self._by_key[full] = ref
            component = build(ref)
            component["properties"] = [self.PART_OF]
            self._components.append(component)
        return ref

    def components(self) -> list[dict[str, Any]]:
        return self._components


def _certificate_parts(row: CbomCollectedAsset, facts: dict[str, Any], size: int | None, curve: str | None,
                       signature: str | None, parts: CertificateParts) -> dict[str, Any]:
    """The certificate's CycloneDX 1.6 references into the export's shared ``parts``: ``signatureAlgorithmRef`` ->
    the signature algorithm; ``subjectPublicKeyRef`` -> the public key (size), whose ``algorithmRef`` -> the key
    algorithm (curve, or the size as its parameter set)."""
    refs: dict[str, Any] = {}
    if signature and signature.lower() != "unknown":
        sig_oid = _first(facts, "sig_alg_oid")
        refs["signatureAlgorithmRef"] = parts.ref("signature-algorithm", (signature, sig_oid), lambda ref: _algorithm(
            ref, signature, "signature", oid=sig_oid))
    key_alg = _first(facts, "key_alg") or _text(row.algorithm)
    key_alg = key_alg if key_alg and key_alg.lower() != "unknown" else None
    if key_alg or size:
        alg_ref = None
        if key_alg:
            key_oid, parameter = _first(facts, "key_alg_oid"), None if curve or not size else str(size)
            alg_ref = parts.ref("public-key-algorithm", (key_alg, key_oid, curve, parameter), lambda ref: _algorithm(
                ref, key_alg, _key_primitive(key_alg), oid=key_oid, curve=curve, parameter=parameter))
        label = ("-".join(str(part) for part in (key_alg, curve or size) if part) or "public key")[:255]

        def public_key(ref: str) -> dict[str, Any]:
            material: dict[str, Any] = {"type": "public-key"}
            if size:
                material["size"] = size
            if alg_ref:
                material["algorithmRef"] = alg_ref
            return {"type": "cryptographic-asset", "bom-ref": ref, "name": label, "cryptoProperties": {
                "assetType": "related-crypto-material", "relatedCryptoMaterialProperties": material}}

        refs["subjectPublicKeyRef"] = parts.ref("public-key", (label, size, alg_ref), public_key)
    return refs


FIX_CLASS_BASIS_CAP = 512


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fix_class_basis(per_code: Any) -> str:
    """``zs:fix_class_basis``: compact JSON ``[{"code","class","rule"}]`` of an asset's codes (``agility.evaluate``'s
    ``by_code``), at most ``FIX_CLASS_BASIS_CAP`` characters; when cut, the list ends with the string ``…+<n>`` (n:
    the codes left out), so the value is always JSON."""
    items = [{"code": p["code"], "class": p["class"], "rule": p["rule"]} for p in per_code]
    out = _compact(items)
    if len(out) <= FIX_CLASS_BASIS_CAP:
        return out
    for keep in range(len(items) - 1, -1, -1):
        out = _compact([*items[:keep], f"…+{len(items) - keep}"])
        if len(out) <= FIX_CLASS_BASIS_CAP:
            return out
    return _compact([f"…+{len(items)}"])


class Assessment:
    """One export's quantum risk grade (CB-19) and fix class (CB-24) per asset, from the same view-time functions the
    run API uses: ``qgrade.load_context`` / ``GradeContext.grade_row`` (the run asset list's grade) and
    ``agility.RunAgility`` (the run posture's accumulator, whose per-asset result is ``agility.evaluate``'s, the list's
    fix class). Contexts are loaded once per export; ``add`` grades one row and counts it. The property list of a
    component is shared by every asset with the same values (a few dozen lists for 50,000 assets), like provenance."""

    def __init__(self, session: Session, run: CbomCollectionRun) -> None:
        self.grading = QG.load_context(session, team_id=run.team_id, run_id=run.id)  # the team's Mosca, as the list
        self.agility = AGILITY.RunAgility(session, run.team_id, run.id, self.grading.sources)
        self.q_grades: dict[str, int] = {g: 0 for g in (*QG.GRADES, "none")}
        self._basis: dict[int, tuple[Any, str]] = {}  # id(by_code tuple) -> (the tuple, kept alive; its JSON)
        self._lists: dict[tuple, list[dict[str, str]]] = {}

    def add(self, row: CbomCollectedAsset, codes: list[str]) -> list[dict[str, str]]:
        graded = self.grading.grade_row(row, codes, explain=False)
        whole, per = self.agility.add(row, codes)
        self.q_grades[graded.q_grade or "none"] += 1
        held = self._basis.get(id(per))
        if held is None or held[0] is not per:
            held = self._basis[id(per)] = (per, fix_class_basis(per))
        key = (graded.q_grade, graded.q_reason, whole["fix_class"], whole["floor"], whole["confidence"], held[1])
        props = self._lists.get(key)
        if props is None:  # "none": the API's null (no grade, no floor, no confidence); every property always present
            props = self._lists[key] = [
                {"name": "zs:q_grade", "value": graded.q_grade or "none"},
                {"name": "zs:q_label", "value": graded.q_label or "none"},
                {"name": "zs:q_reason", "value": graded.q_reason},
                {"name": "zs:fix_class", "value": whole["fix_class"]},
                {"name": "zs:fix_class_floor", "value": whole["floor"] or "none"},
                {"name": "zs:fix_class_confidence", "value": whole["confidence"] or "none"},
                {"name": "zs:fix_class_basis", "value": held[1]},
            ]
        return props

    def metadata(self, session: Session, team_id: int) -> list[dict[str, str]]:
        """The run-level values, equal to the run posture API's (``grade_*``, ``q_grades``, ``fix_classes*``,
        ``fix_class_self_fixable_pct``, ``agility_version``) over the exported components.

        ``zs:grade_inputs`` is the posture's ``grade_inputs`` plus ``captured_at``: with ``source`` "current" (the
        team's Mosca as it is now; CB-19 PR-2 snapshots it per run) that is when the team's settings were last written
        (null when the team has none), never the request time, so repeat downloads of a run stay byte-identical."""
        agility = self.agility.result()
        pct = agility["fix_class_self_fixable_pct"]
        settings = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
        written = (settings.last_updated or settings.created_at) if settings is not None else None
        inputs = {**self.grading.inputs(), "captured_at": iso_z(written) if written else None}
        return [
            {"name": "zs:grade_model", "value": QG.GRADE_MODEL},
            {"name": "zs:grade_model_version", "value": QG.GRADE_MODEL_VERSION},
            {"name": "zs:grade_model_sha256", "value": hashlib.sha256(QG.FORMULA_TEXT.encode("utf-8")).hexdigest()},
            {"name": "zs:grade_inputs", "value": _compact(inputs)},
            {"name": "zs:q_distribution", "value": _compact(self.q_grades)},
            {"name": "zs:agility_model", "value": AGILITY.MODEL},
            {"name": "zs:agility_version", "value": agility["agility_version"]},
            {"name": "zs:fix_class_distribution", "value": _compact(agility["fix_classes"])},
            {"name": "zs:fix_class_distribution_excl_pq", "value": _compact(agility["fix_classes_excl_pq"])},
            {"name": "zs:fix_class_self_fixable_pct", "value": "none" if pct is None else str(pct)},
        ]


def _detail_properties(row: CbomCollectedAsset, facts: dict[str, Any], crypto: dict[str, Any], size: int | None,
                       curve: str | None, signature: str | None, view: dict[str, Any],
                       assessed: list[dict[str, str]] | None = None) -> list[dict[str, str]]:
    """The values the asset table and the oracle compare that CycloneDX has no field for (or not on this asset type):
    PQC class, then the quantum risk grade and fix class (``assessed``: ``Assessment.add``'s list), key size, curve,
    signature algorithm, key-exchange groups, SSH algorithm lists, CB-04 identity facts."""
    out: list[tuple[str, str | None]] = [
        ("zs:pqc_class", pqc_class(row.asset_type, row.quantum_vulnerable, list(view["finding_codes"]), facts)),
        ("zs:key_size", str(size) if size else None), ("zs:curve", curve), ("zs:signature_algorithm", signature),
    ]
    out += [(f"zs:{name}", _text(facts.get(name))) for name in _IDENTITY_FACTS]
    proto = crypto.get("protocolProperties") or {}
    if crypto.get("assetType") == "protocol" and proto.get("type") == "ssh":
        out += [("zs:kex_algorithms", ",".join(_names(facts.get("kex"), facts.get("kexalgorithms"))) or None),
                ("zs:host_key_algorithms", ",".join(_names(facts.get("host_key_algs"), facts.get("hostkey_algorithms"),
                                                           facts.get("hostkeyalgorithms"))) or None),
                ("zs:ciphers", ",".join(_names(facts.get("ciphers"), facts.get("ciphers_s2c"),
                                               facts.get("ciphers_c2s"))) or None),
                ("zs:macs", ",".join(_names(facts.get("macs"), facts.get("macs_s2c"), facts.get("macs_c2s"))) or None)]
    elif crypto.get("assetType") == "protocol":
        # every group the server was seen to offer or accept: its own lists, the negotiated one, the PQ probe's
        # ("<NULL>" is what s_client prints when no handshake completed: not a group)
        groups = sorted(set(_named(_names(*(facts.get(k) for k in ("groups", "supported_groups", "accepted_groups",
                                                                   "pq_groups", "negotiated_group", "group",
                                                                   "pq_group"))))))
        negotiated = _named([v for v in (_text(facts.get("negotiated_group")), _text(facts.get("group"))) if v])
        out += [("zs:groups", ",".join(groups) or None), ("zs:groups_negotiated", negotiated[0] if negotiated else None)]
    props = [{"name": name, "value": value} for name, value in out if value]
    at = 1 if props and props[0]["name"] == "zs:pqc_class" else 0
    props[at:at] = assessed or ()  # the shared (read-only) dicts as they are: next to zs:pqc_class
    return props


def _component(row: CbomCollectedAsset, source_name: str | None, view: dict[str, Any] | None = None,
               prov: PROV.JobProvenance | None = None, shared: dict[tuple, list] | None = None,
               parts: CertificateParts | None = None, assessed: list[dict[str, str]] | None = None) -> dict[str, Any]:
    """One asset as a CycloneDX component. ``shared``: one export's cache of provenance property lists. Rows of one
    job attempt stored in one batch have the same provenance, so their components share the same (read-only)
    property objects: a 50k-asset export then holds a few hundred provenance lists instead of 50,000. ``parts``: the
    export's certificate parts; a certificate references them, and the document lists ``parts.components()`` after
    the assets. ``assessed``: the asset's quantum risk grade and fix class properties (``Assessment.add``)."""
    facts = row.facts or {}
    view = view or shown(row)
    ref = f"zs-asset-{row.id}"
    props = [
        {"name": "zs:location", "value": row.location},
        {"name": "zs:asset_type", "value": row.asset_type},
        {"name": "zs:target", "value": row.target or ""},
        {"name": "zs:source", "value": source_name or ""},
        {"name": "zs:impact", "value": view["impact"] or "Info"},
        {"name": "zs:quantum_vulnerable", "value": "unknown" if row.quantum_vulnerable is None else str(row.quantum_vulnerable).lower()},
    ]
    if view["finding"]:
        props.append({"name": "zs:finding", "value": view["finding"]})
    for code in view["finding_codes"]:
        props.append({"name": "zs:finding_code", "value": str(code)})
    run = view["as_of_run"]
    if run:  # a date-based rule changed this finding since the run: the run's own verdict, kept beside it
        props.append({"name": "zs:judged_on", "value": run["judged_on"]})
        props.append({"name": "zs:run_impact", "value": run["impact"] or "Info"})
        if run["finding"]:
            props.append({"name": "zs:run_finding", "value": run["finding"]})
    name = row.name or row.algorithm or row.location
    size = next((v for v in (row.key_size, facts.get("key_size"))
                 if isinstance(v, int) and not isinstance(v, bool) and 0 < v < 1_000_000), None)
    curve = _first(facts, "curve", "crv")
    signature = _first(facts, "sig_alg", "signature_alg", "signature_algorithm")
    key = (row.job_id, row.attempt, row.created_at)
    provenance = shared.get(key) if shared is not None else None
    if provenance is None:
        provenance = [{"name": name, "value": value} for name, value in PROV.values(row, prov).items()]
        if shared is not None:
            shared[key] = provenance
    if row.cdx_type == "library":
        from backend.utilities.cbom_sources.sbom_link import ecosystem_of, library_purl

        package, version = str(facts.get("package") or name)[:255], str(facts.get("version") or "")
        props += _detail_properties(row, facts, {}, size, curve, signature, view, assessed) + provenance
        out = {"type": "library", "bom-ref": ref, "name": package, "version": version,
               "evidence": {"occurrences": [{"location": row.location}]}, "properties": props}
        # an OS package the node read from a package database carries its own purl (pkg:deb/ubuntu/libssl3@...,
        # agent mode and registry images, WP8b); otherwise build one (OS packages without an ecosystem: pkg:generic)
        own = str(facts.get("purl") or "")
        purl = own[:512] if own.startswith(("pkg:deb/", "pkg:apk/", "pkg:rpm/")) else \
            library_purl(package, version, ecosystem_of(facts.get("ecosystem") or facts.get("language")))
        if purl:
            out["purl"] = purl
        return out
    crypto: dict[str, Any] = {"assetType": row.cdx_type if row.cdx_type in ("certificate", "protocol", "related-crypto-material") else "algorithm"}
    if crypto["assetType"] == "certificate":
        refs = _certificate_parts(row, facts, size, curve, signature, parts if parts is not None else CertificateParts())
        crypto["certificateProperties"] = {
            "subjectName": _text(facts.get("subject"), 2048), "issuerName": _text(facts.get("issuer"), 2048),
            "notValidBefore": _date_time(facts.get("not_before")), "notValidAfter": _date_time(facts.get("not_after")),
            **refs, "certificateFormat": "X.509", "certificateExtension": _text(facts.get("format"), 32) or "pem",
        }
        crypto["certificateProperties"] = {k: v for k, v in crypto["certificateProperties"].items() if v}
    elif crypto["assetType"] == "protocol":
        proto = (row.protocol or ("ssh" if "ssh" in row.asset_type else "tls")).lower()
        versions = _protocol_versions(row, facts)
        crypto["protocolProperties"] = {
            "type": "ssh" if proto.startswith("ssh") else ("tls" if "tls" in proto or "ssl" in proto or proto == "tls" else "other"),
            "version": ",".join(versions)[:255] if versions else None,
            "cipherSuites": _cipher_suites(facts, tls=not proto.startswith("ssh")),
        }
        crypto["protocolProperties"] = {k: v for k, v in crypto["protocolProperties"].items() if v}
    elif crypto["assetType"] == "related-crypto-material":
        crypto["relatedCryptoMaterialProperties"] = {k: v for k, v in {
            "type": _REL_TYPE.get(row.asset_type, "other"), "size": row.key_size,
            "format": facts.get("format"), "state": _KEY_STATE.get(str(facts.get("key_state") or "")),
        }.items() if v}
    else:
        mode = str(facts.get("mode") or "").lower()
        crypto["algorithmProperties"] = {k: v for k, v in {
            "primitive": facts.get("primitive") if facts.get("primitive") in _CDX_PRIMITIVES else "other",
            "parameterSetIdentifier": str(row.key_size) if row.key_size else None,
            "mode": (mode if mode in _CDX_MODES else "other") if mode else None,
            # CycloneDX allows the quantum level only on algorithms: 0 means a quantum computer breaks it
            "nistQuantumSecurityLevel": 0 if row.quantum_vulnerable is True else None,
        }.items() if v is not None and v != ""}
    if row.algorithm:
        props.append({"name": "zs:algorithm", "value": row.algorithm})
    if row.protocol:  # the asset table's protocol column as stored (protocolProperties.type is CycloneDX's enum)
        props.append({"name": "zs:protocol", "value": row.protocol})
    props += _detail_properties(row, facts, crypto, size, curve, signature, view, assessed) + provenance
    if facts.get("source") == "ct":
        props += ct_properties(facts)
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": str(name)[:255], "cryptoProperties": crypto,
            "evidence": {"occurrences": [{"location": row.location}]}, "properties": props}


def coverage_gaps(rows: list[CbomCollectedAsset], names: dict[int, str], job_names: dict[int, Any],
                  provs: dict[int, PROV.JobProvenance]) -> list[dict[str, str]]:
    """The run's coverage rows as document gaps: ``zs:coverage_gap_count`` (all of them) and one ``zs:coverage_gap``
    per row (at most ``COVERAGE_GAP_CAP``), whose value is compact JSON: ``ref`` (``zs-asset-<id>``, the id the asset
    API lists the row under), source, target, location, check, status, detail, scope, incomplete, by_choice, finding,
    and the row's provenance (``provenance.NAMES`` without the ``zs:`` prefix; job_id and attempt as numbers)."""
    out = [{"name": "zs:coverage_gap_count", "value": str(len(rows))}] if rows else []
    for row in rows[:COVERAGE_GAP_CAP]:
        facts = row.facts if isinstance(row.facts, dict) else {}
        gap: dict[str, Any] = {
            "ref": f"zs-asset-{row.id}", "source": names.get(row.source_id or 0) or job_names.get(row.job_id) or "",
            "target": row.target or "", "location": row.location, "check": _text(facts.get("check"), 255),
            "status": _text(facts.get("status"), 64), "detail": _text(facts.get("detail"), 512),
            "scope": _names(facts.get("scope"))[:20], "incomplete": facts.get("incomplete") is True,
            "by_choice": facts.get("by_choice") is True, "finding": row.finding,
        }
        for key, value in PROV.values(row, provs.get(row.job_id)).items():
            gap[key[3:]] = int(value) if key in ("zs:job_id", "zs:attempt") and value.isdigit() else value
        out.append({"name": "zs:coverage_gap", "value": json.dumps(gap, sort_keys=True, separators=(",", ":"),
                                                                     ensure_ascii=False)})
    return out


def _document(session: Session, run: CbomCollectionRun, now: _dt.datetime
              ) -> tuple[dict[str, Any], Iterator[dict[str, Any]], Callable[[], list[dict[str, Any]]]]:
    """The run's CycloneDX document in three parts, for writing it piece by piece: the head (every key before
    ``components``), the components (made one at a time: the assets, one ``zs-asset-<id>`` component each, then the
    certificate parts they reference) and the vulnerabilities (call it once the components are consumed)."""
    rows = session.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.team_id == run.team_id,
                                                         CbomCollectedAsset.run_id == run.id)
                        .order_by(CbomCollectedAsset.id).limit(EXPORT_CAP + 1)).all()
    truncated = len(rows) > EXPORT_CAP
    rows = rows[:EXPORT_CAP]
    coverage = [row for row in rows if row.asset_type == COVERAGE]  # what was not read: gaps of the document
    rows = [row for row in rows if row.asset_type != COVERAGE]  # the cryptographic assets: one component each
    today = now if now.tzinfo is None else now.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    views = {row.id: shown(row, today) for row in rows}
    judged_on = next((v["as_of_run"]["judged_on"] for v in views.values() if v["as_of_run"]), None)
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).all()
    names = _source_names(session, run.team_id, list(jobs))
    job_names = {j.id: names.get(j.source_id or 0) or (j.params or {}).get("source_name") for j in jobs}
    provs = PROV.load(session, run.team_id, jobs)
    shared: dict[tuple, list] = {}
    parts = CertificateParts()
    gaps = []
    for job in jobs:
        info = _job_targets(job, names)
        for target in info["targets"]:
            if target.get("status") not in ("ok", None):
                gaps.append(f"{info['source_name']}: {target.get('target')} {target.get('status')}")
        if job.status != "success":
            gaps.append(f"{info['source_name']}: job {job.status}")
    # CB-19 / CB-24: grade and fix class of every asset before the head (its metadata holds their distributions);
    # each asset keeps a reference to a shared property list, its component is still made in the stream below
    assessment = Assessment(session, run)
    assessed = {row.id: assessment.add(row, views[row.id]["finding_codes"]) for row in rows}
    kb_version = crypto_kb.version()
    versions = [(name, value) for name, value in (("zs:run_kb_version", run.kb_version),
                                                   ("zs:classifier_version", run.classifier_version),
                                                   ("zs:engine_version", run.engine_version)) if value]
    serial = export_serial(run.id or 0, kb_version, judged_on, grade_model_version=QG.GRADE_MODEL_VERSION,
                           grade_inputs_digest=assessment.grading.digest, agility_version=AGILITY.version())
    head = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": iso_z(now),
            # the build that wrote this file; the run's own judge is zs:engine_version (CB-03)
            "tools": {"components": [{"type": "application", "name": "ZeroShield CBOM Sources", "version": build_version()}]},
            "properties": [
                {"name": "zs:run_id", "value": str(run.id)}, {"name": "zs:run_status", "value": run.status},
                {"name": "zs:asset_count", "value": str(len(rows))}, {"name": "zs:truncated", "value": str(truncated).lower()},
                {"name": "zs:kb_version", "value": kb_version}, {"name": "zs:build", "value": build_sha()},
                *[{"name": name, "value": str(value)} for name, value in versions],
                *([{"name": "zs:judged_on", "value": judged_on}] if judged_on else []),
                *assessment.metadata(session, run.team_id),
                *[{"name": "zs:gap", "value": gap[:255]} for gap in gaps[:500]],
                *coverage_gaps(coverage, names, job_names, provs),
            ],
        },
    }

    def components() -> Iterator[dict[str, Any]]:
        for row in rows:  # the assets, then the certificate parts they reference
            yield _component(row, names.get(row.source_id or 0) or job_names.get(row.job_id), views[row.id],
                             provs.get(row.job_id), shared, parts, assessed[row.id])
        yield from parts.components()

    return head, components(), lambda: vulnerabilities(list(rows), views)


def cyclonedx(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> dict[str, Any]:
    """The run's CycloneDX 1.6 document as one dict (what ``write_cyclonedx`` writes, piece by piece)."""
    head, components, vulns = _document(session, run, now)
    return {**head, "components": list(components), "vulnerabilities": vulns()}


def write_cyclonedx(session: Session, run: CbomCollectionRun, now: _dt.datetime, fmt: str, out: BinaryIO) -> None:
    """Write the run's CycloneDX document to ``out`` as JSON or XML (``cdx_xml``), one component at a time: the same
    document as ``cyclonedx``, but neither the whole dict, nor an XML tree, nor the encoded bytes is ever held in
    memory at once (review 5879114669 major 2: a 50,000-component XML export peaked near 2.2 GB)."""
    head, components, vulns = _document(session, run, now)
    if fmt == "xml":
        from backend.utilities.cbom_sources import cdx_xml

        cdx_xml.write_xml(out, head, components, vulns)
        return
    def dumps(value: Any) -> bytes:  # what starlette's JSONResponse writes (the route's JSON before streaming)
        return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":")).encode()

    out.write(dumps(head)[:-1] + b',"components":[')
    for index, component in enumerate(components):
        out.write((b"," if index else b"") + dumps(component))
    out.write(b'],"vulnerabilities":' + dumps(vulns()) + b"}")
