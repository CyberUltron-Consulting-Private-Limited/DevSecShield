"""A run's assets as rows of the unified CBOM results table (CB-38 PR-1a): ``GET /{team}/cbom/sources/runs/{id}/assets``.

Additive over ``inventory.list_assets`` (its items, totals, facets and targets are returned unchanged):

* ``view=all`` (default: today's list) or ``view=findings`` (assets that are not ``coverage`` rows and have an impact,
  judged today exactly as the list shows the impact); ``status=not_started|in_progress|fixed|ignored`` keeps the
  assets whose remediation assignment is in that bucket (``contracts/cbom/status_buckets.json``; no assignment is
  ``not_started``; ``coverage`` rows are never plannable: their ``status`` is null and a status filter leaves them
  out).
* every item gains ``asset_key`` (the stable key ``waves.node_items`` gives the asset; null for a ``coverage`` row,
  whose ``risk_score`` is 0 as it is never a finding),
  ``status`` / ``assignment_status``, ``wave`` (the asset's ``node_items`` entry, computed for the page's assets only),
  ``risk_score`` (0-10, ``bom_risk_score.cbom_finding_risk_score`` over ``collections_view.node_row``), the code-lane
  names from ``node_row`` (``algorithm_name``, ``algorithm_type``, ``crypto_strength``, ``quantum_safe``,
  ``description``) and ``type_label``;
* the response gains ``findings_total`` (the run's findings, judged today) next to ``all_total`` and ``total``.

Fields other features add to the items (``q_grade``, ``q_label``, ``fix_class`` ...) pass through untouched.
"""
from __future__ import annotations

import datetime as _dt
import re
import time
from types import SimpleNamespace
from typing import Any

from sqlalchemy import String, and_, cast, false, func, or_, true
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource
from backend.utilities.cbom_sources import clause_evidence as CE
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources import inventory as INV
from backend.utilities.cbom_sources import qgrade_store as QSTORE
from backend.utilities.cbom_sources import waves as WAVES
from backend.utilities.cbom_sources.collections_view import Collection, node_row
from backend.utilities.cbom_sources.run_list import finding_status, log_line

VIEWS = ("all", "findings")
FINDING_STATUSES = ("not_started", "in_progress", "fixed", "ignored")
IMPACTS = ("Critical", "High", "Medium", "Low")
COVERAGE = "coverage"
_UTC = _dt.timezone.utc
# #270: the compliance mapping's drill-down filters the table by finding codes (a clause's codes)
CODE_RE = re.compile(r"^[A-Z0-9_]{1,64}$")
MAX_CODES = 50
MAX_IDS = 500  # a compliance requirement's assets (its refs, zs-asset-<id>) passed as ``asset_id=1,2,3``
# #271 review: the readiness card's "Show these N": one readiness group (posture.readiness_actions[].code), "none" for
# the group with no quantum finding code, "any" for every quantum-vulnerable asset (posture's class count)
PQC_GROUP_RE = re.compile(r"^(any|none|[A-Z0-9_]{1,64})$")

# The run table's type names (frontend RunResults.tsx ASSET_TYPE_LABEL), so both lanes' tables print one column.
TYPE_LABEL = {
    "certificate": "Certificate", "private_key": "Private key", "public_key": "Public key", "keystore": "Keystore",
    "ssh_host_key": "SSH host key", "ssh_server_config": "SSH server config", "ssh_endpoint": "SSH endpoint",
    "tls_endpoint": "TLS endpoint", "crypto_library": "Crypto library", "process_library": "Process library",
    "disk_encryption": "Disk encryption", "os_crypto_policy": "OS crypto policy", "database_tls": "Database TLS",
    "database_config": "Database settings", "database_user_auth": "Database authentication",
    "k8s_cluster": "Kubernetes cluster", "k8s_tls_secret": "Kubernetes TLS secret",
    "k8s_certificate": "cert-manager certificate", "k8s_ingress_tls": "Ingress TLS",
    "k8s_mesh_policy": "Mesh mTLS policy", "kms_key": "KMS key", "cloud_secret": "Cloud secret",
    "host_secret": "Secret in a service or script", "crypto_config": "Crypto configuration",
    "storage_encryption": "Storage encryption", "load_balancer_tls": "Load balancer TLS", "cdn_tls": "CDN TLS",
    "api_tls": "API TLS", "cloud_ca": "Certificate authority", "iam_certificate": "IAM certificate",
    "identity_provider": "Identity provider", "signing_key": "Signing key", "open_port": "Open port",
    "glue_catalog": "Glue Data Catalog", "glue_connection": "Glue connection", "key_vault": "Key vault",
    # scan-node key, database, CA and network packages (classify_ext/node_keys.py, node_net.py)
    "managed_key": "Managed key", "key_store": "Key store", "db_encryption": "Database encryption",
    "db_login_policy": "Database login policy", "db_crypto_policy": "Database transport policy",
    "ca_authority": "CA", "ca_template": "CA template", "ike_endpoint": "IKE/IPsec endpoint",
    "ot_endpoint": "OT endpoint", "appliance_config": "Network appliance config",
    "k8s_mesh_destination": "Mesh destination rule", "k8s_mesh_server": "Mesh server policy",
    "ad_domain": "Active Directory domain", "kerberos_account": "Kerberos account",  # FIX-B3 (classify_ext/ad.py)
    "coverage": "Not collected",
}
# The same names counted ("Fix 3 CA templates"): one entry per TYPE_LABEL key (test_cbom_results_qa_r4.py keeps the
# two in step). Mass nouns and acronyms take a word instead of a bare "s" ("Database TLS settings").
TYPE_LABEL_PLURAL = {
    "certificate": "Certificates", "private_key": "Private keys", "public_key": "Public keys", "keystore": "Keystores",
    "ssh_host_key": "SSH host keys", "ssh_server_config": "SSH server configs", "ssh_endpoint": "SSH endpoints",
    "tls_endpoint": "TLS endpoints", "crypto_library": "Crypto libraries", "process_library": "Process libraries",
    "disk_encryption": "Disk encryption settings", "os_crypto_policy": "OS crypto policies",
    "database_tls": "Database TLS settings", "database_config": "Database settings",
    "database_user_auth": "Database authentication settings",
    "k8s_cluster": "Kubernetes clusters", "k8s_tls_secret": "Kubernetes TLS secrets",
    "k8s_certificate": "cert-manager certificates", "k8s_ingress_tls": "Ingress TLS settings",
    "k8s_mesh_policy": "Mesh mTLS policies", "kms_key": "KMS keys", "cloud_secret": "Cloud secrets",
    "host_secret": "Secrets in a service or script", "crypto_config": "Crypto configurations",
    "storage_encryption": "Storage encryption settings", "load_balancer_tls": "Load balancer TLS settings",
    "cdn_tls": "CDN TLS settings", "api_tls": "API TLS settings", "cloud_ca": "Certificate authorities",
    "iam_certificate": "IAM certificates", "identity_provider": "Identity providers", "signing_key": "Signing keys",
    "open_port": "Open ports", "glue_catalog": "Glue Data Catalogs", "glue_connection": "Glue connections",
    "key_vault": "Key vaults", "managed_key": "Managed keys", "key_store": "Key stores",
    "db_encryption": "Database encryption settings", "db_login_policy": "Database login policies",
    "db_crypto_policy": "Database transport policies", "ca_authority": "CAs", "ca_template": "CA templates",
    "ike_endpoint": "IKE/IPsec endpoints", "ot_endpoint": "OT endpoints", "appliance_config": "Network appliance configs",
    "k8s_mesh_destination": "Mesh destination rules", "k8s_mesh_server": "Mesh server policies",
    "ad_domain": "Active Directory domains", "kerberos_account": "Kerberos accounts",
    "coverage": "Not collected",
}


def type_label(asset_type: str | None) -> str:
    value = str(asset_type or "")
    return TYPE_LABEL.get(value) or (value.replace("_", " ").capitalize() if value else "Other")


def type_label_plural(asset_type: str | None) -> str:
    """``type_label`` counted (more than one); an unknown future type gets the singular plus "s"."""
    value = str(asset_type or "")
    return TYPE_LABEL_PLURAL.get(value) or f"{type_label(value)}s"


# ----------------------------------------------------------------------------- filters
def _findings_clause(changed: dict[int, dict[str, Any]]):
    """Not ``coverage`` and an impact, by today's verdict (a row a date-based rule changed is judged by today's)."""
    stored = CbomCollectedAsset.impact.in_(IMPACTS)  # type: ignore[union-attr]
    if changed:
        stored = and_(stored, CbomCollectedAsset.id.notin_(list(changed)))  # type: ignore[union-attr]
        today = [aid for aid, view in changed.items() if view.get("impact") in IMPACTS]
        if today:
            stored = or_(stored, CbomCollectedAsset.id.in_(today))  # type: ignore[union-attr]
    return and_(CbomCollectedAsset.asset_type != COVERAGE, stored)


def parse_codes(value: str | None) -> list[str] | None:
    """``code=A,B`` -> ["A", "B"]; None when absent. ValueError on an empty list, a malformed code or more than
    MAX_CODES (the route answers 400 without echoing the value)."""
    if value is None:
        return None
    codes = list(dict.fromkeys(part.strip() for part in value.split(",")))
    if not codes or len(codes) > MAX_CODES or not all(CODE_RE.match(c) for c in codes):
        raise ValueError("code: a comma-separated list of up to 50 finding codes")
    return codes


def parse_ids(value: str | None) -> list[int] | None:
    """``asset_id=1,2`` -> [1, 2]; None when absent. ValueError on an empty list, a non-integer or more than MAX_IDS."""
    if value is None:
        return None
    parts = [part.strip() for part in value.split(",")]
    if not parts or len(parts) > MAX_IDS or not all(p.isdigit() and 0 < len(p) <= 10 for p in parts):
        raise ValueError("asset_id: a comma-separated list of up to 500 asset ids")
    ids = list(dict.fromkeys(int(p) for p in parts))
    if any(i < 1 or i > 2_147_483_647 for i in ids):
        raise ValueError("asset_id: a comma-separated list of up to 500 asset ids")
    return ids


def parse_pqc_group(value: str | None) -> str | None:
    """``pqc_group=NO_PQ_KEX`` / ``none`` / ``any``; None when absent. ValueError on anything else (400, value not echoed)."""
    if value is None:
        return None
    if not PQC_GROUP_RE.match(value):
        raise ValueError("pqc_group: any, none or one finding code")
    return value


def _pqc_group_clause(session: Session, team_id: int, run_id: int, group: str, asset_type: str | None,
                      changed: dict[int, dict[str, Any]]):
    """The run's assets in one PQC readiness group, judged by posture's own functions on today's codes
    (``classify_pqc`` for the class, ``quantum_code`` for the group), so the table lists exactly the N assets the
    readiness card counts. An any-of ``code=`` filter cannot: an ECDHE endpoint that also accepts static RSA suites
    carries STATIC_RSA_KEX and NO_PQ_KEX and belongs to the first group only. Only stored quantum-vulnerable rows can
    be in a group (``classify_pqc``: class quantum-vulnerable needs ``quantum_vulnerable`` true), so only they are read;
    the clause names the smaller side (members, or the vulnerable rows that are not members)."""
    from backend.utilities.cbom_sources.posture import classify_pqc, quantum_code

    vulnerable = and_(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id,
                      CbomCollectedAsset.quantum_vulnerable.is_(True),  # type: ignore[union-attr]
                      CbomCollectedAsset.asset_type != COVERAGE)
    if asset_type:
        vulnerable = and_(vulnerable, CbomCollectedAsset.asset_type == asset_type)
    inside: list[int] = []
    outside: list[int] = []
    for row in session.exec(select(CbomCollectedAsset).where(vulnerable)).all():
        view = changed.get(int(row.id or 0))
        codes = [c for c in (view.get("finding_codes") if view else row.finding_codes) or []
                 if isinstance(c, str) and not c.startswith("COVERAGE_")]
        member = classify_pqc(row, codes)[0] == "quantum-vulnerable" and (
            group == "any" or (quantum_code(codes) or "none") == group)
        (inside if member else outside).append(int(row.id or 0))
    if not inside:
        return false()
    if len(inside) <= len(outside):
        return CbomCollectedAsset.id.in_(inside)  # type: ignore[union-attr]
    return and_(vulnerable, CbomCollectedAsset.id.notin_(outside)) if outside else vulnerable  # type: ignore[union-attr]


def _codes_clause(codes: list[str], changed: dict[int, dict[str, Any]]):
    """Collected assets whose finding codes (today's, for a row a date-based rule changed) include any of ``codes``:
    the assets a compliance clause counts (posture.run_posture: non-coverage rows, today's codes)."""
    text = cast(CbomCollectedAsset.finding_codes, String)
    # the stored JSON array holds each code as "CODE"; "_" is escaped so it is not a LIKE wildcard
    stored = or_(*[text.like('%"' + code.replace("_", "\\_") + '"%', escape="\\") for code in codes])
    if changed:
        stored = and_(stored, CbomCollectedAsset.id.notin_(list(changed)))  # type: ignore[union-attr]
        wanted = set(codes)
        today = [aid for aid, view in changed.items() if wanted & set(view.get("finding_codes") or [])]
        if today:
            stored = or_(stored, CbomCollectedAsset.id.in_(today))  # type: ignore[union-attr]
    return and_(CbomCollectedAsset.asset_type != COVERAGE, stored)


def _clause_clause(session: Session, team_id: int, run_id: int, clause: tuple[str, str | None],
                   changed: dict[int, dict[str, Any]]):
    """Collected assets behind a compliance clause (``clause=<framework>[:<clause id>]``), decided per asset by the
    function the run posture counts with (clause_evidence.matches: the asset's non-coverage codes judged today, the
    algorithms the classifier flagged for them). A clause's evidence-gated rules make "has the code" too wide (#291 x
    #289), so the "N assets" of a clause and this filter's total are the same set of assets.

    #289 review (performance): a code whose own clauses name the clause puts every asset that has it behind the clause,
    so that part is a SQL predicate on the recorded codes. Only the assets whose citing codes are all rule-gated are
    judged in memory (their classifier columns only, the evidence cached per process), and the outcome goes to SQL as
    id ranges of the smaller side (behind / not behind), so no id list of the whole candidate set is built."""
    keys = CE.clause_keys(*clause)
    always, by_rule = CE.codes_citing_split(keys)
    if not always and not by_rule:
        return false()
    parts = []
    if always:
        parts.append(_codes_clause(always, changed))
    if by_rule:
        gated = _codes_clause(by_rule, changed)
        cols = (CbomCollectedAsset.id, CbomCollectedAsset.asset_type, CbomCollectedAsset.algorithm,
                CbomCollectedAsset.key_size, CbomCollectedAsset.protocol, CbomCollectedAsset.facts,
                CbomCollectedAsset.created_at, CbomCollectedAsset.finding_codes)
        query = select(*cols).where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id, gated)
        if always:  # an asset with an always-citing code is behind the clause already (the SQL part above)
            query = query.where(~func.coalesce(_codes_clause(always, changed), false()))
        behind, not_behind = [], []
        for values in session.exec(query.order_by(CbomCollectedAsset.id)).all():
            row = SimpleNamespace(**dict(zip(("id", "asset_type", "algorithm", "key_size", "protocol", "facts",
                                              "created_at", "finding_codes"), values)))
            codes = (changed[row.id].get("finding_codes") if row.id in changed else row.finding_codes) or []
            (behind if CE.matches(row, codes, keys) else not_behind).append(int(row.id))
        if behind:
            parts.append(and_(gated, _id_ranges(behind, not_behind)))
    return or_(*parts) if parts else false()


def _id_ranges(wanted: list[int], other: list[int]):
    """``id`` in ``wanted``, for a SQL query already narrowed to ``wanted + other`` (both ascending): the side with
    fewer runs of consecutive members, as ``BETWEEN`` ranges (a single id in one ``IN``), negated for ``other``. Ids in
    a range that belong to neither side are outside the narrowed query, so the range never widens it."""
    def runs(mine: list[int], theirs: list[int]) -> list[tuple[int, int]]:
        merged = sorted([(i, True) for i in mine] + [(i, False) for i in theirs])
        out: list[tuple[int, int]] = []
        start = prev = None
        for ident, is_mine in merged:
            if is_mine:
                start = ident if start is None else start
                prev = ident
            elif start is not None:
                out.append((start, prev))
                start = None
        if start is not None:
            out.append((start, prev))
        return out

    def predicate(spans: list[tuple[int, int]]):
        singles = [a for a, b in spans if a == b]
        clauses = [CbomCollectedAsset.id.between(a, b) for a, b in spans if a != b]  # type: ignore[union-attr]
        clauses += [CbomCollectedAsset.id.in_(singles[i:i + 500])  # type: ignore[union-attr]
                    for i in range(0, len(singles), 500)]
        return or_(*clauses)

    if not other:
        return true()
    keep, drop = runs(wanted, other), runs(other, wanted)
    return predicate(keep) if len(keep) <= len(drop) else ~predicate(drop)


def _job_refs(session: Session, team_id: int, run: CbomCollectionRun) -> dict[int, str]:
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.run_id == run.id)).all()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    return {int(j.id): ID.job_source_ref(j, sources.get(j.source_id or 0)) for j in jobs}


def run_asset_keys(session: Session, team_id: int, run: CbomCollectionRun) -> dict[int, str]:
    """``asset id -> stable key`` for every non-coverage asset of the run (the key ``waves.node_items`` gives it).
    Certificates are keyed by their subject and issuer, so only their facts are read."""
    refs = _job_refs(session, team_id, run)
    cols = (CbomCollectedAsset.id, CbomCollectedAsset.job_id, CbomCollectedAsset.source_id,
            CbomCollectedAsset.asset_key, CbomCollectedAsset.asset_type, CbomCollectedAsset.cdx_type,
            CbomCollectedAsset.target, CbomCollectedAsset.location)
    scope = (CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id,
             CbomCollectedAsset.asset_type != COVERAGE)
    is_cert = or_(CbomCollectedAsset.cdx_type == ID.CERT_CDX,
                  CbomCollectedAsset.asset_type.in_(("certificate", "k8s_certificate")))  # type: ignore[union-attr]
    out: dict[int, str] = {}
    for with_facts in (False, True):
        query = (select(*cols, CbomCollectedAsset.facts).where(*scope, is_cert) if with_facts
                 else select(*cols).where(*scope, ~is_cert))
        for rec in session.exec(query).all():
            aid, job_id, source_id, asset_key, asset_type, cdx_type, target, location = rec[:8]
            row = SimpleNamespace(asset_key=asset_key, asset_type=asset_type, cdx_type=cdx_type, target=target,
                                  location=location, facts=(rec[8] if with_facts else None) or {})
            ref = refs.get(int(job_id)) if job_id is not None else None
            out[int(aid)] = ID.stable_key("node", ref or f"source-{source_id}", ID.node_identity(row))
    return out


def _status_clause(session: Session, team_id: int, run: CbomCollectionRun, status: str):
    started = time.perf_counter()
    keys = run_asset_keys(session, team_id, run)
    found = WAVES._assignments(session, team_id, keys.values())
    bucket = {aid: finding_status(found[key].status if key in found else None) for aid, key in keys.items()}
    # the cost of this path grows with the run (PR-2's stored keys replace it): one line per request
    log_line(f"cbom run assets status_filter team={team_id} run={run.id} status={status} keys={len(keys)} "
             f"planned={len(found)} ms={int((time.perf_counter() - started) * 1000)}")
    if status == "not_started":  # the common case: exclude the (few) planned assets instead of listing every id
        others = [aid for aid, value in bucket.items() if value != "not_started"]
        clause = CbomCollectedAsset.asset_type != COVERAGE
        return and_(clause, CbomCollectedAsset.id.notin_(others)) if others else clause  # type: ignore[union-attr]
    wanted = [aid for aid, value in bucket.items() if value == status]
    return CbomCollectedAsset.id.in_(wanted) if wanted else false()  # type: ignore[union-attr]


def findings_total(session: Session, team_id: int, run_id: int, changed: dict[int, dict[str, Any]]) -> int:
    """The run's findings judged today (the ``view=findings`` total with no other filter)."""
    query = select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id,
        CbomCollectedAsset.asset_type != COVERAGE, CbomCollectedAsset.impact.in_(IMPACTS))  # type: ignore[union-attr]
    if changed:
        query = query.where(CbomCollectedAsset.id.notin_(list(changed)))  # type: ignore[union-attr]
    stored = int(session.exec(query).one())
    return stored + sum(1 for view in changed.values() if view.get("impact") in IMPACTS)


# ----------------------------------------------------------------------------- item fields
def _aware(moment: _dt.datetime | None) -> _dt.datetime:
    if moment is None:
        return _dt.datetime(1970, 1, 1, tzinfo=_UTC)
    return moment.replace(tzinfo=_UTC) if moment.tzinfo is None else moment.astimezone(_UTC)


def _collections(session: Session, team_id: int, run: CbomCollectionRun, job_ids: set[int]) -> dict[int, Collection]:
    if not job_ids:
        return {}
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.id.in_(sorted(job_ids)))).all()  # type: ignore[union-attr]
    source_ids = sorted({j.source_id for j in jobs if j.source_id is not None})
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id, CbomCollectionSource.id.in_(source_ids))).all()} if source_ids else {}  # type: ignore[union-attr]
    out: dict[int, Collection] = {}
    for job in jobs:
        src = sources.get(job.source_id or 0)
        out[int(job.id)] = Collection(run_id=int(run.id), job_id=int(job.id), source_ref=ID.job_source_ref(job, src),
                                      source_name=ID.job_source_name(job, src),
                                      source_kind=src.kind if src is not None else "",
                                      observed_at=_aware(job.finished_at or job.created_at))
    return out


def enrich_items(session: Session, team_id: int, run: CbomCollectionRun, items: list[dict[str, Any]]) -> None:
    """Add the unified-table fields to a page of ``inventory.public_asset`` items, in place."""
    from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score

    ids = [int(i["id"]) for i in items if i.get("id") is not None]
    if not ids:
        return
    rows = {int(r.id): r for r in session.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.id.in_(ids))).all()}  # type: ignore[union-attr]
    plannable = [aid for aid in ids if aid in rows and rows[aid].asset_type != COVERAGE]
    waves = {int(w["asset_id"]): w for w in WAVES.node_items(session, team_id, run, asset_ids=plannable)} if plannable else {}
    collections = _collections(session, team_id, run, {int(r.job_id) for r in rows.values() if r.job_id is not None})
    for item in items:
        row = rows.get(int(item["id"]))
        wave = waves.get(int(item["id"]))
        assignment = (wave or {}).get("assignment") or None
        raw_status = assignment.get("status") if isinstance(assignment, dict) else None
        coverage = item.get("type") == COVERAGE  # "could not read X": never planned, never a finding
        item["asset_key"] = wave["asset_key"] if wave else None
        item["assignment_status"] = raw_status
        item["status"] = None if coverage else finding_status(raw_status)
        item["wave"] = wave
        item["type_label"] = type_label(item.get("type"))
        collection = collections.get(int(row.job_id)) if row is not None and row.job_id is not None else None
        if row is None or collection is None:
            item.update({"risk_score": 0.0, "algorithm_name": item.get("algorithm") or item.get("name"),
                         "algorithm_type": None, "crypto_strength": None, "quantum_safe": None,
                         "description": item.get("finding") or ""})
            continue
        # judged today, exactly as the item shows it (impact, finding sentence, codes)
        code_row = node_row(row, collection, {"impact": item.get("impact"), "finding": item.get("finding"),
                                              "finding_codes": item.get("finding_codes") or []})
        item["risk_score"] = 0.0 if coverage else cbom_finding_risk_score(code_row)
        for key in ("algorithm_name", "algorithm_type", "crypto_strength", "quantum_safe", "description"):
            item[key] = code_row.get(key)
    for item in items:
        add_code_page_fields(item)


def run_item(session: Session, team_id: int, run: CbomCollectionRun, row: CbomCollectedAsset, *,
             grade: dict[str, Any] | None = None, pqc: tuple[str, str] | None = None) -> dict[str, Any]:
    """One asset exactly as the run's ``/assets`` list shows it (the same functions over one row): the asset detail
    carries it, so a dialog opened from top risks or a certificate (an asset not on the findings page) shows the
    findings table's row. ``grade`` / ``pqc``: the caller's (the detail grades the row once)."""
    from backend.utilities.cbom_sources import agility as AGILITY

    job = session.get(CbomCollectionJob, row.job_id) if row.job_id is not None else None
    jobs = [job] if job is not None and job.team_id == team_id else []
    names = INV._source_names(session, team_id, jobs)  # a deleted source: the job's snapshot name (as the list)
    job_names = {j.id: names.get(j.source_id or 0) or (j.params or {}).get("source_name") for j in jobs}
    item = INV.public_asset(row, names, job_names, None, grade, pqc)
    AGILITY.annotate_assets(session, team_id, jobs, [item])
    enrich_items(session, team_id, run, [item])
    return item


def add_code_page_fields(item: dict[str, Any]) -> None:
    """The code page's ``CbomFinding`` fields a run item lacks (CB-38 W2b parity): ``bom_ref`` (``zs-asset-<id>``: the
    ref the run's distributions, dependency graph and compliance requirement refs use), ``title``, and from the
    knowledge base ``owasp_top_10`` / ``compliance_controls`` (the code page's ``{key: label}`` form) and
    ``suggested_fix``."""
    from backend.utilities.cbom_sources import crypto_kb

    codes = [c for c in item.get("finding_codes") or [] if isinstance(c, str) and not c.startswith("COVERAGE_")]
    finding = bool(codes) and item.get("type") != COVERAGE
    item["bom_ref"] = f"zs-asset-{item['id']}"
    item["title"] = item.get("algorithm_name") or item.get("algorithm") or item.get("name") or item.get("location")
    item["owasp_top_10"] = crypto_kb.owasp_legacy("node", codes) if finding else {}
    item["compliance_controls"] = crypto_kb.controls_legacy("node", codes) if finding else {}
    item["suggested_fix"] = crypto_kb.summary_fix("node", codes) if finding else None


# ----------------------------------------------------------------------------- the page
def list_run_assets(session: Session, *, team_id: int, run: CbomCollectionRun, params: dict[str, Any],
                    view: str = "all", status: str | None = None, codes: list[str] | None = None,
                    asset_ids: list[int] | None = None, pqc_group: str | None = None,
                    clause: tuple[str, str | None] | None = None, q_grade: str | None = None) -> dict[str, Any]:
    """The run's asset page. ``q_grade`` (CB-19 PR-3: "Q0".."Q4" or "none") filters on the grade stored at ingest;
    it raises ``qgrade_store.Unavailable`` when the run's grades were not stored (``grade_filter.reason`` says why)."""
    if view not in VIEWS:
        raise ValueError(f"view: {view}")
    if status is not None and status not in FINDING_STATUSES:
        raise ValueError(f"status: {status}")
    if q_grade is not None and q_grade not in QSTORE.GRADE_FILTERS:
        raise ValueError(f"q_grade: {q_grade}")
    grades = QSTORE.status(session, team_id, run)
    if q_grade is not None and not grades["available"]:
        raise QSTORE.Unavailable(grades["reason"])
    seen: dict[str, Any] = {}

    def refine(query, changed: dict[int, dict[str, Any]]):
        seen["changed"] = changed
        if view == "findings":
            query = query.where(_findings_clause(changed))
        if status is not None:
            query = query.where(_status_clause(session, team_id, run, status))
        if codes:
            query = query.where(_codes_clause(codes, changed))
        if clause:
            query = query.where(_clause_clause(session, team_id, int(run.id), clause, changed))
        if asset_ids:  # the run's own rows only: the base query is already this team's run
            query = query.where(CbomCollectedAsset.id.in_(asset_ids))  # type: ignore[union-attr]
        if pqc_group:
            query = query.where(_pqc_group_clause(session, team_id, int(run.id or 0), pqc_group,
                                                  params.get("asset_type"), changed))
        if q_grade is not None:
            query = query.where(QSTORE.grade_clause(q_grade))
        return query

    out = INV.list_assets(session, team_id=team_id, run_id=run.id, refine=refine, **params)
    out["findings_total"] = findings_total(session, team_id, int(run.id), seen.get("changed") or {})
    out["view"] = view
    out["status_filter"] = status
    out["code_filter"] = codes
    out["asset_id_filter"] = len(asset_ids) if asset_ids else None
    out["pqc_group_filter"] = pqc_group
    out["clause_filter"] = ":".join(p for p in clause if p) if clause else None
    out["q_grade_filter"] = q_grade  # CB-19 PR-3 (facets.q_grade and grade_filter come from inventory.list_assets)
    enrich_items(session, team_id, run, out["items"])
    return out


parse_clause = CE.parse_clause

__all__ = ["FINDING_STATUSES", "TYPE_LABEL", "TYPE_LABEL_PLURAL", "VIEWS", "enrich_items", "findings_total",
           "list_run_assets", "parse_clause", "parse_codes", "parse_ids", "parse_pqc_group", "run_asset_keys", "run_item",
           "type_label", "type_label_plural"]
