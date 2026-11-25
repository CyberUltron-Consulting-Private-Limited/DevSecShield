"""CBOM Sources results next to code-scan results: the ONE rule every team-wide CBOM view applies (M1x).

A completed CBOM Sources collection is a CBOM result, just as a completed code scan is. The CBOM dashboard (cards,
charts, top risks, table), the team home counts, the deliverables manifest and every team deliverable PDF read the
Sources side through this module, so they cannot disagree.

Which collections count
  * Per source (``identity.job_source_ref``: the source uid, which survives renames), its NEWEST ``collect`` job
    whose status is ``success``: the job finished and stored what it read. A run that ended ``partial`` still
    contributes the sources that succeeded. Older collections of the same source are history (drift and run history
    show them; they are not current results), exactly as an older code scan of the same repository is.
  * The assets of that job's current attempt, except ``coverage`` rows (they record what could NOT be read).
  * Findings are judged as the run results page judges them today (``classify.shown``: certificate expiry and end of
    life move with the calendar).

One asset counted once ("latest observation wins")
  * Identity across code scans and Sources: a certificate is identified by its cross-source asset key
    (``asset_keys``, CB-21): the serial (ACM's Issuer "Amazon" and the node's DN agree, SAN-only certificates and CT
    precertificates included), else the DER fingerprint, else the DNs and notAfter (a Windows store row), else the
    subject and issuer CN and dates (a code-scan row, which names CNs only). ``link_certificates`` correlates the
    Sources rows: rows sharing a link key are one certificate unless two of them disagree on a serial, fingerprint,
    thumbprint, issuer DN or notBefore (then that key joins nothing). ``resolve`` maps a code row's token onto the one
    Sources certificate that shares it (notBefore included when the Sources side has one). Any other asset is
    identified within its own source (a code row by its line-independent identity in its repository, a Sources
    asset by ``identity.node_identity`` in its source): a repository path and a host never describe the same asset,
    so they cannot overlap.
  * When one identity is observed more than once (in a code scan and a Sources collection, or by two Sources), only
    the LATEST observation is counted: observation time is the code scan's ``created_at`` and the collection job's
    ``finished_at``; on a tie the code scan is kept. The other observations are left out of every count, chart and
    document, so a total never counts one asset twice. Every row says where it came from (``origin``).

Rows are written in the code-scan ``results[]`` vocabulary (``algorithm_type``, ``crypto_strength``, ``quantum_safe``,
``impact``, ``finding_codes``) so ``cbom_metrics`` counts them by the same rules as code rows (one set of numbers).
Nothing here writes: drift, run history and remediation assignments are untouched.
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

UTC = _dt.timezone.utc
ORIGIN_CODE = "code_scan"
ORIGIN_SOURCES = "sources_run"

# node asset type -> the code-scan results[] algorithm_type the dashboards count (certificates / keys cards)
_KEY_TYPES = frozenset({"ssh_host_key", "ssh_user_key", "private_key", "public_key", "key", "kms_key", "keystore_entry",
                        "secret", "pgp_key", "jwk"})
_CDX_ASSET_TYPES = frozenset({"algorithm", "certificate", "protocol", "related-crypto-material"})
# codes that are not a weakness of the algorithm itself (a quantum verdict, coverage, a calendar date)
_NOT_WEAK = frozenset({"QUANTUM_VULNERABLE", "NO_PQ_KEX"})
_CN = re.compile(r"(?:^|[,/])\s*CN\s*=\s*([^,/]+)", re.IGNORECASE)
# network-probe evidence: assets a scan node read by connecting to an endpoint (TLS handshakes, SSH banners)
NETWORK_TYPES = frozenset({"tls_endpoint", "ssh_endpoint"})


@dataclass(frozen=True)
class Collection:
    """One source's latest completed collection (a collect job of a Sources run)."""

    run_id: int
    job_id: int
    source_ref: str  # source uid (identity.job_source_ref)
    source_name: str
    source_kind: str  # CbomCollectionSource.kind, "" when the source was deleted
    observed_at: _dt.datetime  # job finished_at (tz-aware UTC)
    asset_count: int = 0  # assets counted (coverage rows excluded), before cross-scope de-duplication
    endpoints_probed: int = 0  # TLS / SSH endpoints the node connected to
    # the source's metadata (kinds.METADATA_FIELDS: owner, application, data classification, data lifetime,
    # criticality, exposure, environment): the source's current values, else the run's snapshot of them
    metadata: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)
    # how the collection was made (``collection_info``: method, window, credential reference by name only); D1 prints it
    info: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)
    # where its job read from (``resource_identity.job_scope``): a private address or a single-label name it reports
    # is one resource only within this network (the scan node's segment) or machine (the node), review 6039899144 M2
    network_scope: str = field(default="", compare=False, repr=False)
    machine_scope: str = field(default="", compare=False, repr=False)
    # a newer attempt of this source that read nothing (``latest_collections``): its job id and when it finished; the
    # documents say "newest collection read nothing on <date>; last read <date>" (review 6039899144 M4)
    newer_attempt_job_id: int | None = field(default=None, compare=False, repr=False)
    newer_attempt_at: _dt.datetime | None = field(default=None, compare=False, repr=False)
    # the source's collect-job history (``collection_history``): successful collections, the first one, and the latest
    # attempt whatever its status (D1's "Scans", "First scanned" and "Last attempt"; staging QA2 Q1-02)
    history: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def label(self) -> str:
        """The source's name: a document names a source by the source, never by the run (SOW audit A-18); the run
        number is printed where the documents give provenance (``run_id``)."""
        return self.source_name

    @property
    def key(self) -> str:
        return f"sources:{self.source_ref}"


@dataclass
class SourcesRow:
    """One Sources asset: ``row`` in the results[] vocabulary, its identity and where it came from."""

    row: dict[str, Any]
    collection: Collection
    identity: str
    node_type: str  # CbomCollectedAsset.asset_type, e.g. tls_endpoint, certificate, ssh_host_key
    target: str | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    asset_key: str = ""  # identity.stable_key("node", ...): the key remediation assignments use
    aliases: frozenset[str] = frozenset()  # the group's uncontested certificate link keys (asset_keys.correlate_detail)
    # code -> the algorithms its compliance clause rules read (clause_evidence; None: not recorded), for the codes that
    # have such rules: the deliverables' clause mapping decides as the run posture does (#289)
    clause_evidence: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)
    # the parts its standards statuses are judged on (classify.standards_parts): the team roll-up judges each
    # collection's CNSA 2.0 / FIPS 140-3 requirements on them (cbom_sources.frameworks, CB-16)
    standards_parts: tuple[tuple[str, Any, Any], ...] = field(default=(), compare=False, repr=False)
    # code -> the impact the classifier gave that code on this asset (``classify.shown``'s ``impacts``): a code whose
    # impact depends on the facts (a domain's functional level, a key's size) keeps it in the posture facts, so a
    # deliverable's findings table never falls back to the KB default for it (#493 review 6032906354 M1)
    code_impacts: dict[str, str] = field(default_factory=dict, compare=False, repr=False)
    # the other (still existing) sources that read the same resource, when this row is the observation kept
    # (``resolve``: one asset counted once; staging QA Q3-01)
    also_seen: tuple[str, ...] = field(default=(), compare=False, repr=False)
    also_seen_keys: tuple[str, ...] = field(default=(), compare=False, repr=False)  # their collection keys


def is_deleted_source(collection: Any) -> bool:
    """THE rule for a collection whose source was deleted (``Collection.source_kind`` is "" then): its last collection
    is history, never current population or posture evidence. The team roll-up (D1, D12, D14, posture), the dashboard
    and the certificate / network estates all ask this one function (staging QA2 Q1-01)."""
    return not str(getattr(collection, "source_kind", "") or "")


def current_only(found: SourcesResult) -> SourcesResult:
    """``found`` without the collections (and rows) of deleted sources: what every population count reads."""
    return SourcesResult(collections=[c for c in found.collections if not is_deleted_source(c)],
                         rows=[r for r in found.rows if not is_deleted_source(r.collection)])


# remediation status of a Sources finding (waves) -> the dashboard's finding status buckets
REMEDIATION_BUCKET = {"open": "not_started", "in_progress": "in_progress", "done": "fixed", "accepted_risk": "ignored"}


def _aware(moment: Any) -> _dt.datetime:
    if not isinstance(moment, _dt.datetime):
        return _dt.datetime(1970, 1, 1, tzinfo=UTC)
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _cn(name: Any) -> str:
    text = " ".join(str(name or "").split())
    match = _CN.search(text)
    return (match.group(1) if match else text).strip().casefold()


def _stamp(value: Any) -> str:
    """ISO date-time to the second, no zone suffix ("2026-12-11T04:44:49"); "" when missing."""
    text = str(value or "").strip().replace(" ", "T")
    return text[:19] if len(text) >= 19 else text


def cert_identity(subject: Any, issuer: Any, not_before: Any, not_after: Any) -> str | None:
    """LEGACY (pre CB-21) DN identity: subject CN, issuer CN, notBefore, notAfter; None without a subject or notAfter.
    The team view no longer uses it (``asset_keys``); kept unchanged for ``run_results`` (CB-38), whose per-run
    managed/chain certificate matching can move to ``asset_keys.asset_key`` (ACM "Amazon" vs node DN) later."""
    subject_cn, after = _cn(subject), _stamp(not_after)
    if not subject_cn or not after:
        return None
    return "cert|" + "|".join((subject_cn, _cn(issuer), _stamp(not_before), after))


def origin_label(origin: Mapping[str, Any] | None) -> str:
    """"Code scan: <title>" or "Sources run #<id>: <source name>" (what a table row prints)."""
    origin = origin if isinstance(origin, Mapping) else {}
    if origin.get("kind") == ORIGIN_SOURCES:
        return f"Sources run #{origin.get('run_id')}: {origin.get('source_name') or 'source'}"
    title = origin.get("scan_title")
    return f"Code scan: {title}" if title else "Code scan"


# ----------------------------------------------------------------------------- one asset as a results[] row
def _algorithm_type(node_type: str, cdx_type: str) -> str:
    if cdx_type == "certificate" or node_type in ("certificate", "k8s_certificate"):
        return "certificate"
    if node_type in _KEY_TYPES or cdx_type == "related-crypto-material":
        return "key"
    if cdx_type == "protocol":
        return "protocol"
    if cdx_type == "library":
        return "library"
    if cdx_type == "algorithm":
        return "algorithm"
    return "configuration"


def code_impacts(view: Mapping[str, Any]) -> dict[str, str]:
    """The classifier's impact per code of a judged view (``classify.shown`` / ``classify.classify``), for the codes
    the view shows; empty when the rules could not re-read the asset (``impacts`` None)."""
    impacts = view.get("impacts")
    if not isinstance(impacts, Mapping):
        return {}
    shown_codes = {c for c in view.get("finding_codes") or [] if isinstance(c, str)}
    return {str(c): str(i) for c, i in impacts.items()
            if c in shown_codes and i in ("Critical", "High", "Medium", "Low")}


def node_row(asset: Any, collection: Collection, view: Mapping[str, Any]) -> dict[str, Any]:
    """A stored ``CbomCollectedAsset`` (judged today: ``view`` is ``classify.shown``) as a code-scan results[] row.

    The collector's verdict is kept exactly, so ``cbom_metrics`` counts the same Critical / High / Medium / Low as the
    run page (``posture.run_posture`` counts ``impact``): an asset classify gave an impact is a finding with that
    impact and its codes; an asset classify left without an impact is INFORMATIONAL inventory, even when it carries a
    code such as QUANTUM_VULNERABLE (an RSA host key). Its codes stay on the row as ``collector_codes`` and its
    quantum verdict in ``quantum_safe`` (readiness), but not in ``finding_codes`` / ``weak`` / ``quantum_vulnerable``,
    which ``cbom_rows.is_finding`` would read as a (Low) finding."""
    facts = asset.facts if isinstance(asset.facts, dict) else {}
    codes = [c for c in (view.get("finding_codes") or []) if isinstance(c, str) and c]
    impact = view.get("impact") if view.get("impact") in ("Critical", "High", "Medium", "Low") else None
    qv = asset.quantum_vulnerable
    # a finding is weak unless its only codes are quantum verdicts; an impact without any code is a weakness too
    weak = bool(impact) and (not codes or any(c not in _NOT_WEAK for c in codes))
    name = asset.name or asset.algorithm or asset.asset_type
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
    return {
        "title": name,
        "algorithm_name": asset.algorithm or name,
        "asset_type": asset.cdx_type if asset.cdx_type in _CDX_ASSET_TYPES else "other",
        "algorithm_type": _algorithm_type(asset.asset_type, asset.cdx_type),
        "crypto_strength": "weak" if weak else ("strong" if qv is not None else "not-applicable"),
        "weak": weak,
        "quantum_safe": None if qv is None else (not qv),
        "impact": impact,
        "finding_codes": codes if impact else [],
        "collector_codes": codes,
        "description": view.get("finding") or "",
        "location": asset.location,
        "key_size": None if asset.key_size is None else str(asset.key_size),
        "protocol_version": asset.protocol,
        "not_valid_after": facts.get("not_after") or leaf.get("not_after"),
        "bom_ref": f"zs-asset-{asset.id}",
        "origin": {"kind": ORIGIN_SOURCES, "run_id": collection.run_id, "job_id": collection.job_id,
                   "source_name": collection.source_name, "source_ref": collection.source_ref,
                   "observed_at": collection.observed_at.strftime("%Y-%m-%dT%H:%M:%SZ")},
    }


# ----------------------------------------------------------------------------- loading (the one DB read)
def read_nothing(job: Any) -> bool:
    """A collect job that finished "success" but read nothing: ``jobs`` gives it the ``failed`` outcome exactly when
    it stored no row other than coverage rows (every target skipped, refused or unreachable), and refunds it.  The
    refund rule (``jobs.complete``) and OSCAL (``integrations.oscal``: "nothing read") already treat it as no
    collection; so do the documents (review 6039899144 M4)."""
    return getattr(job, "status", None) == "success" and getattr(job, "outcome", None) == "failed"


def latest_collections(session: Any, team_id: int, *, limit: int = 2_000) -> list[tuple[Any, Any]]:
    """``(job, newer)`` per source, newest first: ``job`` is the source's newest successful collect job that read
    something, ``newer`` the newest attempt after it that read nothing (``read_nothing``), else None.

    A newer attempt that read nothing never replaces the source's last real collection: before review 6039899144 M4
    one failed run with zero assets dropped every certificate of the source from D8 and the certificate hygiene list
    (15 -> 0).  A source whose every job read nothing keeps its newest one (``newer`` None), so D1 / D2 still name it
    with what it read: nothing."""
    from types import SimpleNamespace

    from sqlalchemy import or_
    from sqlmodel import select

    from backend.new_models import CbomCollectionJob, CbomCollectionSource
    from backend.utilities.cbom_sources import identity as ID

    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    usable: dict[str, Any] = {}
    empty: dict[str, Any] = {}  # the newest attempt that read nothing, per source, until a usable one is found
    order: list[str] = []
    seen = 0
    for job in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.status == "success", CbomCollectionJob.run_id.is_not(None))  # type: ignore[union-attr]
            .order_by(CbomCollectionJob.finished_at.desc().nulls_last(),  # type: ignore[union-attr]
                      CbomCollectionJob.id.desc())  # type: ignore[union-attr]
            .limit(limit)).all():
        seen += 1
        ref = ID.job_source_ref(job, sources.get(job.source_id or 0))
        if ref in usable:
            continue
        if ref not in order:
            order.append(ref)
        if read_nothing(job):
            empty.setdefault(ref, job)
            continue
        usable[ref] = job
    # review 6058574998 F7: the window is shared by every job, so a source whose recent attempts all read nothing (an
    # hourly schedule failing for weeks) or that ran long ago can have its last real read outside it.  Each existing
    # source without a real read in the window is asked for its own newest one (one indexed query per such source,
    # usually none); a deleted source is history and keeps what the window holds.
    found = 0
    for source in sources.values():
        ref = ID.job_source_ref(SimpleNamespace(params={}, source_id=source.id, id=0), source)
        if ref in usable or (ref not in empty and seen < limit):
            continue  # a real read in the window, or none anywhere (the window held every job and none of this one)
        job = session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == team_id, CbomCollectionJob.source_id == source.id,
            CbomCollectionJob.kind == "collect", CbomCollectionJob.status == "success",
            CbomCollectionJob.run_id.is_not(None),  # type: ignore[union-attr]
            or_(CbomCollectionJob.outcome.is_(None), CbomCollectionJob.outcome != "failed"))  # type: ignore[union-attr]
            .order_by(CbomCollectionJob.finished_at.desc().nulls_last(),  # type: ignore[union-attr]
                      CbomCollectionJob.id.desc()).limit(1)).first()  # type: ignore[union-attr]
        if job is None or ID.job_source_ref(job, source) != ref:
            continue
        found += 1
        usable[ref] = job
        if ref not in order:
            order.append(ref)
    out = [(usable[ref], empty.get(ref)) if ref in usable else (empty[ref], None) for ref in order]
    if found:  # newest first, as the window gives them
        out.sort(key=lambda pair: (_aware(pair[0].finished_at or pair[0].created_at), pair[0].id or 0), reverse=True)
    return out


def latest_jobs(session: Any, team_id: int, *, limit: int = 2_000) -> list[Any]:
    """The latest collection of each source (``latest_collections``: the newest successful collect job that read
    something, else its newest one), newest first."""
    return [job for job, _newer in latest_collections(session, team_id, limit=limit)]


# "Nothing collected: <target>: <code> (<detail>)" (scan node ``zscollect``): the code is the attempt's reason
_NOTHING_CODE = re.compile(r"Nothing collected: .*?: ([a-z][a-z0-9_]{2,40})\b")
_OPEN_STATUSES = {"pending": "waiting", "claimed": "running"}


def attempt_reason(status: Any, error: Any, outcome: Any = None) -> str | None:
    """A short reason for a collect attempt that did not read everything ("auth_failed", "expired", "partial"), None
    for a complete success. Never a secret: the collector's own error code, else the first words of its message."""
    status = str(status or "")
    if status == "success":
        return None if outcome in (None, "", "ok") else str(outcome)
    if status in _OPEN_STATUSES:
        return _OPEN_STATUSES[status]
    found = _NOTHING_CODE.search(str(error or ""))
    if found:
        return found.group(1)
    if status in ("expired", "cancelled") and not error:
        return status
    text = " ".join(str(error or status or "failed").split())
    return text if len(text) <= 60 else text[:59].rstrip() + "\u2026"


def collection_history(session: Any, team_id: int, sources: Mapping[int, Any]) -> dict[str, dict[str, Any]]:
    """Per source ref (``identity.job_source_ref``): how many collections succeeded (``scans``), when the first one
    finished (``first_scanned``) and the latest attempt whatever its status (``last_attempt_*``: run, job, status,
    reason, time). D1's Sources rows print it (staging QA2 Q1-02).

    Aggregated in SQL (#497 review M3: reading every job's params was 2.1 s and 529 MB at 60k jobs): one statement for
    the per-source totals (success count, first success, newest creation time), grouped by source id over the history
    index (``ix_cbomcollectionjob_team_source_hist``: no row and no params read) plus, UNION ALL, a deleted source's
    detached jobs grouped by the uid their params kept; then one statement for each source's newest job, found by
    (source, created_at) on the same index, of which only status, error and outcome are read."""
    import sqlalchemy as sa

    from backend.new_models import CbomCollectionJob as J

    base = (J.team_id == team_id, J.kind == "collect", J.run_id.is_not(None))  # type: ignore[union-attr]
    ok = J.status == "success"
    done_at = sa.case((ok, sa.func.coalesce(J.finished_at, J.created_at)), else_=None)
    measures = (sa.func.sum(sa.case((ok, 1), else_=0)), sa.func.min(done_at), sa.func.max(J.created_at))
    # a detached job (its source deleted): the uid its params kept, else its name
    uid = J.params["source_uid"].as_string()  # type: ignore[index]
    name = J.params["source_name"].as_string()  # type: ignore[index]
    detached = sa.case((uid.is_not(None), sa.literal("u:") + uid), else_=sa.literal("n:") + sa.func.coalesce(name, ""))
    attached_q = (sa.select(J.source_id, sa.literal(None, sa.String).label("g"), *measures)
                  .where(*base, J.source_id.is_not(None)).group_by(J.source_id))  # type: ignore[union-attr]
    detached_q = (sa.select(sa.literal(None, sa.Integer).label("source_id"), detached.label("g"), *measures)
                  .where(*base, J.source_id.is_(None)).group_by(detached))  # type: ignore[union-attr]
    totals = [(f"i:{sid}" if sid is not None else g, sid, scans, first, newest)
              for sid, g, scans, first, newest in session.execute(sa.union_all(attached_q, detached_q)).all()]
    pairs = sorted({(sid, newest) for _k, sid, _s, _f, newest in totals if sid is not None and newest is not None})
    loose = sorted({newest for _k, sid, _s, _f, newest in totals if sid is None and newest is not None})
    latest: dict[str, Any] = {}  # group -> its newest job (created_at, then id), status / error / outcome only
    for start in range(0, max(len(pairs), len(loose)), 250):
        found = [sa.and_(J.source_id.is_(None), J.created_at.in_(loose[start:start + 250]))]  # type: ignore[union-attr]
        if pairs[start:start + 250]:
            found.append(sa.tuple_(J.source_id, J.created_at).in_(pairs[start:start + 250]))
        for row in session.execute(sa.select(J.source_id, detached, J.id, J.run_id, J.status, J.error, J.outcome,
                                             J.created_at, J.finished_at).where(*base, sa.or_(*found))).all():
            key = f"i:{row[0]}" if row[0] is not None else row[1]
            held = latest.get(key)
            if held is None or (row[7], row[2]) > (held[6], held[1]):
                latest[key] = (key, *row[2:])
    totals = [(key, scans, first, newest) for key, _sid, scans, first, newest in totals]
    rows = []
    for key, scans, first, newest in totals:
        row = latest.get(key)
        if row is not None and row[6] == newest:
            rows.append((key, scans, first, *row[1:]))
    out: dict[str, dict[str, Any]] = {}
    for key, scans, first, job_id, run_id, status, error, outcome, created, finished in rows:
        kind, _sep, value = str(key).partition(":")
        if kind == "i":
            source = sources.get(int(value))
            ref = source.source_uid if source is not None and source.source_uid else f"source-{value}"
        else:
            ref = value if kind == "u" else f"deleted:{value or job_id}"
        if isinstance(first, str):  # SQLite returns the aggregated time as text
            first = _dt.datetime.fromisoformat(first)
        h: dict[str, Any] = {"scans": int(scans or 0), "first_scanned": _aware(first) if first is not None else None,
                             "last_attempt_run_id": int(run_id), "last_attempt_job_id": int(job_id),
                             "last_attempt_status": str(status), "last_attempt_at": _aware(finished or created),
                             "last_attempt_reason": attempt_reason(status, error, outcome)}
        held = out.get(ref)
        if held is not None:  # a source's attached and detached jobs (rare): one history, the newer attempt
            h["scans"] += held["scans"]
            firsts = [f for f in (h["first_scanned"], held["first_scanned"]) if f is not None]
            h["first_scanned"] = min(firsts) if firsts else None
            if (held["last_attempt_at"], held["last_attempt_job_id"]) > (h["last_attempt_at"], h["last_attempt_job_id"]):
                h.update({k: v for k, v in held.items() if k.startswith("last_attempt")})
        out[ref] = h
    return out


@dataclass
class SourcesResult:
    """What the team's Sources contribute: their latest collections and those collections' assets."""

    collections: list[Collection] = field(default_factory=list)
    rows: list[SourcesRow] = field(default_factory=list)

    @property
    def endpoints_probed(self) -> int:
        return sum(c.endpoints_probed for c in self.collections)


# Product text: how each kind collects (cbom_sources.kinds KINDS; SOW audit A-10 d)
_AGENTLESS = "Agentless: remote read from a scan node"
_API = "API: the provider's management interface"
COLLECTION_METHODS = {
    "host_agent": "Agent: installed on the host",
    "network_range": "Agentless: live TLS and SSH handshakes from a scan node",
    "ct_logs": "API: public Certificate Transparency logs",
    "container_images": "Agentless: image pulled from the registry and analysed offline",
    "kubernetes": "API: the Kubernetes API server",
    **{kind: _API for kind in ("aws_account", "azure_subscription", "gcp_project", "oci_tenancy", "key_manager",
                               "ca_connector", "idp")},
}
_CREDENTIAL_TYPES = {
    "node_key": "the scan node's own key", "ssh_cert": "an SSH certificate", "ssh_ca": "a team SSH CA certificate",
    "password": "a stored password", "vault": "a vault secret", "kubeconfig": "a stored kubeconfig",
    "client_secret": "a client secret", "certificate": "a client certificate",
}


def collection_info(session: Any, source: Any, job: Any) -> dict[str, Any]:
    """How a collection was made, for D1 (SOW audit A-10 d): the method, the window it ran in (UTC) and a reference
    to the credential it used. The reference names the credential (its type, a team credential's name, a vault path,
    an IAM role, the NAMES of the stored secret fields), never a secret value."""
    kind = str(getattr(source, "kind", "") or "")
    started = getattr(job, "first_claimed_at", None) or getattr(job, "claimed_at", None) or getattr(job, "created_at",
                                                                                                   None)
    return {"method": COLLECTION_METHODS.get(kind, _AGENTLESS if kind else "Not known (the source was deleted)"),
            "started": _aware(started).isoformat() if started else None,
            # when it ended, as the documents date the collection (``Collection.observed_at``: finished, else created)
            "finished": (_aware(job.finished_at or job.created_at).isoformat()
                         if getattr(job, "finished_at", None) or getattr(job, "created_at", None) else None),
            "credential": credential_reference(session, source)}


def credential_reference(session: Any, source: Any) -> str:
    if source is None:
        return "not known (the source was deleted)"
    cfg = source.config if isinstance(source.config, dict) else {}
    parts: list[str] = []
    if getattr(source, "credential_id", None):
        from backend.utilities.cbom_sources.fleet.models import CbomCredential

        found = session.get(CbomCredential, source.credential_id) if session is not None else None
        if found is not None and found.team_id == source.team_id:
            parts.append(f'team credential "{found.name}"')
    ctype = cfg.get("credential_type")
    if isinstance(ctype, str) and ctype:
        parts.append(_CREDENTIAL_TYPES.get(ctype, ctype.replace("_", " ")))
    vault = cfg.get("vault") if isinstance(cfg.get("vault"), dict) else None
    if vault and vault.get("path"):
        parts.append(f"{str(vault.get('provider') or 'vault').replace('_', ' ')} path {vault['path']}")
    if isinstance(cfg.get("role_arn"), str) and cfg["role_arn"]:
        parts.append(f"IAM role {cfg['role_arn']}")
    names = sorted(str(f) for f in (source.secret_fields or []) if isinstance(f, str))
    if names:
        parts.append("stored secrets (names): " + ", ".join(names))
    return "; ".join(parts) if parts else "none recorded"


def load_sources_result(session: Any, team_id: int, now: _dt.datetime | None = None) -> SourcesResult:
    from sqlmodel import select

    from backend.new_models import (
        CbomCollectedAsset,
        CbomCollectionSource,
    )
    from backend.utilities.cbom_sources import clause_evidence as CE
    from backend.utilities.cbom_sources import crypto_kb
    from backend.utilities.cbom_sources import identity as ID
    from backend.utilities.cbom_sources.classify import shown

    today = _aware(now or _dt.datetime.now(UTC)).replace(tzinfo=None)  # classify works in naive UTC
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    from backend.new_models import CbomScanNode
    from backend.utilities.cbom_sources.resource_identity import job_scope

    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    out = SourcesResult()
    history = collection_history(session, team_id, sources)
    for job, newer in latest_collections(session, team_id):
        source = sources.get(job.source_id or 0)
        network, machine = job_scope(job, nodes.get(job.node_id or 0), ID.job_source_ref(job, source))
        assets = [a for a in session.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.job_id == job.id,
            CbomCollectedAsset.attempt == job.attempts).order_by(CbomCollectedAsset.id)).all()
            if a.asset_type != "coverage"]
        collection = Collection(
            run_id=int(job.run_id), job_id=int(job.id), source_ref=ID.job_source_ref(job, source),
            source_name=ID.job_source_name(job, source), source_kind=(source.kind if source is not None else ""),
            observed_at=_aware(job.finished_at or job.created_at), asset_count=len(assets),
            endpoints_probed=sum(1 for a in assets if a.asset_type in NETWORK_TYPES),
            metadata=_source_metadata(source, job), info=collection_info(session, source, job),
            network_scope=network, machine_scope=machine,
            newer_attempt_job_id=int(newer.id) if newer is not None else None,
            newer_attempt_at=_aware(newer.finished_at or newer.created_at) if newer is not None else None,
            history=history.get(ID.job_source_ref(job, source), {}))
        out.collections.append(collection)
        for asset in assets:
            # its identity in its own source; link_certificates gives certificates their cross-source asset key
            own = ID.node_identity(asset)
            view = shown(asset, today)
            rule_codes = [c for c in view["finding_codes"] or [] if crypto_kb.has_clause_rules("node", c)]
            out.rows.append(SourcesRow(row=node_row(asset, collection, view), collection=collection,
                                       identity=f"node|{collection.source_ref}|{own}", node_type=asset.asset_type,
                                       target=asset.target, facts=dict(asset.facts or {}),
                                       asset_key=ID.stable_key("node", collection.source_ref, own),
                                       clause_evidence=CE.evidence_by_code(asset, rule_codes) if rule_codes else {},
                                       standards_parts=_parts(asset), code_impacts=code_impacts(view)))
    link_certificates(out.rows)
    link_resources(out.rows)
    remediation_statuses(session, team_id, out.rows)
    out.collections.sort(key=lambda c: (c.source_name.casefold(), c.source_ref))
    return out


def remediation_statuses(session: Any, team_id: int, rows: list[SourcesRow]) -> None:
    """Each row's ``remediation_status`` (open / in_progress / done / accepted_risk): the assignment of its RESOURCE,
    ``remediation_group.resolve`` over the group key and every copy's key of the rows that share its identity, the
    rule waves and the run list use too (review 6060688856 M4).  Every copy gets the same status, so the row
    "latest observation wins" keeps carries it whichever source that is."""
    from sqlmodel import select

    from backend.new_models import CbomRemediationAssignment
    from backend.utilities.cbom_sources import remediation_group as RG

    groups: dict[str, list[SourcesRow]] = {}
    group_keys: dict[str, set[str]] = {}
    for item in rows:
        groups.setdefault(item.identity, []).append(item)
        gk = RG.row_group_key(item.node_type, item.target, item.row.get("location"), item.facts,
                              network=item.collection.network_scope, machine=item.collection.machine_scope,
                              cluster=item.collection.source_ref)
        if gk:
            group_keys.setdefault(item.identity, set()).add(gk)
    keys = list(dict.fromkeys([*(item.asset_key for item in rows), *(k for ks in group_keys.values() for k in ks)]))
    found: dict[str, Any] = {}
    for start in range(0, len(keys), 500):
        for a in session.exec(select(CbomRemediationAssignment).where(
                CbomRemediationAssignment.team_id == team_id,
                CbomRemediationAssignment.asset_key.in_(keys[start:start + 500]))).all():  # type: ignore[attr-defined]
            found[a.asset_key] = a
    for ident, members in groups.items():
        own = members[0].asset_key
        resolved = RG.resolve(found, sorted(group_keys.get(ident, ())), [m.asset_key for m in members], own)
        for item in members:
            item.row["remediation_status"] = resolved.status or "open"


def _source_metadata(source: Any, job: Any) -> dict[str, Any]:
    """The source's metadata fields that hold a value: the source's own config, else the snapshot its run took
    (``jobs.metadata_snapshot``; a deleted source keeps only that)."""
    from backend.utilities.cbom_sources.kinds import METADATA_FIELDS

    own = (source.config or {}) if source is not None and isinstance(source.config, dict) else {}
    snap = (job.params or {}).get("metadata") if isinstance(getattr(job, "params", None), dict) else None
    snap = snap if isinstance(snap, dict) else {}
    out: dict[str, Any] = {}
    for name in METADATA_FIELDS:
        value = own.get(name) if own.get(name) not in (None, "") else snap.get(name)
        if value not in (None, ""):
            out[name] = value
    return out


def _parts(asset: Any) -> tuple[tuple[str, Any, Any], ...]:
    from backend.utilities.cbom_sources.classify import fact_obj, standards_parts

    try:
        return tuple(standards_parts(asset.asset_type, asset.algorithm, asset.key_size, fact_obj(asset.facts)))
    except Exception:  # standards never cost an asset its place in the view
        return ()


# ----------------------------------------------------------------------------- certificate correlation (CB-21)
def link_certificates(rows: list[SourcesRow]) -> int:
    """Correlate the certificate rows (``asset_keys.correlate_detail``): rows that share a link key, and disagree on
    nothing both carry, are one certificate whatever their DN spelling (a scan node, ACM, a Windows store, an IdP,
    CT logs) and carry the group's asset key as their identity, so "latest observation wins" counts it once.
    Returns the rows whose identity changed."""
    from backend.utilities.cbom_sources import asset_keys as AK

    certs = [i for i, item in enumerate(rows) if item.node_type in AK.CERT_TYPES
             or item.row.get("algorithm_type") == "certificate"]
    detail = AK.correlate_detail([rows[i] for i in certs])
    changed = 0
    for pos, index in enumerate(certs):
        key = detail.keys[pos]
        if not isinstance(key, str):
            continue  # no cross-source key: identified within its own source
        item = rows[index]
        item.aliases = detail.aliases[pos]
        if item.identity != key:
            item.identity = key
            changed += 1
    return changed


def link_resources(rows: list[SourcesRow]) -> int:
    """Give every row that names a resource two sources can both read (``resource_identity``: a cloud resource id,
    ``host:port``, or target + location) that cross-source identity, so "latest observation wins" counts it once
    (staging QA Q3-01: two IAM roles reading one AWS account printed every key, bucket and listener twice).  A key two
    rows of one collection share is ambiguous: those rows keep their own identity.  Idempotent; returns the rows whose
    identity changed."""
    from backend.utilities.cbom_sources.resource_identity import (
        PREFIX,
        resource_identity,
    )

    keys: dict[int, str] = {}
    seen: dict[tuple[str, str], int] = {}
    for index, item in enumerate(rows):
        if item.identity.startswith(PREFIX):
            continue
        if not item.identity.startswith("node|"):
            continue  # a certificate's cross-source key (link_certificates) or a hand-made identity
        key = resource_identity(item.node_type, item.target, item.row.get("location"), item.facts,
                                network=item.collection.network_scope, machine=item.collection.machine_scope,
                                cluster=item.collection.source_ref)
        if key is None:
            continue
        own = (item.collection.key, key)
        seen[own] = seen.get(own, 0) + 1
        keys[index] = key
    changed = 0
    for index, key in keys.items():
        item = rows[index]
        if seen[(item.collection.key, key)] > 1:
            continue
        item.identity = key
        changed += 1
    return changed


def _rank(item: SourcesRow) -> tuple:
    """The observation kept for an identity (``resource_identity.rank``, the same rule): a source that still exists
    before a deleted one, then an observation with a quantum verdict, then the newer collection, then the higher job
    id.  Latest observation wins, so a stale source never hides a fresh read (review 6060688856 M1); the plan and the
    ticket are the resource's, whichever row is kept (``remediation_group``)."""
    return (not is_deleted_source(item.collection), item.row.get("quantum_safe") is not None,
            item.collection.observed_at, item.collection.job_id)


# ----------------------------------------------------------------------------- latest observation wins
def code_cert_identities(scan_data: Any) -> dict[str, str]:
    """``bom_ref -> asset key`` (``asset_keys.code_certificate_key``) of the certificate components of one code
    scan's ``cbom_json`` (CN-only names: the key is the subject and issuer CN and notAfter)."""
    from backend.utilities.cbom_sources import asset_keys as AK

    data = scan_data if isinstance(scan_data, dict) else {}
    cbom = data.get("cbom_json") if isinstance(data.get("cbom_json"), dict) else {}
    out: dict[str, str] = {}
    for comp in cbom.get("components") or []:
        if not isinstance(comp, dict):
            continue
        crypto = comp.get("cryptoProperties") if isinstance(comp.get("cryptoProperties"), dict) else {}
        if crypto.get("assetType") != "certificate":
            continue
        props = {p.get("name"): p.get("value") for p in comp.get("properties") or [] if isinstance(p, dict)}
        cert = crypto.get("certificateProperties") if isinstance(crypto.get("certificateProperties"), dict) else {}
        ident = AK.code_certificate_key(props.get("crypto:subjectName") or cert.get("subjectName"),
                                        props.get("crypto:issuerName") or cert.get("issuerName"),
                                        props.get("crypto:notValidBefore") or cert.get("notValidBefore"),
                                        props.get("crypto:notValidAfter") or cert.get("notValidAfter"))
        ref = comp.get("bom-ref")
        if ident and isinstance(ref, str):
            out[ref] = ident
    return out


def code_row_identity(row: Mapping[str, Any], cert_ids: Mapping[str, str]) -> str | None:
    """The cross-scope identity of a code row, or None when it can only be the same as another code row."""
    if not isinstance(row, Mapping):
        return None
    if str(row.get("asset_type") or row.get("algorithm_type") or "").lower() != "certificate":
        return None
    return cert_ids.get(str(row.get("bom_ref") or ""))


@dataclass
class Resolution:
    """Which observations survive: Sources rows kept, and code observations (scan id, identity) dropped."""

    sources_rows: list[SourcesRow]
    dropped_code: set[tuple[int, str]]  # (scan id, identity) superseded by a newer Sources observation
    aliases: dict[str, str] = field(default_factory=dict)  # a code row's key -> the Sources certificate identity

    def code_kept(self, scan_id: int, identity: str | None) -> bool:
        return identity is None or (scan_id, identity) not in self.dropped_code

    def canonical(self, identity: str | None) -> str | None:
        """The identity a code row's key is counted under (the Sources certificate it shares a link key with)."""
        return self.aliases.get(identity, identity) if identity is not None else None

    @property
    def replaced_identities(self) -> set[str]:
        """Identities a code scan also holds, now counted from Sources (their code finding is the same asset): the
        code rows' keys and the Sources identities they map to."""
        return {ident for _scan_id, ident in self.dropped_code} | {
            self.canonical(ident) or ident for _scan_id, ident in self.dropped_code}

    def new_findings(self) -> list[SourcesRow]:
        """Sources findings that are not already a code-scan finding of the same asset (finding totals count each
        asset once: a code finding keeps its own status record)."""
        from backend.utilities.cbom_sources.cbom_rows import is_finding

        replaced = self.replaced_identities
        return [item for item in self.sources_rows if is_finding(item.row) and item.identity not in replaced]


def resolve(code_observations: Iterable[tuple[int, _dt.datetime, str]], rows: Iterable[SourcesRow]) -> Resolution:
    """Apply "latest observation wins". ``code_observations``: (scan id, created_at, identity) of code rows that
    have a cross-scope identity. Code-only identities are untouched (the code-scan views keep their own rules)."""
    newest_code: dict[str, _dt.datetime] = {}
    rows = list(rows)
    # a code row's key -> the Sources certificate that shares that link key (dropped when it names two certificates)
    aliases: dict[str, str] = {}
    ambiguous: set[str] = set()
    for item in rows:
        for alias in item.aliases:
            if aliases.setdefault(alias, item.identity) != item.identity:
                ambiguous.add(alias)
    for alias in ambiguous:
        del aliases[alias]
    def canonical(ident: str) -> str:
        # a code token is "<cnb key>+<cn key>" (asset_keys.code_certificate_key): the first that names a certificate
        for part in ident.split("+"):
            if part in aliases:
                return aliases[part]
        return ident

    code_list = [(scan_id, created, ident, canonical(ident)) for scan_id, created, ident in code_observations]
    for _scan_id, created, _ident, canon in code_list:
        at = _aware(created)
        if canon not in newest_code or at > newest_code[canon]:
            newest_code[canon] = at
    link_resources(rows)  # idempotent: rows built without load_sources_result get their resource identities too
    best: dict[str, SourcesRow] = {}
    members: dict[str, list[SourcesRow]] = {}  # only identities read more than once (50k rows: no list per row)
    for item in rows:
        held = best.get(item.identity)
        if held is None:
            best[item.identity] = item
            continue
        members.setdefault(item.identity, [held]).append(item)
        if _rank(item) > _rank(held):
            best[item.identity] = item
    for ident, group in members.items():  # the other sources that read it (deleted sources are never named)
        item = best[ident]
        if len(group) > 1:
            others = [m for m in sorted(group, key=_rank, reverse=True)
                      if m is not item and not is_deleted_source(m.collection)
                      and m.collection.key != item.collection.key]
            item.also_seen = tuple(dict.fromkeys(m.collection.label for m in others
                                                 if m.collection.label != item.collection.label))
            item.also_seen_keys = tuple(dict.fromkeys(m.collection.key for m in others))
    kept: list[SourcesRow] = []
    winners_at: dict[str, _dt.datetime] = {}
    for ident, item in best.items():
        code_at = newest_code.get(ident)
        if code_at is not None and code_at >= item.collection.observed_at:
            continue  # a code scan saw it at the same time or later: the code row is the one counted
        kept.append(item)
        winners_at[ident] = item.collection.observed_at
    dropped = {(scan_id, ident) for scan_id, _created, ident, canon in code_list if canon in winners_at}
    order = {id(item): index for index, item in enumerate(rows)}
    kept.sort(key=lambda item: order.get(id(item), 0))
    return Resolution(sources_rows=kept, dropped_code=dropped,
                      aliases={ident: canon for _s, _c, ident, canon in code_list if canon != ident})


__all__ = [
    "NETWORK_TYPES",
    "ORIGIN_CODE",
    "ORIGIN_SOURCES",
    "REMEDIATION_BUCKET",
    "Collection",
    "Resolution",
    "SourcesResult",
    "SourcesRow",
    "attempt_reason",
    "cert_identity",
    "code_cert_identities",
    "code_row_identity",
    "collection_history",
    "current_only",
    "is_deleted_source",
    "latest_collections",
    "latest_jobs",
    "link_certificates",
    "link_resources",
    "load_sources_result",
    "node_row",
    "origin_label",
    "read_nothing",
    "remediation_statuses",
    "resolve",
]
