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
    subject and issuer CN and notAfter (a code-scan row, which names CNs only). ``link_certificates`` correlates the
    Sources rows (any shared link key = one certificate, never two different serials); ``resolve`` maps a code row's
    key onto the Sources certificate that shares it. Any other asset is identified within its own source (a code row
    by its line-independent identity in its repository, a Sources asset by ``identity.node_identity`` in its
    source): a repository path and a host never describe the same asset, so they cannot overlap.
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

    @property
    def label(self) -> str:
        return f"Sources run #{self.run_id} · {self.source_name}"

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
    aliases: frozenset[str] = frozenset()  # every certificate link key of its group (asset_keys.correlate_detail)


# remediation status of a Sources finding (waves) -> the dashboard's finding status buckets
REMEDIATION_BUCKET = {"open": "not_started", "in_progress": "in_progress", "done": "fixed", "accepted_risk": "ignored"}


def _aware(moment: Any) -> _dt.datetime:
    if not isinstance(moment, _dt.datetime):
        return _dt.datetime(1970, 1, 1, tzinfo=UTC)
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


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


def node_identity_of(asset: Any, collection: Collection) -> str:
    """A certificate's cross-source asset key (before correlation), else the asset's identity in its own source."""
    from backend.utilities.cbom_sources import asset_keys as AK
    from backend.utilities.cbom_sources import identity as ID

    if asset.cdx_type == "certificate" or asset.asset_type in AK.CERT_TYPES:
        cross = AK.asset_key(asset)
        if isinstance(cross, str):
            return cross
    return f"node|{collection.source_ref}|{ID.node_identity(asset)}"


# ----------------------------------------------------------------------------- loading (the one DB read)
def latest_jobs(session: Any, team_id: int, *, limit: int = 2_000) -> list[Any]:
    """The newest successful collect job of each source (newest first)."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionJob, CbomCollectionSource
    from backend.utilities.cbom_sources import identity as ID

    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    latest: dict[str, Any] = {}
    for job in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.status == "success", CbomCollectionJob.run_id.is_not(None))  # type: ignore[union-attr]
            .order_by(CbomCollectionJob.finished_at.desc().nulls_last(),  # type: ignore[union-attr]
                      CbomCollectionJob.id.desc())  # type: ignore[union-attr]
            .limit(limit)).all():
        latest.setdefault(ID.job_source_ref(job, sources.get(job.source_id or 0)), job)
    return list(latest.values())


@dataclass
class SourcesResult:
    """What the team's Sources contribute: their latest collections and those collections' assets."""

    collections: list[Collection] = field(default_factory=list)
    rows: list[SourcesRow] = field(default_factory=list)

    @property
    def endpoints_probed(self) -> int:
        return sum(c.endpoints_probed for c in self.collections)


def load_sources_result(session: Any, team_id: int, now: _dt.datetime | None = None) -> SourcesResult:
    from sqlmodel import select

    from backend.new_models import CbomCollectedAsset, CbomCollectionSource, CbomRemediationAssignment
    from backend.utilities.cbom_sources import identity as ID
    from backend.utilities.cbom_sources.classify import shown

    today = _aware(now or _dt.datetime.now(UTC)).replace(tzinfo=None)  # classify works in naive UTC
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    out = SourcesResult()
    for job in latest_jobs(session, team_id):
        source = sources.get(job.source_id or 0)
        assets = [a for a in session.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.job_id == job.id,
            CbomCollectedAsset.attempt == job.attempts).order_by(CbomCollectedAsset.id)).all()
            if a.asset_type != "coverage"]
        collection = Collection(
            run_id=int(job.run_id), job_id=int(job.id), source_ref=ID.job_source_ref(job, source),
            source_name=ID.job_source_name(job, source), source_kind=(source.kind if source is not None else ""),
            observed_at=_aware(job.finished_at or job.created_at), asset_count=len(assets),
            endpoints_probed=sum(1 for a in assets if a.asset_type in NETWORK_TYPES))
        out.collections.append(collection)
        for asset in assets:
            # its identity in its own source; link_certificates gives certificates their cross-source asset key
            own = ID.node_identity(asset)
            out.rows.append(SourcesRow(row=node_row(asset, collection, shown(asset, today)), collection=collection,
                                       identity=f"node|{collection.source_ref}|{own}", node_type=asset.asset_type,
                                       target=asset.target, facts=dict(asset.facts or {}),
                                       asset_key=ID.stable_key("node", collection.source_ref, own)))
    # the remediation status a finding has on the Sources pages (waves): open / in_progress / done / accepted_risk
    keys = list(dict.fromkeys(item.asset_key for item in out.rows))
    status: dict[str, str] = {}
    for start in range(0, len(keys), 500):
        for a in session.exec(select(CbomRemediationAssignment).where(
                CbomRemediationAssignment.team_id == team_id,
                CbomRemediationAssignment.asset_key.in_(keys[start:start + 500]))).all():  # type: ignore[attr-defined]
            status[a.asset_key] = a.status or "open"
    for item in out.rows:
        item.row["remediation_status"] = status.get(item.asset_key, "open")
    link_certificates(out.rows)
    out.collections.sort(key=lambda c: (c.source_name.casefold(), c.source_ref))
    return out


# ----------------------------------------------------------------------------- certificate correlation (CB-21)
def link_certificates(rows: list[SourcesRow]) -> int:
    """Correlate the certificate rows (``asset_keys.correlate_detail``): rows that share a link key are one
    certificate whatever their DN spelling (a scan node, ACM, a Windows store, an IdP, CT logs) and carry the
    group's asset key as their identity, so "latest observation wins" counts it once. Returns the rows whose
    identity changed."""
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
    code_list = [(scan_id, created, ident, aliases.get(ident, ident)) for scan_id, created, ident in code_observations]
    for _scan_id, created, _ident, canon in code_list:
        at = _aware(created)
        if canon not in newest_code or at > newest_code[canon]:
            newest_code[canon] = at
    best: dict[str, SourcesRow] = {}
    for item in rows:
        held = best.get(item.identity)
        if held is None or (item.collection.observed_at, item.collection.job_id) > (
                held.collection.observed_at, held.collection.job_id):
            best[item.identity] = item
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
                      aliases={a: i for a, i in aliases.items() if a != i})


__all__ = ["Collection", "link_certificates", "NETWORK_TYPES", "REMEDIATION_BUCKET", "ORIGIN_CODE", "ORIGIN_SOURCES", "Resolution", "SourcesResult",
           "SourcesRow", "code_cert_identities", "code_row_identity", "latest_jobs",
           "load_sources_result", "node_row", "origin_label", "resolve"]
