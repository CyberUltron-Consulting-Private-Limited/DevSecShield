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
  * Identity across code scans and Sources: a certificate is the same certificate when its subject CN, issuer CN,
    notBefore and notAfter agree (``cert_identity``); the repository copy of a certificate and the one an endpoint
    presents are one asset. Sources rows that share a link key (``cert_link_keys``: the DER fingerprint, or the serial
    and notAfter day) are one certificate too, whatever their DN spelling: ACM's Issuer "Amazon", a SAN-only
    certificate, a CT log's precertificate (``link_certificates``, the CB-21 slice CT discovery needs). Any other asset is identified within its own source (a code row by its line-independent
    identity in its repository, a Sources asset by ``identity.node_identity`` in its source): a repository path and a
    host never describe the same asset, so they cannot overlap.
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
    """Cross-scope certificate identity, or None when the subject or notAfter is unknown (no safe match)."""
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
    facts = asset.facts if isinstance(asset.facts, dict) else {}
    if asset.cdx_type == "certificate" or asset.asset_type in ("certificate", "k8s_certificate"):
        cross = cert_identity(facts.get("subject"), facts.get("issuer"), facts.get("not_before"), facts.get("not_after"))
        if cross:
            return cross
    from backend.utilities.cbom_sources import identity as ID

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
            out.rows.append(SourcesRow(row=node_row(asset, collection, shown(asset, today)), collection=collection,
                                       identity=node_identity_of(asset, collection), node_type=asset.asset_type,
                                       target=asset.target, facts=dict(asset.facts or {}),
                                       asset_key=ID.stable_key("node", collection.source_ref, ID.node_identity(asset))))
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


# ----------------------------------------------------------------------------- certificate link keys (CB-21 slice)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MIN_SERIAL_HEX = 16  # 64 bits: public CAs use at least that much randomness; small private serials never link


def cert_link_keys(facts: Mapping[str, Any]) -> set[str]:
    """Keys that prove two observations are one certificate whatever their DN spelling: ``fp:<sha256 of the DER>`` and
    ``sn:<serial>|<notAfter day>``.  ACM reports Issuer "Amazon" and no DER; a SAN-only certificate has no CN; a
    precertificate in a CT log has no final fingerprint.  Each of them still shares one of these keys."""
    keys: set[str] = set()
    fp = str(facts.get("fingerprint_sha256") or "").strip().lower().replace(":", "")
    if _HEX64.match(fp):
        keys.add("fp:" + fp)
    serial = re.sub(r"[^0-9a-f]", "", str(facts.get("serial") or "").lower()).lstrip("0")
    day = _stamp(facts.get("not_after"))[:10]
    if len(serial) >= _MIN_SERIAL_HEX and len(day) == 10:
        keys.add(f"sn:{serial}|{day}")
    return keys


def _canonical(items: list[SourcesRow]) -> str:
    """One identity for observations of the same certificate: a DN identity read from a parsed DN (an issuer with
    ``CN=``; not ACM's bare "Amazon"), so code-scan rows, which carry DN identities, still match; else any DN identity;
    else the fingerprint."""
    dn = sorted({i.identity for i in items if i.identity.startswith("cert|") and "cn=" in str(i.facts.get("issuer") or "").lower()})
    if dn:
        return dn[0]
    dn = sorted({i.identity for i in items if i.identity.startswith("cert|")})
    if dn:
        return dn[0]
    fps = sorted(k for i in items for k in cert_link_keys(i.facts) if k.startswith("fp:"))
    return "cert" + fps[0] if fps else sorted(i.identity for i in items)[0]


def link_certificates(rows: list[SourcesRow]) -> int:
    """Give every group of certificate rows that share a link key one identity (so "latest observation wins" counts
    the certificate once across a scan node, ACM, an IdP and CT logs).  Returns the rows whose identity changed."""
    parent: dict[int, int] = {}

    def find(i: int) -> int:
        while parent.setdefault(i, i) != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    certs = [i for i, item in enumerate(rows) if item.node_type in ("certificate", "k8s_certificate")
             or item.row.get("algorithm_type") == "certificate"]
    for index in certs:
        for key in cert_link_keys(rows[index].facts):
            if key in owner:
                parent[find(index)] = find(owner[key])
            else:
                owner[key] = index
    groups: dict[int, list[int]] = {}
    for index in certs:
        groups.setdefault(find(index), []).append(index)
    changed = 0
    for members in groups.values():
        items = [rows[i] for i in members]
        if len({item.identity for item in items}) < 2:
            continue
        canonical = _canonical(items)
        for item in items:
            if item.identity != canonical:
                item.identity = canonical
                changed += 1
    return changed


# ----------------------------------------------------------------------------- latest observation wins
def code_cert_identities(scan_data: Any) -> dict[str, str]:
    """``bom_ref -> cert_identity`` for the certificate components of one code scan's ``cbom_json``."""
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
        ident = cert_identity(props.get("crypto:subjectName") or cert.get("subjectName"),
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

    def code_kept(self, scan_id: int, identity: str | None) -> bool:
        return identity is None or (scan_id, identity) not in self.dropped_code

    @property
    def replaced_identities(self) -> set[str]:
        """Identities a code scan also holds, now counted from Sources (their code finding is the same asset)."""
        return {ident for _scan_id, ident in self.dropped_code}

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
    code_list = list(code_observations)
    rows = list(rows)
    for _scan_id, created, ident in code_list:
        at = _aware(created)
        if ident not in newest_code or at > newest_code[ident]:
            newest_code[ident] = at
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
    dropped = {(scan_id, ident) for scan_id, _created, ident in code_list if ident in winners_at}
    order = {id(item): index for index, item in enumerate(rows)}
    kept.sort(key=lambda item: order.get(id(item), 0))
    return Resolution(sources_rows=kept, dropped_code=dropped)


__all__ = ["Collection", "cert_link_keys", "link_certificates", "NETWORK_TYPES", "REMEDIATION_BUCKET", "ORIGIN_CODE", "ORIGIN_SOURCES", "Resolution", "SourcesResult",
           "SourcesRow", "cert_identity", "code_cert_identities", "code_row_identity", "latest_jobs",
           "load_sources_result", "node_row", "origin_label", "resolve"]
