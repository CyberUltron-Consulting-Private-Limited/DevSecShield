"""Engine step 3, the rest of "Correlate" (diagram; GAP-MATRIX E3, round-5 plan C4): an estate asset (CB-20 store,
CB-21 keys) with the business context it lives in and the code that uses it.

* **Owner, application, data classification** (``business``): the CURRENT metadata of every source that observes the
  asset (``owner``, ``application``, ``data_classification``, ``environment``, ``business_criticality``: the source
  form, or a CMDB import that wrote them, ``integrations/cmdb``); a deleted source's metadata as its latest job
  snapshotted it. Several sources may disagree: every value is listed, the field is named in ``conflicts``, and the
  data classification headline is the highest (public < internal < confidential < restricted: the data the asset
  protects is as sensitive as its most sensitive system). Read from the store and the source rows, per request.
* **Code and SBOM components that use it** (``links``): a library the store holds that an SBOM scan or a CBOM code scan
  lists (``sbom_link.match``: same purl, else same name and version, else same name), and a certificate a code scan
  holds (its CN + dates link keys, stored on the observation by ``agility_store``: CB-21 ``asset_keys``). Built from
  each code source's latest code scan and the newest SBOM scans, stored in ``cbomestatelink`` and rebuilt only when
  those scans or the estate change (``refresh``: a fingerprint compared on read, compare-and-set so one request
  rebuilds), never per request.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from collections import defaultdict
from typing import Any, Iterable, Sequence

import sqlalchemy as sa
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionSource,
    CbomEstateAsset,
    CbomEstateLink,
    CbomEstateLinkState,
    CbomEstateObservation,
    CbomEstateSource,
    Scan,
)

CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
FIELDS = ("owner", "application", "data_classification", "environment", "business_criticality")
LIBRARY_TYPES = ("crypto_library", "process_library")
CERT_TYPES = ("certificate", "k8s_certificate")
LINKS_PER_ASSET = 20
BATCH = 500
_EO, _ES, _EA = CbomEstateObservation.__table__, CbomEstateSource.__table__, CbomEstateAsset.__table__


def _chunks(items: Sequence[Any], size: int = BATCH) -> Iterable[Sequence[Any]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


# ---------------------------------------------------------------------------------------------- business context
def _metadata(source: CbomCollectionSource | None, job: CbomCollectionJob | None) -> dict[str, Any]:
    if source is not None:
        cfg = source.config if isinstance(source.config, dict) else {}
        return {f: cfg.get(f) for f in FIELDS}
    params = (job.params or {}) if job is not None else {}
    snap = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
    return {f: snap.get(f) for f in FIELDS}


def highest_classification(values: Iterable[str]) -> str | None:
    known = [v for v in values if v in CLASSIFICATIONS]
    return max(known, key=CLASSIFICATIONS.index) if known else None


def business(session: Session, team_id: int, keys: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Per asset key: its sources' current owner, application, data classification, environment and criticality."""
    if not keys:
        return {}
    pairs: dict[str, list[tuple[str, int | None, int | None, str | None]]] = defaultdict(list)
    for chunk in _chunks(sorted(set(keys))):
        for key, ref, source_id, job_id, name in session.execute(sa.select(
                _EO.c.asset_key, _EO.c.source_ref, _ES.c.source_id, _ES.c.latest_job_id, _ES.c.source_name)
                .select_from(_EO.join(_ES, sa.and_(_ES.c.team_id == _EO.c.team_id,
                                                   _ES.c.source_ref == _EO.c.source_ref)))
                .where(_EO.c.team_id == team_id, _EO.c.asset_key.in_(list(chunk)),
                       _EO.c.presence != "removed")).all():
            pairs[key].append((ref, source_id, job_id, name))
    source_ids = sorted({p[1] for v in pairs.values() for p in v if p[1]})
    sources = {s.id: s for chunk in _chunks(source_ids) for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id, CbomCollectionSource.id.in_(list(chunk)))).all()}  # type: ignore[union-attr]
    orphan_jobs = sorted({p[2] for v in pairs.values() for p in v if p[2] and p[1] not in sources})
    jobs = {j.id: j for chunk in _chunks(orphan_jobs) for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.id.in_(list(chunk)))).all()}  # type: ignore[union-attr]
    out: dict[str, dict[str, Any]] = {}
    for key in keys:
        per = []
        for ref, source_id, job_id, name in sorted(pairs.get(key, []), key=lambda p: p[0]):
            source = sources.get(source_id or 0)
            meta = _metadata(source, None if source is not None else jobs.get(job_id or 0))
            per.append({"source_ref": ref, "source_name": (source.name if source is not None else name) or ref,
                        **{f: (str(meta[f]).strip() or None) if meta.get(f) is not None else None for f in FIELDS}})
        values = {f: sorted({str(p[f]) for p in per if p[f]}) for f in FIELDS}
        out[key] = {
            "owners": values["owner"], "applications": values["application"],
            "data_classification": highest_classification(values["data_classification"]),
            "data_classifications": values["data_classification"], "environments": values["environment"],
            "criticality": values["business_criticality"],
            "conflicts": [f for f in FIELDS if len(values[f]) > 1],
            "unknown": [f for f in ("owner", "application", "data_classification") if not values[f]],
            "by_source": per[:10],
        }
    return out


# ---------------------------------------------------------------------------------------------- code / SBOM links
def _latest_code_scans(session: Session, team_id: int) -> list[tuple[int, str, str]]:
    """(scan id, source key, title) of each code source's newest successful CBOM code scan."""
    from backend.utilities.cbom_sources import identity as ID

    heads = session.exec(select(Scan.id, Scan.title, Scan.scan_metadata).where(
        Scan.team_id == team_id, Scan.scan_type == "cbom", Scan.scan_status == "success")
        .order_by(Scan.created_at.desc(), Scan.id.desc())).all()  # type: ignore[union-attr]
    chosen: dict[str, tuple[int, str, str]] = {}
    for scan_id, title, meta in heads:
        key, _label = ID.code_source_ref(meta, title or "", scan_id)
        chosen.setdefault(key, (int(scan_id), key, title or f"Scan #{scan_id}"))
    return list(chosen.values())


def fingerprint(session: Session, team_id: int) -> str:
    """What the stored links depend on, read without loading any scan: the newest SBOM scans and each code source's
    newest code scan (ids and update times), the library and certificate assets of the estate, and the certificate
    link keys the agility store has written."""
    from backend.utilities.cbom_sources.sbom_link import SBOM_SCANS_READ

    sbom = session.exec(select(Scan.id, Scan.last_updated).where(
        Scan.team_id == team_id, Scan.scan_type == "sbom_sca", Scan.scan_status == "success")
        .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(SBOM_SCANS_READ)).all()  # type: ignore[union-attr]
    code = sorted(s[0] for s in _latest_code_scans(session, team_id))
    assets = session.execute(sa.select(sa.func.count(), sa.func.max(_EA.c.updated_run_id)).where(
        _EA.c.team_id == team_id, _EA.c.asset_type.in_(LIBRARY_TYPES + CERT_TYPES))).one()
    keyed = session.execute(sa.select(sa.func.count()).select_from(_EO).where(
        _EO.c.team_id == team_id, _EO.c.cert_cnb_key.is_not(None))).scalar()
    doc = [[s[0], str(s[1])] for s in sbom], code, list(assets), keyed
    return hashlib.sha256(json.dumps(doc, default=str).encode()).hexdigest()


def _library_index(session: Session, team_id: int) -> list[dict[str, Any]]:
    """The estate's library assets with the package name, version and purl of their latest stored row."""
    from backend.utilities.cbom_sources import estate as ESTATE
    from backend.utilities.cbom_sources.sbom_link import ecosystem_of, library_purl

    keys = [k for k, in session.execute(sa.select(_EA.c.asset_key).where(
        _EA.c.team_id == team_id, _EA.c.asset_type.in_(LIBRARY_TYPES), _EA.c.presence != "removed")).all()]
    out = []
    for chunk in _chunks(keys):
        latest = ESTATE.latest_rows(session, team_id, list(chunk))
        ids = {k: (latest.get(k, {}).get("latest") or {}).get("asset_id") for k in chunk}
        rows = {r.id: r for r in session.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.team_id == team_id,
            CbomCollectedAsset.id.in_([i for i in ids.values() if i]))).all()}  # type: ignore[union-attr]
        for key in chunk:
            row = rows.get(ids.get(key) or 0)
            if row is None:
                continue
            facts = row.facts if isinstance(row.facts, dict) else {}
            name = str(facts.get("package") or row.name or row.algorithm or "")[:255]
            version = str(facts.get("version") or "")
            own = str(facts.get("purl") or "")
            purl = own[:512] if own.startswith(("pkg:deb/", "pkg:apk/", "pkg:rpm/")) else \
                library_purl(name, version, ecosystem_of(facts.get("ecosystem") or facts.get("language")))
            if name:
                out.append({"key": key, "name": name, "version": version, "purl": purl})
    return out


def _code_index(scans: list[tuple[int, str, str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Code scans as ``sbom_link.match`` reads SBOM scans: the library components of each one's CycloneDX."""
    from backend.utilities.cbom_sources.sbom_link import with_library_purls

    out = []
    for scan_id, _key, title, data in scans:
        bom = with_library_purls(data.get("cbom_json") if isinstance(data.get("cbom_json"), dict) else {})
        comps: dict[str, tuple[str, str, str]] = {}
        for comp in bom.get("components") or []:
            if not isinstance(comp, dict) or comp.get("type") not in ("library", "framework"):
                continue
            props = {p.get("name"): p.get("value") for p in comp.get("properties") or [] if isinstance(p, dict)}
            if comp.get("type") == "framework" and props.get("crypto:role") != "library":
                continue
            name, version = str(comp.get("name") or ""), str(comp.get("version") or props.get("crypto:version") or "")
            if "@" in name and not version:
                name, version = name.rsplit("@", 1)
            if name:
                comps.setdefault(f"{name}@{version}", (name, version, str(comp.get("purl") or "").lower()))
        out.append({"scan_id": scan_id, "title": title, "components": list(comps.values())})
    return out


def _cert_links(session: Session, team_id: int, scans: list[tuple[int, str, str, dict[str, Any]]]
                ) -> list[dict[str, Any]]:
    """A code scan's certificate rows on the estate certificate they name (one asset key per link key, else none)."""
    from backend.utilities.cbom_sources import collections_view as CV

    wanted: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
    for scan_id, _key, title, data in scans:
        cert_ids = CV.code_cert_identities(data)
        for row in data.get("results") or []:
            token = CV.code_row_identity(row, cert_ids) if isinstance(row, dict) else None
            if token:
                label = str(row.get("title") or row.get("location") or "certificate")[:255]
                for part in token.split("+"):
                    wanted[part].append((scan_id, title, label))
    if not wanted:
        return []
    found: dict[str, set[str]] = defaultdict(set)
    parts = sorted(wanted)
    for chunk in _chunks(parts):
        for key, cnb, cn in session.execute(sa.select(_EO.c.asset_key, _EO.c.cert_cnb_key, _EO.c.cert_cn_key).where(
                _EO.c.team_id == team_id, _EO.c.presence != "removed",
                sa.or_(_EO.c.cert_cnb_key.in_(list(chunk)), _EO.c.cert_cn_key.in_(list(chunk))))).all():
            for link in (cnb, cn):
                if link in wanted:
                    found[link].add(key)
    out = []
    seen: set[tuple] = set()
    for link, keys in found.items():
        if len(keys) != 1:
            continue  # a link key two estate certificates share names neither
        key = next(iter(keys))
        for scan_id, title, label in wanted[link]:
            if (key, scan_id, label) in seen:
                continue
            seen.add((key, scan_id, label))
            out.append({"asset_key": key, "kind": "code", "scan_id": scan_id, "scan_title": title,
                        "component": label, "purl": None, "match": "cert_key"})
    return out


def build_links(session: Session, team_id: int) -> list[dict[str, Any]]:
    """Every link of the team (see the module docstring), computed from the scans and the store."""
    from backend.utilities.cbom_sources.sbom_link import match, sbom_index

    code_heads = _latest_code_scans(session, team_id)
    scans = []
    for scan_id, key, title in code_heads:
        data = session.exec(select(Scan.scan_data).where(Scan.id == scan_id, Scan.team_id == team_id)).first()
        scans.append((scan_id, key, title, data if isinstance(data, dict) else {}))
    libraries = _library_index(session, team_id)
    links: list[dict[str, Any]] = []
    if libraries:
        for kind, index in (("sbom", sbom_index(session, team_id)), ("code", _code_index(scans))):
            if not index:
                continue
            for lib in libraries:
                for m in match(index, name=lib["name"], version=lib["version"], purl=lib["purl"])[:LINKS_PER_ASSET]:
                    links.append({"asset_key": lib["key"], "kind": kind, "scan_id": m["scan_id"],
                                  "scan_title": (m.get("scan_title") or None), "component": m["component"][:255],
                                  "purl": (m.get("purl") or None), "match": m["match"]})
    links.extend(_cert_links(session, team_id, scans))
    for link in links:
        link["scan_title"] = str(link["scan_title"])[:255] if link["scan_title"] else None
        link["purl"] = str(link["purl"])[:512] if link["purl"] else None
    return links


def refresh(session: Session, team_id: int, *, force: bool = False) -> bool:
    """Rebuild the team's stored links when their inputs changed (compare-and-set on the fingerprint, so concurrent
    readers rebuild once). Returns True when it rebuilt. The caller commits."""
    fp = fingerprint(session, team_id)
    state = session.exec(select(CbomEstateLinkState).where(CbomEstateLinkState.team_id == team_id)).first()
    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    table = CbomEstateLinkState.__table__
    if state is None:
        try:
            with session.begin_nested():
                session.execute(sa.insert(table).values(team_id=team_id, fingerprint="", links=0, refreshed_at=now))
        except sa.exc.IntegrityError:
            pass  # another request created it
        old = ""
    else:
        if state.fingerprint == fp and not force:
            return False
        old = state.fingerprint
    won = session.execute(sa.update(table).where(table.c.team_id == team_id, table.c.fingerprint == old)
                          .values(fingerprint=fp, refreshed_at=now)).rowcount
    if won != 1:
        return False  # another request is rebuilding the same inputs
    links = build_links(session, team_id)
    lt = CbomEstateLink.__table__
    session.execute(sa.delete(lt).where(lt.c.team_id == team_id))
    for chunk in _chunks(links, 1000):
        session.execute(sa.insert(lt), [{"team_id": team_id, **link} for link in chunk])
    session.execute(sa.update(table).where(table.c.team_id == team_id).values(links=len(links)))
    session.expire_all()
    return True


def refresh_safely(session: Session, team_id: int) -> str:
    """``refresh`` that never fails a read: "rebuilt", "current" or "error" (the stored links stay)."""
    from backend.utilities.cbom_sources.common import log

    try:
        with session.begin_nested():
            rebuilt = refresh(session, team_id)
        session.commit()
        return "rebuilt" if rebuilt else "current"
    except Exception as exc:
        log("estate links refresh FAILED", team=team_id, error=type(exc).__name__)
        session.rollback()
        return "error"


def links(session: Session, team_id: int, keys: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for chunk in _chunks(sorted(set(keys))):
        for row in session.exec(select(CbomEstateLink).where(
                CbomEstateLink.team_id == team_id, CbomEstateLink.asset_key.in_(list(chunk)))  # type: ignore[attr-defined]
                .order_by(CbomEstateLink.kind, CbomEstateLink.scan_id, CbomEstateLink.component)).all():
            out[row.asset_key].append({"kind": row.kind, "scan_id": row.scan_id, "scan_title": row.scan_title,
                                       "component": row.component, "purl": row.purl, "match": row.match})
    return out


def correlation(session: Session, team_id: int, keys: Sequence[str], *, refreshed: bool = False
                ) -> dict[str, dict[str, Any]]:
    """Per key: ``business`` plus ``links`` (refreshing the stored links first unless the caller did)."""
    status = "current" if refreshed else refresh_safely(session, team_id)
    biz = business(session, team_id, keys)
    lnk = links(session, team_id, keys)
    return {k: {**biz.get(k, {}), "links": lnk.get(k, []), "links_state": status} for k in keys}


def estate_key_of_row(session: Session, team_id: int, row: CbomCollectedAsset) -> str | None:
    """The estate asset key of a collected row (its source and observation key), or None when the store has not
    written its run yet."""
    from backend.utilities.cbom_sources import asset_keys as AK
    from backend.utilities.cbom_sources import identity as ID

    job = session.get(CbomCollectionJob, row.job_id) if row.job_id else None
    source = session.get(CbomCollectionSource, row.source_id) if row.source_id else None
    if job is None or job.team_id != team_id:
        return None
    ref = ID.job_source_ref(job, source if source is not None and source.team_id == team_id else None)
    okey = AK.observation_key(row, ref)
    found = session.execute(sa.select(_EO.c.asset_key).where(
        _EO.c.team_id == team_id, _EO.c.source_ref == ref, _EO.c.observation_key == okey[:40])).first()
    return found[0] if found else None


__all__ = ["CLASSIFICATIONS", "FIELDS", "build_links", "business", "correlation", "estate_key_of_row",
           "fingerprint", "highest_classification", "links", "refresh", "refresh_safely"]
