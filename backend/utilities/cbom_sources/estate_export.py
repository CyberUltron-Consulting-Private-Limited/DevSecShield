"""The team's estate CBOM (CB-26; DEVILS-ADVOCATE CB-26, diagram output 01 at estate level).

One CycloneDX 1.6 document (JSON or XML) for the whole team, built from the CB-20 estate store: ONE component per
estate asset key (CB-21 cross-source key), so an asset four collectors see is one component, and the component count
is the number of distinct keys (DA-8). Each component is the run export's own component (``inventory._component``:
the same crypto properties, provenance, PQC class and finding codes) of the key's latest stored row
(``estate.latest_rows``: a present observation first, else the newest), plus:

* ``zs:estate_key``, ``zs:presence`` (present | not_read, with ``zs:presence_reason``), ``zs:sources`` (how many sources
  observe it) and one ``zs:observed_by`` per source;
* the CURRENT quantum risk grade from the team's register (``zs:q_grade`` / ``zs:q_label`` / ``zs:q_reason``, team view:
  PLAN §2.3), or ``none`` when the register has no row for the key yet.

What the export includes (N4): every key the store holds that is not ``removed``. A source whose latest collection
was partial because a range had a never-scan entry still contributes everything it read (``present``); what it did not
read keeps its last known state as ``not_read``. Removed assets are not listed.

Filters (one rule for every surface): ``application`` (the source's application now), ``source`` (source ref) and
``type`` (asset type). The VEX (``vulnerabilities``) is the run export's analysis over the listed rows (CB-22), with
grades from the register. At most ``inventory.EXPORT_CAP`` components; the metadata always carries the exact count and
``zs:truncated``. The document is written one component at a time (``inventory.write_cyclonedx``'s writer), so memory
holds one batch of keys, not the document.

Certificate hygiene (diagram output 04, #263 ``cert_hygiene``; #126 comment 6880488906): every certificate component
whose estate key the hygiene view knows carries ``zeroshield:cert:flags`` (space-separated: unmanaged, prober_only,
orphaned, no_owner, expired_served, stale; only when it has a flag) and ``zeroshield:cert:not_seen_runs``. The module is
imported when present (it ships in #263): until then, and if building the view fails, the metadata says
``zs:cert_hygiene`` ``not_available`` / ``error`` and no component carries the flags.

Correlation (engine step 3, ``estate_links``): every component carries ``zs:owner`` and ``zs:application`` (one per
value its sources name), ``zs:data_classification`` (the most sensitive of its systems) and one ``zs:used_by_sbom`` /
``zs:used_by_code`` per scan component that uses it; the metadata says ``zs:correlation`` ``included`` (or ``error``
when the stored links could not be refreshed: the last stored ones are used).

Signature (D11, audit A-01): the JSON carries an embedded JSF ES256 signature (``bom_signing``), and the route sends a
detached ES256 signature of the exact bytes of either format (``X-ZS-Signature``) with their SHA-256; the public key is
published at ``GET /{team}/bom-signing-keys``. ``zs:signature`` in the metadata names the key (``unsigned`` only when
the deployment has no signing key).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterator

import sqlalchemy as sa
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionSource,
    CbomEstateAsset,
    CbomEstateObservation,
    CbomRiskRegister,
)
from backend.utilities.cbom_sources.common import iso_z

BATCH = 500
_EA = CbomEstateAsset.__table__
_EO = CbomEstateObservation.__table__


@dataclass
class Filters:
    application: str | None = None
    source: str | None = None
    type: str | None = None

    def public(self) -> dict[str, str]:
        return {k: v for k, v in (("application", self.application), ("source", self.source), ("type", self.type))
                if v}


@dataclass
class _State:
    rows: list[CbomCollectedAsset] = field(default_factory=list)
    views: dict[int, dict[str, Any]] = field(default_factory=dict)
    grades: dict[int, str | None] = field(default_factory=dict)


def _sources_of(session: Session, team_id: int, application: str | None) -> list[str] | None:
    """Source refs whose application (the source's setting now) is ``application``; None = no application filter."""
    if not application:
        return None
    wanted = application.strip().casefold()
    refs = []
    for s in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all():
        cfg = s.config if isinstance(s.config, dict) else {}
        if str(cfg.get("application") or "").strip().casefold() == wanted and s.source_uid:
            refs.append(s.source_uid)
    return refs


def _key_query(team_id: int, f: Filters, refs: list[str] | None):
    q = sa.select(_EA.c.asset_key).where(_EA.c.team_id == team_id, _EA.c.presence != "removed")
    if f.type:
        q = q.where(_EA.c.asset_type == f.type)
    sources = [f.source] if f.source else None
    if refs is not None:
        sources = [r for r in refs if sources is None or r in sources]
    if sources is not None:
        q = q.where(sa.exists().where(_EO.c.team_id == _EA.c.team_id, _EO.c.asset_key == _EA.c.asset_key,
                                      _EO.c.source_ref.in_(sources or [""])))
    return q


def count(session: Session, team_id: int, f: Filters) -> int:
    refs = _sources_of(session, team_id, f.application)
    sub = _key_query(team_id, f, refs).subquery()
    return int(session.execute(sa.select(sa.func.count()).select_from(sub)).scalar_one())


def _keys(session: Session, team_id: int, f: Filters, limit: int) -> Iterator[list[str]]:
    refs = _sources_of(session, team_id, f.application)
    after, left = "", limit
    while left > 0:
        batch = list(session.execute(_key_query(team_id, f, refs).where(_EA.c.asset_key > after)
                                     .order_by(_EA.c.asset_key).limit(min(BATCH, left))).scalars())
        if not batch:
            return
        yield batch
        after, left = batch[-1], left - len(batch)


def cert_hygiene(session: Session, team_id: int, now: _dt.datetime) -> tuple[dict[str, Any], str]:
    """(estate key -> hygiene ``Cert``, status) from #263's ``cert_hygiene.cached``: ``included`` (with the view's
    state when not ready: ``included:pending`` / ``included:stale``), ``not_available`` (the module is not deployed)
    or ``error`` (building the view failed: logged, the export goes on without the flags)."""
    import importlib

    from backend.utilities.cbom_sources.common import log

    try:
        module = importlib.import_module("backend.utilities.cbom_sources.cert_hygiene")
    except ImportError:
        return {}, "not_available"
    try:
        moment = now if now.tzinfo is not None else now.replace(tzinfo=_dt.timezone.utc)
        view = module.cached(session, team_id, now=moment)
        state = getattr(view, "state", "ready")
        return {c.key: c for c in view.certs}, "included" if state == "ready" else f"included:{state}"
    except Exception as exc:
        log("estate export cert hygiene FAILED", team=team_id, error=type(exc).__name__)
        return {}, "error"


def _hygiene_properties(cert: Any) -> list[dict[str, str]]:
    out = []
    if cert.flags:
        out.append({"name": "zeroshield:cert:flags", "value": " ".join(cert.flags)})
    out.append({"name": "zeroshield:cert:not_seen_runs", "value": str(int(cert.not_seen_runs or 0))})
    return out


def _correlation_properties(c: dict[str, Any]) -> list[dict[str, str]]:
    """Engine step 3 on a component: its sources' owners and applications (one property each), the data
    classification of the most sensitive system it sits in, and the code / SBOM components that use it."""
    out = [{"name": "zs:owner", "value": v[:255]} for v in c.get("owners", [])]
    out += [{"name": "zs:application", "value": v[:255]} for v in c.get("applications", [])]
    if c.get("data_classification"):
        out.append({"name": "zs:data_classification", "value": c["data_classification"]})
    for link in c.get("links", []):
        out.append({"name": f"zs:used_by_{link['kind']}",
                    "value": f"scan {link['scan_id']}: {link['component']} ({link['match']})"[:512]})
    return out


def _document(session: Session, team_id: int, f: Filters, now: _dt.datetime
              ) -> tuple[dict[str, Any], Iterator[dict[str, Any]], Any]:
    from backend.utilities.build_info import build_sha, build_version
    from backend.utilities.cbom_sources import crypto_kb, estate
    from backend.utilities.cbom_sources import inventory as INV
    from backend.utilities.cbom_sources import provenance as PROV
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.cbom_sources import vex_semantics as VEX
    from backend.utilities.cbom_sources.classify import shown

    today = now if now.tzinfo is None else now.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    total = count(session, team_id, f)
    cap = INV.EXPORT_CAP
    stale = estate.stale_status(session, team_id)
    hygiene, hygiene_status = cert_hygiene(session, team_id, now)
    from backend.utilities.cbom_sources import estate_links as LINKS

    links_status = LINKS.refresh_safely(session, team_id)  # engine step 3: stored code / SBOM links, current
    grades = {g: n for g, n in session.execute(sa.select(CbomRiskRegister.q_grade, sa.func.count()).where(
        CbomRiskRegister.team_id == team_id).group_by(CbomRiskRegister.q_grade)).all()}
    digest = hashlib.sha256(json.dumps([team_id, f.public(), total, crypto_kb.version(), QG.GRADE_MODEL_VERSION],
                                       sort_keys=True).encode()).hexdigest()
    head = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        # a new serial per export: the estate changes with every run, so two exports are two BOMs
        "serialNumber": f"urn:uuid:{_uuid(digest, now)}", "version": 1,
        "metadata": {
            "timestamp": iso_z(now),
            "tools": {"components": [{"type": "application", "name": "ZeroShield CBOM Sources",
                                      "version": build_version()}]},
            "component": {"type": "application", "bom-ref": f"zs-estate-team-{team_id}",
                          "name": f"Team {team_id} cryptographic estate"},
            "properties": [
                {"name": "zs:scope", "value": "estate"},
                {"name": "zs:team_id", "value": str(team_id)},
                # the three counts the documents reconcile (SOW audit A-09): distinct assets of the estate; asset
                # components in this file (one per distinct asset, capped); the certificate part components
                # (zs:part_of = certificate: signature algorithms, public keys) come on top and are not assets
                {"name": "zs:asset_count", "value": str(total)},
                {"name": "zs:asset_components", "value": str(min(total, cap))},
                {"name": "zs:count_basis", "value": "zs:asset_count = distinct assets of the estate; "
                                                    "zs:asset_components = asset components in this file; "
                                                    "components with zs:part_of = certificate are parts of "
                                                    "certificates, not assets"},
                {"name": "zs:truncated", "value": str(total > cap).lower()},
                *[{"name": f"zs:filter:{k}", "value": v} for k, v in f.public().items()],
                {"name": "zs:kb_version", "value": crypto_kb.version()},
                {"name": "zs:build", "value": build_sha()},
                {"name": "zs:vex_rules", "value": VEX.VEX_RULES},
                {"name": "zs:grade_model_version", "value": QG.GRADE_MODEL_VERSION},
                {"name": "zs:grade_source", "value": "register (current grade, team inputs now)"},
                *[{"name": f"zs:register_q_count:{g or 'none'}", "value": str(n)} for g, n in sorted(
                    grades.items(), key=lambda kv: str(kv[0]))],
                {"name": "zs:estate_stale", "value": "true" if stale and stale.get("stale") else "false"},
                {"name": "zs:signature", "value": _signature_value()},
                {"name": "zs:cert_hygiene", "value": hygiene_status},
                {"name": "zs:correlation", "value": "error" if links_status == "error" else "included"},
            ],
        },
    }
    state = _State()

    def components() -> Iterator[dict[str, Any]]:
        parts = INV.CertificateParts()
        shared: dict[tuple, list] = {}
        names: dict[int, str] = {}
        provs: dict[int, Any] = {}
        for keys in _keys(session, team_id, f, cap):
            latest = estate.latest_rows(session, team_id, keys)
            meta = {a.asset_key: a for a in session.exec(select(CbomEstateAsset).where(
                CbomEstateAsset.team_id == team_id, CbomEstateAsset.asset_key.in_(keys))).all()}  # type: ignore[attr-defined]
            reg = {r.item_key: r for r in session.exec(select(CbomRiskRegister).where(
                CbomRiskRegister.team_id == team_id, CbomRiskRegister.item_key.in_(keys))).all()}  # type: ignore[attr-defined]
            ids = {k: (latest.get(k, {}).get("latest") or {}).get("asset_id") for k in keys}
            corr = LINKS.correlation(session, team_id, keys, refreshed=True)
            rows = {r.id: r for r in session.exec(select(CbomCollectedAsset).where(
                CbomCollectedAsset.team_id == team_id,
                CbomCollectedAsset.id.in_([i for i in ids.values() if i]))).all()}  # type: ignore[union-attr]
            new_jobs = {r.job_id for r in rows.values()} - set(provs)
            if new_jobs:
                jobs = list(session.exec(select(CbomCollectionJob).where(CbomCollectionJob.id.in_(sorted(new_jobs)))).all())  # type: ignore[union-attr]
                names.update(INV._source_names(session, team_id, jobs))
                provs.update(PROV.load(session, team_id, jobs))
                for j in jobs:
                    names.setdefault(-(j.id or 0), (j.params or {}).get("source_name") or "")
            for key in keys:
                row = rows.get(ids.get(key) or 0)
                if row is None:
                    continue
                view = shown(row, today)
                state.rows.append(row)
                state.views[row.id] = view  # type: ignore[index]
                r = reg.get(key)
                state.grades[row.id] = r.q_grade if r is not None else None  # type: ignore[index]
                comp = INV._component(row, names.get(row.source_id or 0) or names.get(-row.job_id), view,
                                      provs.get(row.job_id), shared, parts)
                a = meta.get(key)
                obs = sorted((latest.get(key) or {}).get("observations", {}).values(), key=lambda o: o["source_ref"])
                comp["properties"] = [
                    {"name": "zs:estate_key", "value": key},
                    {"name": "zs:presence", "value": a.presence if a is not None else "present"},
                    *([{"name": "zs:presence_reason", "value": a.presence_reason[:255]}]
                      if a is not None and a.presence_reason else []),
                    {"name": "zs:sources", "value": str(len(obs))},
                    *[{"name": "zs:observed_by", "value": f"{o['source_ref']}:{o['presence']}"} for o in obs],
                    {"name": "zs:q_grade", "value": (r.q_grade or "none") if r is not None else "none"},
                    *([{"name": "zs:q_label", "value": QG.LABELS[r.q_grade]}] if r is not None and r.q_grade else []),
                    *([{"name": "zs:q_reason", "value": r.q_reason}] if r is not None else []),
                    *[p for p in comp["properties"] if p["name"] not in ("zs:q_grade", "zs:q_label", "zs:q_reason")],
                    *(_hygiene_properties(hygiene[key]) if key in hygiene else []),
                    *_correlation_properties(corr.get(key) or {}),
                ]
                yield comp
        yield from parts.components()

    def vulns() -> list[dict[str, Any]]:
        return INV.vulnerabilities(state.rows, state.views, grade_of=lambda row: state.grades.get(row.id),
                                   grade_meta={"model_version": QG.GRADE_MODEL_VERSION, "inputs_digest": "register"})

    return head, components(), vulns


def _uuid(digest: str, now: _dt.datetime) -> str:
    import uuid

    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"zeroshield:estate:{digest}:{iso_z(now)}"))


def _signature_value() -> str:
    from backend.utilities.cbom_sources import bom_signing as SIGN

    try:
        return f"JSF {SIGN.ALG} {SIGN.keyring().active.kid} (XML: detached, X-ZS-Signature)"
    except SIGN.SigningUnavailable:
        return "unsigned"


def write(session: Session, team_id: int, f: Filters, now: _dt.datetime, fmt: str, out: BinaryIO) -> None:
    """Write the estate CBOM to ``out`` (JSON with its embedded JSF signature, or XML), one component at a time, with
    its ``dependencies`` (``cdx_write``)."""
    from backend.utilities.cbom_sources import cdx_write

    head, components, vulns = _document(session, team_id, f, now)
    cdx_write.write(out, head, components, vulns, fmt)


def document(session: Session, team_id: int, f: Filters, now: _dt.datetime) -> dict[str, Any]:
    from backend.utilities.cbom_sources import cdx_write

    return cdx_write.document(*_document(session, team_id, f, now))


__all__ = ["Filters", "count", "write", "document", "cert_hygiene", "BATCH"]
