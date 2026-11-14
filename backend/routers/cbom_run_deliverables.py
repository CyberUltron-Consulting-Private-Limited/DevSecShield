"""CBOM Sources run deliverables (CB-38 PR-8): VEX, signature, PDF report and evidence pack of one run, the four the
code-scan page offers (``routers/certin.py``). Built by ``utilities/cbom_sources/run_deliverables.py``; see its
docstring for the VEX analysis table and why the run CBOM JSON is byte-stable.

Every route: team membership (``authorize``), the run loaded with ``_get_owned`` (404 for another team's run), no
credit charge, the CBOM Sources rate limits (VEX and signature as the other run downloads; the PDF and the evidence
pack, which build several documents, under the write limit, as the code lane's evidence pack). Active runs are allowed
and say "as of" (the run CBOM download serves active runs the same way).
"""
from __future__ import annotations

import datetime as _dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from sqlmodel import Session

from backend.new_models import CbomCollectionRun
from backend.utilities.cbom_sources import cdx_xml as CDX_XML
from backend.utilities.cbom_sources import heatmap as HEAT
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import run_deliverables as RD
from backend.utilities.cbom_sources.common import iso_z, utcnow
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    read_limiter,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources.settings import get_or_create_settings
from backend.utilities.pdf.cbom_run_pdf import build_run_pdf

router = APIRouter(tags=["cbom-sources"], route_class=CbomRoute)
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
AuthHeader = Annotated[str | None, Header()]
RUN = "/{team_id}/cbom/sources/runs/{run_id}"
JSON_MEDIA = "application/json"
VEX_MEDIA = "application/vnd.cyclonedx+json; version=1.6"


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom run {what}", exc, team=team_id) from None


def _get_owned(session: Session, run_id: int, team_id: int) -> CbomCollectionRun:
    run = session.get(CbomCollectionRun, run_id)
    if run is None or run.team_id != team_id:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


def _secret() -> bytes:
    from backend.routers.certin import _hmac_secret  # the code lane's key (CERTIN_HMAC_SECRET), same key id

    return _hmac_secret()


def _attachment(body: bytes, media: str, filename: str, **extra: str) -> Response:
    return Response(body, media_type=media,
                    headers={**PRIVATE, "Content-Disposition": f'attachment; filename="{filename}"', **extra})


# ----------------------------------------------------------------------------- builders (one session each)
def _vex(session: Session, run: CbomCollectionRun, doc: dict[str, Any], now: _dt.datetime) -> dict[str, Any]:
    return RD.run_vex(run, doc, RD.asset_context(session, run), now)


def _pdf(session: Session, run: CbomCollectionRun, doc: dict[str, Any], body: bytes, vex: dict[str, Any],
         now: _dt.datetime) -> bytes:
    settings = get_or_create_settings(session, run.team_id)
    posture = POSTURE.run_posture(session, team_id=run.team_id, run_id=run.id, risk_model=settings.risk_model)
    heatmap = HEAT.run_heatmap(session, run.team_id, run.id, by="source")
    states = {p["name"][len("zs:affected_"):]: int(p["value"]) for p in vex["metadata"]["properties"]
              if p["name"].startswith("zs:affected_")}
    run_info = {"id": run.id, "status": run.status, "created_at": iso_z(run.created_at),
                "finished_at": iso_z(run.finished_at), "last_updated": iso_z(run.last_updated)}
    return build_run_pdf(run=run_info, sources=RD.run_sources(session, run), posture=posture, heatmap=heatmap,
                         doc=doc, vex_states=states, provenance=RD.provenance(session, run), now=now,
                         as_of_note=RD.as_of_note(run, now), findings_cap=RD.PDF_FINDINGS_CAP,
                         export_cap=RD.INV.EXPORT_CAP, cbom_sha256=RD.sha256(body))


def _vex_doc(engine, team_id: int, run_id: int) -> bytes:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        return RD.vex_bytes(_vex(session, run, RD.run_cbom(session, run, now), now))


def _signature(engine, team_id: int, run_id: int) -> dict[str, Any]:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        doc = RD.run_cbom(session, run, now)
        return RD.run_signature(run, doc, RD.cbom_bytes(doc), secret=_secret(), now=now)


def _report(engine, team_id: int, run_id: int) -> bytes:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        doc = RD.run_cbom(session, run, now)
        return _pdf(session, run, doc, RD.cbom_bytes(doc), _vex(session, run, doc, now), now)


def _oscal(engine, team_id: int, run_id: int) -> bytes | None:
    """The run's OSCAL download, byte for byte (``integrations._run_oscal``); None while the run is active."""
    from backend.routers.integrations import _run_oscal

    try:
        return bytes(_run_oscal(engine, team_id, run_id).body)
    except HTTPException as exc:
        if exc.status_code == 400:
            return None
        raise


def _evidence_pack(engine, team_id: int, run_id: int) -> bytes:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        doc = RD.run_cbom(session, run, now)
        body = RD.cbom_bytes(doc)
        vex = _vex(session, run, doc, now)
        signature = RD.run_signature(run, doc, body, secret=_secret(), now=now)
        pdf = _pdf(session, run, doc, body, vex, now)
        sources = RD.run_sources(session, run)
        run_status = run.status
    base = f"/{team_id}/cbom/sources/runs/{run_id}"
    files = [("bom.cdx.json", body, JSON_MEDIA, f"{base}/cbom?format=json"),
             ("bom.cdx.xml", CDX_XML.to_xml(doc), CDX_XML.XML_MEDIA_TYPE, f"{base}/cbom?format=xml")]
    omitted = []
    oscal = _oscal(engine, team_id, run_id)
    if oscal is not None:
        files.append(("oscal-assessment-results.json", oscal, JSON_MEDIA, f"{base}/oscal"))
    else:
        omitted.append({"name": "oscal-assessment-results.json",
                        "reason": f"OSCAL assessment results are written for finished runs; run is {run_status}."})
    files += [("vex.json", RD.vex_bytes(vex), VEX_MEDIA, f"{base}/vex"),
              ("bom_signature.json", RD.signature_bytes(signature), JSON_MEDIA, f"{base}/signature"),
              ("report.pdf", pdf, "application/pdf", f"{base}/report.pdf")]
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        return RD.evidence_pack(run=run, sources=sources, now=now, files=files, omitted=omitted, doc=doc,
                                signature=signature)


# ----------------------------------------------------------------------------- routes
@router.get(RUN + "/vex", dependencies=READ,
            summary="CycloneDX 1.6 VEX of a run's findings: exploitable, in triage (quantum-only or inferred), "
                    "resolved or will-not-fix per the remediation plan")
async def run_vex(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    body = await _run("vex", team_id, _vex_doc, engine, team_id, run_id)
    return _attachment(body, VEX_MEDIA, f"cbom-sources-run-{run_id}.vex.json")


@router.get(RUN + "/signature", dependencies=READ,
            summary="HMAC-SHA256 signature (the code lane's bom_signature scheme) over the exact bytes of the run's "
                    "CycloneDX JSON download")
async def run_signature(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    signature = await _run("signature", team_id, _signature, engine, team_id, run_id)
    return _attachment(RD.signature_bytes(signature), JSON_MEDIA, f"cbom-sources-run-{run_id}-signature.json")


@router.get(RUN + "/report.pdf", dependencies=WRITE,
            summary="PDF report of a run: posture, algorithm family x source, certificate expiry, top risks, "
                    "compliance, findings and provenance")
async def run_report_pdf(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    body = await _run("report pdf", team_id, _report, engine, team_id, run_id)
    return _attachment(body, "application/pdf", f"cbom-sources-run-{run_id}-report.pdf")


@router.get(RUN + "/evidence-pack", dependencies=WRITE,
            summary="Zip of the run's CycloneDX JSON and XML, OSCAL, VEX, signature and PDF with a sha256 manifest")
async def run_evidence_pack(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    body = await _run("evidence pack", team_id, _evidence_pack, engine, team_id, run_id)
    return _attachment(body, "application/zip", f"cbom-sources-run-{run_id}-evidence-pack.zip")

