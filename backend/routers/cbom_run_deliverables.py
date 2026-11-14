"""CBOM Sources run deliverables (CB-38 PR-8): VEX, signature (and its verification), PDF report and evidence pack of
one run, the four the code-scan page offers (``routers/certin.py``). Built by
``utilities/cbom_sources/run_deliverables.py``; see its docstring for the VEX analysis table, the signature and why
every file of a finished run is byte-stable.

Every route: team membership (``authorize``), the run loaded with ``_get_owned`` (404 for another team's run), no
credit charge, the CBOM Sources write limit (each builds at least one full pass over the run, as the code lane's
``sign`` and evidence pack are write-limited). A run large enough, counted as assets x the passes the route makes,
takes one of the host-wide export slots the run CBOM download uses (``export_slots``; 429 + Retry-After when busy).
Active runs are allowed and say "as of" (the run CBOM download serves active runs the same way).
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import json
from typing import IO, Annotated, Any, Iterator

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionRun
from backend.utilities.cbom_sources import cdx_xml as CDX_XML
from backend.utilities.cbom_sources import export_slots as EXPORT_SLOTS
from backend.utilities.cbom_sources import heatmap as HEAT
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import run_deliverables as RD
from backend.utilities.cbom_sources.common import iso_z, log, utcnow
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources.settings import get_or_create_settings
from backend.utilities.pdf.cbom_run_pdf import build_run_pdf

router = APIRouter(tags=["cbom-sources"], route_class=CbomRoute)
WRITE = [Depends(write_limiter)]
AuthHeader = Annotated[str | None, Header()]
RUN = "/{team_id}/cbom/sources/runs/{run_id}"
JSON_MEDIA = "application/json"
VEX_MEDIA = "application/vnd.cyclonedx+json; version=1.6"
# Full passes over the run's assets each route makes (export, remediation join, posture, heat-map, OSCAL): a run takes
# an export slot when assets x passes reaches the single export's threshold (export_slots.LARGE_ASSETS).
PASSES = {"signature": 1, "verify": 1, "vex": 2, "report": 4, "pack": 5}
VERIFY_MAX_BYTES = 512 * 1024 * 1024  # a 50,000-component export is far below this


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


def _attachment(body: bytes, media: str, filename: str) -> Response:
    return Response(body, media_type=media,
                    headers={**PRIVATE, "Content-Disposition": f'attachment; filename="{filename}"'})


@contextlib.contextmanager
def _export_slot(session: Session, run: CbomCollectionRun, what: str) -> Iterator[None]:
    """Hold one of the host-wide export slots while a large run's documents are built (module docstring)."""
    rows = int(session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == run.team_id, CbomCollectedAsset.run_id == run.id)).one())
    if not EXPORT_SLOTS.is_large(rows * PASSES[what]):
        yield
        return
    try:
        with EXPORT_SLOTS.slot():
            yield
    except EXPORT_SLOTS.Busy:
        log("run deliverable busy", team=run.team_id, run=run.id, what=what, rows=rows, slots=EXPORT_SLOTS.SLOTS)
        raise HTTPException(
            status_code=429, headers={**PRIVATE, "Retry-After": str(EXPORT_SLOTS.RETRY_AFTER_S)},
            detail=f"The server is busy building other large CBOM exports; retry in {EXPORT_SLOTS.RETRY_AFTER_S} s.",
        ) from None


# ----------------------------------------------------------------------------- builders (one session each)
def _vex(session: Session, run: CbomCollectionRun, data: RD.Summary, at: _dt.datetime) -> dict[str, Any]:
    return RD.run_vex(run, data, RD.asset_context(session, run), at)


def _pdf(session: Session, run: CbomCollectionRun, data: RD.Summary, vex: dict[str, Any], cbom_sha256: str,
         at: _dt.datetime) -> bytes:
    settings = get_or_create_settings(session, run.team_id)
    posture = POSTURE.run_posture(session, team_id=run.team_id, run_id=run.id, risk_model=settings.risk_model)
    heatmap = HEAT.run_heatmap(session, run.team_id, run.id, by="source")
    run_info = {"id": run.id, "status": run.status, "created_at": iso_z(run.created_at),
                "finished_at": iso_z(run.finished_at), "last_updated": iso_z(run.last_updated)}
    return build_run_pdf(run=run_info, sources=RD.run_sources(session, run), posture=posture, heatmap=heatmap,
                         head=data.head, findings=data.findings, vex_states=RD.vex_states(vex),
                         provenance=RD.provenance(session, run), at=at, as_of_note=RD.as_of_note(run, at),
                         findings_cap=RD.PDF_FINDINGS_CAP, export_cap=RD.INV.EXPORT_CAP, cbom_sha256=cbom_sha256)


def _vex_doc(engine, team_id: int, run_id: int) -> bytes:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        with _export_slot(session, run, "vex"):
            at = RD.stamp(session, run, now)
            return RD.vex_bytes(_vex(session, run, RD.summary(session, run, now), at))


def _current_signature(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> dict[str, Any]:
    _out, data, tee = RD.written(session, run, now, "json", _secret(), keep=False)
    return RD.run_signature(run, data.head, tee, RD.stamp(session, run, now))


def _signature(engine, team_id: int, run_id: int) -> dict[str, Any]:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        with _export_slot(session, run, "signature"):
            return _current_signature(session, run, now)


def _verify(engine, team_id: int, run_id: int, upload: RD.Digests, sent_b64: str | None) -> dict[str, Any]:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        with _export_slot(session, run, "verify"):
            current = _current_signature(session, run, now)
    out = RD.verify_upload(upload.sha.hexdigest(), upload.mac.digest(), sent_b64=sent_b64,  # type: ignore[union-attr]
                           current=current)
    out.update({"bytes": upload.size, "run_id": run_id, "current_digest": current["digest"],
                "run_status": current["run_status"]})
    return out


def _report(engine, team_id: int, run_id: int) -> bytes:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        with _export_slot(session, run, "report"):
            at = RD.stamp(session, run, now)
            _out, data, tee = RD.written(session, run, now, "json", keep=False)  # one pass: sha256 and summary
            return _pdf(session, run, data, _vex(session, run, data, at), tee.sha.hexdigest(), at)


def _oscal(session: Session, run: CbomCollectionRun, at: _dt.datetime) -> bytes | None:
    """The run's OSCAL document as ``GET .../runs/{id}/oscal`` writes it (schema-validated, same serialisation as
    ``integrations._oscal_response``), with ``last-modified`` = the run's stamp; None while the run is active (the
    route answers 400 then)."""
    from backend.utilities.cbom_sources.drift import FINISHED
    from backend.utilities.integrations import oscal as OSCAL

    if run.status not in FINISHED:
        return None
    doc = OSCAL.run_document(session, run)
    doc["assessment-results"]["metadata"]["last-modified"] = iso_z(at)
    problems = OSCAL.validate(doc)
    if problems:
        raise RuntimeError(f"OSCAL schema validation failed: {problems[0][:200]}")
    return json.dumps(doc, indent=1, ensure_ascii=False).encode("utf-8")


def _evidence_pack(engine, team_id: int, run_id: int) -> IO[bytes]:
    now = utcnow()
    base = f"/{team_id}/cbom/sources/runs/{run_id}"
    temps: list[Any] = []
    try:
        with Session(engine) as session:
            run = _get_owned(session, run_id, team_id)
            with _export_slot(session, run, "pack"):
                at = RD.stamp(session, run, now)
                json_file, data, json_tee = RD.written(session, run, now, "json", _secret())  # also the summary
                temps.append(json_file)
                xml_file, _xml_data, xml_tee = RD.written(session, run, now, "xml")
                temps.append(xml_file)
                signature = RD.run_signature(run, data.head, json_tee, at)
                vex = _vex(session, run, data, at)
                pdf = _pdf(session, run, data, vex, json_tee.sha.hexdigest(), at)
                sources = RD.run_sources(session, run)
                oscal = _oscal(session, run, at)
                files: list[Any] = [
                    ("bom.cdx.json", (json_file, json_tee), JSON_MEDIA, f"{base}/cbom?format=json"),
                    ("bom.cdx.xml", (xml_file, xml_tee), CDX_XML.XML_MEDIA_TYPE, f"{base}/cbom?format=xml")]
                omitted = []
                if oscal is not None:
                    files.append(("oscal-assessment-results.json", oscal, JSON_MEDIA, f"{base}/oscal"))
                else:
                    omitted.append({"name": "oscal-assessment-results.json",
                                    "reason": "OSCAL assessment results are written for finished runs; "
                                              f"run is {run.status}."})
                files += [("vex.json", RD.vex_bytes(vex), VEX_MEDIA, f"{base}/vex"),
                          ("bom_signature.json", RD.signature_bytes(signature), JSON_MEDIA, f"{base}/signature"),
                          ("report.pdf", pdf, "application/pdf", f"{base}/report.pdf")]
                return RD.evidence_pack(run=run, sources=sources, at=at, files=files, omitted=omitted,
                                        head=data.head, signature=signature)
    finally:
        for temp in temps:
            temp.close()


def _chunks(out: IO[bytes], size: int = 1024 * 1024) -> Iterator[bytes]:
    try:
        while chunk := out.read(size):
            yield chunk
    finally:
        out.close()


# ----------------------------------------------------------------------------- routes
@router.get(RUN + "/vex", dependencies=WRITE,
            summary="CycloneDX 1.6 VEX of a run's findings: exploitable, in triage (quantum-only or inferred), "
                    "resolved or will-not-fix per the remediation plan")
async def run_vex(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    body = await _run("vex", team_id, _vex_doc, engine, team_id, run_id)
    return _attachment(body, VEX_MEDIA, f"cbom-sources-run-{run_id}.vex.json")


@router.get(RUN + "/signature", dependencies=WRITE,
            summary="HMAC-SHA256 signature (the code lane's bom_signature key and fields) over the exact bytes of the "
                    "run's CycloneDX JSON download")
async def run_signature(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    signature = await _run("signature", team_id, _signature, engine, team_id, run_id)
    return _attachment(RD.signature_bytes(signature), JSON_MEDIA, f"cbom-sources-run-{run_id}-signature.json")


@router.post(RUN + "/signature/verify", dependencies=WRITE,
             summary="Verify a downloaded run CycloneDX JSON (the request body, as downloaded) against the signature "
                     "sent in X-ZS-Signature-B64, else against the run's current CBOM")
async def verify_run_signature(team_id: TeamId, run_id: ObjectId, request: Request,
                               Authorization: AuthHeader = None,
                               x_zs_signature_b64: Annotated[str | None, Header(max_length=256)] = None
                               ) -> JSONResponse:
    engine, _user = await authorize(team_id, Authorization)
    upload = RD.Digests(None, _secret())
    async for chunk in request.stream():
        upload.write(chunk)
        if upload.size > VERIFY_MAX_BYTES:
            raise HTTPException(status_code=413, detail="The file is larger than any run CBOM export")
    if not upload.size:
        raise HTTPException(status_code=400, detail="Send the downloaded CycloneDX JSON file as the request body")
    result = await _run("signature verify", team_id, _verify, engine, team_id, run_id, upload, x_zs_signature_b64)
    return JSONResponse(result, headers=PRIVATE)


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
    out = await _run("evidence pack", team_id, _evidence_pack, engine, team_id, run_id)
    length = out.seek(0, 2)
    out.seek(0)
    return StreamingResponse(_chunks(out), media_type="application/zip", headers={
        **PRIVATE, "Content-Length": str(length),
        "Content-Disposition": f'attachment; filename="cbom-sources-run-{run_id}-evidence-pack.zip"'})
