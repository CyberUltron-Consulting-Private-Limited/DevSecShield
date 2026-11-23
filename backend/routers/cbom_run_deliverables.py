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
import hashlib
import json
import time
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
from backend.utilities.cbom_sources import http as _cbom_http
from backend.utilities.rbac.policy import Access
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
from backend.utilities.pdf.report_context import ReportContext
from backend.utilities.pdf.report_http import (
    OPTIONS_BODY_RESPONSES,
    busy_refusal,
    failure_outcome,
    finished_outcome,
    log_export,
    options_body_openapi,
    options_from_request,
    report_headers,
    request_options,
)
from backend.utilities.pdf.report_options import DEFAULT as DEFAULT_OPTIONS, ReportOptions
from backend.utilities.team.branding import load_report_branding

router = APIRouter(tags=["cbom-sources"], route_class=CbomRoute)
access = Access(lambda: _cbom_http.get_db())  # route policies (utilities/rbac): the same database as authorize()
WRITE = [Depends(write_limiter)]
AuthHeader = Annotated[str | None, Header()]
RUN = "/{team_id}/cbom/sources/runs/{run_id}"
JSON_MEDIA = "application/json"
VEX_MEDIA = "application/vnd.cyclonedx+json; version=1.6"
# Full passes over the run's assets each route makes (export, remediation join, posture, heat-map, OSCAL): a run takes
# an export slot when assets x passes reaches the single export's threshold (export_slots.LARGE_ASSETS).
PASSES = {"signature": 1, "verify": 1, "vex": 2, "report": 4, "pack": 5}
VERIFY_MAX_BYTES = 512 * 1024 * 1024  # spooled to disk and hashed as it arrives: a detached / digest check of any export
EMBEDDED_MAX_BYTES = RD.SIGN.EMBEDDED_MAX_BYTES  # D6: a JSON upload up to this size is parsed (once) for its JSF


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


def _secret() -> bytes | None:
    """The code lane's legacy HMAC key (CERTIN_HMAC_SECRET, same key id), or None while it is a placeholder
    (``bom_signing.legacy_hmac_problem``): then no HMAC is issued or accepted (review 6029745818 N3)."""
    from backend.routers.certin import _hmac_secret

    secret = _hmac_secret()  # 503 when neither variable is set, as before
    return None if RD.SIGN.legacy_hmac_problem() else secret


def _attachment(body: bytes, media: str, filename: str) -> Response:
    return Response(body, media_type=media,
                    headers={**PRIVATE, "Content-Disposition": f'attachment; filename="{filename}"'})


@contextlib.contextmanager
def _export_slot(session: Session, run: CbomCollectionRun, what: str, *, large: bool = False) -> Iterator[None]:
    """Hold one of the host-wide export slots while a large run's documents are built (module docstring); ``large``:
    take one whatever the run's size (an upload of ``bom_signing.LARGE_PARSE_BYTES`` or more is parsed)."""
    rows = int(session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == run.team_id, CbomCollectedAsset.run_id == run.id)).one())
    if not large and not EXPORT_SLOTS.is_large(rows * PASSES[what]):
        yield
        return
    try:
        with EXPORT_SLOTS.slot():
            yield
    except EXPORT_SLOTS.Busy:
        log("run deliverable busy", team=run.team_id, run=run.id, what=what, rows=rows, slots=EXPORT_SLOTS.SLOTS)
        raise busy_refusal("cbom") from None


# ----------------------------------------------------------------------------- builders (one session each)
def _vex(session: Session, run: CbomCollectionRun, data: RD.Summary, at: _dt.datetime) -> dict[str, Any]:
    return RD.run_vex(run, data, RD.asset_context(session, run), at)


def _report_context(session: Session, team_id: int, options: ReportOptions = DEFAULT_OPTIONS) -> ReportContext:
    """Report options plus the team's report logo (read in this session; a failure only skips the logo)."""
    return ReportContext(options=options, branding=load_report_branding(session, team_id))


def _pdf(session: Session, run: CbomCollectionRun, data: RD.Summary, vex: dict[str, Any], cbom_sha256: str,
         at: _dt.datetime, ctx: ReportContext | None = None) -> bytes:
    settings = get_or_create_settings(session, run.team_id)
    posture = POSTURE.run_posture(session, team_id=run.team_id, run_id=run.id, risk_model=settings.risk_model)
    heatmap = HEAT.run_heatmap(session, run.team_id, run.id, by="source")
    run_info = {"id": run.id, "status": run.status, "created_at": iso_z(run.created_at),
                "finished_at": iso_z(run.finished_at), "last_updated": iso_z(run.last_updated)}
    # Default options and no logo: build with a fresh default context, exactly what build_run_pdf makes of ctx=None,
    # so the bytes are today's; its counts are then copied to the caller's context, which fills X-Report-Findings
    # and the log line (they read 0/0 when this path built with no context at all).
    fresh = ctx is None or (ctx.options.is_default and not ctx.branding.applied)
    used = ReportContext() if fresh else ctx
    pdf = build_run_pdf(run=run_info, sources=RD.run_sources(session, run), posture=posture, heatmap=heatmap,
                        head=data.head, findings=data.findings, vex_states=RD.vex_states(vex),
                        provenance=RD.provenance(session, run), at=at, as_of_note=RD.as_of_note(run, at),
                        findings_cap=RD.PDF_FINDINGS_CAP, export_cap=RD.INV.EXPORT_CAP, cbom_sha256=cbom_sha256,
                        ctx=used)
    if ctx is not None and used is not ctx:
        ctx.shown, ctx.total = used.shown, used.total
    return pdf


def _vex_doc(engine, team_id: int, run_id: int) -> bytes:  # signed: embedded JSF (RD.vex_bytes), D7
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        with _export_slot(session, run, "vex"):
            at = RD.stamp(session, run, now)
            return RD.vex_bytes(_vex(session, run, RD.summary(session, run, now), at))


def _current_signature(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> dict[str, Any]:
    _out, data, tee = RD.written(session, run, now, "json", _secret(), keep=False)
    return RD.run_signature(run, data.head, tee, RD.stamp(session, run, now), data.jsf)


def _signature(engine, team_id: int, run_id: int) -> dict[str, Any]:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        with _export_slot(session, run, "signature"):
            return _current_signature(session, run, now)


def _embedded(upload: RD.Digests) -> dict[str, Any] | None:
    """The upload's own JSF signature checked against the published keys (``bom_signing.verify_document``), with the
    run the file says it is (``zs:run_id``); None when it is not JSON, too large to parse (``EMBEDDED_MAX_BYTES``),
    carries no signature or no key is configured. Parsed once, as I-JSON: a JSON body with a duplicate member name,
    NaN or an out-of-range number, or a malformed signature member, is 400 (D1); one that is not JSON at all (a
    corrupted download) is compared with the current CBOM as before."""
    if upload.out is None or upload.size > EMBEDDED_MAX_BYTES or not RD.SIGN.available():
        return None
    upload.out.seek(0)
    if not upload.out.read(4096).lstrip().startswith(b"{"):
        return None
    try:
        doc = RD.BV.loads_file(upload.out)
    except RD.BV.NotJSON:  # a corrupted file: compared with the run's current CBOM instead, as before
        return None
    except RD.BV.InputError as exc:
        raise HTTPException(status_code=400, detail=f"Not verified: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("signature"), dict):
        return None
    result = RD.SIGN.verify_document(doc)
    if result.get("malformed"):
        raise HTTPException(status_code=400, detail=f"Not verified: {result['reason']}")
    result["subject"] = RD.BV.subject_of(doc)  # zs:run_id + zs:team_id (bom_signing.binding)
    result["run_id"] = result["subject"].get("run_id")
    return result


def _verify(engine, team_id: int, run_id: int, upload: RD.Digests, sent_b64: str | None) -> dict[str, Any]:
    now = utcnow()
    mac = upload.mac.digest() if upload.mac is not None else None  # None: the legacy key is a placeholder (N3)
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        # the run's current CBOM is rebuilt (an export slot for a large run); a large upload is parsed in a verify
        # slot of its own (one per team, never an export slot: review 6029745818 minor 2)
        with _export_slot(session, run, "verify"):
            try:
                with RD.SIGN.parse_slot(upload.size, team_id):
                    embedded = _embedded(upload) if sent_b64 is None else None
                    current = _current_signature(session, run, now)
                    # D4: a file whose detached signature is good but that is not the run's current CBOM must say it
                    # is this team's run's (zs:run_id + zs:team_id of the CBOM / VEX, the pack manifest's subject):
                    # read only then, after the signature
                    subject = None
                    digest = upload.sha.hexdigest()
                    if sent_b64 is not None and digest != current["digest"] and \
                            RD.sent_signature(digest, mac, sent_b64) is not None:
                        subject = RD.SIGN.file_subject(upload.out, upload.size)
            except EXPORT_SLOTS.Busy:
                log("run verify busy", team=team_id, run=run_id, bytes=upload.size)
                raise busy_refusal("verify") from None
    out = RD.verify_upload(upload.sha.hexdigest(), mac, sent_b64=sent_b64, current=current, embedded=embedded,
                           run_id=run_id, team_id=team_id, subject=subject,
                           legacy_problem=RD.SIGN.legacy_hmac_problem())
    out.update({"bytes": upload.size, "run_id": run_id, "current_digest": current["digest"],
                "run_status": current["run_status"]})
    return out


def _report(engine, team_id: int, run_id: int, options: ReportOptions = DEFAULT_OPTIONS) -> tuple[bytes, ReportContext]:
    now = utcnow()
    with Session(engine) as session:
        ctx = _report_context(session, team_id, options)
    with Session(engine) as session:
        run = _get_owned(session, run_id, team_id)
        with _export_slot(session, run, "report"):
            at = RD.stamp(session, run, now)
            _out, data, tee = RD.written(session, run, now, "json", keep=False)  # one pass: sha256 and summary
            return _pdf(session, run, data, _vex(session, run, data, at), tee.sha.hexdigest(), at, ctx), ctx


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


def _evidence_pack(engine, team_id: int, run_id: int) -> tuple[IO[bytes], ReportContext]:
    now = utcnow()
    base = f"/{team_id}/cbom/sources/runs/{run_id}"
    temps: list[Any] = []
    with Session(engine) as session:
        ctx = _report_context(session, team_id)  # the pack's PDF is the full report; only the logo varies
    try:
        with Session(engine) as session:
            run = _get_owned(session, run_id, team_id)
            with _export_slot(session, run, "pack"):
                at = RD.stamp(session, run, now)
                json_file, data, json_tee = RD.written(session, run, now, "json", _secret())  # also the summary
                temps.append(json_file)
                xml_file, _xml_data, xml_tee = RD.written(session, run, now, "xml")
                temps.append(xml_file)
                signature: dict[str, Any] | None = RD.run_signature(run, data.head, json_tee, at, data.jsf)
                vex = _vex(session, run, data, at)
                pdf = _pdf(session, run, data, vex, json_tee.sha.hexdigest(), at, ctx)
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
                files.append(("vex.json", RD.vex_bytes(vex), VEX_MEDIA, f"{base}/vex"))
                if signature is not None and signature.get("unsigned"):  # N3: nothing signed, nothing claimed
                    omitted.append({"name": "bom_signature.json", "reason": str(signature["reason"])})
                    signature = None
                else:
                    files.append(("bom_signature.json", RD.signature_bytes(signature), JSON_MEDIA,  # type: ignore
                                  f"{base}/signature"))
                files.append(("report.pdf", pdf, "application/pdf", f"{base}/report.pdf"))
                return RD.evidence_pack(run=run, sources=sources, at=at, files=files, omitted=omitted,
                                        head=data.head, signature=signature,
                                        logo_sha256=ctx.branding.sha256 if ctx.branding.applied else None), ctx
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
@router.get(RUN + "/vex", dependencies=[*WRITE, access.team("cbom.read")],
            summary="CycloneDX 1.6 VEX of a run's findings: exploitable, in triage (quantum-only or inferred), "
                    "resolved or will-not-fix per the remediation plan")
async def run_vex(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    body = await _run("vex", team_id, _vex_doc, engine, team_id, run_id)
    response = _attachment(body, VEX_MEDIA, f"cbom-sources-run-{run_id}.vex.json")
    response.headers.update(RD.SIGN.signature_headers(hashlib.sha256(body).digest()))  # D7: detached, as the CBOM
    return response


@router.get(RUN + "/signature", dependencies=[*WRITE, access.team("cbom.read")],
            summary="ES256 signature over the exact bytes of the run's CycloneDX JSON download (also signed inside, "
                    "JSF), with the public key; verify offline (openssl / zs_bom_verify.py) or with .../verify")
async def run_signature(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None) -> Response:
    engine, _user = await authorize(team_id, Authorization)
    signature = await _run("signature", team_id, _signature, engine, team_id, run_id)
    if signature.get("unsigned"):  # no ES256 key and a placeholder legacy key: nothing to hand out (N3)
        raise HTTPException(status_code=503, detail=signature["reason"])
    return _attachment(RD.signature_bytes(signature), JSON_MEDIA, f"cbom-sources-run-{run_id}-signature.json")


@router.post(RUN + "/signature/verify", dependencies=[*WRITE, access.team("cbom.read")],
             summary="Verify a downloaded run file (the request body, as downloaded) against the signature sent in "
                     "X-ZS-Signature-B64 (ES256 or the older HMAC), else its embedded JSF signature, else the run's "
                     "current CBOM; valid only for this run's files (signed_by_deployment says whose signature)")
async def verify_run_signature(team_id: TeamId, run_id: ObjectId, request: Request,
                               Authorization: AuthHeader = None,
                               x_zs_signature_b64: Annotated[str | None, Header(max_length=512)] = None
                               ) -> JSONResponse:
    engine, _user = await authorize(team_id, Authorization)
    # kept (spooled) so its embedded JSF signature can be checked; nodes counted so a body far denser than any BOM is
    # refused while it arrives (review 6029745818 minor 2)
    upload = RD.Digests(RD.spool(), _secret(), count_nodes=True)
    try:
        async for chunk in request.stream():
            upload.write(chunk)
            if upload.size > VERIFY_MAX_BYTES:
                raise HTTPException(status_code=413, detail="The file is larger than any run CBOM export")
            dense = upload.dense()
            if dense:
                raise HTTPException(status_code=400, detail=f"Not verified: {dense}")
        if not upload.size:
            raise HTTPException(status_code=400, detail="Send the downloaded CycloneDX JSON file as the request body")
        result = await _run("signature verify", team_id, _verify, engine, team_id, run_id, upload, x_zs_signature_b64)
    finally:
        upload.out.close()
    return JSONResponse(result, headers=PRIVATE)


@router.get(RUN + "/report.pdf", dependencies=[*WRITE, access.team("cbom.read")],
            summary="PDF report of a run: posture, algorithm family x source, certificate expiry, top risks, "
                    "compliance, findings and provenance")
@router.post(RUN + "/report.pdf", dependencies=[*WRITE, access.team("cbom.read")],
             summary="PDF report of a run, report options in a JSON body", openapi_extra=options_body_openapi("run"),
             responses=OPTIONS_BODY_RESPONSES)
async def run_report_pdf(team_id: TeamId, run_id: ObjectId, request: Request,
                         Authorization: AuthHeader = None) -> Response:
    """Optional report options shape the report: ``preset`` (executive | technical | full), ``sections``
    (summary, posture, catalog, provenance), ``severities``, ``prepared_for``, ``title`` and ``label``; query
    parameters of a GET, or the JSON body of a POST, which keeps a client name out of URLs and access logs
    (``utilities/pdf/report_http.py``). The team's report logo, when set, appears on the cover and in every page
    header."""
    started = time.monotonic()
    engine, user = await authorize(team_id, Authorization)
    user_id = getattr(user, "id", None)
    options = None
    try:
        options = await request_options(request, "run")
        body, ctx = await _run("report pdf", team_id, _report, engine, team_id, run_id, options)
    except HTTPException as exc:  # _run turns anything else into a 500 HTTPException (server_error)
        outcome, code = failure_outcome(exc)
        log_export("run", team=team_id, id=run_id, user=user_id, started=started, outcome=outcome, status=code,
                   options=options)
        raise
    filename = f"cbom-sources-run-{run_id}-report.pdf"
    log_export("run", team=team_id, id=run_id, user=user_id, ctx=ctx, size=len(body), started=started,
               outcome=await finished_outcome(request))
    return Response(body, media_type="application/pdf", headers=report_headers(ctx, filename))


@router.get(RUN + "/evidence-pack", dependencies=[*WRITE, access.team("cbom.read")],
            summary="Zip of the run's CycloneDX JSON and XML, OSCAL, VEX, signature and PDF with a signed sha256 "
                    "manifest, the public key and an offline verifier")
async def run_evidence_pack(team_id: TeamId, run_id: ObjectId, request: Request,
                            Authorization: AuthHeader = None) -> Response:
    started = time.monotonic()
    engine, user = await authorize(team_id, Authorization)
    user_id = getattr(user, "id", None)
    try:
        options_from_request(request.query_params, "pack")  # any report option: 422 (a pack is the full record)
        out, ctx = await _run("evidence pack", team_id, _evidence_pack, engine, team_id, run_id)
    except HTTPException as exc:
        outcome, code = failure_outcome(exc)
        log_export("run_pack", team=team_id, id=run_id, user=user_id, started=started, outcome=outcome, status=code)
        raise
    length = out.seek(0, 2)
    out.seek(0)
    log_export("run_pack", team=team_id, id=run_id, user=user_id, ctx=ctx, size=length, started=started,
               outcome=await finished_outcome(request))
    return StreamingResponse(_chunks(out), media_type="application/zip", headers={
        **report_headers(ctx, f"cbom-sources-run-{run_id}-evidence-pack.zip", findings=False),
        "Content-Length": str(length)})
