"""CERT-In Phase 4 API — attestations, sign, VEX, evidence-pack."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from backend.utilities.ratelimit import RateLimiter
from backend.utilities.rbac.policy import Access
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import Scan, scan_types
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.cbom_sources import bom_signing as SIGN
from backend.utilities.compliance import served_artifacts as ARTIFACTS
from backend.utilities.compliance import served_bom as SERVED
from backend.utilities.compliance.certin_attest import (
    compliance_key_for,
    delete_attestation,
    recompute_compliance_for_scan,
    requirement_ids_in_compliance,
    subject_name_for,
    upsert_attestation,
)
from backend.utilities.pdf import generate_pdf_for_type
from backend.utilities.pdf.report_context import ReportContext
from backend.utilities.pdf.report_http import (
    PRIVATE,
    failure_outcome,
    finished_outcome,
    log_export,
    options_from_request,
    report_headers,
)
from backend.utilities.team.branding import load_report_branding
from backend.utilities.team import check_if_user_is_in_team
from rich.console import Console

router = APIRouter(tags=["certin"])
access = Access(lambda: get_db())  # route policies (utilities/rbac), bound to this module's get_db (tests replace it)
console = Console()
# Per verified user, per worker (backend/utilities/ratelimit.py).
read_limiter = RateLimiter("certin.read", times=120, seconds=60)
write_limiter = RateLimiter("certin.write", times=30, seconds=60)  # also the evidence-pack PDF

_BOM_TYPES = frozenset({"ai_bom", "cbom", "sbom_sca"})


def _certin_module_candidates(name: str) -> list[Path]:
    """Paths that may hold stdlib ``cert_in/{name}.py`` (vex/sign).

    Backend images are built from the ``backend/`` context, so
    ``/aibom/src/aibom/compliance/cert_in/*.py`` is **not** in the image.
    The copies under ``backend/utilities/compliance/cert_in/`` ship with the
    API (last candidate). Repo checkouts resolve ``aibom/src/...`` first.
    """
    filename = f"{name}.py"
    here = Path(__file__).resolve()
    rel = Path("aibom") / "src" / "aibom" / "compliance" / "cert_in" / filename
    backend_copy = here.parents[1] / "utilities" / "compliance" / "cert_in" / filename
    docker_abs = Path("/aibom/src/aibom/compliance/cert_in") / filename
    out: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        key = str(path)
        if key not in seen:
            seen.add(key)
            out.append(path)

    for parent in here.parents:
        add(parent / rel)
    add(docker_abs)
    add(backend_copy)
    return out


def _vex_is_current(scan_type: str, vex: dict) -> bool:
    """A VEX stored by older rules is rebuilt: CBOM (rules 2: everything in triage; before: everything not
    affected), SBOM and AI BOM (before FIX-C1: a blanket not_affected per component, cert_in/vex.py)."""
    if scan_type != "cbom":
        return bool(_load_certin_module("vex").is_current(vex))
    from backend.utilities.cbom_sources.vex_semantics import is_current

    return is_current(scan_type, vex)


def _build_vex(engine, scan: Scan, scan_type: str, bom: dict | None, findings: list | None, vex_mod=None) -> dict:
    """A CBOM code scan's VEX comes from the one CBOM rule set (``cbom_sources.vex_semantics``, CB-22), with the
    findings this scan's drift resolved, also when the scan stored no result rows (every component gets the F5
    stub); SBOM and AI BOM keep ``cert_in/vex.py``."""
    if scan_type == "cbom":
        from backend.utilities.cbom_sources import drift as DRIFT
        from backend.utilities.cbom_sources import identity as ID
        from backend.utilities.cbom_sources import vex_semantics as VEX

        rows = findings if isinstance(findings, list) else []
        components = [str(c.get("bom-ref")) for c in (bom or {}).get("components") or []
                      if isinstance(c, dict) and c.get("bom-ref")]
        baselines: dict[int, tuple[str, int] | None] = {}
        with Session(engine) as session:
            resolved = VEX.drift_resolved(session, team_id=scan.team_id, scan_id=scan.id)
            truncated = bool(resolved) and VEX.drift_truncated(session, team_id=scan.team_id, scan_id=scan.id)
            for base_id in {e["baseline"] for e in resolved if e.get("baseline") is not None}:
                base = session.get(Scan, base_id)
                cbom_json = ((base.scan_data or {}).get("cbom_json") if base is not None and
                             base.team_id == scan.team_id and isinstance(base.scan_data, dict) else None)
                serial = cbom_json.get("serialNumber") if isinstance(cbom_json, dict) else None
                baselines[base_id] = (serial, int(cbom_json.get("version") or 1)) if serial else None
        ref_of: dict[str, str] = {}
        if resolved:
            key, _label = DRIFT.code_source(scan)
            for raw in rows:
                if isinstance(raw, dict) and raw.get("bom_ref"):
                    ref_of.setdefault(ID.stable_key("code", key, ID.code_identity(raw)), str(raw["bom_ref"]))

        def link_of(event: dict) -> str | None:  # the gone asset in the baseline scan's CBOM, when it has a serial
            identity = baselines.get(event.get("baseline"))
            ref = event.get("baseline_bom_ref")
            return VEX.bom_link(identity[0], identity[1], str(ref)) if identity and ref else None

        stored = scan.scan_data.get("vex_json") if isinstance(scan.scan_data, dict) else None
        # every affected asset is a BOM-Link into the served CBOM (A-13d); a scan with no stored CBOM has no document
        # to link into, so its rows keep their bare refs
        serial = (bom or {}).get("serialNumber") if isinstance(bom, dict) and bom.get("components") else None
        return VEX.code_scan_vex(rows, scan_id=scan.id, components=components, resolved=resolved, ref_of=ref_of,
                                 link_of=link_of, truncated=truncated,
                                 supersedes=stored if isinstance(stored, dict) else None,
                                 bom_serial=serial, bom_version=(bom or {}).get("version") or 1)
    if vex_mod is None:
        vex_mod = _load_certin_module("vex")
    return vex_mod.build_vex(bom=bom, findings=findings, scan_type=scan_type)


def _load_certin_module(name: str):
    """Load ``cert_in/{name}.py`` without importing ``aibom.compliance`` (jsonschema)."""
    # Prefer normal import when aibom is fully installed (worker / aibom venv).
    try:
        return importlib.import_module(f"aibom.compliance.cert_in.{name}")
    except Exception:
        pass
    tried: list[str] = []
    for path in _certin_module_candidates(name):
        tried.append(str(path))
        if not path.is_file():
            continue
        # vex.py / sign.py are stdlib-only (no sibling cert_in imports).
        mod_name = f"_certin_phase4_{name}_{abs(hash(str(path.resolve())))}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {path}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
        return mod
    raise ImportError(
        f"cert_in/{name}.py not found (tried {', '.join(tried)})"
    )


def _require_bom_type(scan_type: scan_types) -> None:
    if scan_type not in _BOM_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CERT-In Phase 4 endpoints apply only to ai_bom, cbom, or sbom_sca",
        )


def _load_success_scan(
    engine, team_id: int, scan_type: scan_types, scan_id: int
) -> Scan:
    with Session(engine) as session:
        scan = session.exec(
            select(Scan)
            .where(Scan.id == scan_id)
            .where(Scan.team_id == team_id)
            .where(Scan.scan_type == scan_type)
        ).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.scan_status != "success":
            raise HTTPException(
                status_code=400, detail="Scan has not completed successfully"
            )
        # Detach scan_data copy for mutation outside session
        scan.scan_data = dict(scan.scan_data) if isinstance(scan.scan_data, dict) else {}
        return scan


def _save_scan_data(engine, scan_id: int, team_id: int, scan_type: str, data: dict) -> None:
    with Session(engine) as session:
        scan = session.exec(
            select(Scan)
            .where(Scan.id == scan_id)
            .where(Scan.team_id == team_id)
            .where(Scan.scan_type == scan_type)
        ).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan.scan_data = data
        session.add(scan)
        session.commit()


def _hmac_secret() -> bytes:
    raw = os.environ.get("CERTIN_HMAC_SECRET") or ""
    # Fall back to JWT secret for local/dev only when CERTIN_HMAC_SECRET unset —
    # still non-empty so hermetic/live tests work; production should set CERTIN.
    if not raw:
        raw = os.environ.get("JWT_SECRET_KEY") or ""
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CERTIN_HMAC_SECRET (or JWT_SECRET_KEY) not configured",
        )
    return raw.encode("utf-8")


@router.get("/{team_id}/{type}/scan/{scan_id}/attestations", dependencies=[Depends(read_limiter), access.team("scan.read")])
async def list_attestations(
    team_id: int,
    type: scan_types,
    scan_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    return {"attestations": data.get("attestations") or {}}


@router.post("/{team_id}/{type}/scan/{scan_id}/attestations", dependencies=[Depends(write_limiter), access.team("certin.write")])
async def upload_attestation(
    team_id: int,
    type: scan_types,
    scan_id: int,
    framework: str = Form(...),
    requirement_id: str = Form(...),
    note: str | None = Form(None),
    file: UploadFile | None = File(None),
    Authorization: Annotated[str | None, Header()] = None,
):
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    ckey = compliance_key_for(type)
    compliance = data.get(ckey)
    if not isinstance(compliance, dict) or not compliance:
        raise HTTPException(
            status_code=409,
            detail="Scan has no compliance data; cannot attest",
        )
    known = requirement_ids_in_compliance(compliance, framework)
    if requirement_id not in known:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown requirement_id {requirement_id!r} for framework {framework!r}",
        )
    filename = file.filename if file and file.filename else (note or "attestation.txt")
    attestations = upsert_attestation(
        data.get("attestations"),
        framework=framework,
        requirement_id=requirement_id,
        filename=filename,
        note=note,
    )
    try:
        updated = recompute_compliance_for_scan(type, data, attestations)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    _save_scan_data(engine, scan_id, team_id, type, updated)
    return {
        "attestations": updated.get("attestations") or {},
        "compliance": updated.get(ckey),
        "framework": framework,
        "requirement_id": requirement_id,
    }


@router.delete("/{team_id}/{type}/scan/{scan_id}/attestations/{framework}/{requirement_id}", dependencies=[Depends(write_limiter), access.team("certin.write")])
async def remove_attestation(
    team_id: int,
    type: scan_types,
    scan_id: int,
    framework: str,
    requirement_id: str,
    Authorization: Annotated[str | None, Header()] = None,
):
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    attestations = delete_attestation(
        data.get("attestations"),
        framework=framework,
        requirement_id=requirement_id,
    )
    try:
        updated = recompute_compliance_for_scan(type, data, attestations)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    _save_scan_data(engine, scan_id, team_id, type, updated)
    return {
        "attestations": updated.get("attestations") or {},
        "compliance": updated.get(compliance_key_for(type)),
    }


@router.post("/{team_id}/{type}/scan/{scan_id}/sign", dependencies=[Depends(write_limiter), access.team("certin.write")])
async def sign_scan_bom(
    team_id: int,
    type: scan_types,
    scan_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    # the document the downloads serve, so the HMAC covers it
    bom = _scan_bom(type, scan_id, data, team_id, subject_name=subject_name_for(scan.scan_metadata))
    if not bom:
        raise HTTPException(status_code=409, detail="No BOM JSON available to sign")
    secret = _hmac_secret()
    try:
        sign_mod = _load_certin_module("sign")
        signature = sign_mod.sign_bom(bom, secret=secret)
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"aibom sign unavailable: {e}") from e
    data = dict(data)
    data["bom_signature"] = signature
    _save_scan_data(engine, scan_id, team_id, type, data)
    return {"bom_signature": signature}


# the one builder of the served document (review 6032108510 M-3): /bom, /vex, /sign, the pack, and the SBOM PDF's
# minimum-elements page (pdf/sbom_sca_pdf.py, from /export and the pack) all call it
_scan_serial = SERVED.scan_serial
_scan_bom = SERVED.served_bom


def _served_vex(scan_type: str, scan_id: int, team_id: int, vex: dict, bom: dict | None) -> dict:
    """The VEX as served (route and pack): the stored document with the identity properties the server asserts
    (``zs:scan_id``, ``zs:scan_type``, ``zs:team_id`` and ``zs:bom_serial``, the BOM it states about) replacing any it
    carried, so its signature says which scan of which team it is of (D4 / D7, review 6029745818 N1). Its other
    ``zs:`` properties are the VEX builder's own rule markers and are kept."""
    serial = (bom or {}).get("serialNumber")
    facts = SIGN.scan_facts(scan_type, scan_id, team_id) + ([("zs:bom_serial", serial)] if isinstance(serial, str) else [])
    return SIGN.stamp_subject(vex, facts, drop_all_zs=False)


def _signed_vex_response(scan_type: str, scan_id: int, team_id: int, vex: dict, bom: dict | None) -> Response:
    """D7: the VEX download signed like a BOM download, an embedded JSF signature and the detached ``X-ZS-Signature``
    header over the exact bytes."""
    body = _signed_bom_bytes(_served_vex(scan_type, scan_id, team_id, vex, bom))
    return Response(body, media_type="application/json", headers={
        **PRIVATE, **SIGN.signature_headers(hashlib.sha256(body).digest()),
        "Content-Disposition": f'inline; filename="{scan_type}-vex-{scan_id}.cdx.json"'})


@router.get("/{team_id}/{type}/scan/{scan_id}/vex", dependencies=[Depends(read_limiter), access.team("scan.read")])
async def get_scan_vex(
    team_id: int,
    type: scan_types,
    scan_id: int,
    refresh: bool = False,
    Authorization: Annotated[str | None, Header()] = None,
):
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    bom = _scan_bom(type, scan_id, data, team_id, subject_name=subject_name_for(scan.scan_metadata))
    if not refresh and isinstance(data.get("vex_json"), dict) and _vex_is_current(type, data["vex_json"]):
        return await run_in_threadpool(_signed_vex_response, type, scan_id, team_id, data["vex_json"], bom)
    findings = data.get("results") if type in ("sbom_sca", "cbom") else None
    if not isinstance(findings, list):
        findings = None
    try:
        vex = _build_vex(engine, scan, type, bom, findings)
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"aibom vex unavailable: {e}") from e
    data = dict(data)
    # stored as served (identity stamped), so the page's copy (scan metadata) and the download are the same document
    data["vex_json"] = vex = _served_vex(type, scan_id, team_id, vex, bom)
    _save_scan_data(engine, scan_id, team_id, type, data)
    return await run_in_threadpool(_signed_vex_response, type, scan_id, team_id, vex, bom)


@router.get("/{team_id}/{type}/scan/{scan_id}/bom", dependencies=[Depends(read_limiter), access.team("scan.read")])
async def download_scan_bom(
    team_id: int,
    type: scan_types,
    scan_id: int,
    format: str = Query(default="json", pattern="^(json|xml)$"),
    Authorization: Annotated[str | None, Header()] = None,
):
    """The scan's CycloneDX document: ``format=json`` (what ``bom_signature`` signs) or ``format=xml`` (CBOM scans:
    the same document written as CycloneDX 1.6 XML, valid against the official XSD; the signature covers the JSON
    form only, which the ``X-ZS-Signature-Scope`` header states)."""
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    bom = _scan_bom(type, scan_id, scan.scan_data if isinstance(scan.scan_data, dict) else {}, team_id,
                    subject_name=subject_name_for(scan.scan_metadata))
    if not bom:
        raise HTTPException(status_code=409, detail="No CycloneDX document is stored for this scan")
    if format == "json":
        body = await run_in_threadpool(_signed_bom_bytes, bom)
        return Response(body, media_type="application/json", headers={
            **PRIVATE, **SIGN.signature_headers(hashlib.sha256(body).digest()),
            "Content-Disposition": f'attachment; filename="{type}-cyclonedx-{scan_id}.cdx.json"'})
    if type != "cbom":
        raise HTTPException(status_code=400, detail="format=xml: XML export is available for CBOM scans")
    from backend.utilities.cbom_sources import cdx_xml

    body = await run_in_threadpool(cdx_xml.to_xml, bom)
    signed = SIGN.signature_headers(hashlib.sha256(body).digest())
    # the scope names the detached signature; an unsigned download (no key) names none (review 6029745818 minor 4)
    scope = {} if signed["X-ZS-Signature"] == "unsigned" else {"X-ZS-Signature-Scope": cdx_xml.SIGNATURE_SCOPE}
    return Response(body, media_type=cdx_xml.XML_MEDIA_TYPE, headers={
        **PRIVATE, "Content-Disposition": f'attachment; filename="cbom-cyclonedx-{scan_id}.cdx.xml"', **scope, **signed})


async def _artifact_response(team_id: int, scan_id: int, artifact: str, authorization: str | None) -> Response:
    """The AI BOM's stored SPDX 3.0 / SARIF 2.1.0 file (``served_artifacts``) with a detached ES256 signature over the
    exact bytes (``X-ZS-Signature``, as for the CBOM XML; D5 / review 6036875286). Verify it with
    ``zs_bom_verify.py detached FILE FILE.sig`` (the pack carries the ``.sig``), or send the file and the header's base64
    value to ``POST /signature/verify``, which binds it to the scan by its bytes (``_own_artifact``)."""
    from backend.utilities.cbom_sources import cdx_xml

    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, "ai_bom", scan_id)
    body = ARTIFACTS.stored_artifact(scan.scan_data, artifact)
    if body is None:
        raise HTTPException(status_code=409, detail=f"No {ARTIFACTS.ARTIFACTS[artifact][3]} is stored for this scan")
    signed = SIGN.signature_headers(hashlib.sha256(body).digest())
    scope = {} if signed["X-ZS-Signature"] == "unsigned" else {"X-ZS-Signature-Scope": cdx_xml.SIGNATURE_SCOPE}
    return Response(body, media_type=ARTIFACTS.ARTIFACTS[artifact][1], headers={
        **PRIVATE, **signed, **scope,
        "Content-Disposition": f'attachment; filename="{ARTIFACTS.file_name(scan_id, artifact)}"'})


@router.get("/{team_id}/ai_bom/scan/{scan_id}/spdx", dependencies=[Depends(read_limiter), access.team("scan.read")])
async def download_ai_bom_spdx(
    team_id: int,
    scan_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    """The AI BOM scan's SPDX 3.0.1 JSON-LD document, as stored, signed detached."""
    return await _artifact_response(team_id, scan_id, "spdx", Authorization)


@router.get("/{team_id}/ai_bom/scan/{scan_id}/sarif", dependencies=[Depends(read_limiter), access.team("scan.read")])
async def download_ai_bom_sarif(
    team_id: int,
    scan_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    """The AI BOM scan's SARIF 2.1.0 log, as stored, signed detached."""
    return await _artifact_response(team_id, scan_id, "sarif", Authorization)


def _signed_bom_bytes(bom: dict, *, indent: int | None = None) -> bytes:
    """The stored BOM as served: with an embedded JSF ES256 signature (``bom_signing``; D11 / G-X-3) when the
    deployment has a key, else as stored. The stored ``bom_signature`` HMAC still verifies it (``cert_in/sign.py``
    leaves the JSF member out of its canonical form)."""
    try:
        return SIGN.bom_bytes(bom, indent=indent)
    except SIGN.SigningUnavailable:
        seps = (",", ":") if indent is None else (",", ": ")
        return json.dumps(bom, ensure_ascii=False, indent=indent, separators=seps).encode("utf-8")


# D6: the upload is spooled to a temp file and hashed while it is received (never held twice); a JSON body is parsed
# once, and one this large is the most any scan's BOM, VEX or pack manifest comes to (nginx admits 64 MB uploads).
VERIFY_MAX_BYTES = SIGN.EMBEDDED_MAX_BYTES


@router.post("/{team_id}/{type}/scan/{scan_id}/signature/verify",
             dependencies=[Depends(write_limiter), access.team("scan.read")])
async def verify_scan_bom_signature(
    team_id: int,
    type: scan_types,
    scan_id: int,
    request: Request,
    Authorization: Annotated[str | None, Header()] = None,
    x_zs_signature_b64: Annotated[str | None, Header(max_length=512)] = None,
):
    """Verify a downloaded file of this scan (the request body, as downloaded; audit C G-X-3): the ES256 detached
    signature sent in ``X-ZS-Signature-B64`` (the download's ``X-ZS-Signature``, or a pack's ``.sig`` in base64),
    else the JSF signature embedded in a JSON BOM or VEX, else, for a BOM signed before the ES256 key, the scan's
    stored HMAC ``bom_signature`` over the same document.

    ``valid`` is true only when the signature is this deployment's AND the file is this scan's (D4): the
    ``zs:scan_id``, ``zs:scan_type`` and ``zs:team_id`` the server stamped on the BOM / VEX, or the pack manifest's
    ``subject`` (kind, scan id, team), never a serial number alone (review 6029745818 N1); an AI BOM's SPDX / SARIF
    file, which carries no such stamp, by byte equality with this scan's stored file (review 6038801363 m-1), checked
    only after its signature verifies. ``signed_by_deployment`` says the first alone (a file of another scan or team
    is ``valid: false`` with ``signed_by_deployment: true``).
    JSON that is not I-JSON (duplicate member names, NaN, out-of-range numbers), far denser than any BOM, or carrying a
    malformed signature member is 400 (a body that is not JSON at all is ``valid: false``, as before); one over 64 MB
    is 413. Offline checks need only the key at ``GET /{team}/bom-signing-keys``."""
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    from backend.utilities.cbom_sources import run_deliverables as RD

    upload = RD.Digests(RD.spool(), count_nodes=True)
    try:
        async for chunk in request.stream():
            upload.write(chunk)
            if upload.size > VERIFY_MAX_BYTES:
                raise HTTPException(status_code=413, detail="The file is larger than any BOM this scan produces")
            dense = upload.dense()
            if dense:  # minor 2: refused while it arrives, never parsed
                raise _malformed(dense)
        if not upload.size:
            raise HTTPException(status_code=400, detail="Send the downloaded file as the request body")
        data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
        result = await run_in_threadpool(_verify_scan_file, type, scan_id, data, upload, x_zs_signature_b64,
                                         team_id=team_id)
    finally:
        upload.out.close()
    return JSONResponse(result, headers=PRIVATE)


SUBJECT_KEYS = ("serial", "scan_id", "scan_type", "team_id", "run_id", "kind", "bom_serial", "ambiguous")


def _malformed(reason: str) -> HTTPException:
    """400 for a body no signature can be checked over (D1, minor 1); the detail is the reason, shown as is."""
    return HTTPException(status_code=400, detail=f"Not verified: {reason}")


def _own_artifact(scan_type: str, data: dict, sha256_hex: str) -> str | None:
    """``ai_bom-spdx`` / ``ai_bom-sarif`` when ``sha256_hex`` is that of this scan's own stored SPDX / SARIF file as
    GET /spdx and /sarif serve it, else None. Those files carry no ``zs:`` subject stamp (the stored documents stay
    unchanged and SHACL-valid), so the binding of N1 is byte equality with this scan's stored file (review 6038801363
    m-1), and nothing more: another scan whose file is byte-identical binds too (same inputs in the same second, or
    a document built without ``generated_at``, which carries ``PINNED_TIMESTAMP``), which is harmless since the
    content is the same. The route loaded ``data`` for this team's scan only, and calls
    this only after the detached signature has verified (review 6039705173: the bytes never stand in for it)."""
    if scan_type != "ai_bom":
        return None
    for artifact in ARTIFACTS.ARTIFACTS:
        body = ARTIFACTS.stored_artifact(data, artifact)
        if body is not None and hashlib.sha256(body).hexdigest() == sha256_hex:
            return f"ai_bom-{artifact}"
    return None


def _verify_scan_file(scan_type: str, scan_id: int, data: dict, upload: Any, sent_b64: str | None, *,
                      team_id: int) -> dict:
    import base64

    from backend.utilities.cbom_sources import bom_verify as BV
    from backend.utilities.cbom_sources import export_slots as EXPORT_SLOTS
    from backend.utilities.pdf.report_http import busy_refusal

    out: dict[str, Any] = {"sha256": upload.sha.hexdigest(), "bytes": upload.size, "scan_id": scan_id}
    fh = upload.out

    def bound(checked: dict, subject: dict, method: str) -> dict:
        ok = SIGN.binding(subject, team_id=team_id, scan_id=scan_id, scan_type=scan_type)
        res = {**out, "method": method, **checked, "signed_by_deployment": True, "bound": ok,
               "file_subject": {k: v for k, v in subject.items() if k in SUBJECT_KEYS},
               "valid": ok}
        if not ok:
            res["reason"] = "signed by this deployment but not this scan's file (another scan, type or team)"
        return res

    try:
        with SIGN.parse_slot(upload.size, team_id):
            if sent_b64 is not None:
                try:
                    der = base64.b64decode(sent_b64.strip(), validate=True)
                except (ValueError, TypeError):
                    der = b""
                if not der:
                    return {**out, "method": "detached ES256", "valid": False, "signed_by_deployment": False,
                            "reason": "X-ZS-Signature-B64 is not base64"}
                try:
                    checked = SIGN.verify_detached_digest(upload.sha.digest(), der)
                except SIGN.SigningUnavailable as exc:
                    return {**out, "method": "detached ES256", "valid": False, "reason": str(exc)}
                if not checked["valid"]:
                    return {**out, "method": "detached ES256", **checked, "signed_by_deployment": False}
                own = _own_artifact(scan_type, data, out["sha256"])
                if own:  # an AI BOM's SPDX / SARIF carries no zs: stamp: its bytes are the scan's own stored file
                    return {**out, "method": "detached ES256", **checked, "signed_by_deployment": True, "bound": True,
                            "file_subject": {"scan_id": scan_id, "scan_type": scan_type, "team_id": team_id,
                                             "kind": own},
                            "valid": True}
                return bound(checked, SIGN.file_subject(fh, upload.size), "detached ES256")
            try:
                doc = BV.loads_file(fh)
            except BV.NotJSON:  # a corrupted or non-JSON file: it does not verify (as before)
                return {**out, "valid": False, "method": None,
                        "reason": "not JSON: send the detached signature (X-ZS-Signature) in X-ZS-Signature-B64"}
            except BV.InputError as exc:  # JSON that two readers could read differently (D1): refused
                raise _malformed(str(exc)) from None
            if not isinstance(doc, dict):
                return {**out, "valid": False, "method": None, "reason": "not a CycloneDX document"}
            if isinstance(doc.get("signature"), dict):
                try:
                    checked = SIGN.verify_document(doc)
                except SIGN.SigningUnavailable as exc:
                    return {**out, "valid": False, "method": "embedded JSF", "reason": str(exc)}
                if checked.get("malformed"):
                    raise _malformed(checked["reason"])
                if not checked["valid"]:
                    return {**out, "method": "embedded JSF", **checked, "signed_by_deployment": False}
                return bound(checked, BV.subject_of(doc), "embedded JSF")
    except EXPORT_SLOTS.Busy:
        raise busy_refusal("verify") from None
    stored = data.get("bom_signature")
    if not isinstance(stored, dict):
        return {**out, "valid": False, "method": None, "reason": "the file carries no signature and the scan has no "
                                                                   "stored HMAC signature"}
    sign_mod = _load_certin_module("sign")
    try:
        ok = bool(sign_mod.verify_signature(doc, stored, secret=_hmac_secret()))
    except UnicodeError:  # never the codec's own words in the answer (staging QA N8)
        raise _malformed("the document holds text that is not valid Unicode, so it has no canonical form to check")\
            from None
    except (TypeError, ValueError) as exc:
        raise _malformed(f"cannot be canonicalised for the HMAC check: {str(exc)[:200]}") from None
    # the stored HMAC is this scan's own: a match is a file of this scan
    return {**out, "valid": ok, "method": "stored HMAC-SHA256 (legacy)", "kid": stored.get("key_id"),
            "signed_by_deployment": ok, "bound": ok}


def _pack_pdf(scan_type: str, data: dict, ctx: ReportContext) -> bytes | None:
    """The pack's report.pdf (default options, the team logo when set); None when it cannot be built."""
    pdf_tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    pdf_path = pdf_tmp.name
    pdf_tmp.close()
    try:
        generate_pdf_for_type(scan_type, data, pdf_path, ctx=ctx)
        with open(pdf_path, "rb") as pf:
            return pf.read()
    except Exception as e:  # the pack's other members stand on their own
        console.print(f"evidence-pack PDF skipped: {e.__class__.__name__}", style="yellow", markup=False)
        return None
    finally:
        try:
            os.unlink(pdf_path)
        except OSError:
            pass


def _signature_matches(bom: dict | None, signature: dict) -> bool:
    """A stored signature ships only when its digest is the SHA-256 of the canonical ``bom.cdx.json`` packed next to
    it (review 6028132826 M6): a scan signed before its SBOM was re-emitted (CycloneDX 1.7 -> 1.6) would otherwise ship
    a ``bom_signature.json`` that does not match. Signing itself is PR #484's; this only leaves a stale one out."""
    if not isinstance(bom, dict) or not isinstance(signature, dict):
        return False
    return str(signature.get("digest") or "") == SERVED.bom_sha256(bom)


def _build_evidence_pack(engine, team_id: int, scan_type: str, scan_id: int) -> tuple[str, ReportContext]:
    """Write the pack to a temp zip (removed here on any failure; the caller schedules its removal after sending)."""
    scan = _load_success_scan(engine, team_id, scan_type, scan_id)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}

    # Ensure vex + signature exist when possible
    subject = subject_name_for(scan.scan_metadata)
    bom = _scan_bom(scan_type, scan_id, data, team_id, subject_name=subject)
    try:
        vex_mod = _load_certin_module("vex")
        sign_mod = _load_certin_module("sign")

        if not isinstance(data.get("vex_json"), dict) or not _vex_is_current(scan_type, data["vex_json"]):
            findings = data.get("results") if scan_type in ("sbom_sca", "cbom") else None
            data["vex_json"] = _served_vex(scan_type, scan_id, team_id,
                                           _build_vex(engine, scan, scan_type, bom,
                                                      findings if isinstance(findings, list) else None, vex_mod), bom)
        if bom and not isinstance(data.get("bom_signature"), dict):
            try:
                data["bom_signature"] = sign_mod.sign_bom(bom, secret=_hmac_secret())
            except HTTPException:
                pass
        _save_scan_data(engine, scan_id, team_id, scan_type, data)
    except ImportError:
        pass

    with Session(engine) as session:
        ctx = ReportContext(branding=load_report_branding(session, team_id))
        profile = None
        if scan_type == "cbom":
            from backend.utilities.cbom_sources.regulated_entity import team_profile as _team_profile

            profile = _team_profile(session, team_id)

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_path = tmp.name
    tmp.close()
    try:
        files = _pack_members(scan_type, scan_id, team_id, data, bom, ctx, subject_name=subject,
                              team_profile=profile)
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, body in files:
                zf.writestr(name, body)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return tmp_path, ctx


def _pack_members(scan_type: str, scan_id: int, team_id: int, data: dict, bom: dict | None,
                  ctx: ReportContext, *, subject_name: str | None = None,
                  team_profile: dict | None = None) -> list[tuple[str, bytes]]:
    """The pack's files in zip order. D11 / C G-X-3: the JSON BOM carries its embedded JSF signature; with a signing
    key the pack also holds the public key, the offline verifier, the detached signature of each BOM file and a
    signed ``manifest.json`` (SHA-256 and size of every file) and ``SHA256SUMS`` (``bom_signing.pack_files``)."""
    files: list[tuple[str, bytes]] = []
    if bom:
        files.append(("bom.cdx.json", _signed_bom_bytes(bom, indent=2)))
        if scan_type == "cbom":  # the same document as CycloneDX XML, signed detached
            try:
                from backend.utilities.cbom_sources import cdx_xml

                files.append(("bom.cdx.xml", cdx_xml.to_xml(bom)))
            except Exception as e:  # never fail the pack over the XML copy
                console.print(f"evidence-pack XML skipped: {e.__class__.__name__}", style="yellow")
    if scan_type == "ai_bom":  # D5: the SPDX 3.0 and SARIF files as GET /spdx and /sarif serve them, signed detached
        for artifact, member in (("spdx", "bom.spdx.json"), ("sarif", "bom.sarif")):
            body = ARTIFACTS.stored_artifact(data, artifact)
            if body is not None:
                files.append((member, body))
    if isinstance(data.get("vex_json"), dict):  # D7: signed inside (JSF) and detached, like the BOM
        files.append(("vex.json", _signed_bom_bytes(_served_vex(scan_type, scan_id, team_id, data["vex_json"], bom),
                                                     indent=2)))
    # a stored HMAC ships only when it signs the bom.cdx.json packed next to it (review 6028132826 M6)
    if isinstance(data.get("bom_signature"), dict) and _signature_matches(bom, data["bom_signature"]):
        files.append(("bom_signature.json", json.dumps(data["bom_signature"], indent=2).encode("utf-8")))
    ckey = compliance_key_for(scan_type)
    if isinstance(data.get(ckey), dict):
        files.append(("compliance.json", json.dumps(data[ckey], indent=2).encode("utf-8")))
    if isinstance(data.get("attestations"), dict):
        files.append(("attestations.json", json.dumps(data["attestations"], indent=2).encode("utf-8")))
    pdf_data = data
    if scan_type == "sbom_sca":  # the report's SBOM pages read this pack's bom.cdx.json: the same builder and subject
        from backend.utilities.pdf.sbom_sca_pdf import SUBJECT_NAME_KEY

        pdf_data = {**data, SUBJECT_NAME_KEY: subject_name,
                    SERVED.SCAN_IDENTITY_KEY: SERVED.pdf_identity(scan_type, scan_id, team_id, subject_name)}
    elif scan_type == "cbom" and team_profile is not None:
        # the report's framework table lists the frameworks that bind the team, as GET /export does (Q2-03)
        from backend.utilities.pdf.rbi_compliance_pdf import TEAM_PROFILE_KEY

        pdf_data = {**data, TEAM_PROFILE_KEY: team_profile}
    pdf = _pack_pdf(scan_type, pdf_data, ctx)
    if pdf is not None:
        files.append(("report.pdf", pdf))
    try:
        files += SIGN.pack_files(files, subject={"kind": f"{scan_type}-scan", "scan_id": scan_id, "team_id": team_id,
                                                 "bom_serial": (bom or {}).get("serialNumber")},
                                 detached_for=[n for n, _b in files if n.startswith(("bom.cdx.", "bom.spdx.", "bom.sarif"))
                                               or n == "vex.json"])
    except SIGN.SigningUnavailable as exc:  # say so in the pack (review 6029745818 minor 4); the reason names no value
        files.append(("UNSIGNED.txt", SIGN.unsigned_note(str(exc)).encode("utf-8")))
    return files


@router.get("/{team_id}/{type}/scan/{scan_id}/evidence-pack", dependencies=[Depends(write_limiter), access.team("scan.read")])
async def download_evidence_pack(
    team_id: int,
    type: scan_types,
    scan_id: int,
    request: Request,
    background_tasks: BackgroundTasks,
    Authorization: Annotated[str | None, Header()] = None,
):
    """Zip of the scan's BOM, VEX, signature, compliance, attestations and PDF report. The pack's PDF is always the
    full report (report options are refused with 422); the team's report logo appears in it when set."""
    started = time.monotonic()
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    try:
        options_from_request(request.query_params, "pack")  # any report option: 422 (a pack is the full record)
        tmp_path, ctx = await run_in_threadpool(_build_evidence_pack, engine, team_id, type, scan_id)
    except HTTPException as e:
        outcome, code = failure_outcome(e)
        log_export("pack", type=type, team=team_id, id=scan_id, user=user.id, started=started, outcome=outcome,
                   status=code)
        raise
    except Exception as e:
        console.print(f"evidence-pack failed for scan {scan_id} team {team_id}: {e.__class__.__name__}",
                      style="bold red", markup=False)
        log_export("pack", type=type, team=team_id, id=scan_id, user=user.id, started=started, outcome="error",
                   status=500)
        raise HTTPException(status_code=500, detail="Error building the evidence pack, please try again later") from None
    background_tasks.add_task(os.unlink, tmp_path)
    filename = f"certin-evidence-pack-{type}-{scan_id}.zip"
    log_export("pack", type=type, team=team_id, id=scan_id, user=user.id, ctx=ctx,
               size=os.path.getsize(tmp_path), started=started, outcome=await finished_outcome(request))
    # the file name travels in report_headers' Content-Disposition (FileResponse adds its own only for filename=)
    return FileResponse(tmp_path, media_type="application/zip", headers=report_headers(ctx, filename, findings=False))
