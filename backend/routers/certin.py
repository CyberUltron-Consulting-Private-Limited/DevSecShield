"""CERT-In Phase 4 API — attestations, sign, VEX, evidence-pack."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
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
    UploadFile,
    status,
)
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from backend.utilities.ratelimit import RateLimiter
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import Scan, scan_types
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.compliance.certin_attest import (
    bom_dict_from_scan_data,
    compliance_key_for,
    delete_attestation,
    recompute_compliance_for_scan,
    requirement_ids_in_compliance,
    upsert_attestation,
)
from backend.utilities.pdf import generate_pdf_for_type
from backend.utilities.team import check_if_user_is_in_team
from rich.console import Console

router = APIRouter(tags=["certin"])
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
    """A CBOM VEX stored by older rules (rules 2: everything in triage; before: everything not affected) is rebuilt."""
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
        return VEX.code_scan_vex(rows, scan_id=scan.id, components=components, resolved=resolved, ref_of=ref_of,
                                 link_of=link_of, truncated=truncated,
                                 supersedes=stored if isinstance(stored, dict) else None)
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


@router.get("/{team_id}/{type}/scan/{scan_id}/attestations", dependencies=[Depends(read_limiter)])
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


@router.post("/{team_id}/{type}/scan/{scan_id}/attestations", dependencies=[Depends(write_limiter)])
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


@router.delete("/{team_id}/{type}/scan/{scan_id}/attestations/{framework}/{requirement_id}", dependencies=[Depends(write_limiter)])
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


@router.post("/{team_id}/{type}/scan/{scan_id}/sign", dependencies=[Depends(write_limiter)])
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
    bom = bom_dict_from_scan_data(type, data)
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


@router.get("/{team_id}/{type}/scan/{scan_id}/vex", dependencies=[Depends(read_limiter)])
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
    if not refresh and isinstance(data.get("vex_json"), dict) and _vex_is_current(type, data["vex_json"]):
        return JSONResponse(data["vex_json"])
    bom = bom_dict_from_scan_data(type, data)
    findings = data.get("results") if type in ("sbom_sca", "cbom") else None
    if not isinstance(findings, list):
        findings = None
    try:
        vex = _build_vex(engine, scan, type, bom, findings)
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"aibom vex unavailable: {e}") from e
    data = dict(data)
    data["vex_json"] = vex
    _save_scan_data(engine, scan_id, team_id, type, data)
    return JSONResponse(vex)


@router.get("/{team_id}/{type}/scan/{scan_id}/bom", dependencies=[Depends(read_limiter)])
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
    bom = bom_dict_from_scan_data(type, scan.scan_data if isinstance(scan.scan_data, dict) else {})
    if not bom:
        raise HTTPException(status_code=409, detail="No CycloneDX document is stored for this scan")
    if format == "json":
        return JSONResponse(bom, headers={
            "Content-Disposition": f'attachment; filename="{type}-cyclonedx-{scan_id}.cdx.json"'})
    if type != "cbom":
        raise HTTPException(status_code=400, detail="format=xml: XML export is available for CBOM scans")
    from backend.utilities.cbom_sources import cdx_xml

    body = await run_in_threadpool(cdx_xml.to_xml, bom)
    return Response(body, media_type=cdx_xml.XML_MEDIA_TYPE, headers={
        "Content-Disposition": f'attachment; filename="cbom-cyclonedx-{scan_id}.cdx.xml"',
        "X-ZS-Signature-Scope": cdx_xml.SIGNATURE_SCOPE})


@router.get("/{team_id}/{type}/scan/{scan_id}/evidence-pack", dependencies=[Depends(write_limiter)])
async def download_evidence_pack(
    team_id: int,
    type: scan_types,
    scan_id: int,
    background_tasks: BackgroundTasks,
    Authorization: Annotated[str | None, Header()] = None,
):
    _require_bom_type(type)
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    scan = _load_success_scan(engine, team_id, type, scan_id)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}

    # Ensure vex + signature exist when possible
    bom = bom_dict_from_scan_data(type, data)
    try:
        vex_mod = _load_certin_module("vex")
        sign_mod = _load_certin_module("sign")

        if not isinstance(data.get("vex_json"), dict) or not _vex_is_current(type, data["vex_json"]):
            findings = data.get("results") if type in ("sbom_sca", "cbom") else None
            data["vex_json"] = _build_vex(engine, scan, type, bom,
                                          findings if isinstance(findings, list) else None, vex_mod)
        if bom and not isinstance(data.get("bom_signature"), dict):
            try:
                data["bom_signature"] = sign_mod.sign_bom(bom, secret=_hmac_secret())
            except HTTPException:
                pass
        _save_scan_data(engine, scan_id, team_id, type, data)
    except ImportError:
        pass

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_path = tmp.name
    tmp.close()
    with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if bom:
            zf.writestr("bom.cdx.json", json.dumps(bom, indent=2))
            if type == "cbom":  # the same document as CycloneDX XML; bom_signature.json signs the JSON form only
                try:
                    from backend.utilities.cbom_sources import cdx_xml

                    zf.writestr("bom.cdx.xml", cdx_xml.to_xml(bom))
                except Exception as e:  # the JSON is the signed original; never fail the pack over the XML copy
                    console.print(f"evidence-pack XML skipped: {e.__class__.__name__}", style="yellow")
        if isinstance(data.get("vex_json"), dict):
            zf.writestr("vex.json", json.dumps(data["vex_json"], indent=2))
        if isinstance(data.get("bom_signature"), dict):
            zf.writestr("bom_signature.json", json.dumps(data["bom_signature"], indent=2))
        ckey = compliance_key_for(type)
        if isinstance(data.get(ckey), dict):
            zf.writestr("compliance.json", json.dumps(data[ckey], indent=2))
        if isinstance(data.get("attestations"), dict):
            zf.writestr("attestations.json", json.dumps(data["attestations"], indent=2))
        # PDF
        try:
            pdf_tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
            pdf_path = pdf_tmp.name
            pdf_tmp.close()
            generate_pdf_for_type(type, data, pdf_path)
            with open(pdf_path, "rb") as pf:
                zf.writestr("report.pdf", pf.read())
            os.unlink(pdf_path)
        except Exception as e:
            console.print(f"evidence-pack PDF skipped: {e}", style="yellow")

    background_tasks.add_task(os.unlink, tmp_path)
    return FileResponse(
        tmp_path,
        media_type="application/zip",
        filename=f"certin-evidence-pack-{type}-{scan_id}.zip",
    )
