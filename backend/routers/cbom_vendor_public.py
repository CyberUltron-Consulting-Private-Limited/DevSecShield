"""Public, single-use vendor questionnaire links (no login).

``GET`` shows the questions; ``POST`` stores the answers and burns the link in one guarded UPDATE, so
a link can be answered once.  Unknown, used, expired and deleted links all return the same 404.
Only the vendor name, the team name and the questions are disclosed.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import update
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import CbomEvidenceVendor, Team
from backend.utilities.cbom_sources import q0register as Q0REG
from backend.utilities.cbom_sources.common import audit, iso_z, log, sha256_hex, utcnow
from backend.utilities.cbom_sources.evidence import AREAS, clean_answers
from backend.utilities.cbom_sources.http import CbomRoute, bad_request, read_capped_json, server_error, vendor_limiter
from backend.utilities.cbom_sources.schemas import VendorAnswer

router = APIRouter(tags=["cbom-vendor-questionnaire"], route_class=CbomRoute)
HEADERS = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
_GONE = HTTPException(status_code=404, detail="This link is not valid any more. Ask your contact for a new one.")
MAX_BODY = 32 * 1024


def _lookup(session: Session, token: str) -> CbomEvidenceVendor:
    if not token.startswith("zsv_") or len(token) > 96:
        raise _GONE
    now = utcnow()
    row = session.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.link_token_hash == sha256_hex(token))).first()
    # single use: answering clears the token hash; a vendor that answered before can answer a new link (a refresh)
    if row is None or row.link_expires_at is None or row.link_expires_at <= now:
        raise _GONE
    return row


def _show(token: str) -> dict:
    with Session(get_db()) as session:
        row = _lookup(session, token)
        team = session.get(Team, row.team_id)
        area = AREAS.get(row.area_key) or AREAS["third_party_vendors"]
        return {"vendor_name": row.name, "team_name": team.name if team else "", "area": area["title"],
                "questions": area["questions"], "expires_at": iso_z(row.link_expires_at)}


@router.get("/cbom/vendor-questionnaire/{token}", dependencies=[Depends(vendor_limiter)],
            summary="Questions behind a single-use vendor link")
async def show_questionnaire(token: str):
    try:
        payload = await run_in_threadpool(_show, token)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error("cbom vendor show", exc) from None
    return JSONResponse(payload, headers=HEADERS)


def _answer(token: str, body: VendorAnswer) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        row = _lookup(session, token)
        try:
            answers = clean_answers(row.area_key, body.answers)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        if not answers:
            raise HTTPException(status_code=400, detail="Answer at least one question")
        confidence = "E2" if body.evidence_url else "E1"  # documented with an evidence link, else self-attested
        changed = session.exec(
            update(CbomEvidenceVendor)
            .where(CbomEvidenceVendor.id == row.id, CbomEvidenceVendor.link_token_hash == sha256_hex(token),
                   CbomEvidenceVendor.link_expires_at > now)
            .values(answered_at=now, answers=answers, evidence_url=body.evidence_url, confidence=confidence,
                    link_token_hash=None, row_version=row.row_version + 1, last_updated=now)
        ).rowcount
        if changed != 1:
            raise _GONE
        audit(session, team_id=row.team_id, actor_type="vendor", actor_id=row.id, action="vendor.answer",
              object_type="vendor", object_id=row.id, changed_fields=answers.keys())
        team_id, vendor_id, refresh = row.team_id, row.id, bool(row.answered_at)
        session.expire_all()  # the UPDATE above bypassed the ORM: re-read the vendor's level for the register
        Q0REG.sync_evidence_safely(session, team_id, now)  # CB-23: the vendor's gap closes (cause evidence)
        session.commit()
        log("vendor answered", team=team_id, vendor=vendor_id, level=confidence, refresh=refresh)
        return {"received": True}  # the vendor is not told the team's internal level (CB-18 EC-12)


@router.post("/cbom/vendor-questionnaire/{token}", dependencies=[Depends(vendor_limiter)],
             summary="Submit answers; the link stops working afterwards")
async def answer_questionnaire(token: str, request: Request):
    data = await read_capped_json(request, MAX_BODY)
    try:
        body = VendorAnswer.model_validate(data)
    except ValidationError as exc:
        raise bad_request(exc) from None
    try:
        payload = await run_in_threadpool(_answer, token, body)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error("cbom vendor answer", exc) from None
    return JSONResponse(payload, headers=HEADERS)
