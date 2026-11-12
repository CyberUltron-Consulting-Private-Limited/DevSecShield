"""Scan-node route of the SSH CA (F1.4): ``POST /cbom/node/jobs/{job_id}/ssh-cert``.

A node running a job of an ``ssh_ca`` source asks here for its certificate when the claim did not carry one (a Vault
CA, or a claim made before this deployment had the plugin) and to renew it before it expires during a long job.

Same authentication as every node route (token, then client certificate and request signature on the raw bytes before
anything is parsed), then the lease: only the node that holds the job, under the lease it was given, gets a
certificate, and only for that job's source (its principals, its CA, the node's own key).  Issue rules and the audit
row: ``utilities/cbom_sources/sshca/issue.py``.  404 while ``CBOM_SSH_CA`` is off.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlmodel import Session

from backend.get_db import get_db
from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.routers import cbom_node as NODE
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import node_auth as NA
from backend.utilities.cbom_sources.common import utcnow
from backend.utilities.cbom_sources.http import PRIVATE, bad_request, node_limiter, parse_json, read_capped_body, server_error
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca.ca import IssueError
from backend.utilities.cbom_sources.sshca.issue import issue_for_job

router = APIRouter(tags=["cbom-node"], route_class=flags.route_class())
node_token_header = APIKeyHeader(name="X-ZS-Node-Token", auto_error=False)
SMALL_BODY = 4 * 1024

# F1.1 publishes authenticate_node and jobs.leased_job; until it is on dev the same functions are used under their
# current names (optional-import seam, removed in the F1 integration PR).
authenticate_node = getattr(NODE, "authenticate_node", None) or NODE._authenticate


def _leased_job(session: Session, node: CbomScanNode, job_id: int, lease_id: str) -> CbomCollectionJob:
    published = getattr(J, "leased_job", None)
    if published is not None:
        return published(session, node, job_id, lease_id)
    job = J._owned_job(session, node, job_id, node.team_id)
    if job.status != "claimed" or job.lease_id != lease_id:
        raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    return job


class CertBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lease_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def _issue(token: str | None, job_id: int, req: NA.NodeRequest, raw: bytes) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        node = authenticate_node(session, token, req, raw, now)
        try:
            body = CertBody.model_validate(parse_json(raw))
        except ValidationError as exc:
            raise bad_request(exc) from None
        job = _leased_job(session, node, job_id, body.lease_id)
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        reason = J._invalid_reason(job, source, node)  # a job that must stop gets no new certificate
        if reason:
            raise HTTPException(status_code=409, detail=f"Stop this job: {reason}")
        try:
            minted = issue_for_job(session, node, job, source, now, via="refresh")
        except IssueError as exc:
            session.rollback()
            raise HTTPException(status_code=400, detail=str(exc)[:300]) from None
        session.commit()
        return minted.payload(now)


@router.post("/cbom/node/jobs/{job_id}/ssh-cert", dependencies=[Depends(node_limiter)],
             openapi_extra={"x-zs-permission": "cbom.node"},  # a scan-node token, not a team role (F4: machine)
             summary="A short-lived SSH certificate for the node's own key, for a job it holds")
async def ssh_cert(job_id: int, request: Request,
                   token: Annotated[str | None, Security(node_token_header)] = None):
    if job_id < 1 or job_id > 2_147_483_647:
        raise HTTPException(status_code=404, detail="Job not found")
    raw = await read_capped_body(request, SMALL_BODY)
    try:
        payload = await run_in_threadpool(_issue, token, job_id, NA.NodeRequest.of(request), raw)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error("cbom node ssh-cert", exc) from None
    return JSONResponse(payload, headers=PRIVATE)
