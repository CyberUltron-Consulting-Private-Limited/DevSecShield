"""Scan-node route of the SSH CA (F1.4): ``POST /cbom/node/jobs/{job_id}/ssh-cert``.

A node running a job of an ``ssh_ca`` source asks here for its certificate when the claim did not carry one (a Vault
CA, or a claim made before this deployment had the plugin) and to renew it before it expires during a long job.

Same authentication as every node route (token, then client certificate and request signature on the raw bytes before
anything is parsed), then the lease: only the node that holds the job, under the lease it was given, gets a
certificate, and only for that job's source (its principals, its CA, the node's own key).  Issue rules and the audit
row: ``utilities/cbom_sources/sshca/issue.py``.  404 while ``CBOM_SSH_CA`` is off.

Answers: 200 the certificate; 400 refused (the reason); 404 not this node's job; 409 the lease is gone, or "Stop this
job: …" (cancelled, source changed or disabled, a certificate of this run revoked); 503 + ``Retry-After`` when AWS KMS
did not answer (the node retries).  No transaction is open while KMS or Vault is called (``release``): the request's
reads are committed first, and the lease is checked again once they answered, before anything is recorded.  Every refusal after authentication is audited and logged once per (node, job,
reason) and minute (``sshca/denials.py``).
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
from backend.utilities.cbom_sources.common import log
from backend.utilities.cbom_sources.sshca import denials as DEN
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca.ca import IssueError
from backend.utilities.cbom_sources.sshca.issue import issue_for_job

router = APIRouter(tags=["cbom-node"], route_class=flags.route_class())

# Access declaration: a scan node is not a person with a team role.  F4's marker form for such a credential is
# "machine:<credential>" (rbac/policy.py, no import needed); the handler checks the credential (node token, request
# signature, the job's lease).  #34's fleet route guard accepts machine: markers on /cbom/node/ paths.
OPENAPI_EXTRA = {"x-zs-permission": "machine:scan-node token"}
RETRY_AFTER_S = 15
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


_HTTP_CODES = {400: "bad_request", 404: "not_this_node", 409: "lease_lost"}


def _denied(session: Session, node: CbomScanNode, job_id: int, code: str, status: int,
            source_id: int | None = None, ca_id: int | None = None) -> None:
    """One audit row and one log line for a refusal, in its own transaction (the request's was rolled back)."""
    try:
        session.rollback()
        if DEN.record(session, team_id=node.team_id, node_id=int(node.id or 0), job_id=job_id, code=code,
                      via="route", source_id=source_id, ca_id=ca_id, status=status):
            session.commit()
    except Exception as exc:  # the refusal itself must still reach the node
        session.rollback()
        log("ssh certificate refusal not audited", node=node.id, job=job_id, reason=code, error=type(exc).__name__)


def _issue(token: str | None, job_id: int, req: NA.NodeRequest, raw: bytes) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        node = authenticate_node(session, token, req, raw, now)  # before anything: no node, nothing to attribute
        try:
            try:
                body = CertBody.model_validate(parse_json(raw))
            except ValidationError as exc:
                raise bad_request(exc) from None
            job = _leased_job(session, node, job_id, body.lease_id)
        except HTTPException as exc:
            _denied(session, node, job_id, _HTTP_CODES.get(exc.status_code, f"http_{exc.status_code}"), exc.status_code)
            raise
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        ca_id = (source.config or {}).get("ssh_ca_id") if source is not None and isinstance(source.config, dict) else None
        reason = J._invalid_reason(job, source, node)  # a job that must stop gets no new certificate
        if reason:
            _denied(session, node, job_id, "job_must_stop", 409, job.source_id, ca_id)
            raise HTTPException(status_code=409, detail=f"Stop this job: {reason}")
        released: list[bool] = []

        def release() -> None:  # before a KMS or Vault call: end the read transaction (its connection goes back to
            session.commit()    # the pool), so an outage holds no connection idle in a transaction
            released.append(True)

        source_id = job.source_id
        try:
            minted = issue_for_job(session, node, job, source, now, via="refresh", release=release)
            if released:  # KMS or Vault answered: the job may have been cancelled or lost meanwhile
                job = _leased_job(session, node, job_id, body.lease_id)
                reason = J._invalid_reason(job, session.get(CbomCollectionSource, source_id) if source_id else None,
                                           node)
                if reason:
                    raise IssueError(f"Stop this job: {reason}", "job_must_stop", status=409)
        except IssueError as exc:
            _denied(session, node, job_id, exc.code, exc.status, source_id, ca_id)
            headers = {"Retry-After": str(RETRY_AFTER_S)} if exc.transient else None
            raise HTTPException(status_code=exc.status, detail=str(exc)[:300], headers=headers) from None
        except HTTPException as exc:  # the lease went while KMS or Vault answered: nothing is recorded
            _denied(session, node, job_id, _HTTP_CODES.get(exc.status_code, f"http_{exc.status_code}"), exc.status_code,
                    source_id, ca_id)
            raise
        session.commit()
        return minted.payload(now)


@router.post("/cbom/node/jobs/{job_id}/ssh-cert", dependencies=[Depends(node_limiter)],
             openapi_extra=OPENAPI_EXTRA,
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
