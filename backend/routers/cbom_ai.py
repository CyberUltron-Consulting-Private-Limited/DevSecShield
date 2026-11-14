"""CBOM AI remediation assistant (CB-38 PR-6): ``/{team_id}/cbom/ai/status`` and ``/{team_id}/cbom/ai/assist``.

Team-membership auth like every CBOM route; the subject is loaded team-scoped from ids only (a run asset through the
Sources router's ``_asset_detail`` / ``_get_owned``, a code-scan finding through the team's ``Scan`` row and its stored
finding). Off (status unavailable, assist 404, no socket opened) unless the deployment sets ``CBOM_AI_PROVIDER=bedrock``
(AWS Bedrock, the product's only outbound call) or an on-prem ``CBOM_AI_BASE_URL`` + ``CBOM_AI_MODEL``. The status
route lists every host the assistant will contact (``egress``). No credits are charged.

Team opt-out (OQ-8) is not in this PR: ``cbomcollectionsettings`` has no general settings JSON column (``risk_model`` is
the Mosca model, cleared by ``risk_model: null``), and this lane adds no migration.
"""
from __future__ import annotations

import time
from typing import Annotated, Literal, Union

from bson import ObjectId as BsonObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlmodel import Session, select

from backend.new_models import Scan
from backend.utilities.cbom_ai import config as C
from backend.utilities.cbom_ai import grounding as G
from backend.utilities.cbom_ai import service as S
from backend.utilities.cbom_ai import transport as T
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize, read_limiter, server_error
from backend.utilities.ratelimit import RateLimiter, user_key

router = APIRouter(tags=["cbom-ai"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
BASE = "/{team_id}/cbom/ai"
MAX_ID = 2_147_483_647
NOT_CONFIGURED = "AI assistant is not configured"

assist_limiter = RateLimiter("cbom_ai.assist", times=20, seconds=60, key_func=user_key)

_address_ok: dict[tuple, tuple[float, list[dict] | None]] = {}
ADDRESS_TTL_S = 60.0


class RunAssetSubject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["run_asset"]
    asset_id: int = Field(ge=1, le=MAX_ID)


class ScanFindingSubject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["scan_finding"]
    scan_id: int = Field(ge=1, le=MAX_ID)
    finding_id: str = Field(pattern=r"^[0-9a-fA-F]{24}$")


class AssistBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: Annotated[Union[RunAssetSubject, ScanFindingSubject], Field(discriminator="kind")]
    mode: Literal["explain", "plan", "question"]
    question: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _question(self) -> "AssistBody":
        if self.mode == "question" and not (self.question or "").strip():
            raise ValueError("enter a question")
        if self.mode != "question":
            self.question = None
        return self


def _egress(cfg: C.AiConfig) -> list[dict] | None:
    """Where the assistant will connect, or None when it may not / cannot (address policy, endpoint override rule, no
    AWS credentials). Checked at most once a minute per configuration (status is polled by every panel)."""
    key = (cfg.provider, cfg.base_url, cfg.region, cfg.allow_nonprivate, cfg.endpoint_override, cfg.aws_profile,
           cfg.aws_credentials, cfg.aws_settings, cfg.allow_loopback)
    hit = _address_ok.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < ADDRESS_TTL_S:
        return hit[1]
    egress: list[dict] | None
    try:
        if cfg.provider == "bedrock":
            # configuration only: no credential lookup here (that may call IMDS / STS; it happens on the first assist)
            T.check_bedrock_endpoint(cfg, S.resolve)
            egress = T.bedrock_egress(cfg)
        else:
            T.pin_address(cfg, S.resolve)
            where = "any address (CBOM_AI_ALLOW_NONPRIVATE=1)" if cfg.allow_nonprivate else "private address"
            egress = [{"host": cfg.host, "port": cfg.port, "purpose": f"model {cfg.model} on {where}"}]
    except T.EndpointRefused as exc:
        S.log.warning("cbom_ai endpoint not usable: %s", exc)
        egress = None
    except Exception as exc:  # a broken AWS config file, for example: unavailable, never a 500 on status
        S.log.warning("cbom_ai endpoint check failed: %s", exc.__class__.__name__)
        egress = None
    _address_ok[key] = (now, egress)
    return egress


async def _available() -> tuple[C.AiConfig, list[dict]] | None:
    cfg = C.load()
    if cfg is None:
        return None
    egress = await run_in_threadpool(_egress, cfg)
    if egress is None:
        return None
    return cfg, egress


@router.get(BASE + "/status", dependencies=[Depends(read_limiter)],
            summary="Whether the on-prem AI remediation assistant is configured for this deployment")
async def ai_status(team_id: TeamId, Authorization: AuthHeader = None):
    await authorize(team_id, Authorization)
    found = await _available()
    if found is None:
        return JSONResponse({"available": False}, headers=PRIVATE)
    cfg, egress = found
    return JSONResponse({"available": True, "provider": cfg.provider, "model": cfg.model, "region": cfg.region,
                         "kb_version": crypto_kb.version(), "egress": egress,
                         "allow_nonprivate": cfg.allow_nonprivate if cfg.provider == "openai_compat" else False},
                        headers=PRIVATE)


def _run_asset_grounding(engine, team_id: int, asset_id: int, minimise: bool) -> G.Grounding:
    from backend.routers.cbom_sources import _asset_detail  # team-scoped (_get_owned): another team's asset is a 404

    return G.for_run_asset(_asset_detail(engine, team_id, asset_id)["asset"], minimise=minimise)


def _scan_finding_grounding(engine, team_id: int, scan_id: int, finding_id: str, minimise: bool) -> G.Grounding:
    from backend.get_db import get_mongo_client_db
    from backend.utilities.cbom_sources.kb_remediation import explain

    with Session(engine) as session:
        scan = session.exec(select(Scan).where(Scan.id == scan_id, Scan.team_id == team_id,
                                               Scan.scan_type == "cbom")).first()
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found for this team")
    try:
        oid = BsonObjectId(finding_id)
    except (InvalidId, TypeError):
        raise HTTPException(status_code=404, detail="Finding not found") from None
    finding = get_mongo_client_db()["scan_findings"].find_one({"_id": oid})
    if not finding or finding.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    data = finding.get("finding_data") or {}
    return G.for_code_finding(scan_id, finding_id, data, explain(data, "code"), minimise=minimise)


@router.post(BASE + "/assist", dependencies=[Depends(assist_limiter)],
             summary="Explain / plan / answer a question about one finding, grounded on the KB and checked against it")
async def ai_assist(team_id: TeamId, body: AssistBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    found = await _available()
    if found is None:
        raise HTTPException(status_code=404, detail=NOT_CONFIGURED)
    cfg, _egress_list = found
    subject = body.subject
    try:
        if isinstance(subject, RunAssetSubject):
            grounding = await run_in_threadpool(_run_asset_grounding, engine, team_id, subject.asset_id,
                                                cfg.redact_hosts)
        else:
            grounding = await run_in_threadpool(_scan_finding_grounding, engine, team_id, subject.scan_id,
                                                subject.finding_id, cfg.redact_hosts)
        result = await S.assist(cfg, grounding, mode=body.mode, question=body.question, kb_version=crypto_kb.version(),
                                team_id=team_id, user_id=user.id)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error("cbom ai assist", exc, team=team_id) from None
    return JSONResponse(result, headers=PRIVATE)
