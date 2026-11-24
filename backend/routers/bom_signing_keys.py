"""The BOM signing public keys (D11; D4 / D5 evidence packs): ``GET /{team_id}/bom-signing-keys``.

Every team member (``scan.read``) can read the deployment's ES256 public key(s) that sign CycloneDX JSON (embedded JSF),
XML and evidence pack manifests (detached), as a JWK set with each key's PEM, fingerprint (RFC 7638 thumbprint) and the
offline verification steps; ``?format=pem`` answers the active key's PEM alone (``openssl dgst -sha256 -verify``).
Retired keys stay listed so files signed before a rotation still verify. Nothing secret is served. 503 when the
deployment has no signing key (``bom_signing`` module docstring: CBOM_SIGNING_KEY_PEM / _PATH or CERTIN_HMAC_SECRET).
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import JSONResponse, Response

from backend.utilities.cbom_sources import bom_signing as SIGN
from backend.utilities.cbom_sources import http as _cbom_http
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize
from backend.utilities.ratelimit import RateLimiter
from backend.utilities.rbac.policy import Access

router = APIRouter(tags=["bom-signing"], route_class=CbomRoute)
access = Access(lambda: _cbom_http.get_db())  # the same database as authorize()
read_limiter = RateLimiter("bom_signing_keys.read", times=120, seconds=60)


@router.get(SIGN.KEYS_ROUTE, dependencies=[Depends(read_limiter), access.team("scan.read")],
            summary="Public keys (JWKS + PEM) that sign this deployment's CycloneDX BOMs and evidence packs, with "
                    "offline verification steps")
async def bom_signing_keys(team_id: TeamId, format: str = Query(default="json", pattern="^(json|pem)$"),
                           Authorization: Annotated[str | None, Header()] = None) -> Response:
    await authorize(team_id, Authorization)
    try:
        doc = SIGN.public_keys_document()
    except SIGN.SigningUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    if format == "pem":
        kid = doc["active_kid"]
        return Response(doc["pem"][kid], media_type="application/x-pem-file", headers={
            **PRIVATE, "Content-Disposition": f'attachment; filename="{kid}.pem"', "X-ZS-Signature-Key-Id": kid})
    return JSONResponse(doc, headers=PRIVATE)
