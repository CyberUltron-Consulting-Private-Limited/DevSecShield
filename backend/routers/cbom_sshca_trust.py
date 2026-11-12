"""Machine read path of the SSH CA trust bundle (F1.4, PR #65 review round 7): ``/cbom/ssh-ca-trust/...``.

Servers (or the configuration management that installs their files) read what sshd needs for the ``zs-cbom`` login
with a team's trust token, never a user session:

* ``GET /cbom/ssh-ca-trust/trusted-keys``  TrustedUserCAKeys (text)
* ``GET /cbom/ssh-ca-trust/revoked``       RevokedKeys, an OpenSSH KRL (binary)
* ``GET /cbom/ssh-ca-trust/principals?group=<g>&group=…``  AuthorizedPrincipalsFile for the server's group(s) (text)

The token (``X-ZS-Trust-Token``) names the team; there is no team id in the path, and a token reads its own team's
files only.  A missing, unknown or revoked token is a 401.  Every answer has a strong ``ETag`` and
``X-ZS-Trust-Generation``; ``If-None-Match`` gets a 304.  ``X-ZS-Fetcher`` (the server's name) is recorded with the
generation it received, for promote readiness (``sshca/trust.py``).  404 while ``CBOM_SSH_CA`` is off.

Access declaration: ``x-zs-permission: machine:ssh-ca trust token`` (F4's marker for a credential that is not a
team role; the handler checks it).  Rate limit: per token (servers of one team share it), unknown tokens per address.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Security
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from fastapi.security import APIKeyHeader
from sqlmodel import Session

from backend.utilities.cbom_sources import http as H
from backend.utilities.cbom_sources.common import log, utcnow
from backend.utilities.cbom_sources.http import PRIVATE, client_ip, server_error
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca import registry as R
from backend.utilities.cbom_sources.sshca import trust as T
from backend.utilities.ratelimit import Key, RateLimiter, ip_key

router = APIRouter(tags=["cbom-ssh-ca-trust"], route_class=flags.route_class())
PREFIX = "/cbom/ssh-ca-trust"
ACCESS = {"x-zs-permission": "machine:ssh-ca trust token"}
token_header = APIKeyHeader(name="X-ZS-Trust-Token", auto_error=False)
UNAUTHORIZED = "A valid SSH CA trust token is required (X-ZS-Trust-Token)"


def _token_id(secret: str) -> int | None:
    with Session(H.get_db()) as session:
        row = T.authenticate(session, secret)
        return row.id if row else None


async def trust_key(request: Request) -> Key:
    """A live token is charged by its id (all servers of one team share it, so the budget is generous); anything else
    by the address, so guessing tokens never buys fresh budgets."""
    secret = request.headers.get("x-zs-trust-token") or ""
    if T.TOKEN_RE.match(secret):
        token_id = await run_in_threadpool(_token_id, secret)
        if token_id is not None:
            return ("trust", str(token_id))
    return await ip_key(request)


trust_limiter = RateLimiter("cbom_sshca.trust", times=6000, seconds=60, key_func=trust_key)
LIMIT = [Depends(trust_limiter)]


def _serve(secret: str | None, fetcher: str | None, ip: str, what: str, groups: list[str]) -> tuple[bytes, int, str]:
    now = utcnow()
    with Session(H.get_db()) as session:
        token = T.authenticate(session, secret)
        if token is None:
            raise HTTPException(status_code=401, detail=UNAUTHORIZED)
        team_id = token.team_id
        trust_gen, revocation_gen, _at = T.generations(session, team_id)
        if what == "trusted-keys":
            body = R.trusted_keys_text(session, team_id, now).encode()
            T.record_fetch(session, token, T.fetcher_name(fetcher, token), ip, now, trust_generation=trust_gen)
        elif what == "revoked":
            body, revocation_gen = T.krl_bytes(session, team_id)
            T.record_fetch(session, token, T.fetcher_name(fetcher, token), ip, now,
                           revocation_generation=revocation_gen)
        else:
            body = T.principals_text(team_id, T.check_groups(groups)).encode()  # checked after the token
        session.commit()
        return body, trust_gen, T.etag_of(body)


async def _answer(request: Request, secret: str | None, what: str, media: str, groups: list[str] | None = None):
    try:
        body, generation, etag = await run_in_threadpool(_serve, secret, request.headers.get("x-zs-fetcher"),
                                                         client_ip(request), what, groups or [])
    except HTTPException as exc:
        if exc.status_code == 401:
            log("ssh ca trust fetch refused", what=what, ip=client_ip(request))
        raise
    except Exception as exc:
        raise server_error(f"cbom ssh ca trust {what}", exc) from None
    headers = {**PRIVATE, "ETag": etag, "X-ZS-Trust-Generation": str(generation)}
    if T.etag_matches(request.headers.get("if-none-match"), etag):
        return Response(status_code=304, headers=headers)
    return Response(body, headers={**headers, "Content-Type": media})


@router.get(PREFIX + "/trusted-keys", dependencies=LIMIT, openapi_extra=ACCESS,
            summary="TrustedUserCAKeys for this token's team (ETag / If-None-Match)")
async def trusted_keys(request: Request, token: Annotated[str | None, Security(token_header)] = None):
    return await _answer(request, token, "trusted-keys", "text/plain; charset=utf-8")


@router.get(PREFIX + "/revoked", dependencies=LIMIT, openapi_extra=ACCESS,
            summary="RevokedKeys (OpenSSH KRL) for this token's team (ETag / If-None-Match)")
async def revoked(request: Request, token: Annotated[str | None, Security(token_header)] = None):
    return await _answer(request, token, "revoked", "application/octet-stream")


@router.get(PREFIX + "/principals", dependencies=LIMIT, openapi_extra=ACCESS,
            summary="AuthorizedPrincipalsFile for the server's group(s) (ETag / If-None-Match)")
async def principals(request: Request, token: Annotated[str | None, Security(token_header)] = None,
                     group: list[str] = Query(default=[])):
    return await _answer(request, token, "principals", "text/plain; charset=utf-8", group[:T.MAX_GROUPS + 1])
