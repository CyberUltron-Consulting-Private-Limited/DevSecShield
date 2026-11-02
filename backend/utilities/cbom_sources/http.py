"""HTTP plumbing shared by the CBOM Sources routers: errors, limits, auth helpers, body caps.

* Validation errors become a 400 with one readable sentence and never echo the submitted value
  (FastAPI's default 422 includes ``input``, which would put a mistyped password in the response,
  and the frontend shows only "Validation error" for a 422).
* No 403 is raised here for ordinary denials: the frontend logs the user out on a 403.
"""
from __future__ import annotations

import json
from typing import Annotated, Any, Callable

from fastapi import HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import ValidationError
from sqlmodel import Session, select
from starlette.responses import JSONResponse, Response

from backend.get_db import get_db
from backend.new_models import CbomScanNode, TeamMembership
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.cbom_sources.common import log, new_ref, sha256_hex
from backend.utilities.ratelimit import Key, RateLimiter, ip_key, user_key
from backend.utilities.team import check_if_user_is_in_team

MAX_TEAM_ID = 2_147_483_647
TeamId = Annotated[int, Path(ge=1, le=MAX_TEAM_ID, description="Team id")]
ObjectId = Annotated[int, Path(ge=1, le=MAX_TEAM_ID)]
PRIVATE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}


def format_errors(errors: list[dict[str, Any]]) -> str:
    first = errors[0] if errors else {}
    loc = [str(p) for p in first.get("loc", ()) if p not in ("body", "query", "path")]
    message = str(first.get("msg", "Invalid input"))
    for prefix in ("Value error, ", "Assertion failed, "):
        if message.startswith(prefix):
            message = message[len(prefix):]
    field = ".".join(loc[-2:]) if loc else ""
    return f"{field}: {message}" if field and not message.startswith(field) else message


class CbomRoute(APIRoute):
    """Turn request validation errors into a 400 with a safe, readable message."""

    def get_route_handler(self) -> Callable:
        handler = super().get_route_handler()

        async def route(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as exc:
                return JSONResponse({"detail": format_errors(list(exc.errors()))}, status_code=400, headers=PRIVATE)

        return route


def bad_request(exc: ValidationError | ValueError) -> HTTPException:
    if isinstance(exc, ValidationError):
        return HTTPException(status_code=400, detail=format_errors(list(exc.errors())))
    return HTTPException(status_code=400, detail=str(exc)[:500])


def client_ip(request: Request) -> str:
    """The client address as recorded on nodes.  ``request.client.host`` only: uvicorn has already applied
    ``X-Forwarded-For`` when (and only when) the proxy is in FORWARDED_ALLOW_IPS; the header itself is
    client-controlled and never read here."""
    return (request.client.host if request.client else "unknown")[:64]


def _node_id_for_token(token: str) -> int | None:
    with Session(get_db()) as session:
        return session.exec(select(CbomScanNode.id).where(CbomScanNode.node_token_hash == sha256_hex(token))).first()


async def node_key(request: Request) -> Key:
    """A verified scan node is charged by node id; an unknown token falls back to the address, so guessing
    tokens never buys fresh budgets."""
    token = request.headers.get("x-zs-node-token") or ""
    if token.startswith("zsn_") and len(token) <= 128:
        node_id = await run_in_threadpool(_node_id_for_token, token)
        if node_id is not None:
            return ("node", str(node_id))
    return await ip_key(request)


# Team UI routes: by verified user (the CBOM Sources tabs poll every 6 to 30 s).  Vendor links and node
# enrollment: by client address (a per-token budget would let a guesser use a fresh budget per guess).
read_limiter = RateLimiter("cbom_sources.read", times=300, seconds=60, key_func=user_key)
write_limiter = RateLimiter("cbom_sources.write", times=60, seconds=60, key_func=user_key)
node_limiter = RateLimiter("cbom_sources.node", times=120, seconds=60, key_func=node_key)
enroll_limiter = RateLimiter("cbom_sources.enroll", times=20, seconds=60, key_func=ip_key)
vendor_limiter = RateLimiter("cbom_sources.vendor", times=20, seconds=60, key_func=ip_key)


async def authorize(team_id: int, authorization: str | None):
    """Bearer token -> user -> team membership (existing 403 for non-members).  Returns (engine, user)."""
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, authorization)
    await run_in_threadpool(check_if_user_is_in_team, user.id, team_id, engine)
    return engine, user


def is_team_admin(session: Session, user_id: int, team_id: int) -> bool:
    row = session.exec(
        select(TeamMembership).where(TeamMembership.user_id == user_id, TeamMembership.team_id == team_id)
    ).first()
    return bool(row and row.role == "admin")


def require_owner_or_admin(session: Session, user_id: int, team_id: int, owner_user_id: int | None, what: str) -> None:
    if owner_user_id is not None and owner_user_id == user_id:
        return
    if is_team_admin(session, user_id, team_id):
        return
    raise HTTPException(status_code=400, detail=f"Only the person who added this {what} or a team admin can change it")


def require_admin(session: Session, user_id: int, team_id: int, what: str) -> None:
    if not is_team_admin(session, user_id, team_id):
        raise HTTPException(status_code=400, detail=f"Only a team admin can change {what}")


def check_version(row: Any, expected: int | None) -> None:
    if expected is not None and getattr(row, "row_version", None) != expected:
        raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")


async def read_capped_json(request: Request, limit: int) -> Any:
    """Read the body with a hard cap before parsing it (FastAPI would otherwise buffer it all)."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=f"Body larger than {limit // 1024} KB")
    total = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail=f"Body larger than {limit // 1024} KB")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Body is not valid JSON") from exc


def server_error(what: str, exc: BaseException, **fields: Any) -> HTTPException:
    ref = new_ref()
    log(f"{what} FAILED", ref=ref, error=type(exc).__name__, **fields)
    return HTTPException(status_code=500, detail=f"Something went wrong; please try again (ref {ref})")
