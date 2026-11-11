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
from sqlalchemy import update
from sqlalchemy.orm.attributes import set_committed_value
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


# What the forms call a field, for the few names a plain "word word" spelling would get wrong.
_FIELD_LABELS = {
    "url": "URL", "uri": "URI", "ip": "IP address", "ips": "IP addresses", "cidr": "Network range",
    "cidrs": "Network ranges", "ca_pem": "CA certificate", "proxy_url": "Proxy URL", "proxy_ca_pem": "Proxy CA certificate",
    "api_key": "API key", "hec_token": "HEC token", "sni": "SNI", "tls": "TLS", "aws_source_id": "AWS account",
    "cloud_source_id": "Cloud account", "node_id": "Scan node", "kubeconfig": "Kubeconfig",
}


def field_label(name: str) -> str:
    """A field as the customer sees it ("ssh_port" -> "Ssh port", "url" -> "URL"), never a path like "config.url"
    (X1, Nov 11: source and integration errors said "config.hosts: ..." and "config.Line 1: ...")."""
    return _FIELD_LABELS.get(name) or name.replace("_", " ").strip().capitalize()


def format_errors(errors: list[dict[str, Any]]) -> str:
    first = errors[0] if errors else {}
    loc = [p for p in first.get("loc", ()) if p not in ("body", "query", "path", "config")]
    message = str(first.get("msg", "Invalid input"))
    for prefix in ("Value error, ", "Assertion failed, "):
        if message.startswith(prefix):
            message = message[len(prefix):]
    names = [p for p in loc if isinstance(p, str) and not p.startswith("function-")]
    field = field_label(names[-1]) if names else ""
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


CHANGED_ELSEWHERE = "This was changed elsewhere. Reload to see the latest version."


def check_version(row: Any, expected: int | None) -> None:
    if expected is not None and getattr(row, "row_version", None) != expected:
        raise HTTPException(status_code=409, detail=CHANGED_ELSEWHERE)


def bump_version(session: Session, row: Any) -> None:
    """``row.row_version += 1`` as a compare-and-set on the version this request read (``UPDATE ... WHERE row_version =
    :read``), instead of an ORM read-modify-write: two edits that both passed ``check_version`` (READ COMMITTED lets
    them read the same version) cannot both be saved; the one that writes second gets the same 409.  Call it where the
    row is changed, before the commit (the transaction is rolled back with the 409)."""
    model = type(row)
    read = row.row_version
    won = session.exec(  # type: ignore[call-overload]
        update(model).where(model.id == row.id, model.row_version == read)
        .values(row_version=read + 1).execution_options(synchronize_session=False)
    ).rowcount
    if won != 1:
        raise HTTPException(status_code=409, detail=CHANGED_ELSEWHERE)
    set_committed_value(row, "row_version", read + 1)


async def read_capped_body(request: Request, limit: int) -> bytes:
    """Read the raw body with a hard cap (FastAPI would otherwise buffer it all).  Signed scan-node requests are
    verified on exactly these bytes before anything parses them."""
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
    return b"".join(chunks)


def parse_json(raw: bytes) -> Any:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Body is not valid JSON") from exc


async def read_capped_json(request: Request, limit: int) -> Any:
    """Read the body with a hard cap before parsing it (FastAPI would otherwise buffer it all)."""
    return parse_json(await read_capped_body(request, limit))


def server_error(what: str, exc: BaseException, **fields: Any) -> HTTPException:
    ref = new_ref()
    log(f"{what} FAILED", ref=ref, error=type(exc).__name__, **fields)
    return HTTPException(status_code=500, detail=f"Something went wrong; please try again (ref {ref})")
