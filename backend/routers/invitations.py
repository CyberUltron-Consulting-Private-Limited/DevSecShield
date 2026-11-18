"""The invitee's side of a team invitation (the page /invite/<token>; see utilities/team/invitations.py).

* GET    /invitations/{token}           what the link offers: team, who invited, the address, whether it has an account
* POST   /invitations/{token}/register  a new address chooses its password; the account is created and joins
* POST   /invitations/{token}/accept    an existing account, signed in as the invited address, joins
* POST   /invitations/{token}/decline   signed in as the address (or, for an address without an account, the link alone)

The link is the credential (it proves the mailbox), so these never answer with anything about another address.
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from backend.get_db import get_db
from backend.routers.auth import _tokens
from backend.utilities.auth.auth_schema import NoEchoValidationRoute, clean_new_password
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.ratelimit import RateLimiter, ip_key
from backend.utilities.team import invitations
from backend.utilities.rbac.policy import Access, public, request_meta

log = logging.getLogger("backend.team")

router = APIRouter(tags=["team invitations"], route_class=NoEchoValidationRoute)  # a 422 never echoes the password
read_limiter = RateLimiter("invitations.read", times=30, seconds=60, key_func=ip_key)
write_limiter = RateLimiter("invitations.write", times=10, seconds=60, key_func=ip_key)

MAX_NAME_CHARS = 64
access = Access(lambda: get_db())  # route policies (utilities/rbac), bound to this module's get_db


def _clean_name(value: str) -> str:
    value = " ".join((value or "").split())
    if not value:
        raise ValueError("Enter your name")
    if len(value) > MAX_NAME_CHARS or any(c in value for c in "<>\x00"):
        raise ValueError(f"Names are at most {MAX_NAME_CHARS} characters, without < or >")
    return value


class InvitationRegister(BaseModel):
    first_name: str = Field(..., description="first name")
    last_name: str = Field(..., description="last name")
    password: str = Field(..., description="the password you choose: 8 to 128 characters")

    check_names = field_validator("first_name", "last_name")(_clean_name)
    check_password = field_validator("password")(clean_new_password)


async def _optional_user(Authorization: str | None):
    if not Authorization:
        return None
    return await get_user_from_header_or_raise_exception(get_db(), Authorization)


@router.get("/invitations/{token}", summary="What an invitation link offers",
            dependencies=[Depends(read_limiter), public("the invitation link is the credential")])
async def get_invitation(token: str):
    return await run_in_threadpool(invitations.describe, token, get_db())


@router.post("/invitations/{token}/register", summary="Accept with a new account (the address has none)",
             dependencies=[Depends(write_limiter), public("the invitation link is the credential")])
async def register_from_invitation(token: str, data: InvitationRegister, request: Request):
    user, team_id = await invitations.register(token, data.password, data.first_name, data.last_name, get_db(),
                                               meta=request_meta(request))
    return {**_tokens(user), "team_id": team_id}


@router.post("/invitations/{token}/accept", summary="Accept, signed in as the invited address",
             dependencies=[Depends(write_limiter), access.authenticated()])
async def accept_invitation(token: str, request: Request, Authorization: Annotated[str | None, Header()] = None):
    user = await _optional_user(Authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to accept this invitation")
    team_id = await run_in_threadpool(invitations.accept, token, user, get_db(), request_meta(request))
    return {"message": "You joined the team", "team_id": team_id}


@router.post("/invitations/{token}/decline", summary="Decline an invitation",
             dependencies=[Depends(write_limiter), public("the link, plus sign-in when the address has an account")])
async def decline_invitation(token: str, Authorization: Annotated[str | None, Header()] = None):
    user = await _optional_user(Authorization)
    await run_in_threadpool(invitations.decline, token, user, get_db())
    return {"message": "Invitation declined"}
