"""Sign-up, sign-in, token refresh, verification codes, password reset, logout.

Every sign-in, sign-up and reset needs the one-time code mailed to the address.  Codes are single-use, one
live code per email, compared at most five times, and new codes are capped per email per hour; past the cap the
live code is mailed again (``auth_utils``).  The fixed local code works only on a DSS_DEV_MODE=1 server and never
resets a password.  Reset and logout revoke every token issued before them.

Rate limits: by client address in the decorator, plus by email inside the handler (the email is in the body).
"""
import logging
from typing import Annotated

import psycopg2
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlmodel import Session, select, update
from starlette.concurrency import run_in_threadpool

from backend.get_db import get_db
from backend.new_models import Team, TeamMembership, User
from backend.utilities.auth.auth_schema import (
    CodeSend,
    NoEchoValidationRoute,
    RefreshToken,
    ResetPassword,
    TokenSchema,
    UserLogin,
    UserSignup,
)
from backend.utilities.auth.auth_utils import (
    CodeSendLimited,
    consume_verification_code,
    create_access_token,
    create_refresh_token,
    get_current_user_from_access_token,
    get_current_user_from_refresh_token,
    get_hashed_password,
    get_user_from_header_or_raise_exception,
    issue_verification_code,
    send_verification_email,
    user_by_email,
    verify_and_update_password,
)
from backend.utilities.ratelimit import RateLimiter, ip_key, user_key

log = logging.getLogger("backend.auth")

router = APIRouter(
    tags=["auth"],
    route_class=NoEchoValidationRoute,  # a 422 never echoes the submitted password
)

# Per worker (gunicorn runs several): see backend/utilities/ratelimit.py.
credentials_ip_limiter = RateLimiter("auth.credentials_ip", times=10, seconds=60, key_func=ip_key)  # signup, login, reset
send_code_ip_limiter = RateLimiter("auth.send_code_ip", times=5, seconds=120, key_func=ip_key)
refresh_limiter = RateLimiter("auth.refresh_ip", times=20, seconds=30, key_func=ip_key)
session_limiter = RateLimiter("auth.session", times=20, seconds=30, key_func=user_key)  # get_user, logout
# charged by hand with the (normalised) email from the body
email_limiter = RateLimiter("auth.credentials_email", times=10, seconds=600, key_func=ip_key)


def _tokens(user: User) -> dict:
    version = user.token_version or 0
    return {
        "access_token": create_access_token(user.email, version=version),
        "refresh_token": create_refresh_token(user.email, version=version),
    }


def _db_error(exc: Exception, what: str) -> HTTPException:
    if isinstance(exc, HTTPException):
        return exc
    log.error("%s failed: %s", what, type(exc).__name__)
    if isinstance(exc, psycopg2.Error):
        return HTTPException(status_code=500, detail="Server is busy, please try again later")
    return HTTPException(status_code=500, detail=f"Could not {what}, please try again later")


@router.post('/signup', summary="Create new user", dependencies=[Depends(credentials_ip_limiter)])
async def create_user(data: UserSignup, request: Request):
    """
    Request Fields:
    - email: str
    - verification_code: str
    - password: str (8 to 128 characters)
    - first_name: str
    - last_name: str
    """
    await email_limiter.charge(request, ("email", data.email))
    try:
        engine = get_db()
        if not await run_in_threadpool(consume_verification_code, engine, data.email, data.verification_code,
                                       allow_dev_code=True):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code",
            )
        with Session(engine) as session:
            if user_by_email(session, data.email) is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exist"
                )
        hashed_password = await run_in_threadpool(get_hashed_password, data.password)
        with Session(engine) as session:
            new_team = Team(
                name=f"{data.first_name}'s Default Team",
                description=f"Default team for {data.first_name}",
            )
            session.add(new_team)
            session.commit()
            session.refresh(new_team)
            new_user = User(
                email=data.email,
                password=hashed_password,
                first_name=data.first_name,
                last_name=data.last_name,
                session_active=True, # activating session for new user
                teams =  [ new_team ],
                default_team_id = new_team.id
            )
            team_membership = TeamMembership( team=new_team, user=new_user, role="admin" )
            session.add(team_membership)
            session.commit()
            session.refresh(new_user)
            log.info("user signed up user_id=%s", new_user.id)
            return _tokens(new_user)
    except Exception as e:
        raise _db_error(e, "create user") from None


@router.post('/login', summary="Create access and refresh tokens for user", response_model=TokenSchema,
             dependencies=[Depends(credentials_ip_limiter)])
async def login(form_data: UserLogin, request: Request):
    """
    Request Fields:
    - email: str
    - verification_code: str
    - password: str
    """
    await email_limiter.charge(request, ("email", form_data.email))
    try:
        engine = get_db()
        if not await run_in_threadpool(consume_verification_code, engine, form_data.email,
                                       form_data.verification_code, allow_dev_code=True):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code",
            )
        with Session(engine) as session:
            user = user_by_email(session, form_data.email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password"
            )
        old_hash = user.password
        is_valid, new_hash = await run_in_threadpool(verify_and_update_password, form_data.password, old_hash)
        if not is_valid:
            log.info("login refused: credentials do not match user_id=%s", user.id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password"
            )

        with Session(engine) as session:
            if new_hash is not None:
                # compare-and-swap: a concurrent reset or upgrade that already changed the hash wins
                upgraded = session.exec(
                    update(User).where(User.id == user.id, User.password == old_hash).values(password=new_hash)
                ).rowcount
                if upgraded:
                    log.info("login: stored hash upgraded to argon2id user_id=%s", user.id)
            session.exec(update(User).where(User.id == user.id).values(session_active=True))
            session.commit()
            user = session.exec(select(User).where(User.id == user.id)).first()
            log.info("user logged in user_id=%s", user.id)
        return _tokens(user)
    except Exception as e:
        raise _db_error(e, "login user") from None


@router.post('/refresh', summary="Create new access token from refresh token", dependencies=[Depends(refresh_limiter)])
async def refresh(data:RefreshToken,Authorization: Annotated[str | None, Header()] = None, ):
    """
    Request Fields:
    - refresh_token: str
    """
    try:
        engine = get_db()
        user = await get_current_user_from_refresh_token(engine, data.refresh_token)
        return {
            "access_token": create_access_token(user.email, version=user.token_version or 0),
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        if isinstance(e, psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        raise HTTPException(status_code=403, detail="Could not refresh token, please try again later")


@router.get('/get_user', summary="Get user details", dependencies=[Depends(session_limiter)])
async def get_user(Authorization: Annotated[str | None, Header()] = None):
    try:
        engine = get_db()
        if Authorization is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header is required"
            )
        parts = Authorization.split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format"
            )
        user = await get_current_user_from_access_token(engine, parts[1])
        return {
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "profile_photo": user.profile_photo
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        log.error("get_user failed: %s", type(e).__name__)
        if isinstance(e, psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        raise HTTPException(status_code=403, detail="Could not get user details, please try again later")


@router.post("/send_code", summary="Send verification code to user", dependencies=[Depends(send_code_ip_limiter)])
async def send_verification_code(data: CodeSend):
    """
    Request Fields:
    - email: str

    Stores a new code (replacing any earlier one for the email) and mails it before answering.  Past the hourly
    cap of new codes for this email the live code is mailed again instead; 429 with Retry-After when it was
    re-sent less than a minute ago or no live code is left (its attempts are spent) until the hour ends.
    """
    try:
        engine = get_db()
        code = await run_in_threadpool(issue_verification_code, engine, data.email)
    except CodeSendLimited as limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many verification codes were requested for this email. Try again later.",
            headers={"Retry-After": str(limited.retry_after)},
        ) from None
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        log.error("send_code failed: %s", type(e).__name__)
        if isinstance(e, psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        raise HTTPException(status_code=400, detail="Could not send verification code, please try again later")
    if code is not None:  # None: the local dev account on a DSS_DEV_MODE=1 server (fixed code, no mail)
        try:
            await run_in_threadpool(send_verification_email, data.email, code)
        except HTTPException as e:
            if e.status_code == 400:  # the address itself was refused (for example a header-injection attempt)
                raise
            log.error("verification email not sent (status %s)", e.status_code)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="We could not send the verification code right now. Please try again in a few minutes.") from None
        except Exception as e:
            log.error("verification email not sent: %s", type(e).__name__)
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail="We could not send the verification code right now. Please try again in a few minutes.") from None
    return {
        "message": "Verification code sent to user"
    }


@router.post("/reset_password", summary="Reset password for user", dependencies=[Depends(credentials_ip_limiter)])
async def reset_password(data: ResetPassword, request: Request):
    """
    Request Fields:
    - email: str
    - verification_code: str (the emailed code; the fixed dev code never works here)
    - password: str (8 to 128 characters)

    Every token issued before the reset stops working.
    """
    await email_limiter.charge(request, ("email", data.email))
    try:
        engine = get_db()
        if not await run_in_threadpool(consume_verification_code, engine, data.email, data.verification_code,
                                       allow_dev_code=False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code",
            )
        hashed_pwd = await run_in_threadpool(get_hashed_password, data.password)
        with Session(engine) as session:
            user = user_by_email(session, data.email)
            if user is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No account uses this email")
            session.exec(
                update(User).where(User.id == user.id)
                .values(password=hashed_pwd, token_version=User.token_version + 1)
            )
            session.commit()
            log.info("credential reset done, earlier tokens revoked user_id=%s", user.id)
        return {
            "message": f"Password reset successfully for user {data.email}"
        }
    except Exception as e:
        raise _db_error(e, "reset password") from None


@router.get("/logout", summary="Logout user", dependencies=[Depends(session_limiter)])
async def logout(Authorization: Annotated[str | None, Header()] = None):
    """
    Request Fields:
    - Authorization: str

    Every access and refresh token issued so far stops working for good (token_version is bumped): signing in
    again issues new tokens and never revives the old ones.
    """
    try:
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization, ignore_session_active=True)
        with Session(engine) as session:
            session.exec(update(User).where(User.id == user.id)
                         .values(session_active=False, token_version=User.token_version + 1))
            session.commit()
        log.info("user logged out user_id=%s", user.id)
        return {
            "message": f"User {user.email} logged out and session deactivated 🟩"
        }, 200
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        log.error("logout failed: %s", type(e).__name__)
        if isinstance(e, psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        raise HTTPException(status_code=403, detail="Could not logout user, please try again later")
