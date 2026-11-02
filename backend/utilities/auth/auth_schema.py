from typing import Callable

from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field, field_validator
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class NoEchoValidationRoute(APIRoute):
    """422 as usual (``detail`` = list of {type, loc, msg}), but without FastAPI's ``input`` and ``ctx``: a
    refused password must not come back in the response body (and from there into proxies and logs)."""

    def get_route_handler(self) -> Callable:
        handler = super().get_route_handler()

        async def route(request: Request) -> Response:
            try:
                return await handler(request)
            except RequestValidationError as exc:
                errors = [{k: e[k] for k in ("type", "loc", "msg") if k in e} for e in exc.errors()]
                return JSONResponse({"detail": errors}, status_code=422)

        return route

# Kept in step with backend/utilities/auth/auth_utils.py (MIN_NEW_PASSWORD_CHARS, MAX_PASSWORD_CHARS) and
# frontend/utils/password_rules.ts.  Lengths count Unicode code points.
MAX_EMAIL_CHARS = 254
MAX_LOGIN_PASSWORD_CHARS = 128


def clean_email(value: str) -> str:
    """Emails are compared lower-cased and without surrounding spaces on every auth path."""
    email = (value or "").strip().lower()
    if not email or len(email) > MAX_EMAIL_CHARS or "@" not in email or any(c.isspace() for c in email):
        raise ValueError("Enter a valid email address")
    return email


def clean_code(value: str) -> str:
    """Codes are often pasted with spaces ("123 456"); they are compared without any whitespace."""
    return "".join((value or "").split())


def clean_new_password(value: str) -> str:
    from backend.utilities.auth.auth_utils import new_password_problem

    problem = new_password_problem(value)
    if problem:
        raise ValueError(problem)
    return value


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str


class CodeSend(BaseModel):
    email: str = Field(..., description="user email")

    check_email = field_validator("email")(clean_email)


class ResetPassword(BaseModel):
    email: str = Field(..., description="user email")
    verification_code: str = Field(..., max_length=64, description="verification code")
    password: str = Field(..., description="new password: 8 to 128 characters")

    check_email = field_validator("email")(clean_email)
    check_code = field_validator("verification_code")(clean_code)
    check_password = field_validator("password")(clean_new_password)


class RefreshToken(BaseModel):
    refresh_token: str = Field(..., max_length=4096, description="refresh token")


class UserLogin(BaseModel):
    verification_code: str = Field(..., max_length=64, description="verification code")
    email: str = Field(..., description="user email")
    # 1..128 so every existing password (older rules allowed 5..24, admin-made ones had no limit) still signs in
    password: str = Field(..., min_length=1, max_length=MAX_LOGIN_PASSWORD_CHARS, description="user password")

    check_email = field_validator("email")(clean_email)
    check_code = field_validator("verification_code")(clean_code)


class UserSignup(BaseModel):
    verification_code: str = Field(..., max_length=64, description="verification code")
    email: str = Field(..., description="user email")
    password: str = Field(..., description="password: 8 to 128 characters")
    first_name: str = Field(..., description="user first name")
    last_name: str = Field(..., description="user last name")

    check_email = field_validator("email")(clean_email)
    check_code = field_validator("verification_code")(clean_code)
    check_password = field_validator("password")(clean_new_password)
