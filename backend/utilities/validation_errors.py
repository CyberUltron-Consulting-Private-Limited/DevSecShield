"""Validation errors without the values that failed (review 5909551771, follow-up to #88).

Pydantic's ``errors()`` and FastAPI's default 422 carry each error's ``input``; for a missing field that is the whole
object, so a refused payload's PAT, api_key, password or headers came back in the response and from there into logs
and proxies. Every 422 / 400 built from a validation error uses these instead: ``type``, ``loc``, ``msg`` (and
``ctx``) stay, so the frontend still shows which field and why.
"""
from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

DROPPED = ("input", "url")


def public_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in e.items() if k not in DROPPED} for e in errors]


async def request_validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """FastAPI's 422, minus every error's input."""
    return JSONResponse({"detail": jsonable_encoder(public_errors(list(exc.errors())))}, status_code=422)
