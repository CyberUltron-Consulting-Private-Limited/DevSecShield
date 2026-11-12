"""Build identity (CB-03): which commit this API was built from, and the request id of the request being served.

* ``DSS_BUILD_SHA``: the full 40-character git commit the image was built from. backend/Dockerfile bakes it in from
  the build argument that scripts/deploy/build_images.sh passes (the same commit as the image's
  ``org.opencontainers.image.revision`` label). Anything else reads as "unknown".
* ``DSS_BUILD_VERSION``: the release or version string (build_images.sh: the image tag unless set). When it is not a
  plain version string the short commit is used instead.

Reported by ``GET /health`` (``build``, ``version``), on every response (``X-ZS-Build``), recorded on each collection
run (``engine_version``) and written into the CBOM exports. Every response also carries ``X-ZS-Request-Id``: the
caller's own id when it sent a well-formed one, else a new one; the ``cbom sources`` log lines of that request carry
it too, so a 500's ref, the response and the log line can be joined without relying on timestamps.
"""
from __future__ import annotations

import contextvars
import datetime as _dt
import logging
import os
import re
import uuid

UNKNOWN = "unknown"
BUILD_HEADER = "X-ZS-Build"
REQUEST_ID_HEADER = "X-ZS-Request-Id"

_SHA = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}")
# A caller's id is echoed only when it cannot carry anything but an id: no spaces, quotes, separators or control
# characters (it goes into a header and into log lines), 8-64 characters.
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,63}")

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("zs_request_id", default=None)


def build_sha() -> str:
    value = (os.environ.get("DSS_BUILD_SHA") or "").strip().lower()
    return value if _SHA.fullmatch(value) else UNKNOWN


def build_version() -> str:
    value = (os.environ.get("DSS_BUILD_VERSION") or "").strip()
    if _VERSION.fullmatch(value):
        return value
    sha = build_sha()
    return sha[:12] if sha != UNKNOWN else UNKNOWN


def short_build() -> str | None:
    sha = build_sha()
    return sha[:12] if sha != UNKNOWN else None


def current_request_id() -> str | None:
    return _request_id.get()


def utc_timestamp(moment: _dt.datetime | None = None) -> str:
    """ISO 8601 UTC with milliseconds and a Z, e.g. 2026-11-12T08:30:00.123Z (log lines)."""
    moment = moment or _dt.datetime.now(_dt.timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return moment.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class UtcIsoFormatter(logging.Formatter):
    """``%(asctime)s`` as ISO 8601 UTC with a Z, whatever the container's time zone."""

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:  # noqa: N802 (logging API)
        return utc_timestamp(_dt.datetime.fromtimestamp(record.created, _dt.timezone.utc))


def _request_id_from(scope) -> str:
    for name, value in scope.get("headers") or []:
        if name.lower() == b"x-zs-request-id":
            try:
                text = value.decode("ascii")
            except UnicodeDecodeError:
                break
            if _REQUEST_ID.fullmatch(text):
                return text
            break
    return uuid.uuid4().hex


class BuildIdentityMiddleware:
    """Pure ASGI wrapper: ``X-ZS-Build`` and ``X-ZS-Request-Id`` on every HTTP response.

    It must wrap Starlette's ServerErrorMiddleware (see ``backend.main.DssApp``), which answers an unhandled exception
    outside every user middleware; CORS preflights, 401s raised in dependencies and 404/405 from the router pass
    through it as well. Headers of the same name set further in are replaced, never duplicated."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        rid = _request_id_from(scope)
        stamp = [(b"x-zs-build", build_sha().encode("ascii")), (b"x-zs-request-id", rid.encode("ascii"))]
        names = {name for name, _value in stamp}

        async def send_with_identity(message) -> None:
            if message.get("type") == "http.response.start":
                headers = [h for h in message.get("headers") or [] if h[0].lower() not in names]
                message = {**message, "headers": headers + stamp}
            await send(message)

        token = _request_id.set(rid)
        try:
            await self.app(scope, receive, send_with_identity)
        finally:
            _request_id.reset(token)
