"""Build identity (CB-03): which commit this API was built from, and the request id of the request being served.

* ``DSS_BUILD_SHA``: the full 40-character git commit the image was built from. backend/Dockerfile bakes it in from
  the build argument that scripts/deploy/build_images.sh passes (the same commit as the image's
  ``org.opencontainers.image.revision`` label). Anything else reads as "unknown".
* ``DSS_BUILD_VERSION``: the release or version string (build_images.sh: the image tag unless set). When it is not a
  plain version string the short commit is used instead.

Who sees it (PR #72 security review, ASVS V14.3.3):
* Always, behind sign-in: ``GET /version`` (any signed-in user or operator), each collection run's
  ``engine_version`` and the CBOM exports, the logs, and the images' OCI labels.
* Publicly only where the deployment opts in with ``DSS_EXPOSE_BUILD=1`` (the local stack, the lab and staging, so
  the gate's G0 check can compare it without an account): ``GET /health`` adds ``build`` / ``version`` and every
  response carries ``X-ZS-Build``. Default off (production): /health says only that it is healthy and no response
  names the commit. "Only on authenticated responses" was not chosen: this wrapper runs before routing and
  authentication, so it could only guess from a header any caller can send.

Every response carries ``X-ZS-Request-Id``, always generated here (a random id discloses nothing). The ``cbom
sources`` log lines of that request carry it as ``request_id=``, so a 500's ref, the response and the log line join
without timestamps. A caller's own ``X-ZS-Request-Id`` is never adopted (it could reuse another request's id); when
it is well formed it is logged next to ours as ``client_request_id=``.
"""
from __future__ import annotations

import contextvars
import datetime as _dt
import logging
import os
import re
import uuid

UNKNOWN = "unknown"
DIRTY = "-dirty"  # scripts/deploy/build_images.sh ends a dirty tree's version (it has no commit) with this
BUILD_HEADER = "X-ZS-Build"
REQUEST_ID_HEADER = "X-ZS-Request-Id"

_SHA = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}")
# A caller's id is echoed only when it cannot carry anything but an id: no spaces, quotes, separators or control
# characters (it goes into a header and into log lines), 8-64 characters.
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,63}")

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("zs_request_id", default=None)
_client_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("zs_client_request_id", default=None)
_TRUE = {"1", "true", "yes", "on"}


def expose_build() -> bool:
    """``DSS_EXPOSE_BUILD``: name the build on public responses (/health, X-ZS-Build). Default off."""
    return (os.environ.get("DSS_EXPOSE_BUILD") or "").strip().lower() in _TRUE


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


def current_client_request_id() -> str | None:
    return _client_request_id.get()


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


def _client_request_id_from(scope) -> str | None:
    """The caller's X-ZS-Request-Id when it is 8-64 safe characters (then only logged), else None."""
    for name, value in scope.get("headers") or []:
        if name.lower() == b"x-zs-request-id":
            try:
                text = value.decode("ascii")
            except UnicodeDecodeError:
                return None
            return text if _REQUEST_ID.fullmatch(text) else None
    return None


class BuildIdentityMiddleware:
    """Pure ASGI wrapper: ``X-ZS-Request-Id`` on every HTTP response, and ``X-ZS-Build`` when the deployment
    exposes the build (``DSS_EXPOSE_BUILD``).

    It must wrap Starlette's ServerErrorMiddleware (see ``backend.main.DssApp``), which answers an unhandled exception
    outside every user middleware; CORS preflights, 401s raised in dependencies and 404/405 from the router pass
    through it as well. Headers of the same names set further in are removed (replaced, never duplicated; and with
    the build hidden, never let through)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        rid = uuid.uuid4().hex
        stamp = [(b"x-zs-request-id", rid.encode("ascii"))]
        if expose_build():
            stamp.append((b"x-zs-build", build_sha().encode("ascii")))
        names = {b"x-zs-build", b"x-zs-request-id"}

        async def send_with_identity(message) -> None:
            if message.get("type") == "http.response.start":
                headers = [h for h in message.get("headers") or [] if h[0].lower() not in names]
                message = {**message, "headers": headers + stamp}
            await send(message)

        token = _request_id.set(rid)
        client_token = _client_request_id.set(_client_request_id_from(scope))
        try:
            await self.app(scope, receive, send_with_identity)
        finally:
            _client_request_id.reset(client_token)
            _request_id.reset(token)
