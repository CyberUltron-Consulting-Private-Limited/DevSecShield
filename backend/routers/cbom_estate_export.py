"""The team's estate CBOM (CB-26): ``GET /{team_id}/cbom/estate-export?format=json|xml&application&source&type``.

One CycloneDX 1.6 document for the whole estate, one component per estate asset key (``estate_export``). Team members
only (``authorize``; another team gets the usual 403), the CBOM Sources write limit (one full pass over the estate, as
the run export), and one of the host-wide export slots when the estate is large (``export_slots``; 429 + Retry-After
when every slot is busy). The document is written to a spooled temporary file one component at a time and streamed;
the response says it is unsigned (``X-Cbom-Signature: unsigned``) and carries the SHA-256 of the exact bytes
(``X-Cbom-Sha256``), so anyone can check the file outside ZeroShield.
"""
from __future__ import annotations

import contextlib
import hashlib
import tempfile
from typing import IO, Annotated, Any, Iterator

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlmodel import Session

from backend.utilities.cbom_sources import estate_export as EXPORT
from backend.utilities.cbom_sources import export_slots as EXPORT_SLOTS
from backend.utilities.cbom_sources.common import log, utcnow
from backend.utilities.cbom_sources import http as _cbom_http
from backend.utilities.rbac.policy import Access
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize, server_error, write_limiter
from backend.utilities.pdf.report_http import busy_refusal

router = APIRouter(tags=["cbom-estate"], route_class=CbomRoute)
access = Access(lambda: _cbom_http.get_db())  # route policies (utilities/rbac): the same database as authorize()
AuthHeader = Annotated[str | None, Header()]
WRITE = [Depends(write_limiter)]
SPOOL_BYTES = 8 * 1024 * 1024
MEDIA = {"json": "application/vnd.cyclonedx+json; version=1.6", "xml": "application/vnd.cyclonedx+xml; version=1.6"}


class _Hashing:
    """A write-through wrapper that hashes every byte written."""

    def __init__(self, out: IO[bytes]):
        self.out, self.sha = out, hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.sha.update(data)
        return self.out.write(data)


def _build(engine, team_id: int, f: EXPORT.Filters, fmt: str) -> tuple[IO[bytes], str, int]:
    now = utcnow()
    with Session(engine) as session:
        total = EXPORT.count(session, team_id, f)
        try:
            with EXPORT_SLOTS.slot() if EXPORT_SLOTS.is_large(total) else contextlib.nullcontext():
                out: IO[bytes] = tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES)  # noqa: SIM115 (streamed, closed below)
                try:
                    sink = _Hashing(out)
                    EXPORT.write(session, team_id, f, now, fmt, sink)  # type: ignore[arg-type]
                except BaseException:
                    out.close()
                    raise
        except EXPORT_SLOTS.Busy:
            raise busy_refusal("cbom") from None
    size = out.tell()
    out.seek(0)
    log("estate cbom exported", team=team_id, assets=total, format=fmt, bytes=size, **f.public())
    return out, sink.sha.hexdigest(), total


def _chunks(out: IO[bytes], size: int = 1024 * 1024) -> Iterator[bytes]:
    try:
        while True:
            block = out.read(size)
            if not block:
                return
            yield block
    finally:
        out.close()


@router.get("/{team_id}/cbom/estate-export", dependencies=[*WRITE, access.team("cbom.read")],
            summary="The team's estate CBOM: one CycloneDX component per asset across sources (unsigned; SHA-256 "
                    "in X-Cbom-Sha256)")
async def estate_export(team_id: TeamId, format: str = Query(default="json", pattern="^(json|xml)$"),
                        application: str | None = Query(default=None, max_length=128),
                        source: str | None = Query(default=None, max_length=255),
                        type: str | None = Query(default=None, max_length=32, pattern="^[a-z0-9_]+$"),
                        Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    f = EXPORT.Filters(application=(application or "").strip() or None, source=(source or "").strip() or None,
                       type=type)
    try:
        out, sha, total = await run_in_threadpool(_build, engine, team_id, f, format)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error("cbom estate export", exc, team=team_id) from None
    name = f"cbom-estate-team{team_id}-{utcnow().date().isoformat()}.cdx.{format}"
    headers: dict[str, Any] = {**PRIVATE, "Content-Disposition": f'attachment; filename="{name}"',
                               "X-Cbom-Signature": "unsigned", "X-Cbom-Sha256": sha, "X-Cbom-Assets": str(total)}
    return StreamingResponse(_chunks(out), media_type=MEDIA[format], headers=headers)
