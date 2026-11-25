"""Team-wide CBOM regulatory deliverables: manifest and PDF download (WP4, plan 5.3).

Two read-only routes for the Deliverables menu on the team CBOM landing page:

* ``GET /{team_id}/cbom/deliverables`` - JSON manifest (which documents exist, whether they have
  anything to show).  Reads only the HEADS of the team's CBOM scans, never ``scan_data``.
* ``GET /{team_id}/cbom/deliverables/{slug}`` - one PDF built in memory from every completed CBOM
  scan of the team (``load_team_cbom_view`` then the renderer registered for the slug).

Status codes: 401 for a missing, malformed, invalid or expired bearer token; 403 for a user who
is not a member of the team or whose session is not active; 404 only for an unknown slug; 429
from the rate limiter; 500 with one generic body (the detail goes to the server log only).  An
empty team, a team whose scans all failed and a team with only legacy-format scans are DATA
conditions: they get a 200 and a PDF with a banner, never a 4xx, because the frontend signs the
user out on a 403.

The limiter is attached in the decorator (``dependencies=[...]``).  The parameter-default form
``dependencies=[Depends(limiter)]`` used by older routers is a no-op: FastAPI treats it as a query
parameter.  One budget (30 requests per 60 seconds) covers both routes and is keyed by the subject of
a VERIFIED access token; a missing or invalid token is charged to the client address instead, so a
forged token never gets a budget of its own (``backend/utilities/ratelimit.py``).

Hard rules (enforced by ``test_cbom_deliverables_no_llm.py``): no language-model or network
client, no import of another router, no subprocess; the PDF is built in memory and returned as
bytes, so there is no temporary file to clean up.
"""
from __future__ import annotations

import functools
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from rich.console import Console
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.utilities.rbac.policy import Access
from backend.new_models import Scan
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.dashboard.cbom_team_rollup import ScanHead, load_team_cbom_view
from backend.utilities.ratelimit import RateLimiter, user_key
from backend.utilities.pdf.cbom_deliverable_common import document_id
from backend.utilities.pdf.cbom_deliverables import (
    DELIVERABLES,
    build_manifest,
    deliverable_filename,
    summarize_heads,
)
from backend.utilities.team import check_if_user_is_in_team
from backend.utilities.pdf.branding_input import ReportBranding
from backend.utilities.pdf.report_context import ReportContext
from backend.utilities.pdf.report_http import (
    OPTIONS_BODY_RESPONSES,
    PRIVATE,
    failure_outcome,
    finished_outcome,
    options_body_openapi,
    report_headers,
    request_options,
)
from backend.utilities.team.branding import load_report_branding

router = APIRouter(tags=["cbom-deliverables"])
access = Access(lambda: get_db())  # route policies (utilities/rbac), bound to this module's get_db (tests replace it)
console = Console()

GENERIC_ERROR_DETAIL = "Error generating deliverable, please try again later"
UNKNOWN_DELIVERABLE_DETAIL = "Unknown deliverable"
_MAX_TEAM_ID = 2_147_483_647  # a Postgres integer; larger values can only be malformed input
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


limiter = RateLimiter("cbom_deliverables", times=30, seconds=60, key_func=user_key)

_ERRORS: dict[int | str, dict[str, Any]] = {
    401: {"description": "Missing, malformed, invalid or expired bearer token."},
    403: {"description": "Not a member of the team, or the session is not active."},
    429: {"description": "Rate limit exceeded: 30 requests per 60 seconds per user (Retry-After says when to retry)."},
    500: {"description": "Generic server error; the detail is only in the server log."},
}
_MANIFEST_EXAMPLE = {
    "team_id": 1,
    "generated_at": "2026-10-19T12:28:00Z",
    "basis": {
        "eligible": 9,
        "included_hint": 9,
        "sources": 8,
        "excluded": {"failure": 1, "not_completed": 2},
    },
    "deliverables": [
        {
            "slug": "certificate-estate-register",
            "number": 7,
            "title": "Certificate Estate Register",
            "description": "Every unique X.509 certificate found across the team's scans.",
            "format": "pdf",
            "available": True,
            "reason": None,
        }
    ],
}


def _utcnow() -> datetime:
    """The only clock read of this module (tests replace it to freeze the document date)."""
    return datetime.now(timezone.utc)


def _aware(moment: datetime | None) -> datetime:
    if moment is None:
        return _EPOCH
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment


def _count_collections(engine: Any, team_id: int) -> int:
    """CBOM Sources sources with a completed collection: CBOM results like completed code scans (jobs only). A deleted
    source's last collection is not counted (staging QA2 Q1-01: the roll-up's rule)."""
    from backend.new_models import CbomCollectionSource
    from backend.utilities.cbom_sources.collections_view import latest_jobs

    with Session(engine) as session:
        live = set(session.exec(select(CbomCollectionSource.id).where(CbomCollectionSource.team_id == team_id)).all())
        return sum(1 for job in latest_jobs(session, team_id) if job.source_id in live)


def _load_heads(engine: Any, team_id: int) -> list[ScanHead]:
    """Pass 1 of the roll-up for the manifest: every column except ``scan_data``."""
    with Session(engine) as session:
        rows = session.exec(
            select(
                Scan.id, Scan.team_id, Scan.scan_type, Scan.title, Scan.scan_status,
                Scan.created_at, Scan.last_updated, Scan.scan_metadata,
            ).where(Scan.team_id == team_id, Scan.scan_type == "cbom")
        ).all()  # fmt: skip
    heads = []
    for scan_id, owner, kind, title, status, created, updated, meta in rows:
        made = _aware(created)
        heads.append(
            ScanHead(
                id=scan_id, team_id=owner, scan_type=kind, title=title or "", status=status or "",
                created_at=made, last_updated=_aware(updated) if updated else made,
                scan_metadata=meta if isinstance(meta, dict) else None,
            )  # fmt: skip
        )
    return heads


def _log_outcome(team_id: int, slug: str, outcome: str, status: int, started: float) -> None:
    """The one line of a refused or failed deliverable request (the success line is in the route); ``slug`` is a
    known slug or ``unknown``, never the raw path segment."""
    console.print(
        f"cbom deliverable team={team_id} slug={slug} outcome={outcome} status={status} "
        f"ms={int((time.perf_counter() - started) * 1000)}",
        markup=False,
        highlight=False,
        soft_wrap=True,
    )


def _log_failure(what: str, team_id: int, exc: BaseException) -> None:
    """Server-side only: the exception class on one line, then the traceback."""
    console.print(
        f"cbom deliverables {what} FAILED team={team_id} error={type(exc).__name__}",
        style="bold red",
        markup=False,
        highlight=False,
        soft_wrap=True,
    )
    console.print_exception(show_locals=False)


async def _authorize(team_id: int, authorization: str | None) -> Any:
    """Bearer token -> user -> team membership.  Returns the engine for the work that follows."""
    engine, _user_id = await _authorize_user(team_id, authorization)
    return engine


async def _authorize_user(team_id: int, authorization: str | None) -> tuple[Any, int | None]:
    """``_authorize`` that also returns the user id (the board report records who issued it)."""
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, authorization)
    await run_in_threadpool(check_if_user_is_in_team, user.id, team_id, engine)
    return engine, getattr(user, "id", None)


BOARD_SLUG = "board-executive-report"  # SOW D14: its issues are recorded for the trend (cbom_board_issues)


def _previous_issue(engine: Any, team_id: int, number: int, content_id: str) -> dict[str, Any] | None:
    """The issue this content is compared with (``cbom_board_issues.previous``: fixed once the content is issued)."""
    from backend.utilities.dashboard.cbom_board_issues import previous

    with Session(engine) as session:
        return previous(session, team_id, number, content_id)


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes")


ACTIVE_RUN_WINDOW = timedelta(hours=24)  # an open run older than this never holds a formal issue back


def _active_runs(session: Session, team_id: int, now: datetime | None = None) -> int:
    """Open runs (queued or running) that changed in the last ``ACTIVE_RUN_WINDOW``: a run that waits for days on an
    offline scan node (staging run #50, open since 18 Nov) changes nothing the report reads, so it never freezes the
    trend at "first issue" (#497 review m1)."""
    from sqlalchemy import func

    from backend.new_models import CbomCollectionRun

    since = (now or _utcnow()).replace(tzinfo=None) - ACTIVE_RUN_WINDOW
    return int(session.exec(select(func.count()).select_from(CbomCollectionRun).where(
        CbomCollectionRun.team_id == team_id, CbomCollectionRun.status.in_(("queued", "running")),  # type: ignore[attr-defined]
        func.coalesce(CbomCollectionRun.last_updated, CbomCollectionRun.created_at) >= since)).one() or 0)


def _record_issue(engine: Any, team_id: int, number: int, snapshot: dict[str, Any], user_id: int | None, *,
                  explicit: bool = False, preview: bool = False) -> None:
    """Record this download as a formal issue of the board report when it is one (``cbom_board_issues.formal_issue``:
    an explicit ``issue=1``, else the first download of the day while no run is active; never a preview). A failure
    is logged and never fails the download."""
    from backend.utilities.dashboard.cbom_board_issues import formal_issue, record

    try:
        with Session(engine) as session:
            if formal_issue(explicit=explicit, preview=preview, active_runs=_active_runs(session, team_id)) is None:
                return
            record(session, team_id, number, snapshot, user_id)
    except Exception as exc:  # noqa: BLE001 - the PDF was built; the trend of the next issue is what is lost
        _log_failure("issue record", team_id, exc)


TeamId = Annotated[int, Path(ge=1, le=_MAX_TEAM_ID, description="Team id")]


@router.get(
    "/{team_id}/cbom/deliverables",
    summary="List the team-wide CBOM regulatory deliverables",
    description=(
        "Manifest for the Deliverables menu: the nine documents in menu order and whether each "
        "has anything to show. Reads only scan heads (no scan data), so it is cheap. "
        "`available` is a UI hint; the PDF route always answers 200."
    ),
    dependencies=[Depends(limiter), access.team("cbom.read")],
    response_model=None,
    responses={
        200: {
            "description": "The manifest.",
            "content": {"application/json": {"example": _MANIFEST_EXAMPLE}},
        },
        **_ERRORS,
    },
)
async def list_cbom_deliverables(
    team_id: TeamId,
    Authorization: Annotated[str | None, Header()] = None,
) -> Response:
    try:
        engine = await _authorize(team_id, Authorization)
        heads = await run_in_threadpool(_load_heads, engine, team_id)
        collections = await run_in_threadpool(_count_collections, engine, team_id)
        summary = summarize_heads(heads, team_id=team_id, collections=collections)
        manifest = build_manifest(team_id, _utcnow(), summary)
    except HTTPException:
        raise
    except Exception as exc:
        _log_failure("manifest", team_id, exc)
        raise HTTPException(status_code=500, detail=GENERIC_ERROR_DETAIL) from None
    return JSONResponse(manifest, headers=PRIVATE)


def _branding(engine: Any, team_id: int) -> ReportBranding:
    with Session(engine) as session:  # a session of its own: a failed read never touches another transaction
        return load_report_branding(session, team_id)


def _posture_header(view: Any) -> str:
    """``assessed``, ``mixed``, ``not_assessed`` or ``none``."""
    state = getattr(getattr(view, "posture", None), "state", "none")
    if state in ("assessed", "mixed", "not_assessed", "none"):
        return state
    return "none"


@router.get(
    "/{team_id}/cbom/deliverables/{slug}.csv",
    summary="Download one team-wide CBOM regulatory deliverable as CSV",
    description=(
        "The CSV rendering of a deliverable that has one (today the Certificate Estate Register, SOW D8): the same "
        "rows as the PDF in the same order, UTF-8 with a byte-order mark, RFC 4180, every cell safe from spreadsheet "
        "formula injection. 404 for an unknown slug or a deliverable without a CSV."
    ),
    dependencies=[Depends(limiter), access.team("cbom.read")],
    response_model=None,
    responses={
        200: {"description": "The CSV.", "content": {"text/csv": {"schema": {"type": "string"}}}},
        404: {"description": "Unknown deliverable slug, or the deliverable has no CSV."},
        **_ERRORS,
    },
)
async def download_cbom_deliverable_csv(
    team_id: TeamId,
    slug: str,
    Authorization: Annotated[str | None, Header()] = None,
) -> Response:
    started = time.perf_counter()
    authorized = False
    spec = DELIVERABLES.get(slug)
    known = slug if spec is not None else "unknown"
    try:
        engine = await _authorize(team_id, Authorization)
        authorized = True
        if spec is None or spec.build_csv is None:
            raise HTTPException(status_code=404, detail=UNKNOWN_DELIVERABLE_DETAIL)
        view = await run_in_threadpool(load_team_cbom_view, engine, team_id, now=_utcnow())
        body = await run_in_threadpool(spec.build_csv, view)
        if not isinstance(body, bytes):
            raise ValueError("the renderer did not return CSV bytes")
    except HTTPException as exc:
        if authorized:
            _log_outcome(team_id, known, *failure_outcome(exc), started)
        raise
    except Exception as exc:
        _log_failure("csv", team_id, exc)
        if authorized:
            _log_outcome(team_id, known, "error", 500, started)
        raise HTTPException(status_code=500, detail=GENERIC_ERROR_DETAIL) from None
    filename = deliverable_filename(spec, team_id, view.as_of, "csv")
    console.print(
        f"cbom deliverable team={team_id} slug={spec.slug} format=csv scans={view.included} "
        f"sources={len(view.sources)} bytes={len(body)} ms={int((time.perf_counter() - started) * 1000)} outcome=ok",
        markup=False,
        highlight=False,
        soft_wrap=True,
    )
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={
            **PRIVATE,
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "X-Cbom-Fingerprint": view.document_digest,  # the Document ID's digest (M1)
        },
    )


_PDF_DESCRIPTION = (
    "Builds the document in memory from every completed CBOM scan of the team. Always 200 "
    "for a member and a known slug: a team without completed scans gets a PDF with a "
    "'NO COMPLETED CBOM SCANS' banner. Response headers X-Cbom-Scans-Included, "
    "X-Cbom-Sources, X-Cbom-Fidelity (full, mixed, reduced or none), X-Cbom-Fingerprint "
    "and X-Cbom-Posture (assessed, mixed, not_assessed or none) are informational. "
    "Cover options (prepared_for, label): query parameters of a GET, or the JSON body of a POST, which keeps a "
    "client name out of URLs and access logs. Board report (D14) only: `issue=1` records the download as a formal "
    "issue (the next issue's trend compares with it); `preview=1` never does; a plain download is a formal issue "
    "when it is the Document ID's first download of the day and no CBOM Sources run that changed in the last 24 "
    "hours is queued or running."
)
_PDF_RESPONSES: dict[int | str, dict[str, Any]] = {
    200: {
        "description": "The PDF.",
        "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}},
    },
    404: {"description": "Unknown deliverable slug."},
    422: {"description": "A cover option is not valid; the detail names it (`<field>: message`)."},
    **_ERRORS,
}


@router.get(
    "/{team_id}/cbom/deliverables/{slug}",
    summary="Download one team-wide CBOM regulatory deliverable (PDF)",
    description=_PDF_DESCRIPTION,
    dependencies=[Depends(limiter), access.team("cbom.read")],
    response_model=None,
    responses=_PDF_RESPONSES,
)
@router.post(
    "/{team_id}/cbom/deliverables/{slug}",
    summary="Download one team-wide CBOM regulatory deliverable (PDF), cover options in a JSON body",
    description=_PDF_DESCRIPTION,
    dependencies=[Depends(limiter), access.team("cbom.read")],
    response_model=None,
    responses={**_PDF_RESPONSES, **OPTIONS_BODY_RESPONSES},
    openapi_extra=options_body_openapi("deliverable"),
)
async def download_cbom_deliverable(
    team_id: TeamId,
    slug: str,
    request: Request,
    Authorization: Annotated[str | None, Header()] = None,
) -> Response:
    started = time.perf_counter()
    authorized = False  # a request that passed the token and membership checks logs one line, whatever its outcome
    known = slug if slug in DELIVERABLES else "unknown"
    try:
        engine, user_id = await _authorize_user(team_id, Authorization)
        authorized = True
        spec = DELIVERABLES.get(slug)
        if spec is None:
            raise HTTPException(status_code=404, detail=UNKNOWN_DELIVERABLE_DETAIL)
        options = await request_options(request, "deliverable")
        view = await run_in_threadpool(load_team_cbom_view, engine, team_id, now=_utcnow())
        content_id = document_id(view, spec.number)  # the content alone: no previous issue in the digest yet
        if spec.slug == BOARD_SLUG:  # the trend against the previous issue (review M7c)
            # the previous issue's Document ID is part of D14's digest (review 2 m5): one ID, one trend
            view.previous_issue = await run_in_threadpool(_previous_issue, engine, team_id, spec.number, content_id)
        ctx = ReportContext(options=options, branding=await run_in_threadpool(_branding, engine, team_id))
        if options.is_default and not ctx.branding.applied:
            pdf = await run_in_threadpool(spec.build, view)  # today's document, byte for byte
        else:
            pdf = await run_in_threadpool(functools.partial(spec.build, view, ctx=ctx))
        if not isinstance(pdf, bytes) or not pdf.startswith(b"%PDF-"):
            raise ValueError("the renderer did not return a PDF")
    except HTTPException as exc:
        if authorized:
            _log_outcome(team_id, known, *failure_outcome(exc), started)
        raise
    except Exception as exc:
        _log_failure("pdf", team_id, exc)
        if authorized:
            _log_outcome(team_id, known, "error", 500, started)
        raise HTTPException(status_code=500, detail=GENERIC_ERROR_DETAIL) from None
    if spec.slug == BOARD_SLUG and not view.is_empty:
        from backend.utilities.pdf.cbom_board_report_pdf import issue_snapshot

        snapshot = {**issue_snapshot(view), "content_id": content_id}
        await run_in_threadpool(functools.partial(
            _record_issue, engine, team_id, spec.number, snapshot, user_id,
            explicit=_truthy(request.query_params.get("issue")), preview=_truthy(request.query_params.get("preview"))))
    filename = deliverable_filename(spec, team_id, view.as_of)
    headers = {
        **report_headers(ctx, filename, findings=False),
        "X-Cbom-Scans-Included": str(view.included),
        "X-Cbom-Sources": str(len(view.sources)),
        "X-Cbom-Fidelity": view.fidelity_summary,
        "X-Cbom-Fingerprint": view.document_digest,  # the Document ID's digest (M1)
        "X-Cbom-Posture": _posture_header(view),
    }
    if ctx.branding.applied:
        headers["X-Cbom-Logo-Sha256"] = ctx.branding.sha256
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    console.print(
        f"cbom deliverable team={team_id} slug={spec.slug} scans={view.included} "
        f"sources={len(view.sources)} bytes={len(pdf)} ms={elapsed_ms} logo={ctx.branding.status} "
        f"label={options.label} prepared_for_set={int(options.prepared_for is not None)} "
        f"outcome={await finished_outcome(request)}",
        markup=False,
        highlight=False,
        soft_wrap=True,  # one log line per request, never wrapped, so it stays greppable
    )
    return Response(content=pdf, media_type="application/pdf", headers=headers)
