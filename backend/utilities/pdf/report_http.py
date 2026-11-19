"""HTTP plumbing shared by the PDF report routes (R1 scan export, R2 certin pack, R3 regulated deliverables,
R4 run report, R5 run evidence pack).

* ``options_from_request``: report options from the query string, 422 naming the field on any error.
* ``report_headers``: ``X-Report-Findings`` (rows shown / rows the scan has), ``X-Report-Logo``
  (applied | none | skipped) and ``Content-Disposition``; ``main.py`` exposes them through CORS.
* ``status_join_error``: the 409 / 503 a status filter answers when the stored statuses cannot be joined.
* ``log_export``: one line per export with ids, enums, flags and numbers only. The free-text options (prepared for,
  title) are never logged: they can name a client.
"""
from __future__ import annotations

import datetime as _dt
import time
from typing import Any, Iterable

from fastapi import HTTPException
from rich.console import Console

from backend.utilities.build_info import current_request_id
from backend.utilities.db.finding_rows import StatusesUnavailable, StatusStoreDown
from backend.utilities.pdf.report_context import ReportContext
from backend.utilities.pdf.report_options import ReportOptions, ReportOptionsError, parse_report_options

console = Console()

# Every header a PDF/report route sets that the browser must be able to read (CORS expose_headers).
REPORT_EXPOSED_HEADERS = ("Content-Disposition", "X-Report-Findings", "X-Report-Logo")
# The CBOM download headers the UI reads (estate SHA-256, deliverable fidelity and logo, ...).
CBOM_EXPOSED_HEADERS = ("X-Cbom-Assets", "X-Cbom-Fidelity", "X-Cbom-Fingerprint", "X-Cbom-Logo-Sha256",
                        "X-Cbom-Posture", "X-Cbom-Scans-Included", "X-Cbom-Sha256", "X-Cbom-Signature",
                        "X-Cbom-Sources")

# Rows at or above which a code-lane PDF build takes one of the host-wide export slots (429 when all are busy).
LARGE_PDF_ROWS = 500


def options_from_request(query_params: Any, family: str, *, scan_type: str | None = None,
                         ignore: Iterable[str] = ()) -> ReportOptions:
    """``query_params`` is Starlette's ``QueryParams`` (repeated keys kept) or any (key, value) iterable."""
    items = query_params.multi_items() if hasattr(query_params, "multi_items") else query_params
    try:
        return parse_report_options(items, family, scan_type=scan_type, ignore=ignore)
    except ReportOptionsError as exc:
        raise HTTPException(status_code=422, detail=f"{exc.field}: {exc.message}") from None


def status_join_error(exc: BaseException) -> HTTPException:
    if isinstance(exc, StatusStoreDown):
        return HTTPException(status_code=503, headers={"Retry-After": "30"},
                             detail="Finding statuses cannot be read right now; retry shortly, or export without "
                                    "the status filter.")
    if isinstance(exc, StatusesUnavailable):
        return HTTPException(status_code=409,
                             detail="Finding statuses for this scan cannot be matched to its results, so the report "
                                    "cannot be filtered by status. Export it without the status filter.")
    raise TypeError(type(exc).__name__)


def logo_state(ctx: ReportContext) -> str:
    return ctx.branding.status


def report_headers(ctx: ReportContext, filename: str, *, findings: bool = True) -> dict[str, str]:
    headers = {"Content-Disposition": f'attachment; filename="{filename}"', "X-Report-Logo": logo_state(ctx)}
    if findings:
        headers["X-Report-Findings"] = f"{ctx.shown}/{ctx.total}"
    return headers


def log_export(family: str, *, team: int, id: int, user: int | None, ctx: ReportContext, size: int,
               started: float, type: str | None = None, slot_wait_ms: int | None = None,
               outcome: str = "ok") -> None:
    """One greppable line per export (see module docstring for what may be logged)."""
    fields: dict[str, Any] = {"family": family, "type": type, "team": team, "id": id, "user": user,
                              "outcome": outcome}
    fields.update(ctx.options.log_fields())
    fields.update({"logo": logo_state(ctx), "shown": ctx.shown, "total": ctx.total, "bytes": size,
                   "ms": int((time.monotonic() - started) * 1000), "slot_wait_ms": slot_wait_ms})
    parts = [_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "pdf report export"]
    parts += [f"{key}={value}" for key, value in fields.items() if value is not None]
    request_id = current_request_id()
    if request_id:
        parts.append(f"request_id={request_id}")
    try:
        console.print(" ".join(parts), markup=False, highlight=False, soft_wrap=True)
    except Exception:  # noqa: BLE001 - logging never fails an export
        pass


__all__ = ["CBOM_EXPOSED_HEADERS", "LARGE_PDF_ROWS", "REPORT_EXPOSED_HEADERS", "log_export", "logo_state", "options_from_request",
           "report_headers", "status_join_error"]
