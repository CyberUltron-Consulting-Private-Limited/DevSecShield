"""HTTP plumbing shared by the PDF report routes (R1 scan export, R2 certin pack, R3 regulated deliverables,
R4 run report, R5 run evidence pack).

* ``request_options``: a route's report options, 422 ``"<field>: message"`` on any error. A GET reads them from the
  query string (``options_from_request``); a POST reads the same options from a JSON body (``options_from_body``), so a
  client name or title never travels in a URL, where access logs, proxies and browser history keep it. R1, R3 and R4
  answer both methods with one handler (same auth, permission, rate limit, thread pool, export slot, headers and log
  line); the GET stays for old clients and option-less downloads. The body is an object of the query's keys with the
  query's string values (``{"sections": "summary,catalog", "hide_evidence": "true"}``); a list of strings is accepted
  for ``sections``, ``severities`` and ``statuses`` and a boolean for ``hide_evidence``; ``null`` means not set. A key
  that is not a report option, a non-object body or a POST with report options in its query string is refused (422),
  so a typo never silently builds the full report; a body over ``BODY_MAX_BYTES`` answers 413. An empty body is no
  option (today's report).
* ``report_headers``: ``X-Report-Findings`` (rows shown / rows the scan has), ``X-Report-Logo``
  (applied | none | skipped) and ``Content-Disposition``; ``main.py`` exposes them through CORS.
* ``status_join_error``: the 409 / 503 a status filter answers when the stored statuses cannot be joined.
* ``log_export``: one line per export with ids, enums, flags and numbers only. The free-text options (prepared for,
  title) are never logged: they can name a client.
"""
from __future__ import annotations

import datetime as _dt
import json
import time
from typing import Any, Iterable

from fastapi import HTTPException, Request
from rich.console import Console

from backend.utilities.build_info import current_request_id
from backend.utilities.db.finding_rows import StatusesUnavailable, StatusStoreDown
from backend.utilities.pdf.report_context import ReportContext
from backend.utilities.pdf.report_options import (
    ALL_KEYS,
    FAMILY_KEYS,
    LABELS,
    PRESETS,
    ReportOptions,
    ReportOptionsError,
    parse_report_options,
)

console = Console()

# Every header a PDF/report route sets that the browser must be able to read (CORS expose_headers).
REPORT_EXPOSED_HEADERS = ("Content-Disposition", "X-Report-Findings", "X-Report-Logo")
# The CBOM download headers the UI reads (estate SHA-256, deliverable fidelity and logo, ...).
CBOM_EXPOSED_HEADERS = ("X-Cbom-Assets", "X-Cbom-Fidelity", "X-Cbom-Fingerprint", "X-Cbom-Logo-Sha256",
                        "X-Cbom-Posture", "X-Cbom-Scans-Included", "X-Cbom-Sha256", "X-Cbom-Signature",
                        "X-Cbom-Sources")

# Rows at or above which a code-lane PDF build takes one of the host-wide scan PDF slots (``export_slots.pdf_slot``,
# a pool of its own: big scan PDFs never hold up CBOM exports, nor CBOM exports them; 429 when all are busy).
LARGE_PDF_ROWS = 500


def options_from_request(query_params: Any, family: str, *, scan_type: str | None = None,
                         ignore: Iterable[str] = ()) -> ReportOptions:
    """``query_params`` is Starlette's ``QueryParams`` (repeated keys kept) or any (key, value) iterable."""
    items = query_params.multi_items() if hasattr(query_params, "multi_items") else query_params
    try:
        return parse_report_options(items, family, scan_type=scan_type, ignore=ignore)
    except ReportOptionsError as exc:
        raise HTTPException(status_code=422, detail=f"{exc.field}: {exc.message}") from None


# A POST's JSON body of report options: a few hundred bytes in practice (two names of at most 140 characters).
BODY_MAX_BYTES = 16 * 1024
_LIST_KEYS = ("sections", "severities", "statuses")


def _refuse(field: str, message: str) -> HTTPException:
    return HTTPException(status_code=422, detail=f"{field}: {message}")


class _Pairs(list):
    """A JSON object's (key, value) pairs in order, repeats kept."""


def options_from_body(raw: bytes, family: str, *, scan_type: str | None = None) -> ReportOptions:
    """Report options from a POST's JSON body (module docstring), validated exactly as the query string is."""
    if not raw.strip():
        return options_from_request((), family, scan_type=scan_type)
    try:
        data = json.loads(raw, object_pairs_hook=_Pairs)  # pairs, not a dict: a repeated key is refused, as in a query
    except (ValueError, UnicodeDecodeError):
        data = None
    if not isinstance(data, _Pairs):
        raise _refuse("body", "must be a JSON object of report options")
    items: list[tuple[str, str]] = []
    for key, value in data:
        if key not in ALL_KEYS:
            if key.isidentifier() and len(key) <= 40:
                raise _refuse(key, "is not a report option")
            raise _refuse("body", "has a key that is not a report option")
        if value is None:
            continue
        if key in _LIST_KEYS and isinstance(value, list) and all(isinstance(v, str) for v in value):
            value = ",".join(value)
        elif key == "hide_evidence" and isinstance(value, bool):
            value = "true" if value else "false"
        elif not isinstance(value, str):
            raise _refuse(key, "must be a string" + (" or a list of strings" if key in _LIST_KEYS else
                                                     " or a boolean" if key == "hide_evidence" else ""))
        items.append((key, value))
    return options_from_request(items, family, scan_type=scan_type)


async def request_options(request: Request, family: str, *, scan_type: str | None = None) -> ReportOptions:
    """The route's report options: from the query string of a GET, from the JSON body of a POST (module docstring)."""
    if request.method != "POST":
        return options_from_request(request.query_params, family, scan_type=scan_type)
    in_query = [key for key in request.query_params.keys() if key in ALL_KEYS]
    if in_query:
        raise _refuse(in_query[0], "send report options in the JSON body of a POST, not in its address")
    raw = bytearray()
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > BODY_MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"Report options are limited to {BODY_MAX_BYTES // 1024} KiB")
    return options_from_body(bytes(raw), family, scan_type=scan_type)


def options_body_openapi(family: str) -> dict[str, Any]:
    """``openapi_extra`` of a POST route: its optional JSON body, with the keys ``family`` takes."""
    listed = {"type": "string", "description": "comma list (or an array of strings)"}
    schemas: dict[str, Any] = {
        "preset": {"type": "string", "enum": list(PRESETS)},
        "sections": listed, "severities": listed, "statuses": listed,
        "prepared_for": {"type": "string", "maxLength": 120}, "title": {"type": "string", "maxLength": 140},
        "label": {"type": "string", "enum": list(LABELS)},
        "hide_evidence": {"type": "string", "enum": ["true", "false"], "description": "or a boolean"},
    }
    properties = {key: schemas[key] for key in FAMILY_KEYS[family]}
    return {"requestBody": {"required": False, "content": {"application/json": {"schema": {
        "type": "object", "additionalProperties": False, "properties": properties}}}}}


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


__all__ = ["BODY_MAX_BYTES", "CBOM_EXPOSED_HEADERS", "LARGE_PDF_ROWS", "REPORT_EXPOSED_HEADERS", "log_export", "logo_state",
           "options_body_openapi", "options_from_body", "options_from_request", "report_headers", "request_options",
           "status_join_error"]
