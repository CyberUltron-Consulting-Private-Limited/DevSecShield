"""HTTP plumbing shared by the PDF report routes (R1 scan export, R2 certin pack, R3 regulated deliverables,
R4 run report, R5 run evidence pack).

* ``request_options``: a route's report options, 422 ``"<field>: message"`` on any error. A GET reads them from the
  query string (``options_from_request``); a POST reads the same options from a JSON body (``options_from_body``), so a
  client name or title never travels in a URL, where access logs, proxies and browser history keep it. R1, R3 and R4
  answer both methods with one handler (same auth, permission, rate limit, thread pool, export slot, headers and log
  line); the GET stays for old clients and option-less downloads. The body is an object of the query's keys with the
  query's string values (``{"sections": "summary,catalog", "hide_evidence": "true"}``); a list of strings is accepted
  for ``sections``, ``severities`` and ``statuses`` and a boolean for ``hide_evidence``; ``null`` means not set. A key
  that is not a report option, a key given twice (even as ``null``), a body that is not one JSON object (malformed,
  nested too deeply to parse) or a POST with report options in its query string is refused (422), so a typo never
  silently builds the full report; a body over ``BODY_MAX_BYTES`` answers 413, and a POST whose ``Content-Type`` is not
  ``application/json`` (parameters such as ``charset`` allowed) answers 415. An empty JSON body is no option (today's
  report).
* Export slots: a large scan PDF (``LARGE_PDF_ROWS`` rows or more) takes a slot of the scan PDF pool and a large CBOM
  export one of the CBOM pool (``cbom_sources/export_slots.py``). With the defaults a host builds at most 2 large
  CBOM exports and 2 large scan PDFs at once (4 in all, where one shared pool of 2 allowed 2), each pool's lock files
  in ``ZS_CBOM_EXPORT_LOCK_DIR``; size the memory of a host, or lower ``ZS_CBOM_EXPORT_SLOTS`` /
  ``ZS_PDF_EXPORT_SLOTS``, accordingly.
* ``report_headers``: the headers of every report download (R1-R5): ``PRIVATE`` (``Cache-Control: no-store``,
  ``X-Content-Type-Options: nosniff``: a report names a client and its findings, so no cache keeps it and no browser
  sniffs it into something else), ``Content-Disposition``, ``X-Report-Logo`` (applied | none | skipped) and, for the
  reports that count findings (R1, R4), ``X-Report-Findings`` (rows shown / rows the scan has); ``main.py`` exposes
  them through CORS. Routes add their own (``X-Cbom-*``, ``Content-Length``) beside them, never instead of them.
* ``busy_refusal``: the 429 of a full export-slot pool: ``PRIVATE``, ``Retry-After`` and ``X-Export-Busy: <pool>``
  (``export_slots.BUSY_HEADER``), the stable signal a client uses to tell "busy building other exports" (show the
  server's words) from the rate limiter's 429 (too many requests).
* ``status_join_error``: the 409 / 503 a status filter answers when the stored statuses cannot be joined.
* ``log_export``: one line per export attempt with ids, enums, flags and numbers only, and its ``outcome``: ``ok``,
  ``client_gone`` (built, but the client had disconnected by then: ``finished_outcome``), ``busy`` (slot 429),
  ``refused`` (any other 4xx, ``status=``) or ``error`` (5xx, ``status=``) (``failure_outcome``). The free-text
  options (prepared for, title) are never logged: they can name a client.
"""
from __future__ import annotations

import datetime as _dt
import json
import time
from typing import Any, Iterable

from fastapi import HTTPException, Request
from rich.console import Console

from backend.utilities.build_info import current_request_id
from backend.utilities.cbom_sources import export_slots as EXPORT_SLOTS
from backend.utilities.db.finding_rows import StatusesUnavailable, StatusStoreDown
from backend.utilities.pdf.report_context import ReportContext
from backend.utilities.pdf.report_options import (
    ALL_KEYS,
    FAMILY_KEYS,
    LABELS,
    PREPARED_FOR_MAX,
    PRESETS,
    RUN_SECTIONS,
    SCAN_SECTIONS,
    SEVERITIES,
    STATUSES,
    TITLE_MAX,
    ReportOptions,
    ReportOptionsError,
    parse_report_options,
)

console = Console()

# Every header a PDF/report route sets that the browser must be able to read (CORS expose_headers).
REPORT_EXPOSED_HEADERS = ("Content-Disposition", "X-Report-Findings", "X-Report-Logo", EXPORT_SLOTS.BUSY_HEADER)
# On every report response and slot refusal (module docstring); the same pair as ``cbom_sources.http.PRIVATE``.
PRIVATE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
OUTCOMES = ("ok", "client_gone", "busy", "refused", "error")
# The CBOM download headers the UI reads (estate SHA-256, deliverable fidelity and logo, ...).
CBOM_EXPOSED_HEADERS = ("X-Cbom-Assets", "X-Cbom-Fidelity", "X-Cbom-Fingerprint", "X-Cbom-Logo-Sha256",
                        "X-Cbom-Posture", "X-Cbom-Scans-Included", "X-Cbom-Sha256", "X-Cbom-Signature",
                        "X-Cbom-Sources", "X-ZS-Signature", "X-ZS-Signature-Alg", "X-ZS-Signature-Key-Id")

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


# Report options are one object holding strings, lists of strings and booleans, so they need two levels; up to
# BODY_MAX_DEPTH levels are accepted (room for a little growth) and anything deeper is refused before parsing.
BODY_MAX_DEPTH = 4


def _too_deep(raw: bytes) -> bool:
    """True when ``raw`` nests arrays or objects deeper than ``BODY_MAX_DEPTH`` (brackets inside strings ignored)."""
    depth = 0
    in_string = escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > BODY_MAX_DEPTH:
                return True
        elif byte in (0x5D, 0x7D):  # ] }
            depth -= 1
    return False


class _Pairs(list):
    """A JSON object's (key, value) pairs in order, repeats kept."""


def options_from_body(raw: bytes, family: str, *, scan_type: str | None = None) -> ReportOptions:
    """Report options from a POST's JSON body (module docstring), validated exactly as the query string is."""
    if not raw.strip():
        return options_from_request((), family, scan_type=scan_type)
    if _too_deep(raw):  # checked before parsing: the same answer on every Python (3.12 parses 5,000 levels)
        raise _refuse("body", "is nested too deeply; send one JSON object of report options")
    try:
        data = json.loads(raw, object_pairs_hook=_Pairs)  # pairs, not a dict: a repeated key is refused, as in a query
    except (ValueError, UnicodeDecodeError):
        data = None
    except RecursionError:  # belt and braces: _too_deep already refused anything this deep
        raise _refuse("body", "is nested too deeply; send one JSON object of report options") from None
    if not isinstance(data, _Pairs):
        raise _refuse("body", "must be a JSON object of report options")
    items: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, value in data:
        if key not in ALL_KEYS:
            if key.isidentifier() and len(key) <= 40:
                raise _refuse(key, "is not a report option")
            raise _refuse("body", "has a key that is not a report option")
        if key in seen:  # checked before null is dropped: {"label": "internal", "label": null} is ambiguous too
            raise _refuse(key, "was given more than once")
        seen.add(key)
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
    media = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media != "application/json":
        raise HTTPException(status_code=415, detail="Send the report options as JSON (Content-Type: application/json)")
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
    def listed(allowed: Iterable[str]) -> dict[str, Any]:
        return {"anyOf": [{"type": "string", "description": "comma list"},
                          {"type": "array", "items": {"type": "string", "enum": list(allowed)}},
                          {"type": "null"}]}

    def text(limit: int) -> dict[str, Any]:
        return {"anyOf": [{"type": "string", "maxLength": limit}, {"type": "null"}]}

    schemas: dict[str, Any] = {
        "preset": {"anyOf": [{"type": "string", "enum": list(PRESETS)}, {"type": "null"}]},
        "sections": listed(RUN_SECTIONS if family == "run" else SCAN_SECTIONS),
        "severities": listed(SEVERITIES), "statuses": listed(STATUSES),
        "prepared_for": text(PREPARED_FOR_MAX), "title": text(TITLE_MAX),
        "label": {"anyOf": [{"type": "string", "enum": list(LABELS)}, {"type": "null"}]},
        "hide_evidence": {"anyOf": [{"type": "boolean"}, {"type": "string", "enum": ["true", "false"]},
                                    {"type": "null"}]},
    }
    properties = {key: schemas[key] for key in FAMILY_KEYS[family]}
    return {"requestBody": {"required": False, "content": {"application/json": {"schema": {
        "type": "object", "additionalProperties": False, "properties": properties}}}}}


# The answers only the POST form adds (``responses=`` of the POST routes, for their OpenAPI).
OPTIONS_BODY_RESPONSES: dict[int | str, dict[str, Any]] = {
    413: {"description": f"The JSON body of report options is larger than {BODY_MAX_BYTES // 1024} KiB."},
    415: {"description": "The body is not sent as Content-Type: application/json."},
    422: {"description": "A report option, or the body itself, is not valid; the detail names it "
                         "(`<field>: message`, `body: ...` for the body)."},
}


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
    """Every report download's headers (module docstring); ``findings=False`` for the documents that do not count
    findings (deliverables, evidence packs)."""
    headers = {**PRIVATE, "Content-Disposition": f'attachment; filename="{filename}"', "X-Report-Logo": logo_state(ctx)}
    if findings:
        headers["X-Report-Findings"] = f"{ctx.shown}/{ctx.total}"
    return headers


def busy_refusal(pool: str) -> HTTPException:
    """The 429 of a full export-slot pool (``"pdf"``: scan PDFs, ``"cbom"``: CBOM exports), in that pool's words."""
    detail = EXPORT_SLOTS.PDF_BUSY if pool == "pdf" else EXPORT_SLOTS.CBOM_BUSY
    return HTTPException(status_code=429, detail=detail, headers={
        **PRIVATE, "Retry-After": str(EXPORT_SLOTS.RETRY_AFTER_S), EXPORT_SLOTS.BUSY_HEADER: pool})


def failure_outcome(exc: BaseException) -> tuple[str, int]:
    """(outcome, status) of an export that raised ``exc``: ``busy`` for a slot 429 (it carries ``X-Export-Busy``),
    ``refused`` for any other 4xx, else ``error`` (an exception that is not an HTTPException answers 500)."""
    status = exc.status_code if isinstance(exc, HTTPException) else 500
    if status == 429 and EXPORT_SLOTS.BUSY_HEADER in ((exc.headers or {}) if isinstance(exc, HTTPException) else {}):
        return "busy", status
    return ("refused" if 400 <= status < 500 else "error"), status


async def finished_outcome(request: Request) -> str:
    """``ok``, or ``client_gone`` when the client disconnected while the report was built (one non-blocking look at the
    ASGI receive channel: an abandoned download is never counted as delivered)."""
    try:
        return "client_gone" if await request.is_disconnected() else "ok"
    except Exception:  # noqa: BLE001 - the outcome is for the log only; never fail an export over it
        return "ok"


def log_export(family: str, *, team: int, id: int, user: int | None, ctx: ReportContext | None = None,
               size: int | None = None, started: float, type: str | None = None, slot_wait_ms: int | None = None,
               outcome: str = "ok", status: int | None = None, options: ReportOptions | None = None) -> None:
    """One greppable line per export attempt (see module docstring for what may be logged). A refused or failed
    attempt has no built context: it logs its ``status`` and the ``options`` it was asked for, when they were read."""
    fields: dict[str, Any] = {"family": family, "type": type, "team": team, "id": id, "user": user,
                              "outcome": outcome, "status": status}
    chosen = ctx.options if ctx is not None else options
    if chosen is not None:
        fields.update(chosen.log_fields())
    if ctx is not None:
        fields.update({"logo": logo_state(ctx), "shown": ctx.shown, "total": ctx.total})
    fields.update({"bytes": size, "ms": int((time.monotonic() - started) * 1000), "slot_wait_ms": slot_wait_ms})
    parts = [_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "pdf report export"]
    parts += [f"{key}={value}" for key, value in fields.items() if value is not None]
    request_id = current_request_id()
    if request_id:
        parts.append(f"request_id={request_id}")
    try:
        console.print(" ".join(parts), markup=False, highlight=False, soft_wrap=True)
    except Exception:  # noqa: BLE001 - logging never fails an export
        pass


__all__ = ["BODY_MAX_BYTES", "BODY_MAX_DEPTH", "OPTIONS_BODY_RESPONSES", "CBOM_EXPOSED_HEADERS", "LARGE_PDF_ROWS", "OUTCOMES",
           "PRIVATE", "REPORT_EXPOSED_HEADERS", "busy_refusal", "failure_outcome", "finished_outcome", "log_export",
           "logo_state", "options_body_openapi", "options_from_body", "options_from_request", "report_headers",
           "request_options", "status_join_error"]
