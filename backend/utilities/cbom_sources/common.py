"""Shared helpers for CBOM Sources: clock, ids, logging, audit, string hygiene."""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
import secrets
import sys
from typing import Any, Iterable

from rich.console import Console
from sqlmodel import Session

from backend.new_models import CbomCollectionAuditEvent
from backend.utilities.build_info import (DIRTY, UNKNOWN, build_version, current_client_request_id,
                                          current_request_id, short_build, utc_timestamp)

console = Console()

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_NUL = "\x00"


def utcnow() -> _dt.datetime:
    """Naive UTC, matching the ``DateTime`` columns (which carry no time zone)."""
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def naive_utc(moment: _dt.datetime | None) -> _dt.datetime | None:
    if moment is None:
        return None
    if moment.tzinfo is not None:
        return moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return moment


def iso_z(moment: _dt.datetime | None) -> str | None:
    """Serialise a stored (naive UTC) or aware time as ISO-8601 with a trailing Z."""
    value = naive_utc(moment)
    if value is None:
        return None
    return value.replace(microsecond=0).isoformat() + "Z"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def engine_version() -> str:
    """The API build that classifies node facts, recorded on each run (``engine_version``, 32 characters): the
    12-character commit the image was built from (``DSS_BUILD_SHA``, backend/utilities/build_info.py), else its
    version string (``DSS_BUILD_VERSION``; "-dirty" for a tree with changes), else "unknown"."""
    short = short_build()
    if short:
        return short
    version = build_version()
    if version == UNKNOWN:
        return UNKNOWN
    if len(version) > 32 and version.endswith(DIRTY):  # cut the version, never build_images.sh's dirty-tree marker
        return version[:32 - len(DIRTY)] + DIRTY
    return version[:32]


def new_token(prefix: str, nbytes: int = 32) -> str:
    return f"{prefix}{secrets.token_urlsafe(nbytes)}"


def new_ref() -> str:
    """Short id put in a generic 500 body and in the matching server log line."""
    return secrets.token_hex(4)


def clean_text(value: Any, limit: int) -> str | None:
    """Strip NUL bytes (Postgres rejects them) and truncate to the column length."""
    if value is None:
        return None
    text = str(value).replace(_NUL, "").strip()
    return text[:limit] if text else None


FRAMES_CAP = 20  # frames per line: the innermost ones (where it went wrong), "…" first when cut


def _frame_path(filename: str) -> str:
    """A frame's file, short and stable: repo-relative under backend/ (or scan_node/), the package path under
    site-packages, else the file name."""
    path = filename.replace("\\", "/")
    for marker in ("/site-packages/", "/dist-packages/"):
        if marker in path:
            return path.rsplit(marker, 1)[1]
    for root in ("/backend/", "/scan_node/"):
        if root in path:
            return root.strip("/") + "/" + path.rsplit(root, 1)[1]
    return path.rsplit("/", 1)[-1]


def frames(exc: BaseException | None) -> str | None:
    """CB-31 (X3, R4 OBS-7): an exception's traceback as ``file:line:function`` frames, outermost first, joined by
    commas.  Never the exception's message and never a frame's locals: either can hold a secret.  The root cause of a
    500 can be found from its ref's log line without them."""
    import traceback

    tb = exc.__traceback__ if exc is not None else None
    if tb is None:
        return None
    listed = [f"{_frame_path(f.filename)}:{f.lineno}:{f.name}" for f in traceback.extract_tb(tb)]
    listed = [text.replace(" ", "_").replace(",", "_") for text in listed]
    if len(listed) > FRAMES_CAP:
        listed = ["…"] + listed[-FRAMES_CAP:]
    return ",".join(listed) or None


def log(action: str, **fields: Any) -> None:
    """One greppable line per state change.  Only ids, enums and numbers belong in ``fields``.  The line starts with
    an ISO UTC timestamp and, inside a request, ends with that request's ``request_id`` (the X-ZS-Request-Id the
    response carries) and, when the caller sent a well-formed one, its ``client_request_id``."""
    if "ref" in fields and "frames" not in fields:  # a ref'd failure logged while its exception is handled (X3)
        fields["frames"] = frames(sys.exc_info()[1])
    parts = [utc_timestamp(), f"cbom sources {action}"]
    for key, value in fields.items():
        if value is None:
            continue
        parts.append(f"{key}={value}")
    request_id = current_request_id()
    if request_id and "request_id" not in fields:
        parts.append(f"request_id={request_id}")
        client_id = current_client_request_id()  # the caller's own id, only when well formed (build_info)
        if client_id:
            parts.append(f"client_request_id={client_id}")
    try:
        console.print(" ".join(parts), markup=False, highlight=False, soft_wrap=True)
    except Exception:  # logging must never fail a request
        pass


def log_failure(what: str, ref: str, exc: BaseException, **fields: Any) -> None:
    log(f"{what} FAILED", ref=ref, error=type(exc).__name__, frames=frames(exc), **fields)


def audit(
    session: Session,
    *,
    team_id: int,
    actor_type: str,
    actor_id: int | None,
    action: str,
    object_type: str,
    object_id: int | None,
    changed_fields: Iterable[str] = (),
) -> None:
    """Add an audit row to the caller's transaction (field names only, never values).  A change made with a CBOM API
    key is marked as a machine call: ``actor_type="api_key"``, ``actor_id`` = the key's id (its row names its
    creator)."""
    if actor_type == "user":
        from backend.utilities.cbom_sources.api_keys import active_key_id  # api_keys imports this module
        key_id = active_key_id()
        if key_id is not None:
            actor_type, actor_id = "api_key", key_id
    session.add(
        CbomCollectionAuditEvent(
            team_id=team_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action[:48],
            object_type=object_type[:24],
            object_id=object_id,
            changed_fields=sorted({str(f)[:64] for f in changed_fields}),
        )
    )


def quote_sh(value: str) -> str:
    """POSIX single-quote a value for a shell command shown to the customer."""
    return "'" + value.replace("'", "'\"'\"'") + "'"
