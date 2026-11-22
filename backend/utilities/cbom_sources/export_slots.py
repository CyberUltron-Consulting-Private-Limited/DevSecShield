"""A host-wide bound on concurrent large run exports (CB-06, review 5879114669 major 2).

Building a run's CycloneDX export holds the whole document in memory (the dict, then the JSON bytes, or the lxml tree
and the XML bytes): a 50,000-component export peaks near 1 GB. The backend runs several gunicorn worker processes on a
host it shares with Postgres, Mongo and RabbitMQ, so a few concurrent large downloads could reach the OOM killer.

A large export (``LARGE_ASSETS`` stored rows or more) first takes one of ``SLOTS`` slots. A slot is an exclusive
``flock`` on a file in ``LOCK_DIR``: it is shared by every worker process of the container, and the kernel releases it
when its holder ends, even when the process is killed. With every slot taken the route answers 429 with Retry-After
(the UI's error handler then says when to retry); smaller exports never wait. Configuration (environment, read at import): ``ZS_CBOM_EXPORT_SLOTS`` (default 2),
``ZS_CBOM_EXPORT_LARGE_ASSETS`` (default 10,000), ``ZS_CBOM_EXPORT_LOCK_DIR`` (default the system temp directory).

Scan PDF reports (``GET|POST /{team}/{type}/scan/{id}/export`` with ``report_http.LARGE_PDF_ROWS`` rows or more) take a
slot of their own pool, ``pdf_slot``: the same mechanism with its own lock files and capacity ``PDF_SLOTS``
(``ZS_PDF_EXPORT_SLOTS``, default 2), so a burst of big scan PDFs never makes a CBOM export answer 429, nor the other way
round, and each 429 names the work that is actually busy (``CBOM_BUSY`` / ``PDF_BUSY``).
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import tempfile
from typing import Iterator


def _int_env(name: str, default: int, low: int) -> int:
    try:
        return max(low, int(os.environ.get(name, default)))
    except ValueError:
        return default


SLOTS = _int_env("ZS_CBOM_EXPORT_SLOTS", 2, 1)
PDF_SLOTS = _int_env("ZS_PDF_EXPORT_SLOTS", 2, 1)
LARGE_ASSETS = _int_env("ZS_CBOM_EXPORT_LARGE_ASSETS", 10_000, 1)
LOCK_DIR = os.environ.get("ZS_CBOM_EXPORT_LOCK_DIR") or tempfile.gettempdir()
RETRY_AFTER_S = 30
# The 429 detail of each pool: it names the exports that hold that pool's slots, and only those.
CBOM_BUSY = f"The server is busy building other large CBOM exports; retry in {RETRY_AFTER_S} s."
PDF_BUSY = f"The server is busy building other large scan PDF reports; retry in {RETRY_AFTER_S} s."


class Busy(Exception):
    """Every export slot is taken."""


def is_large(asset_rows: int) -> bool:
    return asset_rows >= LARGE_ASSETS


@contextlib.contextmanager
def _take(prefix: str, count: int) -> Iterator[int]:
    """Hold one free slot of the pool whose lock files start with ``prefix``; ``Busy`` at once when all are taken."""
    os.makedirs(LOCK_DIR, exist_ok=True)
    for index in range(count):
        fd = os.open(os.path.join(LOCK_DIR, f"{prefix}-{index}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            continue
        try:
            yield index
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        return
    raise Busy()


def slot() -> contextlib.AbstractContextManager[int]:
    """Hold one free CBOM export slot for the block (its index); raise ``Busy`` at once when every slot is taken."""
    return _take("zs-cbom-export-slot", SLOTS)


def pdf_slot() -> contextlib.AbstractContextManager[int]:
    """Hold one free scan PDF slot (a pool of its own, ``PDF_SLOTS``); raise ``Busy`` at once when all are taken."""
    return _take("zs-pdf-export-slot", PDF_SLOTS)


__all__ = ["Busy", "CBOM_BUSY", "LARGE_ASSETS", "LOCK_DIR", "PDF_BUSY", "PDF_SLOTS", "RETRY_AFTER_S", "SLOTS",
           "is_large", "pdf_slot", "slot"]
