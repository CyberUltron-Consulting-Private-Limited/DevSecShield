"""A host-wide bound on concurrent large run exports (CB-06, review 5879114669 major 2).

Building a run's CycloneDX export holds the whole document in memory (the dict, then the JSON bytes, or the lxml tree
and the XML bytes): a 50,000-component export peaks near 1 GB. The backend runs several gunicorn worker processes on a
host it shares with Postgres, Mongo and RabbitMQ, so a few concurrent large downloads could reach the OOM killer.

A large export (``LARGE_ASSETS`` stored rows or more) first takes one of ``SLOTS`` slots. A slot is an exclusive
``flock`` on a file in ``LOCK_DIR``: it is shared by every worker process of the container, and the kernel releases it
when its holder ends, even when the process is killed. With every slot taken the route answers 503 with Retry-After;
smaller exports never wait. Configuration (environment, read at import): ``ZS_CBOM_EXPORT_SLOTS`` (default 2),
``ZS_CBOM_EXPORT_LARGE_ASSETS`` (default 10,000), ``ZS_CBOM_EXPORT_LOCK_DIR`` (default the system temp directory).
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
LARGE_ASSETS = _int_env("ZS_CBOM_EXPORT_LARGE_ASSETS", 10_000, 1)
LOCK_DIR = os.environ.get("ZS_CBOM_EXPORT_LOCK_DIR") or tempfile.gettempdir()
RETRY_AFTER_S = 30


class Busy(Exception):
    """Every export slot is taken."""


def is_large(asset_rows: int) -> bool:
    return asset_rows >= LARGE_ASSETS


@contextlib.contextmanager
def slot() -> Iterator[int]:
    """Hold one free export slot for the block (its index); raise ``Busy`` at once when every slot is taken."""
    os.makedirs(LOCK_DIR, exist_ok=True)
    for index in range(SLOTS):
        fd = os.open(os.path.join(LOCK_DIR, f"zs-cbom-export-slot-{index}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
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


__all__ = ["Busy", "LARGE_ASSETS", "LOCK_DIR", "RETRY_AFTER_S", "SLOTS", "is_large", "slot"]
