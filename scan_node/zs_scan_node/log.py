"""One-line, key=value logs on stdout.  Every value passes through the job's scrubber before it is printed."""
from __future__ import annotations

import datetime as _dt
import sys
import threading

from zs_scan_node.scrub import Scrubber, printable

_lock = threading.Lock()
_global_scrubber = Scrubber()


def global_scrubber() -> Scrubber:
    return _global_scrubber


def log(msg: str, scrubber: Scrubber | None = None, level: str = "info", **fields) -> None:
    s = scrubber or _global_scrubber
    parts = [_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), level, printable(s.text(msg), 300)]
    for key, value in fields.items():
        if value is None:
            continue
        text = printable(s.text(str(value)), 300)
        if " " in text or "=" in text:
            text = '"' + text.replace('"', "'") + '"'
        parts.append(f"{key}={text}")
    line = " ".join(parts)
    with _lock:
        print(line, file=sys.stdout, flush=True)
