"""What an MCP or LLM scan may connect to (issue #53): the CBOM SSRF guard's address rule, applied at connect time.

The rule is not in the worker. ``RULE`` is ``backend/utilities/cbom_sources/address_rule.py`` itself, the file the CBOM
SSRF guard (``safe_fetch.py``) and the scan API (``utilities/scan/target_address.py``) run: it is standard library only,
and the worker image carries it at the same path relative to this file (RabbitMQ/worker/Dockerfile copies it to
``/build/backend/utilities/cbom_sources/``), so a checkout and the image load the same file. There is no copy to drift.

The API checks a target before it queues a scan; DNS can answer differently when the worker connects (DNS rebinding)
and a server can redirect, so every connection of a scan goes through ``TargetGuard`` (helpers/net/egress.py):

* ``RULE.scan_target``: only http:// and https:// URLs with a host;
* ``RULE.checked_addresses``: every address the host resolves to must be public (no allowlist: the product has no
  documented setting that opens private addresses to MCP or LLM scans);
* the guard pins a host's checked answer for ``PIN_SECONDS``, so an answer that changes after the check is never
  followed. After that the host is resolved and checked again, so a long LLM scan follows a provider's address
  rotation, and every answer it uses was checked. ``refused`` records each refusal.
"""
from __future__ import annotations

import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path
from types import ModuleType
from typing import Callable

PIN_SECONDS = 60.0  # a load balancer's DNS answers live about this long (e.g. 60 s for an AWS ALB)
RULE_FILE = Path(__file__).resolve().parents[4] / "backend" / "utilities" / "cbom_sources" / "address_rule.py"
_RULE_MODULE = "zeroshield_cbom_address_rule"


def _load_rule() -> ModuleType:
    """The address rule file, loaded once per process. Missing, the worker does not start: it never scans unchecked."""
    loaded = sys.modules.get(_RULE_MODULE)
    if loaded is not None:
        return loaded
    spec = importlib.util.spec_from_file_location(_RULE_MODULE, RULE_FILE)
    if spec is None or spec.loader is None or not RULE_FILE.is_file():
        raise ImportError(f"the CBOM SSRF guard's address rule is missing ({RULE_FILE}): MCP and LLM scans cannot run")
    module = importlib.util.module_from_spec(spec)
    sys.modules[_RULE_MODULE] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(_RULE_MODULE, None)
        raise
    return module


RULE = _load_rule()


class TargetRefused(ConnectionRefusedError):
    """A connection a scan may not make: a private or reserved address, or a URL that is not http(s). Never made."""


class TargetGuard:
    """The checked addresses of every host one scan connects to. Thread-safe; one guard per scan (or estimate)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._pinned: dict[str, tuple[float, tuple[str, ...]]] = {}  # host -> (checked until, addresses)
        self._lock = threading.Lock()
        self.refused: list[str] = []  # what was refused: a refusal in a client's background task may reach the
        # caller only as that task group's cancellation (mcp's streamable HTTP client), or not at all (garak's exit)

    def addresses(self, host: str, port: int) -> tuple[str, ...]:
        """The checked addresses of ``host`` in the order to try them: the pinned answer while it is fresh, else
        ``RULE.checked_addresses`` (resolved, every address checked). Raises TargetRefused, or OSError when the name
        does not resolve."""
        key = str(host or "").strip().strip("[]").lower()
        now = self._clock()
        with self._lock:
            pinned = self._pinned.get(key)
        if pinned is not None and now < pinned[0]:
            return pinned[1]
        try:
            checked = tuple(RULE.checked_addresses(key, port))
        except RULE.AddressRefused:
            message = f"{key[:100]} resolves to a private or reserved address; only public addresses can be scanned"
            with self._lock:
                self.refused.append(message)
            raise TargetRefused(message) from None
        except RULE.Unresolvable as exc:  # a network failure, not a refusal (a plain OSError: any process can read it)
            raise OSError(str(exc)[:200]) from None
        with self._lock:
            self._pinned[key] = (now + PIN_SECONDS, checked)
        return checked

    def check_url(self, url: str) -> tuple[str, ...]:
        """The checked addresses of ``url``'s host (``RULE.scan_target``). Raises TargetRefused or OSError."""
        try:
            host, port = RULE.scan_target(url)
        except RULE.TargetURLError as exc:
            raise TargetRefused(f"the URL {exc}") from None
        return self.addresses(host, port)

    def connect(self, host: str, port: int, timeout: float = 30.0) -> socket.socket:
        """A TCP connection to ``host``:``port`` at the first of its checked addresses that accepts one
        (``RULE.connect_first``). Raises TargetRefused, or the last connect error."""
        return RULE.connect_first(list(self.addresses(host, port)), port, timeout)
