"""The network gate for database drivers that open their own sockets (python-tds, python-oracledb thin).

Both drivers resolve names and connect by calling ``socket.getaddrinfo`` / ``socket.create_connection`` from their
own modules, and both can be sent elsewhere by the server after the first connection (a SQL Server routing
ENVCHANGE, an Oracle listener REDIRECT).  ``install(module)`` replaces that module's ``socket`` name with a stand-in:

* ``create_connection`` connects only through ``netutil.connect``, i.e. to an address checked against the never-scan
  list of the job running in this thread at the moment of connecting;
* ``getaddrinfo`` answers a pinned name (the target the collector already resolved and checked) with the checked
  address, so the driver never resolves it again, and resolves any other name through ``netutil.resolve_checked``;
* everything else is the real socket module.

The job's state lives in a context variable set by ``scope()``.  Outside a scope every connection and lookup is
refused, so a driver can never connect on its own.
"""
from __future__ import annotations

import contextlib
import contextvars
import socket as _socket
import types
from typing import Iterator

from zs_scan_node import netutil
from zs_scan_node.netutil import Blocked, NeverScan

_STATE: contextvars.ContextVar["Scope | None"] = contextvars.ContextVar("zs_driver_gate", default=None)


def _norm(name: str) -> str:
    return str(name or "").strip().strip("[]").lower().rstrip(".")


class Scope:
    def __init__(self, never: NeverScan, pins: dict[str, str]) -> None:
        self.never = never
        self.pins = {_norm(k): v for k, v in (pins or {}).items() if k and v}
        self.connected: list[tuple[str, int]] = []  # every address the driver connected to (for tests and logs)


@contextlib.contextmanager
def scope(never: NeverScan, pins: dict[str, str] | None = None) -> Iterator[Scope]:
    """Driver connections inside this block go through the gate with this job's never-scan list.  ``pins`` maps a
    name the collector already resolved and checked to that address."""
    state = Scope(never, pins or {})
    token = _STATE.set(state)
    try:
        yield state
    finally:
        _STATE.reset(token)


class OutsideScope(Blocked):
    """A driver tried to connect or resolve a name outside a gated scan job."""

    def __init__(self) -> None:
        Exception.__init__(self, "a database driver tried to connect outside a gated scan job")
        self.what = "driver"


def _state() -> Scope:
    state = _STATE.get()
    if state is None:
        raise OutsideScope()
    return state


def _addresses(state: Scope, host: str) -> list[str]:
    name = _norm(host)
    if name in state.pins:
        return [netutil.checked_ip(state.pins[name], state.never)]
    return netutil.resolve_checked(name, state.never)


def create_connection(address, timeout=_socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, **_kwargs):
    state = _state()
    host, port = address[0], int(address[1])
    ip = _addresses(state, host)[0]
    sock = netutil.connect(ip, port, state.never, None if timeout is _socket._GLOBAL_DEFAULT_TIMEOUT else timeout)
    state.connected.append((ip, port))
    return sock


def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002 - socket's own signature
    state = _state()
    out = []
    for ip in _addresses(state, host):
        fam = _socket.AF_INET6 if ":" in ip else _socket.AF_INET
        if family and family != fam:
            continue
        sockaddr = (ip, int(port or 0), 0, 0) if fam == _socket.AF_INET6 else (ip, int(port or 0))
        out.append((fam, _socket.SOCK_STREAM, _socket.IPPROTO_TCP, "", sockaddr))
    if not out:
        raise _socket.gaierror(_socket.EAI_NONAME, "no allowed address")
    return out


class _GatedSocketModule(types.ModuleType):
    create_connection = staticmethod(create_connection)
    getaddrinfo = staticmethod(getaddrinfo)

    def __getattr__(self, name: str):
        return getattr(_socket, name)


def install(module) -> None:
    """Route ``module``'s use of the socket module through the gate (idempotent)."""
    if not isinstance(getattr(module, "socket", None), _GatedSocketModule):
        module.socket = _GatedSocketModule("socket")


def installed(module) -> bool:
    return isinstance(getattr(module, "socket", None), _GatedSocketModule)
