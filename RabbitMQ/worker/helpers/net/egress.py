"""Connect-time egress control for MCP and LLM scans (issue #53).

Every connection an MCP or LLM scan makes goes to an address its ``TargetGuard`` checked (address_rule.py: the CBOM
SSRF guard's rule): every address of a host's DNS answer must be public before the answer is used, and the connection
is pinned to a checked address, redirect hops included. A proxy from the environment is never used: it would resolve
the name itself, after the check.

* MCP (the ``mcp`` client library, over httpx): ``guarded_http_client_factory`` is the client's
  ``httpx_client_factory``, with mcp's own defaults (``create_mcp_http_client``: redirects followed, 30 s) and
  ``PinnedTransport``: each request is sent to a checked address of its host, while TLS keeps the host name for SNI
  and the certificate check.
* LLM (garak, a subprocess using ``requests``): garak's REST generator reaches the network only through
  ``GuardedSocksProxy``, a local SOCKS5 proxy owned by the scan (the generator's ``proxies`` option, ``socks5h``: the
  proxy gets the host name and resolves it). Each CONNECT goes to a checked address, or is refused (reply 0x02).
  ``requests`` speaks SOCKS through PySocks (``requests[socks]``, in the worker lock); without it every request of the
  scan fails (closed), and tests/test_scan_target_egress.py fails.
"""
from __future__ import annotations

import ipaddress
import selectors
import socket
import socketserver
import threading
from typing import Any, Callable

import anyio
import httpx
from rich.console import Console

from helpers.net.address_rule import TargetGuard, TargetRefused

console = Console(markup=False)


def _inner_transport() -> httpx.AsyncBaseTransport:
    """The transport pinned requests are sent with: one per host name, so a connection is never shared by two names."""
    return httpx.AsyncHTTPTransport()


def _literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class PinnedTransport(httpx.AsyncBaseTransport):
    """An httpx transport that sends every request (each redirect hop is one) to a checked address of its host."""

    def __init__(self, guard: TargetGuard):
        self._guard = guard
        self._transports: dict[str, httpx.AsyncBaseTransport] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        host = url.raw_host.decode("ascii")
        port = url.port or (443 if url.scheme == "https" else 80)
        addresses = await anyio.to_thread.run_sync(self._guard.addresses, host, port)  # TargetRefused / OSError
        transport = self._transports.get(host)
        if transport is None:
            transport = self._transports[host] = _inner_transport()
        if _literal(host):  # the address itself: nothing to resolve
            return await transport.handle_async_request(request)
        last: httpx.TransportError | None = None
        for address in addresses:
            pinned = httpx.Request(request.method, url.copy_with(host=address), headers=request.headers,
                                   stream=request.stream, extensions={**request.extensions, "sni_hostname": host})
            try:
                return await transport.handle_async_request(pinned)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:  # this address does not answer: the next one
                last = exc
        raise last if last is not None else httpx.ConnectError(f"could not connect to {host[:100]}", request=request)

    async def aclose(self) -> None:
        for transport in self._transports.values():
            await transport.aclose()


def guarded_http_client_factory(guard: TargetGuard) -> Callable[..., httpx.AsyncClient]:
    """An ``httpx_client_factory`` for mcp's ``streamablehttp_client`` / ``sse_client``."""
    def factory(headers: dict[str, str] | None = None, timeout: httpx.Timeout | None = None,
                auth: httpx.Auth | None = None) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {"follow_redirects": True,
                                  "timeout": timeout if timeout is not None else httpx.Timeout(30.0),
                                  "transport": PinnedTransport(guard), "trust_env": False}
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)
    return factory


# --------------------------------------------------------------------------------------------------------- SOCKS5
_SOCKS_OK, _SOCKS_NOT_ALLOWED, _SOCKS_REFUSED, _SOCKS_BAD_COMMAND, _SOCKS_BAD_ADDRESS = 0, 2, 5, 7, 8


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("client closed")
        data += chunk
    return data


def _reply(conn: socket.socket, code: int) -> None:
    conn.sendall(bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0]))


def _relay(a: socket.socket, b: socket.socket, idle_seconds: float) -> None:
    """Copy bytes both ways until either side closes, or nothing moves (and nothing can be sent) for idle_seconds.
    Every byte read was already sent on, so the first end of the stream ends the exchange: an HTTP client (garak's
    requests) never half-closes, and a server's close follows its whole response."""
    for sock in (a, b):
        sock.settimeout(idle_seconds)
    with selectors.DefaultSelector() as selector:  # not select(): a busy worker's descriptors can pass 1024
        selector.register(a, selectors.EVENT_READ, b)
        selector.register(b, selectors.EVENT_READ, a)
        while True:
            events = selector.select(idle_seconds)
            if not events:
                return
            for key, _ in events:
                try:
                    data = key.fileobj.recv(65536)  # type: ignore[union-attr]
                    if not data:
                        return
                    key.data.sendall(data)
                except OSError:
                    return


def _serve(conn: socket.socket, guard: TargetGuard, connect_timeout: float, idle_seconds: float) -> None:
    """One SOCKS5 client: no authentication, CONNECT only, to a checked address of the host it names."""
    upstream: socket.socket | None = None
    try:
        conn.settimeout(connect_timeout)
        version, n_methods = _recv_exact(conn, 2)
        if version != 5:
            return
        if 0 not in _recv_exact(conn, n_methods):  # "no authentication" not offered
            conn.sendall(b"\x05\xff")
            return
        conn.sendall(b"\x05\x00")
        _, command, _, atyp = _recv_exact(conn, 4)
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, _recv_exact(conn, 4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(conn, 16))
        elif atyp == 3:
            host = _recv_exact(conn, _recv_exact(conn, 1)[0]).decode("ascii", "replace")
        else:
            _reply(conn, _SOCKS_BAD_ADDRESS)
            return
        port = int.from_bytes(_recv_exact(conn, 2), "big")
        if command != 1:
            _reply(conn, _SOCKS_BAD_COMMAND)
            return
        try:
            upstream = guard.connect(host, port, connect_timeout)
        except TargetRefused as exc:
            console.print(f"Scan egress refused: {exc}", style="bold red")
            _reply(conn, _SOCKS_NOT_ALLOWED)
            return
        except OSError:
            _reply(conn, _SOCKS_REFUSED)
            return
        _reply(conn, _SOCKS_OK)
        _relay(conn, upstream, idle_seconds)
    except (OSError, ValueError, IndexError):
        return
    finally:
        if upstream is not None:
            upstream.close()


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False


class GuardedSocksProxy:
    """A local SOCKS5 proxy on 127.0.0.1 for one garak run; ``url`` goes in the REST generator's ``proxies``.

    ``idle_seconds`` is longer than the REST generator's ``request_timeout`` (10000 s in llm_agent/rest_configs), so the
    proxy never cuts a request garak still waits for; garak's own timeout, or its exit, ends a connection first."""

    def __init__(self, guard: TargetGuard, connect_timeout: float = 30.0, idle_seconds: float = 10800.0):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                _serve(self.request, guard, connect_timeout, idle_seconds)

        self._server = _Server(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="scan-egress-proxy", daemon=True)
        self._thread.start()
        self.url = f"socks5h://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> "GuardedSocksProxy":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
