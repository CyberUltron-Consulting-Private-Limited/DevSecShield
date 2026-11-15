"""Errors in the customer's words (#152, #153, #198, #214): the cause of a failed connection, never a Python exception
class name.  Each function returns the node's outcome vocabulary (``no_route``, ``refused``, ``timeout``,
``unreachable``, ``tls_unavailable`` ...) and one plain sentence.

Only what the exception says about the network or TLS is used: OpenSSL's verify message ("self-signed
certificate", "unable to get local issuer certificate") and the OS's socket error text.  A server's answer and a
credential never reach these sentences.
"""
from __future__ import annotations

import errno
import re
import socket
import ssl
from typing import Iterator

CA_HINT = "If a proxy inspects TLS, set ZS_CA_FILE to its CA certificate"
_NO_ROUTE = {errno.ENETUNREACH, errno.EHOSTUNREACH}
_VERIFY = re.compile(r"certificate verify failed:\s*([^(\]\n]+)", re.I)
_ERRNO = re.compile(r"\[Errno (-?\d+)\]\s*([^'\")\]]+)")


def chain(exc: BaseException | None, limit: int = 8) -> Iterator[BaseException]:
    """The exception and the ones it was raised from or during (``__cause__``, then ``__context__``)."""
    seen = 0
    while exc is not None and seen < limit:
        yield exc
        exc, seen = exc.__cause__ or exc.__context__, seen + 1


def tls_verify_problem(exc: BaseException) -> str | None:
    """OpenSSL's reason when a peer certificate failed verification anywhere in the chain ("self-signed
    certificate", "unable to get local issuer certificate", "certificate has expired" ...), else None."""
    for e in chain(exc):
        if isinstance(e, ssl.SSLCertVerificationError):
            return (e.verify_message or "certificate verify failed").strip()
        m = _VERIFY.search(str(e))
        if m:
            return m.group(1).strip()
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            return "certificate verify failed"
    return None


def os_error(exc: BaseException) -> tuple[int | None, str]:
    """(errno, OS text) of the first socket error in the chain, read from its args or its message
    ("[Errno 111] Connection refused" inside a requests / urllib3 / httpx error)."""
    for e in chain(exc):
        if isinstance(e, OSError) and e.errno is not None:
            return e.errno, (e.strerror or "").strip()
        m = _ERRNO.search(str(e))
        if m:
            return int(m.group(1)), m.group(2).strip()
    return None, ""


def _timed_out(exc: BaseException) -> bool:
    return any(isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in str(e).lower() or
               e.__class__.__name__.endswith("Timeout") for e in chain(exc))


def _no_name(exc: BaseException) -> bool:
    return any(isinstance(e, socket.gaierror) or "Name or service not known" in str(e)
               or "nodename nor servname" in str(e) or "Temporary failure in name resolution" in str(e)
               for e in chain(exc))


def socket_problem(exc: BaseException, host: str, port: int | None) -> tuple[str, str]:
    """(status, sentence) for a connection to ``host``:``port`` that failed below TLS."""
    where = f"{host}:{port}" if port else host
    code, text = os_error(exc)
    if code == errno.ECONNREFUSED or any(isinstance(e, ConnectionRefusedError) for e in chain(exc)):
        return "refused", f"port {port} refused" if port else f"{host} refused the connection"
    if code in _NO_ROUTE:
        return "no_route", f"no route to {host}"
    if _no_name(exc):
        return "unreachable", f"{host} does not resolve from the scan node"
    if code == errno.ETIMEDOUT or _timed_out(exc):
        return "timeout", f"no answer from {host}" + (f" on port {port}" if port else "")
    if code in (errno.ECONNRESET, errno.EPIPE) or any(isinstance(e, ConnectionResetError) for e in chain(exc)):
        return "unreachable", f"{where} closed the connection (connection reset)"
    if text:
        return "unreachable", f"could not connect to {where} ({text})"
    return "unreachable", f"could not connect to {where}"


def api_transport_error(exc: BaseException) -> str:
    """What stopped a call to the ZeroShield API (#198): an untrusted certificate with the ZS_CA_FILE hint, a TLS
    failure, or the socket cause."""
    verify = tls_verify_problem(exc)
    if verify:
        return f"the ZeroShield API certificate is not trusted ({verify}). {CA_HINT}"
    if any("407" in str(e) for e in chain(exc)):  # #199: the proxy wants a login
        return ("the proxy asked for a login (HTTP 407): put user:password in a file and set ZS_PROXY_AUTH_FILE to "
                "it (the Add scan node wizard's Proxy user)")
    for e in chain(exc):
        if isinstance(e, ssl.SSLError):
            reason = getattr(e, "reason", None) or str(e)
            return f"TLS to the ZeroShield API failed ({str(reason)[:120]})"
    return socket_problem(exc, "the ZeroShield API", None)[1]


__all__ = ["CA_HINT", "chain", "tls_verify_problem", "os_error", "socket_problem", "api_transport_error"]
