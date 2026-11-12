"""HTTPS clients for a customer's control plane (AWX/AAP, salt-api), through the scan node's network gate.

The control plane is a customer host too: its name is resolved once and checked against the never-scan list
(``netutil.resolve_checked``), and the client is pinned to the checked address (``netutil.http_client``), with the
URL's name kept for the Host header, SNI and the certificate check.  Only ``https`` URLs are accepted; ``verify_tls``
false is allowed only together with nothing else to check (a lab), and ``ca_pem`` pins a private CA.
"""
from __future__ import annotations

import ssl
from typing import Any, Mapping
from urllib.parse import urlsplit

from zs_scan_node import netutil
from zs_scan_node.netutil import NeverScan
from zs_scan_node.transports.base import TransportError


def tls_context(config: Mapping[str, Any]) -> ssl.SSLContext | bool:
    ca = config.get("ca_pem")
    if ca:
        return ssl.create_default_context(cadata=str(ca))
    if config.get("verify_tls") is False:
        return False
    return ssl.create_default_context()


def client(config: Mapping[str, Any], never: NeverScan, headers: Mapping[str, str] | None = None,
           timeout: float = 30.0, what: str = "control plane"):
    """An httpx client for ``config["base_url"]`` pinned to its checked address.  Raises TransportError."""
    base = str(config.get("base_url") or "").rstrip("/")
    parts = urlsplit(base)
    if parts.scheme != "https" or not parts.hostname:
        raise TransportError("error", f"the {what} URL must be https://")
    try:
        ip = netutil.resolve_checked(parts.hostname, never)[0]
    except netutil.Blocked as exc:
        raise TransportError("skipped_never_scan", f"the {what} ({exc.what}) is on the never-scan list") from None
    except OSError as exc:
        raise TransportError("unreachable", f"the {what} name {parts.hostname} does not resolve "
                                            f"({exc.__class__.__name__})") from None
    return netutil.http_client(base, ip, never, verify=tls_context(config), headers=dict(headers or {}),
                               timeout=timeout)


def request(http, method: str, path: str, what: str, **kwargs):
    """One request; transport-level failures become TransportError with a target status."""
    import httpx

    try:
        return http.request(method, path, **kwargs)
    except httpx.ConnectTimeout:
        raise TransportError("timeout", f"the {what} did not answer in time") from None
    except httpx.ConnectError as exc:
        text = str(exc).lower()
        if "certificate" in text or "ssl" in text or "tls" in text:
            raise TransportError("identity_unverified", f"the {what}'s TLS certificate was not accepted") from None
        raise TransportError("unreachable", f"cannot connect to the {what}") from None
    except httpx.TimeoutException:
        raise TransportError("timeout", f"the {what} did not answer in time") from None
    except httpx.HTTPError as exc:
        raise TransportError("error", f"{what}: {exc.__class__.__name__}") from None


def raise_for_auth(resp, what: str) -> None:
    if resp.status_code == 401:
        raise TransportError("auth_failed", f"the {what} refused the login (401)")
    if resp.status_code == 403:
        raise TransportError("refused", f"the {what} refused the request (403): check the account's permissions")
