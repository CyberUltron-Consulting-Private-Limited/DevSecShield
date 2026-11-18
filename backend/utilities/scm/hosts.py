"""Which SCM API base URLs a connection may call.

The SaaS APIs are fixed (api.github.com, gitlab.com, api.bitbucket.org). A self-hosted server (GitHub Enterprise
Server, GitLab self-managed, Bitbucket Data Center) is allowed only when its host is listed in ``GIT_ALLOWED_HOSTS``,
the operator allow-list that already decides which Git servers a scan may clone from (``backend/utilities/
git_hosts.py``): a team admin cannot point the backend at an arbitrary host, and the API host is the clone host.
Plain HTTP only for a host listed as ``http://host[:port]``. No user info, query or fragment; the path is kept (GHES
serves its API under ``/api/v3``). The HTTP client never follows redirects and follows pagination links only on the
same scheme, host and port (``providers/base.py``).
"""
from __future__ import annotations

import os
from urllib.parse import urlsplit

from backend.utilities.git_hosts import ENV, parse_allowed_hosts

DEFAULT_API = {"github": "https://api.github.com", "gitlab": "https://gitlab.com", "bitbucket": "https://api.bitbucket.org"}
_PORTS = {"https": 443, "http": 80}


def check_api_base(provider: str, url: str | None) -> str:
    """The normalised API base URL, or ValueError with a sentence that is safe to show."""
    if provider not in DEFAULT_API:
        raise ValueError("provider must be github, gitlab or bitbucket")
    text = (url or "").strip().rstrip("/")
    if not text or text == DEFAULT_API[provider]:
        return DEFAULT_API[provider]
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise ValueError("API URL is not a valid URL") from None
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if scheme not in _PORTS or not host:
        raise ValueError("API URL must start with https://")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("API URL must not contain a user name, password, query or fragment")
    effective = port if port is not None else _PORTS[scheme]
    for allowed in parse_allowed_hosts(os.environ.get(ENV)):
        if allowed.host != host:
            continue
        if (allowed.port if allowed.port is not None else _PORTS[scheme]) != effective:
            continue
        if scheme == "http" and not allowed.allow_http:
            raise ValueError(f"API URL must start with https:// (plain HTTP only for hosts listed in {ENV} as "
                             "http://host)")
        netloc = host if port is None else f"{host}:{port}"
        return f"{scheme}://{netloc}{parts.path.rstrip('/')}"
    raise ValueError(f"API URL host '{host}' is not allowed: a self-hosted server must be listed in {ENV} by the "
                     "operator (the same list that allows cloning from it)")


def same_origin(base: str, url: str) -> bool:
    """True when ``url`` has the scheme, host and port of ``base`` (pagination links are only followed then)."""
    try:
        a, b = urlsplit(base), urlsplit(url)
        return (a.scheme.lower(), (a.hostname or "").lower(), a.port or _PORTS.get(a.scheme.lower())) == \
               (b.scheme.lower(), (b.hostname or "").lower(), b.port or _PORTS.get(b.scheme.lower())) and \
            not b.username and not b.password
    except ValueError:
        return False


__all__ = ["DEFAULT_API", "check_api_base", "same_origin"]
