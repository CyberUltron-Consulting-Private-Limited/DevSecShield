"""Which Git servers a repository scan may clone from, and the clone URL handed to git.

Kept byte-identical in two places (the backend and the scan worker are separate images):
    backend/utilities/git_hosts.py                    validates the URL when a scan is started
    RabbitMQ/worker/helpers/context/git_hosts.py      validates again and builds the clone URL
A test fails if they differ.

Public providers: github.com, gitlab.com, bitbucket.org and their sub-domains, over https on port 443.

Self-hosted servers (air-gapped installs): environment variable GIT_ALLOWED_HOSTS, a comma-separated list of
    git.corp.example          https, default port 443
    git.corp.example:8443     https on that port
    http://git.lab:3000       plain HTTP allowed for that host (and https); the token then travels unencrypted
Host names match exactly (no sub-domains), case-insensitively. Set the same value on the backend and the workers.
"""
from __future__ import annotations

import functools
import logging
import os
import re
from dataclasses import dataclass
from urllib.parse import quote, urlsplit

logger = logging.getLogger(__name__)

ENV = "GIT_ALLOWED_HOSTS"
_DEFAULT_PORTS = {"https": 443, "http": 80}


@dataclass(frozen=True)
class AllowedHost:
    host: str
    port: int | None  # None: the default port of the URL's scheme
    allow_http: bool


@dataclass(frozen=True)
class RepoUrl:
    scheme: str
    host: str
    port: int | None
    path: str

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}" if self.port is not None else host


@functools.lru_cache(maxsize=8)
def parse_allowed_hosts(text: str | None) -> tuple[AllowedHost, ...]:
    """Entries of GIT_ALLOWED_HOSTS. An entry that is not a host[:port] (optionally with http:// or https://) is
    ignored with a warning, so one typo cannot open anything else."""
    out: list[AllowedHost] = []
    for raw in (text or "").split(","):
        entry = raw.strip()
        if not entry:
            continue
        scheme, _, rest = entry.rpartition("://") if "://" in entry else ("https", "", entry)
        scheme = scheme.lower()
        try:
            parts = urlsplit(f"{scheme}://{rest}")
            port = parts.port
            ok = (scheme in _DEFAULT_PORTS and parts.hostname and not parts.username and not parts.password
                  and parts.path in ("", "/") and not parts.query and not parts.fragment)
        except ValueError:
            ok = False
        if not ok:
            logger.warning("git_allowed_hosts entry_ignored entry=%r (expected host, host:port or http://host[:port])",
                           entry[:200])
            continue
        out.append(AllowedHost(parts.hostname.lower(), port, scheme == "http"))
    return tuple(out)


def _public(host: str, provider_host: str) -> bool:
    return host == provider_host or host.endswith("." + provider_host)


def check_repo_url(repo_url: str, provider_host: str, provider_label: str) -> RepoUrl:
    """The parsed URL if a scan may clone it as provider ``provider_label``; ValueError (safe to show) otherwise."""
    if not repo_url or not repo_url.strip():
        raise ValueError(f"{provider_label} repo_url is required")
    try:
        parts = urlsplit(repo_url.strip())
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"{provider_label} repo_url is not a valid URL") from exc
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        raise ValueError(f"{provider_label} repo_url must start with https://")
    path = parts.path or ""
    if path.strip("/") == "":
        raise ValueError(f"{provider_label} repo_url must name a repository, e.g. https://{provider_host}/owner/repo")
    effective_port = port if port is not None else _DEFAULT_PORTS[scheme]
    if _public(host, provider_host):
        if scheme != "https":
            raise ValueError(f"{provider_label} repo_url must start with https://")
        if effective_port != 443:
            raise ValueError(f"{provider_label} repo_url must use the standard https port")
        return RepoUrl(scheme, host, None, path)
    for allowed in parse_allowed_hosts(os.environ.get(ENV)):
        if allowed.host != host:
            continue
        if (allowed.port if allowed.port is not None else _DEFAULT_PORTS[scheme]) != effective_port:
            continue
        if scheme == "http" and not allowed.allow_http:
            raise ValueError(f"{provider_label} repo_url must start with https:// (plain HTTP to {host} is allowed only "
                             f"when {ENV} lists it as http://{host})")
        return RepoUrl(scheme, host, port, path)
    raise ValueError(f"{provider_label} repo_url host must be '{provider_host}' (or a subdomain of it) or a "
                     f"self-hosted server listed in {ENV}, got '{parts.netloc.rpartition('@')[2] or host}'")


def clone_url(repo_url: str, provider_host: str, provider_label: str, *, user: str | None = None,
              secret: str | None = None) -> str:
    """The URL git clones: rebuilt from the checked scheme, host, port and path (never by searching the text for a
    provider name), with any user info in the input dropped and the credentials percent-encoded."""
    repo = check_repo_url(repo_url, provider_host, provider_label)
    cred = ""
    if user:
        cred = quote(user, safe="") + (":" + quote(secret, safe="") if secret else "") + "@"
    return f"{repo.scheme}://{cred}{repo.netloc}{repo.path}"


def redact(text: str) -> str:
    """``text`` with the user info of every URL in it replaced, for logs and error messages."""
    return re.sub(r"(?i)\b(https?://)[^/@\s'\"]+@", r"\1***@", text)
