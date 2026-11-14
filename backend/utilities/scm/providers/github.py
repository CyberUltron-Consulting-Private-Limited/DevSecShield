"""GitHub (github.com and GitHub Enterprise Server): a GitHub App installation, or a token for an organisation / user.

* App: the connection stores the App id, the installation id and the App's private key (PEM). The client signs a
  short JWT (RS256, ``iat`` 60 s in the past, 9 minutes of validity, ``iss`` = App id), exchanges it for an
  installation token (1 hour, ``ghs_``) and caches that token per connection until 5 minutes before it expires. The
  token lists the installation's repositories (``GET /installation/repositories``) and is the clone credential.
* Token: a fine-grained or classic token that can read the organisation's repositories; ``GET /orgs/{org}/repos``
  (scope org) or ``GET /user/repos`` (scope user: the repositories the token's user can see).

100 repositories per page (5,000 repositories = 50 calls). GitHub's repository ``size`` is in KB and includes history.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import threading
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from backend.utilities.scm.providers.base import DiscoveredRepo, HttpClient, ScmError, parse_time

API_VERSION = "2022-11-28"
_TOKEN_CACHE: dict[tuple[str, str, str, str], tuple[str, float]] = {}
_CACHE_LOCK = threading.Lock()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: str, private_key_pem: str, now: float | None = None) -> str:
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except (ValueError, TypeError):
        raise ScmError("The GitHub App private key is not a PEM private key", "auth") from None
    issued = int(now if now is not None else time.time()) - 60
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps({"iat": issued, "exp": issued + 600, "iss": str(app_id)}, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    try:
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr,call-arg]
    except (TypeError, AttributeError):
        raise ScmError("The GitHub App private key must be an RSA key", "auth") from None
    return f"{header}.{payload}.{_b64(signature)}"


def normalise(item: dict[str, Any]) -> DiscoveredRepo:
    owner = (item.get("owner") or {}).get("login") or str(item.get("full_name", "")).split("/")[0]
    visibility = item.get("visibility") or ("private" if item.get("private") else "public")
    return DiscoveredRepo(
        external_id=str(item.get("id")), full_name=str(item.get("full_name") or ""), name=str(item.get("name") or ""),
        owner=str(owner or ""), web_url=str(item.get("html_url") or ""), clone_url=str(item.get("html_url") or ""),
        default_branch=str(item.get("default_branch") or "main"), visibility=str(visibility),
        archived=bool(item.get("archived")), fork=bool(item.get("fork")),
        language=item.get("language") or None, topics=[str(t) for t in (item.get("topics") or [])][:50],
        size_kb=int(item.get("size") or 0), pushed_at=parse_time(item.get("pushed_at")),
    )


class GitHubProvider:
    def __init__(self, api_base: str, auth_kind: str, scope_kind: str, scope_name: str, config: dict[str, Any],
                 secrets: dict[str, str], **client_kw: Any):
        self.api_base = api_base
        self.auth_kind = auth_kind
        self.scope_kind = scope_kind
        self.scope_name = scope_name
        self.config = config
        self.secrets = secrets
        self.http = HttpClient(api_base, {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION},
                               flavour="github", **client_kw)
        if auth_kind == "token":
            self.http.headers["Authorization"] = f"token {secrets.get('token', '')}"

    @property
    def stats(self) -> dict[str, Any]:
        return self.http.stats

    def close(self) -> None:
        self.http.close()

    # ---------------------------------------------------------------- App installation token
    def _installation_token(self) -> str:
        app_id = str(self.config.get("app_id") or "")
        installation = str(self.config.get("installation_id") or "")
        if not app_id or not installation:
            raise ScmError("A GitHub App connection needs the App id and the installation id", "auth")
        # keyed on the key too: a connection whose key was replaced never reuses a token the old key minted
        key_digest = hashlib.sha256(self.secrets.get("private_key", "").encode()).hexdigest()
        cache_key = (self.api_base, app_id, installation, key_digest)
        with _CACHE_LOCK:
            cached = _TOKEN_CACHE.get(cache_key)
            if cached and cached[1] - time.time() > 300:
                return cached[0]
        jwt = app_jwt(app_id, self.secrets.get("private_key", ""))
        response = self.http.request("POST", f"/app/installations/{quote(installation, safe='')}/access_tokens",
                                     headers={"Authorization": f"Bearer {jwt}"})
        try:
            body = response.json()
            token = str(body["token"])
            expires = parse_time(body.get("expires_at"))
        except (ValueError, KeyError, TypeError):
            raise ScmError("GitHub did not return an installation token", "bad_response") from None
        expires_epoch = (expires.replace(tzinfo=dt.timezone.utc).timestamp() if expires else time.time() + 3000)
        with _CACHE_LOCK:
            _TOKEN_CACHE[cache_key] = (token, expires_epoch)
        return token

    def _authorise(self) -> None:
        if self.auth_kind == "github_app":
            self.http.headers["Authorization"] = f"token {self._installation_token()}"

    def clone_token(self) -> str:
        if self.auth_kind == "github_app":
            return self._installation_token()
        return self.secrets.get("token", "")

    # ---------------------------------------------------------------- discovery
    def _list_path(self) -> tuple[str, dict[str, Any], str | None]:
        if self.auth_kind == "github_app":
            return "/installation/repositories", {"per_page": 100}, "repositories"
        if self.scope_kind == "user":
            return "/user/repos", {"per_page": 100, "affiliation": "owner,collaborator,organization_member"}, None
        org = quote(self.scope_name.strip(), safe="")
        if not org:
            raise ScmError("The organisation name is required", "not_found")
        return f"/orgs/{org}/repos", {"per_page": 100, "type": "all"}, None

    def iter_repos(self) -> Iterator[DiscoveredRepo]:
        self._authorise()
        path, params, key = self._list_path()
        for item in self.http.paginate_link(path, params, items_key=key):
            if isinstance(item, dict) and item.get("id") is not None:
                yield normalise(item)

    def get_repo(self, full_name: str) -> DiscoveredRepo | None:
        self._authorise()
        owner, _, name = full_name.partition("/")
        try:
            body, _h = self.http.get_json(f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}")
        except ScmError as err:
            if err.kind == "not_found":
                return None
            raise
        return normalise(body) if isinstance(body, dict) else None

    def test(self) -> str:
        self._authorise()
        if self.auth_kind == "github_app":
            body, _h = self.http.get_json("/installation/repositories", {"per_page": 1})
            return f"GitHub App installation can read {int(body.get('total_count') or 0)} repositories"
        if self.scope_kind == "user":
            body, _h = self.http.get_json("/user")
            return f"Token works for GitHub user {body.get('login', '')}"
        body, _h = self.http.get_json(f"/orgs/{quote(self.scope_name.strip(), safe='')}")
        return f"Token can read the GitHub organisation {body.get('login', self.scope_name)}"


__all__ = ["GitHubProvider", "app_jwt", "normalise"]
