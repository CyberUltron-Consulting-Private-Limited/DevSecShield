"""Bitbucket Cloud: a workspace access token and the workspace slug.

Discovery: ``GET /2.0/repositories/{workspace}`` with ``pagelen=100``, following the ``next`` URL of each page.
The token needs repository read; it is also the clone credential (``x-token-auth:<token>``). Bitbucket answers a
rate limit with 429 (and ``Retry-After``), which the client waits out. Bitbucket has no "archived" flag.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

from backend.utilities.scm.providers.base import DiscoveredRepo, HttpClient, ScmError, parse_time


def normalise(item: dict[str, Any]) -> DiscoveredRepo:
    links = item.get("links") or {}
    web = str(((links.get("html") or {}) if isinstance(links, dict) else {}).get("href") or "")
    full = str(item.get("full_name") or "")
    return DiscoveredRepo(
        external_id=str(item.get("uuid") or full), full_name=full, name=str(item.get("slug") or full.rsplit("/", 1)[-1]),
        owner=str((item.get("workspace") or {}).get("slug") or full.split("/")[0]), web_url=web, clone_url=web,
        default_branch=str((item.get("mainbranch") or {}).get("name") or "main"),
        visibility="private" if item.get("is_private", True) else "public", archived=False,
        fork=bool(item.get("parent")), language=item.get("language") or None, topics=[],
        size_kb=int(item.get("size") or 0) // 1024, pushed_at=parse_time(item.get("updated_on")),
    )


class BitbucketProvider:
    def __init__(self, api_base: str, auth_kind: str, scope_kind: str, scope_name: str, config: dict[str, Any],
                 secrets: dict[str, str], **client_kw: Any):
        if auth_kind != "token":
            raise ScmError("Bitbucket connections use an access token", "auth")
        self.workspace = scope_name.strip()
        self.token = secrets.get("token", "")
        self.http = HttpClient(api_base.rstrip("/") + "/2.0", {"Authorization": f"Bearer {self.token}"},
                               flavour="bitbucket", **client_kw)

    @property
    def stats(self) -> dict[str, Any]:
        return self.http.stats

    def close(self) -> None:
        self.http.close()

    def clone_token(self) -> str:
        return self.token

    def iter_repos(self) -> Iterator[DiscoveredRepo]:
        if not self.workspace:
            raise ScmError("The workspace is required", "not_found")
        url: str | None = f"/repositories/{quote(self.workspace, safe='')}"
        params: dict[str, Any] | None = {"pagelen": 100}
        while url:
            body, _h = self.http.get_json(url, params)
            params = None
            self.http.stats["pages"] += 1
            values = body.get("values") if isinstance(body, dict) else None
            if not isinstance(values, list):
                raise ScmError("The provider's answer had an unexpected shape", "bad_response")
            for item in values:
                if isinstance(item, dict):
                    yield normalise(item)
            nxt = body.get("next")
            url = str(nxt) if isinstance(nxt, str) and nxt else None

    def get_repo(self, full_name: str) -> DiscoveredRepo | None:
        workspace, _, slug = full_name.partition("/")
        try:
            body, _h = self.http.get_json(f"/repositories/{quote(workspace, safe='')}/{quote(slug, safe='')}")
        except ScmError as err:
            if err.kind == "not_found":
                return None
            raise
        return normalise(body) if isinstance(body, dict) else None

    def test(self) -> str:
        body, _h = self.http.get_json(f"/workspaces/{quote(self.workspace, safe='')}")
        return f"Token can read the Bitbucket workspace {body.get('slug', self.workspace)}"


__all__ = ["BitbucketProvider", "normalise"]
