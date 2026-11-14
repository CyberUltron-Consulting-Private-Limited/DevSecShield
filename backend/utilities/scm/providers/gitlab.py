"""GitLab (gitlab.com and self-managed): a group access token (or a personal / project token) and a group path.

Discovery: ``GET /api/v4/groups/{path}/projects`` with ``include_subgroups``, keyset pagination ordered by id (the
recommended pagination for large groups; offset pagination is capped by GitLab), 100 per page, ``statistics=true`` for
the repository size. The token needs ``read_api`` and ``read_repository``; it is also the clone credential
(``oauth2:<token>``). GitLab's list API does not return a language, so language filters do not match GitLab projects.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

from backend.utilities.scm.providers.base import DiscoveredRepo, HttpClient, ScmError, parse_time


def normalise(item: dict[str, Any]) -> DiscoveredRepo:
    full = str(item.get("path_with_namespace") or "")
    stats = item.get("statistics") or {}
    size_bytes = int(stats.get("repository_size") or 0) if isinstance(stats, dict) else 0
    return DiscoveredRepo(
        external_id=str(item.get("id")), full_name=full, name=str(item.get("path") or full.rsplit("/", 1)[-1]),
        owner=str((item.get("namespace") or {}).get("full_path") or full.rsplit("/", 1)[0]),
        web_url=str(item.get("web_url") or ""), clone_url=str(item.get("web_url") or ""),
        default_branch=str(item.get("default_branch") or "main"), visibility=str(item.get("visibility") or "private"),
        archived=bool(item.get("archived")), fork=bool(item.get("forked_from_project")), language=None,
        topics=[str(t) for t in (item.get("topics") or item.get("tag_list") or [])][:50],
        size_kb=size_bytes // 1024, pushed_at=parse_time(item.get("last_activity_at")),
    )


class GitLabProvider:
    def __init__(self, api_base: str, auth_kind: str, scope_kind: str, scope_name: str, config: dict[str, Any],
                 secrets: dict[str, str], **client_kw: Any):
        if auth_kind != "token":
            raise ScmError("GitLab connections use an access token", "auth")
        self.group = scope_name.strip().strip("/")
        self.config = config
        self.token = secrets.get("token", "")
        self.http = HttpClient(api_base.rstrip("/") + "/api/v4", {"PRIVATE-TOKEN": self.token}, flavour="gitlab",
                               **client_kw)

    @property
    def stats(self) -> dict[str, Any]:
        return self.http.stats

    def close(self) -> None:
        self.http.close()

    def clone_token(self) -> str:
        return self.token

    def iter_repos(self) -> Iterator[DiscoveredRepo]:
        if not self.group:
            raise ScmError("The group path is required", "not_found")
        params = {"include_subgroups": "true" if self.config.get("include_subgroups", True) else "false",
                  "per_page": 100, "pagination": "keyset", "order_by": "id", "sort": "asc", "statistics": "true"}
        for item in self.http.paginate_link(f"/groups/{quote(self.group, safe='')}/projects", params):
            if isinstance(item, dict) and item.get("id") is not None:
                yield normalise(item)

    def get_repo(self, full_name: str) -> DiscoveredRepo | None:
        try:
            body, _h = self.http.get_json(f"/projects/{quote(full_name, safe='')}", {"statistics": "true"})
        except ScmError as err:
            if err.kind == "not_found":
                return None
            raise
        return normalise(body) if isinstance(body, dict) else None

    def test(self) -> str:
        body, _h = self.http.get_json(f"/groups/{quote(self.group, safe='')}")
        return f"Token can read the GitLab group {body.get('full_path', self.group)}"


__all__ = ["GitLabProvider", "normalise"]
