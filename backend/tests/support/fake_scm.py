"""A fake GitHub / GitLab / Bitbucket REST API on a real local HTTP server, for the F3 tests and bench/scm.

It answers the endpoints ``backend/utilities/scm/providers`` call, with the providers' own JSON shapes, pagination
(GitHub ``Link``, GitLab keyset ``Link``, Bitbucket ``next``) and their rate-limit behaviour:

* a primary budget per window: ``X-RateLimit-Limit / -Remaining / -Reset`` (GitHub), ``RateLimit-*`` (GitLab); an
  exhausted budget answers 403 (GitHub) or 429 (GitLab, Bitbucket) until the window resets;
* secondary limits: every ``secondary_every``-th request answers 403 (GitHub) / 429 with ``Retry-After``;
* faults: the request numbers in ``fail_requests`` answer 502;
* ``latency_s`` per request, so a bench is not measuring a free server.

Auth is checked: GitHub App JWTs are verified with the App's public key (RS256, ``iss`` = app id) before an
installation token is issued; every other call needs a token the server issued or was given. Nothing here talks to
the internet.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

LANGS = ["Python", "Java", "JavaScript", "Go", "TypeScript", "Ruby", "C#", "HCL", None]


def make_repos(owner: str, n: int, *, start_id: int = 1000, seed: int = 7) -> list[dict[str, Any]]:
    """``n`` GitHub-shaped repositories: a deterministic mix of languages, topics, archived repos and forks."""
    out = []
    for i in range(n):
        rid = start_id + i
        name = f"svc-{i:05d}" if i % 10 else f"legacy-{i:05d}"
        topics = ["pci"] if i % 7 == 0 else (["internal-tools"] if i % 11 == 0 else [])
        if i % 13 == 0:
            topics = topics + ["deprecated"]
        out.append({
            "id": rid, "node_id": f"R_{rid}", "name": name, "full_name": f"{owner}/{name}",
            "owner": {"login": owner, "type": "Organization"},
            "html_url": f"https://github.com/{owner}/{name}", "clone_url": f"https://github.com/{owner}/{name}.git",
            "default_branch": "main" if i % 5 else "master", "private": i % 3 != 0,
            "visibility": "private" if i % 3 else "public", "archived": i % 17 == 0, "fork": i % 19 == 0,
            "language": LANGS[(i + seed) % len(LANGS)], "topics": topics, "size": 200 + (i * 37) % 9000,
            "pushed_at": "2026-11-0%dT10:00:00Z" % (1 + i % 9),
        })
    return out


def rsa_keypair() -> tuple[str, Any]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return pem, key.public_key()


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


@dataclass
class FakeScmState:
    github_orgs: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    github_user_repos: list[dict[str, Any]] = field(default_factory=list)
    github_installations: dict[int, dict[str, Any]] = field(default_factory=dict)  # id -> {"app_id", "repos"}
    github_app_keys: dict[str, Any] = field(default_factory=dict)  # app_id -> public key
    gitlab_groups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    bitbucket_workspaces: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    tokens: set[str] = field(default_factory=set)
    installation_tokens: dict[str, int] = field(default_factory=dict)
    rate_limit: int = 5000
    rate_window_s: float = 3600.0
    secondary_every: int = 0
    fail_requests: set[int] = field(default_factory=set)
    latency_s: float = 0.0
    # observed
    requests: list[tuple[float, str, str]] = field(default_factory=list)
    responses: dict[int, int] = field(default_factory=dict)
    window_start: float = field(default_factory=time.time)
    used: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_tokens(self, *tokens: str) -> None:
        self.tokens.update(tokens)


class _Handler(BaseHTTPRequestHandler):
    server_version = "fake-scm/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a: Any) -> None:  # quiet
        return

    @property
    def state(self) -> FakeScmState:
        return self.server.state  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ plumbing
    def _send(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)
        with self.state.lock:
            self.state.responses[status] = self.state.responses.get(status, 0) + 1

    def _base(self) -> str:
        host = self.headers.get("Host") or f"127.0.0.1:{self.server.server_address[1]}"
        return f"http://{host}"

    def _token(self) -> str:
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith(("bearer ", "token ")):
            return auth.split(" ", 1)[1].strip()
        return (self.headers.get("PRIVATE-TOKEN") or "").strip()

    def _limits(self, flavour: str) -> tuple[bool, dict[str, str], int]:
        """(allowed, headers, request number)."""
        st = self.state
        with st.lock:
            now = time.time()
            if now - st.window_start >= st.rate_window_s:
                st.window_start, st.used = now, 0
            st.requests.append((now, self.command, self.path))
            number = len(st.requests)
            reset = int(st.window_start + st.rate_window_s + 0.999)
            allowed = st.used < st.rate_limit
            if allowed:
                st.used += 1
            remaining = max(0, st.rate_limit - st.used)
        if flavour == "gitlab":
            headers = {"RateLimit-Limit": str(st.rate_limit), "RateLimit-Remaining": str(remaining),
                       "RateLimit-Reset": str(reset)}
        elif flavour == "github":
            headers = {"X-RateLimit-Limit": str(st.rate_limit), "X-RateLimit-Remaining": str(remaining),
                       "X-RateLimit-Reset": str(reset), "X-RateLimit-Used": str(st.rate_limit - remaining)}
        else:
            headers = {}
        return allowed, headers, number

    def _guard(self, flavour: str) -> dict[str, str] | None:
        """Latency, faults, rate limits and auth. Returns headers to add, or None when it already answered."""
        st = self.state
        if st.latency_s:
            time.sleep(st.latency_s)
        allowed, headers, number = self._limits(flavour)
        if number in st.fail_requests:
            self._send(502, {"message": "Bad gateway"}, headers)
            return None
        if not allowed:
            wait = max(1, int(float(headers.get("X-RateLimit-Reset") or headers.get("RateLimit-Reset")
                                    or time.time() + 1) - time.time()))
            status = 403 if flavour == "github" else 429
            self._send(status, {"message": "API rate limit exceeded"},
                       {**headers, "Retry-After": str(wait)} if flavour != "github" else headers)
            return None
        if st.secondary_every and number % st.secondary_every == 0:
            status = 403 if flavour == "github" else 429
            self._send(status, {"message": "You have exceeded a secondary rate limit"}, {**headers, "Retry-After": "1"})
            return None
        return headers

    # ------------------------------------------------------------------ routing
    def do_POST(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        segs = [s for s in parts.path.split("/") if s]
        if len(segs) == 4 and segs[0] == "app" and segs[1] == "installations" and segs[3] == "access_tokens":
            headers = self._guard("github")
            if headers is None:
                return
            inst = self.state.github_installations.get(int(segs[2]))
            if not inst or not self._verify_app_jwt(self._token(), str(inst["app_id"])):
                return self._send(401, {"message": "A JSON web token could not be decoded"}, headers)
            token = f"ghs_fake{int(segs[2])}x{len(self.state.requests)}"
            self.state.add_tokens(token)
            self.state.installation_tokens[token] = int(segs[2])
            expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            return self._send(201, {"token": token, "expires_at": expires}, headers)
        self._send(404, {"message": "Not Found"})

    def _verify_app_jwt(self, token: str, app_id: str) -> bool:
        key = self.state.github_app_keys.get(app_id)
        try:
            head, payload, sig = token.split(".")
            key.verify(_b64d(sig), f"{head}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
            claims = json.loads(_b64d(payload))
            now = time.time()
            return str(claims.get("iss")) == app_id and claims["iat"] <= now + 5 and claims["exp"] > now \
                and claims["exp"] - claims["iat"] <= 660 and json.loads(_b64d(head)).get("alg") == "RS256"
        except Exception:
            return False

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        query = {k: v[-1] for k, v in parse_qs(parts.query).items()}
        segs = [s for s in parts.path.split("/") if s]
        if segs[:2] == ["api", "v4"]:
            return self._gitlab(segs[2:], query, parts.path)
        if segs[:1] == ["2.0"]:
            return self._bitbucket(segs[1:], query)
        return self._github(segs, query, parts.path)

    # ------------------------------------------------------------------ GitHub
    def _page(self, items: list, query: dict[str, str], path: str) -> tuple[list, dict[str, str]]:
        per = max(1, min(100, int(query.get("per_page") or 30)))
        page = max(1, int(query.get("page") or 1))
        chunk = items[(page - 1) * per: page * per]
        links = []
        last = max(1, -(-len(items) // per))
        if page < last:
            links.append(f'<{self._base()}{path}?per_page={per}&page={page + 1}>; rel="next"')
            links.append(f'<{self._base()}{path}?per_page={per}&page={last}>; rel="last"')
        return chunk, ({"Link": ", ".join(links)} if links else {})

    def _github(self, segs: list[str], query: dict[str, str], path: str) -> None:
        headers = self._guard("github")
        if headers is None:
            return
        if self._token() not in self.state.tokens:
            return self._send(401, {"message": "Bad credentials"}, headers)
        st = self.state
        if segs == ["installation", "repositories"]:
            inst_id = st.installation_tokens.get(self._token())
            if inst_id is None:  # a PAT cannot list an installation's repositories
                return self._send(403, {"message": "Resource not accessible by personal access token"}, headers)
            repos = st.github_installations[inst_id]["repos"]
            chunk, link = self._page(repos, query, path)
            return self._send(200, {"total_count": len(repos), "repositories": chunk}, {**headers, **link})
        if len(segs) == 3 and segs[0] == "orgs" and segs[2] == "repos":
            if segs[1] not in st.github_orgs:
                return self._send(404, {"message": "Not Found"}, headers)
            chunk, link = self._page(st.github_orgs[segs[1]], query, path)
            return self._send(200, chunk, {**headers, **link})
        if len(segs) == 2 and segs[0] == "orgs":
            if segs[1] not in st.github_orgs:
                return self._send(404, {"message": "Not Found"}, headers)
            return self._send(200, {"login": segs[1], "public_repos": len(st.github_orgs[segs[1]])}, headers)
        if segs == ["user", "repos"]:
            chunk, link = self._page(st.github_user_repos, query, path)
            return self._send(200, chunk, {**headers, **link})
        if segs == ["user"]:
            return self._send(200, {"login": "fake-user"}, headers)
        if len(segs) == 3 and segs[0] == "repos":
            full = f"{segs[1]}/{segs[2]}"
            for repos in [*st.github_orgs.values(), st.github_user_repos,
                          *[i["repos"] for i in st.github_installations.values()]]:
                for repo in repos:
                    if repo["full_name"].lower() == full.lower():
                        return self._send(200, repo, headers)
            return self._send(404, {"message": "Not Found"}, headers)
        return self._send(404, {"message": "Not Found"}, headers)

    # ------------------------------------------------------------------ GitLab
    def _gitlab(self, segs: list[str], query: dict[str, str], path: str) -> None:
        headers = self._guard("gitlab")
        if headers is None:
            return
        if self._token() not in self.state.tokens:
            return self._send(401, {"message": "401 Unauthorized"}, headers)
        groups = self.state.gitlab_groups
        if len(segs) >= 2 and segs[0] == "groups":
            group = segs[1].replace("%2F", "/").replace("%2f", "/")
            if group not in groups:
                return self._send(404, {"message": "404 Group Not Found"}, headers)
            if len(segs) == 2:
                return self._send(200, {"id": 77, "full_path": group}, headers)
            if segs[2] == "projects":
                per = max(1, min(100, int(query.get("per_page") or 20)))
                after = int(query.get("id_after") or 0)
                items = [p for p in groups[group] if p["id"] > after][:per]
                link = {}
                if len(items) == per and any(p["id"] > items[-1]["id"] for p in groups[group]):
                    nxt = (f"{self._base()}{path}?include_subgroups=true&per_page={per}&pagination=keyset"
                           f"&order_by=id&sort=asc&id_after={items[-1]['id']}&statistics=true")
                    link = {"Link": f'<{nxt}>; rel="next"'}
                return self._send(200, items, {**headers, **link})
        if len(segs) == 2 and segs[0] == "projects":
            for projects in groups.values():
                for p in projects:
                    if str(p["id"]) == segs[1] or p["path_with_namespace"] == segs[1].replace("%2F", "/"):
                        return self._send(200, p, headers)
            return self._send(404, {"message": "404 Project Not Found"}, headers)
        return self._send(404, {"message": "404 Not Found"}, headers)

    # ------------------------------------------------------------------ Bitbucket
    def _bitbucket(self, segs: list[str], query: dict[str, str]) -> None:
        headers = self._guard("bitbucket")
        if headers is None:
            return
        if self._token() not in self.state.tokens:
            return self._send(401, {"type": "error", "error": {"message": "Unauthorized"}}, headers)
        spaces = self.state.bitbucket_workspaces
        if len(segs) == 2 and segs[0] == "workspaces":
            if segs[1] not in spaces:
                return self._send(404, {"type": "error"}, headers)
            return self._send(200, {"slug": segs[1]}, headers)
        if len(segs) == 2 and segs[0] == "repositories":
            if segs[1] not in spaces:
                return self._send(404, {"type": "error"}, headers)
            per = max(1, min(100, int(query.get("pagelen") or 10)))
            page = max(1, int(query.get("page") or 1))
            items = spaces[segs[1]]
            chunk = items[(page - 1) * per: page * per]
            body: dict[str, Any] = {"pagelen": per, "page": page, "size": len(items), "values": chunk}
            if page * per < len(items):
                body["next"] = f"{self._base()}/2.0/repositories/{segs[1]}?pagelen={per}&page={page + 1}"
            return self._send(200, body, headers)
        if len(segs) == 3 and segs[0] == "repositories":
            for repo in spaces.get(segs[1], []):
                if repo["slug"] == segs[2]:
                    return self._send(200, repo, headers)
            return self._send(404, {"type": "error"}, headers)
        return self._send(404, {"type": "error"}, headers)


def gitlab_projects(group: str, n: int, *, start_id: int = 5000) -> list[dict[str, Any]]:
    out = []
    for i in range(n):
        path = f"proj-{i:04d}"
        out.append({
            "id": start_id + i, "path": path, "name": path, "path_with_namespace": f"{group}/{path}",
            "namespace": {"full_path": group}, "web_url": f"https://gitlab.com/{group}/{path}",
            "http_url_to_repo": f"https://gitlab.com/{group}/{path}.git", "default_branch": "main",
            "visibility": "private" if i % 2 else "internal", "archived": i % 9 == 0,
            "topics": ["pci"] if i % 4 == 0 else [], "statistics": {"repository_size": 1024 * (100 + i)},
            "last_activity_at": "2026-11-05T10:00:00.000Z", **({"forked_from_project": {"id": 1}} if i % 10 == 3 else {}),
        })
    return out


def bitbucket_repos(workspace: str, n: int) -> list[dict[str, Any]]:
    out = []
    for i in range(n):
        slug = f"bb-{i:04d}"
        out.append({
            "uuid": "{%08d-0000-4000-8000-000000000000}" % i, "slug": slug, "name": slug,
            "full_name": f"{workspace}/{slug}", "workspace": {"slug": workspace},
            "links": {"html": {"href": f"https://bitbucket.org/{workspace}/{slug}"},
                      "clone": [{"name": "https", "href": f"https://bitbucket.org/{workspace}/{slug}.git"}]},
            "mainbranch": {"name": "main"}, "is_private": True, "language": "python" if i % 2 else "java",
            "size": 2048 * (10 + i), "updated_on": "2026-11-05T10:00:00+00:00",
            **({"parent": {"full_name": "x/y"}} if i % 8 == 5 else {}),
        })
    return out


class FakeScmServer:
    """``with FakeScmServer(state) as srv: srv.url`` -- a threaded server on 127.0.0.1 and a free port."""

    def __init__(self, state: FakeScmState | None = None):
        self.state = state or FakeScmState()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.state = self.state  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "FakeScmServer":
        self.thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


__all__ = ["FakeScmServer", "FakeScmState", "bitbucket_repos", "gitlab_projects", "make_repos", "rsa_keypair"]
