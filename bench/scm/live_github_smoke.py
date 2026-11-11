"""F3 live proof against api.github.com: read-only discovery through the real provider client, no scans.

What it does (every call is a GET; nothing is written to GitHub and no scan is started):
1. organisation / user listing with scope "user" (``GET /user/repos``) -- the code path a token connection uses;
2. ``GET /repos/{owner}/{repo}`` for each repository named on the command line, normalised exactly as discovery does;
3. one paginated listing (``GET /repos/{owner}/{repo}/branches``, 2 per page, at most 3 pages) through the client's
   ``Link`` pagination, recording the rate-limit headers it read;
4. the repositories it could read go into a throwaway SQLite inventory through ``inventory.upsert_repo`` with the
   default filters, so the in-scope decision is shown.

The token comes from GH_TOKEN / GITHUB_TOKEN (or --token-env); it is never printed. In an environment whose egress
proxy only allows repository-scoped endpoints, step 1 is answered 403 and recorded as such.

    PYTHONPATH=. python bench/scm/live_github_smoke.py AnshSinghal-CyberUltron/devsecshield --out live.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
os.environ.setdefault("JWT_SECRET_KEY", "bench-only")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "bench-only")
if not os.environ.get("ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet

    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import Team  # noqa: E402
from backend.utilities.scm import filters as F  # noqa: E402
from backend.utilities.scm import inventory as INV  # noqa: E402
from backend.utilities.scm.models import ScmConnection, ScmRepository  # noqa: E402
from backend.utilities.scm.providers import ScmError, build_provider  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repos", nargs="+", help="owner/name of repositories to read (read-only)")
    ap.add_argument("--token-env", default="GH_TOKEN")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    token = os.environ.get(args.token_env) or os.environ.get("GITHUB_TOKEN") or ""
    out: dict = {"at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "api": "https://api.github.com"}

    user = build_provider("github", "token", "", "user", "", {}, {"token": token}, max_wait_s=30)
    try:
        listed = []
        for repo in user.iter_repos():
            listed.append(repo.full_name)
            if len(listed) >= 300:
                break
        out["user_listing"] = {"ok": True, "repos": len(listed), "pages": user.stats["pages"]}
    except ScmError as err:
        out["user_listing"] = {"ok": False, "kind": err.kind, "status": err.status, "message": str(err)}
    finally:
        user.close()

    prov = build_provider("github", "token", "", "org", "unused", {}, {"token": token}, max_wait_s=30)
    found = []
    out["repositories"] = []
    for full_name in args.repos:
        try:
            repo = prov.get_repo(full_name)
        except ScmError as err:
            out["repositories"].append({"full_name": full_name, "ok": False, "kind": err.kind, "message": str(err)})
            continue
        if repo is None:
            out["repositories"].append({"full_name": full_name, "ok": False, "kind": "not_found"})
            continue
        found.append(repo)
        out["repositories"].append({"ok": True, "external_id": repo.external_id, "full_name": repo.full_name,
                                    "default_branch": repo.default_branch, "visibility": repo.visibility,
                                    "archived": repo.archived, "fork": repo.fork, "language": repo.language,
                                    "topics": repo.topics, "size_kb": repo.size_kb,
                                    "pushed_at": repo.pushed_at.isoformat() if repo.pushed_at else None,
                                    "web_url": repo.web_url})
    if found:
        owner, name = found[0].full_name.split("/", 1)
        pages, names = 0, []
        url: str | None = f"/repos/{owner}/{name}/branches"
        params: dict | None = {"per_page": 2}
        from backend.utilities.scm.providers.base import next_link

        refused = None
        next_url = None
        while url and pages < 3:
            try:
                body, headers = prov.http.get_json(url, params)
            except ScmError as err:  # e.g. a proxy that only allows /repos/{owner}/{repo}/... paths
                refused = {"url_path": url.split("api.github.com", 1)[-1].split("?", 1)[0], "kind": err.kind,
                           "status": err.status}
                break
            params = None
            pages += 1
            names += [b.get("name") for b in body if isinstance(b, dict)]
            url = next_link(headers.get("link") or "")
            next_url = url
        out["pagination"] = {"pages_read": pages, "items": len(names), "next_link_path":
                             (next_url or "").split("api.github.com", 1)[-1].split("?", 1)[0] or None,
                             "next_page_refused": refused}
    out["client_stats"] = {k: prov.stats[k] for k in ("api_calls", "pages", "retries", "waits", "rate_limit",
                                                       "rate_remaining")}
    prov.close()

    with tempfile.TemporaryDirectory() as tmp:
        engine = create_engine(f"sqlite:///{tmp}/live.db")
        SQLModel.metadata.create_all(engine)
        with Session(engine) as s:
            s.add(Team(id=1, name="live", credit_balance=0))
            s.commit()
            conn = ScmConnection(team_id=1, owner_user_id=1, provider="github", auth_kind="token", name="live",
                                 name_lower="live", api_base="https://api.github.com", scope_kind="user",
                                 webhook_uid=os.urandom(16).hex())
            s.add(conn)
            s.commit()
            now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
            out["inventory"] = []
            for repo in found:
                row, outcome = INV.upsert_repo(s, conn, repo, now, F.RepoFilters(), None)
                s.commit()
                out["inventory"].append({"full_name": row.full_name, "outcome": outcome, "in_scope": row.in_scope,
                                         "scope_reason": row.scope_reason})
            again = []
            for repo in found:  # the same repositories again: an idempotent sync reports "same"
                existing = s.exec(select(ScmRepository).where(ScmRepository.external_id == repo.external_id)).first()
                again.append(INV.upsert_repo(s, conn, repo, now, F.RepoFilters(), existing)[1])
            s.commit()
            out["inventory_resync_outcomes"] = again
    text = json.dumps(out, indent=2)
    if token:
        assert token not in text
    print(text)
    if args.out:
        Path(args.out).write_text(text)
    return 0 if found else 1


if __name__ == "__main__":
    raise SystemExit(main())
