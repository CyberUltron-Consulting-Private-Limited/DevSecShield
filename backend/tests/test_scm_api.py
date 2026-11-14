"""F3 API end to end on the SQLite + real-router harness of the CBOM Sources tests, against the fake SCM API.

Connect (admin only, credential write-only, webhook secret shown once) -> discover -> preview filters with a count
and a credit estimate -> import -> inventory list, facets and bulk actions -> policies -> estimate and run (409 on a
changed price, charged once) -> cancel (refunded) -> signed webhooks (GitHub, GitLab, Bitbucket; bad or missing
signatures change nothing) -> roll-up.

    cd backend && PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y \
      AWS_DEFAULT_REGION=us-east-1 uv run --with pytest python -m pytest tests/test_scm_api.py -q -p no:cacheprovider
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as _cbom_api  # noqa: E402

from backend.new_models import Team  # noqa: E402
from backend.routers import scm as scm_router  # noqa: E402
from backend.tests.support.fake_scm import FakeScmServer, FakeScmState, make_repos  # noqa: E402
from backend.utilities.scm import rollup as R  # noqa: E402
from backend.utilities.scm.models import ScmRepository, ScmScanRequest, ScmScanRun  # noqa: E402

api, world = _cbom_api.api, _cbom_api.world  # the CBOM Sources harness fixtures
CANARY = "ghp_Canary7f3a91c2SCMtoken000000000000"
# F4 (PR #42) enforces each route's x-zs-permission before the handler runs: a member's change is then refused by F4
# with 403 and its role sentence; before F4 the handler refuses it with a 400 sentence (never 403). Either way the
# member changes nothing; tests/test_scm_permissions.py pins the permission names.
def _f4_enforces() -> bool:
    try:
        return importlib.util.find_spec("backend.utilities.rbac.policy") is not None
    except ModuleNotFoundError:  # no backend.utilities.rbac package at all: F4 is not on this branch
        return False


F4_ENFORCES = _f4_enforces()


def assert_member_refused(response) -> None:
    if F4_ENFORCES:
        assert response.status_code == 403 and response.json()["detail"].startswith("Your role (member) cannot"), \
            response.text
    else:
        assert response.status_code == 400 and "admin" in response.json()["detail"], response.text


@pytest.fixture()
def fake(monkeypatch):
    state = FakeScmState()
    state.add_tokens(CANARY)
    state.github_orgs["acme"] = make_repos("acme", 120)
    with FakeScmServer(state) as srv:
        monkeypatch.setenv("GIT_ALLOWED_HOSTS", f"http://127.0.0.1:{srv.port}")
        yield srv


@pytest.fixture()
def scm(api, world, monkeypatch):
    engine, _ids = world
    monkeypatch.setattr(scm_router, "get_db", lambda: engine)
    scm_router.webhook_limiter.requests.clear()
    return api


def connect(api, fake, who="alice", **over):
    body = {"name": "Acme GitHub", "provider": "github", "auth_kind": "token", "api_base": fake.url,
            "scope_kind": "org", "scope_name": "acme", "secrets": {"token": CANARY}, **over}
    return api("POST", "/1/scm/connections", who, json=body)


def setup_connection(api, fake):
    r = connect(api, fake)
    assert r.status_code == 201, r.text
    cid = r.json()["connection"]["id"]
    assert api("POST", f"/1/scm/connections/{cid}/sync").status_code == 202
    return cid, r.json()["webhook"]


def test_connect_is_admin_only_and_the_credential_never_comes_back(scm, fake):
    assert_member_refused(connect(scm, fake, who="bob"))  # member
    bad = connect(scm, fake, api_base="https://ghe.corp.example/api/v3")
    assert bad.status_code == 400 and "GIT_ALLOWED_HOSTS" in bad.json()["detail"]
    assert connect(scm, fake, auth_kind="github_app", scope_kind="installation").status_code == 400  # no App ids
    assert connect(scm, fake, secrets={}).status_code == 400
    assert connect(scm, fake, scope_kind="group").status_code == 400
    assert connect(scm, fake, secrets={"token": CANARY, "password": "x"}).status_code == 400
    r = connect(scm, fake)
    assert r.status_code == 201, r.text
    body = r.json()
    conn, hook = body["connection"], body["webhook"]
    assert conn["secrets_set"] == ["token"] and hook["path"].startswith("/scm/webhooks/github/")
    assert len(hook["secret"]) >= 40
    assert connect(scm, fake).status_code == 409  # same name
    listed = scm("GET", "/1/scm/connections").json()["connections"]
    assert len(listed) == 1 and "secret" not in json.dumps(listed[0]["sync"])
    assert scm("GET", f"/1/scm/connections/{conn['id']}", "carol").status_code in (403, 404)  # another team
    assert scm("GET", f"/2/scm/connections/{conn['id']}", "carol").status_code == 404
    test = scm("POST", f"/1/scm/connections/{conn['id']}/test").json()
    assert test == {"ok": True, "message": "Token can read the GitHub organisation acme"}
    # moving the connection elsewhere without re-entering the credential is refused
    moved = scm("PATCH", f"/1/scm/connections/{conn['id']}", json={"scope_name": "other-org"})
    assert moved.status_code == 400 and "re-enter" in moved.json()["detail"]
    assert scm("PATCH", f"/1/scm/connections/{conn['id']}", json={"name": "Renamed", "expected_version": 99}
               ).status_code == 409
    rotated = scm("POST", f"/1/scm/connections/{conn['id']}/webhook-secret").json()["webhook"]["secret"]
    assert rotated != hook["secret"]
    for text in scm.seen:
        assert CANARY not in text


def test_discover_preview_import_and_inventory(scm, fake):
    cid, _hook = setup_connection(scm, fake)
    conn = scm("GET", f"/1/scm/connections/{cid}").json()["connection"]
    assert conn["sync"]["status"] == "ok" and conn["sync"]["summary"]["discovered"] == 120
    preview = scm("POST", f"/1/scm/connections/{cid}/preview",
                  json={"filters": {"exclude_topics": ["deprecated"], "languages": ["Python", "Java"]},
                        "products": ["sbom_sca", "iac"]}).json()
    assert preview["discovered"] == 120 and 0 < preview["in_scope"] < 120
    assert sum(preview["reasons"].values()) == 120 and preview["reasons"]["language"] > 0
    assert preview["estimate"]["credits"] > 0 and set(preview["estimate"]["per_product"]) == {"sbom_sca", "iac"}
    assert_member_refused(scm("PUT", f"/1/scm/connections/{cid}/filters", "bob", json={"filters": {}}))
    imported = scm("PUT", f"/1/scm/connections/{cid}/filters",
                   json={"filters": {"exclude_topics": ["deprecated"], "languages": ["Python", "Java"]}}).json()
    assert imported["in_scope"] == preview["in_scope"]
    page = scm("GET", "/1/scm/repositories?scope=in&page_size=10").json()
    assert page["total"] == preview["in_scope"] and len(page["items"]) == 10
    assert page["facets"]["in_scope"] == preview["in_scope"]
    out = scm("GET", "/1/scm/repositories?scope=out&reason=language").json()
    assert out["total"] == preview["reasons"]["language"]
    assert scm("GET", "/1/scm/repositories?q=legacy-0001").json()["total"] == 1
    # bulk: pin an excluded repository in, then reset it
    target = out["items"][0]["id"]
    assert_member_refused(scm("POST", "/1/scm/repositories/bulk", "bob", json={"repo_ids": [target], "action": "include"}))
    assert scm("POST", "/1/scm/repositories/bulk", json={"repo_ids": [target], "action": "include"}).json() == {"changed": 1}
    pinned = scm("GET", "/1/scm/repositories?q=" + out["items"][0]["full_name"]).json()["items"][0]
    assert pinned["in_scope"] and pinned["scope_reason"] == "manual_include"
    scm("POST", "/1/scm/repositories/bulk", json={"repo_ids": [target], "action": "reset"})
    assert scm("GET", "/1/scm/repositories?q=" + out["items"][0]["full_name"]).json()["items"][0]["in_scope"] is False
    assert scm("GET", "/2/scm/repositories", "carol").json()["total"] == 0  # tenancy


def test_policies_estimates_runs_and_cancel(scm, fake, world):
    engine, _ids = world
    cid, _hook = setup_connection(scm, fake)
    scm("PUT", f"/1/scm/connections/{cid}/filters", json={"filters": {"topics_any": ["pci"]}})
    in_scope = scm("GET", "/1/scm/repositories?scope=in&page_size=200").json()
    policy = {"name": "PCI nightly", "selector": {"topics_any": ["pci"]}, "products": ["sbom_sca", "iac"],
              "on_push": True, "schedule": {"frequency": "daily", "time_of_day": "02:00", "timezone": "Asia/Kolkata"},
              "options": {"iac_modes": ["terraform", "k8s"]}}
    assert_member_refused(scm("POST", "/1/scm/policies", "bob", json=policy))
    assert scm("POST", "/1/scm/policies", json={**policy, "options": {"nope": 1}}).status_code == 400
    assert scm("POST", "/1/scm/policies", json={**policy, "products": ["dast"]}).status_code == 400
    created = scm("POST", "/1/scm/policies", json=policy)
    assert created.status_code == 201, created.text
    pol = created.json()["policy"]
    assert pol["repos_matched"] == in_scope["total"] and pol["next_run_at"].endswith(":30:00Z")  # 02:00 IST
    preview = scm("POST", "/1/scm/policies/preview", json={"selector": {"topics_any": ["pci"]},
                                                          "products": ["sbom_sca"], "position": 200}).json()
    assert preview["repos"] == 0 and preview["taken_by_other_policies"] == {"PCI nightly": in_scope["total"]}
    est = scm("POST", "/1/scm/runs/estimate", json={"policy_id": pol["id"]}).json()
    assert est["scans"] == 2 * in_scope["total"] and est["affordable"] is True
    with Session(engine) as s:
        before = s.get(Team, 1).credit_balance
    assert scm("POST", "/1/scm/runs", json={"policy_id": pol["id"]}).status_code == 400  # no estimate shown
    changed = scm("POST", "/1/scm/runs", json={"policy_id": pol["id"], "expected_credits": est["credits"] + 5,
                                               "client_request_id": "ui-1"})
    assert changed.status_code == 409 and changed.json()["code"] == "estimate_changed"
    assert changed.json()["estimate"]["credits"] == est["credits"]
    assert_member_refused(scm("POST", "/1/scm/runs", "bob", json={"policy_id": pol["id"], "expected_credits": est["credits"],
                                                                   "client_request_id": "ui-1"}))
    run = scm("POST", "/1/scm/runs", json={"policy_id": pol["id"], "expected_credits": est["credits"],
                                           "client_request_id": "ui-1"})
    assert run.status_code == 201, run.text
    run_id = run.json()["run"]["run_id"]
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance, 2) == round(before - est["credits"], 2)
    listed = scm("GET", "/1/scm/runs").json()
    assert listed["runs"][0]["requests"] == {"queued": est["scans"]} and listed["queue"]["by_status"]["queued"] > 0
    detail = scm("GET", f"/1/scm/runs/{run_id}?page_size=5").json()
    assert len(detail["requests"]) == 5 and detail["requests"][0]["repo"].startswith("acme/")
    cancelled = scm("POST", f"/1/scm/runs/{run_id}/cancel").json()
    assert cancelled["refunded"] == est["credits"]
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance, 2) == round(before, 2)
    # a policy that cannot be afforded: team 2 has 0.5 credits
    assert scm("POST", "/2/scm/runs/estimate", "carol", json={"repo_ids": [1], "products": ["cbom"]}).json()["scans"] == 0


def _gh(scm, hook, event, payload, secret=None):
    raw = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    if secret is not False:
        headers["X-Hub-Signature-256"] = "sha256=" + hmac.new((secret or hook["secret"]).encode(), raw,
                                                               hashlib.sha256).hexdigest()
    return scm("POST", hook["path"], None, content=raw, headers=headers)


def test_github_push_webhook_is_signed_idempotent_and_branch_aware(scm, fake, world):
    engine, _ids = world
    cid, hook = setup_connection(scm, fake)
    scm("PUT", f"/1/scm/connections/{cid}/filters", json={"filters": {"topics_any": ["pci"]}})
    scm("POST", "/1/scm/policies", json={"name": "on push", "selector": {}, "products": ["sbom_sca"], "on_push": True})
    repo = fake.state.github_orgs["acme"][7]  # topic pci, default branch main
    push = {"ref": "refs/heads/main", "after": "c" * 40, "deleted": False,
            "repository": {"id": repo["id"], "full_name": repo["full_name"]}}
    assert _gh(scm, hook, "push", push, secret=False).status_code == 401  # unsigned
    assert _gh(scm, hook, "push", push, secret="wrong-secret").status_code == 401
    bad_uid = scm("POST", "/scm/webhooks/github/" + "0" * 32, None, content=b"{}",
                  headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": "sha256=00"})
    assert bad_uid.status_code == 401
    with Session(engine) as s:
        assert s.exec(select(ScmScanRequest)).all() == []
    ok = _gh(scm, hook, "push", push)
    assert ok.status_code == 202 and ok.json()["pushes"][0]["status"] == "queued", ok.text
    again = _gh(scm, hook, "push", push)  # GitHub redelivery
    assert again.json()["pushes"][0]["status"] == "duplicate"
    other = _gh(scm, hook, "push", {**push, "ref": "refs/heads/feature-x", "after": "d" * 40})
    assert other.json()["pushes"][0]["status"] == "other_branch"
    tag = _gh(scm, hook, "push", {**push, "ref": "refs/tags/v1", "after": "e" * 40})
    assert tag.json()["status"] == "ignored"
    out_of_scope = fake.state.github_orgs["acme"][1]  # no pci topic
    oos = _gh(scm, hook, "push", {**push, "repository": {"id": out_of_scope["id"]}})
    assert oos.json()["pushes"][0]["status"] == "out_of_scope"
    assert _gh(scm, hook, "ping", {"zen": "x"}).json()["status"] == "ping"
    with Session(engine) as s:
        reqs = s.exec(select(ScmScanRequest)).all()
        assert [(r.trigger, r.priority, r.commit_sha) for r in reqs] == [("push", 0, "c" * 40)]
        assert s.exec(select(ScmScanRun)).one().trigger == "push"
    # repository events keep the inventory current without a full sync
    new_repo = {**make_repos("acme", 1, start_id=99999)[0], "name": "brand-new", "full_name": "acme/brand-new",
                "topics": ["pci"]}
    assert _gh(scm, hook, "repository", {"action": "created", "repository": new_repo}).json()["status"] == \
        "repository_added"
    assert _gh(scm, hook, "repository", {"action": "deleted", "repository": new_repo}).json()["status"] == \
        "repository_removed"
    with Session(engine) as s:
        row = s.exec(select(ScmRepository).where(ScmRepository.external_id == "99999")).one()
        assert row.removed_at is not None and row.in_scope is False


def test_gitlab_and_bitbucket_webhooks(scm, fake, world):
    engine, _ids = world
    from backend.tests.support.fake_scm import bitbucket_repos, gitlab_projects

    fake.state.gitlab_groups["bank/platform"] = gitlab_projects("bank/platform", 5)
    fake.state.bitbucket_workspaces["bankws"] = bitbucket_repos("bankws", 5)
    gl = scm("POST", "/1/scm/connections", json={"name": "GitLab", "provider": "gitlab", "api_base": fake.url,
                                                 "scope_kind": "group", "scope_name": "bank/platform",
                                                 "secrets": {"token": CANARY}}).json()
    bb = scm("POST", "/1/scm/connections", json={"name": "Bitbucket", "provider": "bitbucket", "api_base": fake.url,
                                                 "scope_kind": "workspace", "scope_name": "bankws",
                                                 "secrets": {"token": CANARY}}).json()
    for c in (gl, bb):
        scm("POST", f"/1/scm/connections/{c['connection']['id']}/sync")
        scm("PUT", f"/1/scm/connections/{c['connection']['id']}/filters", json={"filters": {"include_archived": True}})
    scm("POST", "/1/scm/policies", json={"name": "all", "selector": {"include_archived": True}, "products": ["iac"],
                                         "on_push": True})
    project = fake.state.gitlab_groups["bank/platform"][1]
    gl_body = json.dumps({"object_kind": "push", "ref": "refs/heads/main", "after": "f" * 40,
                          "project_id": project["id"], "project": {"path_with_namespace": project["path_with_namespace"]}})
    assert scm("POST", gl["webhook"]["path"], None, content=gl_body,
               headers={"X-Gitlab-Token": "nope", "X-Gitlab-Event": "Push Hook"}).status_code == 401
    r = scm("POST", gl["webhook"]["path"], None, content=gl_body,
            headers={"X-Gitlab-Token": gl["webhook"]["secret"], "X-Gitlab-Event": "Push Hook"})
    assert r.status_code == 202 and r.json()["pushes"][0]["status"] == "queued", r.text
    repo = fake.state.bitbucket_workspaces["bankws"][2]
    bb_body = json.dumps({"repository": {"uuid": repo["uuid"], "full_name": repo["full_name"]},
                          "push": {"changes": [{"new": {"type": "branch", "name": "main",
                                                        "target": {"hash": "a1" * 20}}}]}}).encode()
    sig = "sha256=" + hmac.new(bb["webhook"]["secret"].encode(), bb_body, hashlib.sha256).hexdigest()
    assert scm("POST", bb["webhook"]["path"], None, content=bb_body,
               headers={"X-Event-Key": "repo:push", "X-Hub-Signature": "sha256=" + "0" * 64}).status_code == 401
    r = scm("POST", bb["webhook"]["path"], None, content=bb_body, headers={"X-Event-Key": "repo:push",
                                                                         "X-Hub-Signature": sig})
    assert r.status_code == 202 and r.json()["pushes"][0]["status"] == "queued", r.text
    # a GitHub-signed body sent to the GitLab URL is refused (each provider checks its own header)
    assert scm("POST", gl["webhook"]["path"].replace("gitlab", "github"), None, content=gl_body,
               headers={"X-GitHub-Event": "push"}).status_code == 401
    with Session(engine) as s:
        assert len(s.exec(select(ScmScanRequest)).all()) == 2


def test_rollup_and_findings_endpoints(scm, fake, world):
    engine, _ids = world
    cid, _hook = setup_connection(scm, fake)
    with Session(engine) as s:
        repos = s.exec(select(ScmRepository).where(ScmRepository.connection_id == cid).limit(4)).all()
        for i, repo in enumerate(repos):
            rows = [{"dependency": "lodash@4.17.15", "title": "Prototype pollution", "impact": "high",
                     "cves": ["CVE-2020-8203"], "location": f"r{i}/package-lock.json"}]
            R.fold_scan(s, team_id=1, repo_id=repo.id, product="sbom_sca", scan_id=1000 + i,
                        scan_data={"results": rows}, now=repo.first_seen_at)
        s.commit()
    roll = scm("GET", "/1/scm/rollup").json()
    assert roll["products"]["sbom_sca"] == {"findings_total": 1, "occurrences": 4, "findings_open": 1,
                                            "repos_affected": 4, "dedup_ratio": 4.0}
    assert roll["top"][0]["repo_count"] == 4 and roll["by_severity"] == {"high": 1}
    listed = scm("GET", "/1/scm/findings?product=sbom_sca&min_repos=2").json()
    assert listed["total"] == 1 and listed["items"][0]["key_fields"]["cves"] == ["CVE-2020-8203"]
    detail = scm("GET", f"/1/scm/findings/{listed['items'][0]['id']}").json()
    assert len(detail["repositories"]) == 4 and detail["repositories"][0]["locations"]
    assert scm("GET", f"/2/scm/findings/{listed['items'][0]['id']}", "carol").status_code == 404


def test_deleting_a_connection_refunds_its_queued_scans(scm, fake, world):
    engine, _ids = world
    cid, _hook = setup_connection(scm, fake)
    with Session(engine) as s:
        ids = [r.id for r in s.exec(select(ScmRepository).where(ScmRepository.connection_id == cid).limit(3)).all()]
        before = s.get(Team, 1).credit_balance
    est = scm("POST", "/1/scm/runs/estimate", json={"repo_ids": ids, "products": ["sbom_sca"]}).json()
    assert scm("POST", "/1/scm/runs", json={"repo_ids": ids, "products": ["sbom_sca"],
                                            "expected_credits": est["credits"], "client_request_id": "del"}
               ).status_code == 201
    assert_member_refused(scm("DELETE", f"/1/scm/connections/{cid}", "bob"))
    gone = scm("DELETE", f"/1/scm/connections/{cid}").json()
    assert gone["refunded"] == est["credits"] and gone["repositories"] == 120
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance, 2) == round(before, 2)
        assert s.exec(select(ScmRepository)).all() == [] and s.exec(select(ScmScanRequest)).all() == []


def test_scheduler_loops_sync_requested_connections_and_drain_the_queue(scm, fake, world):
    """The worker's two loops: a requested sync runs; a due policy slot fires, and the queue loop sends its scans."""
    import datetime as dt

    from test_scm_queue import FakeLauncher, FakeWorker, token_for

    from backend.utilities.scm.models import ScmConnection, ScmScanPolicy
    from backend.workers import repo_scheduler as RS

    engine, _ids = world
    cid = connect(scm, fake).json()["connection"]["id"]
    now = dt.datetime(2026, 11, 11, 12, 0)
    with Session(engine) as s:
        conn = s.get(ScmConnection, cid)
        conn.sync_requested_at = now - dt.timedelta(minutes=1)
        s.add(conn)
        s.commit()
    synced = RS.sync_tick(engine, now)
    assert [x["connection_id"] for x in synced] == [cid] and synced[0]["discovered"] == 120
    assert RS.sync_tick(engine, now + dt.timedelta(seconds=30)) == []  # the next sync is not due yet
    scm("PUT", f"/1/scm/connections/{cid}/filters", json={"filters": {"topics_any": ["pci"]}})
    pol = scm("POST", "/1/scm/policies", json={"name": "nightly", "selector": {}, "products": ["sbom_sca"],
                                               "schedule": {"frequency": "daily", "time_of_day": "13:00"}}).json()
    with Session(engine) as s:
        p = s.get(ScmScanPolicy, pol["policy"]["id"])
        p.next_run_at = now
        s.add(p)
        s.commit()
    launcher = FakeLauncher()
    out = RS.queue_tick(engine, now, launcher=launcher, token_for=token_for, status_reader=FakeWorker(engine),
                        max_inflight=3, team_max=2)
    assert out["fired"][0]["status"] == "queued" and out["dispatched"] == 2  # team cap 2 under a global cap of 3
    assert {c["type"] for c in launcher.sent} == {"sbom_sca"}
