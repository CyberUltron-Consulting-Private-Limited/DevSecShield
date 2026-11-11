"""F3: org-level discovery of code repositories (GitHub App / token, GitLab group, Bitbucket workspace), include /
exclude filters and the idempotent repository inventory, against a real local fake SCM API (tests/support/fake_scm.py)
that paginates, rate-limits (primary and secondary limits) and fails with 502s like the real ones.

    cd backend && PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r uv run --with pytest python -m pytest \
      tests/test_scm_discovery.py -q -p no:cacheprovider
"""
from __future__ import annotations

import datetime as dt
import os
import sys
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "scm-test-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "scm-test-refresh")
os.environ.setdefault("ENCRYPTION_KEY", Fernet.generate_key().decode())

from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.tests.support.fake_scm import (  # noqa: E402
    FakeScmServer,
    FakeScmState,
    bitbucket_repos,
    gitlab_projects,
    make_repos,
    rsa_keypair,
)
from backend.utilities.cbom_sources.crypto import encrypt_secrets  # noqa: E402
from backend.utilities.db.encryption import _get_fernet  # noqa: E402
from backend.utilities.scm import filters as F  # noqa: E402
from backend.utilities.scm import hosts as H  # noqa: E402
from backend.utilities.scm import inventory as INV  # noqa: E402
from backend.utilities.scm.models import ScmConnection, ScmRepository  # noqa: E402
from backend.utilities.scm.providers import ScmError, build_provider  # noqa: E402

TOKEN = "fake-pat-0001"


# ----------------------------------------------------------------------------- filters (pure, deterministic)
def repo(**kw):
    base = {"full_name": "acme/payments-api", "name": "payments-api", "archived": False, "fork": False,
            "topics": ["pci"], "language": "Python", "visibility": "private", "size_kb": 2048}
    return {**base, **kw}


def test_filters_each_rule_and_its_reason():
    f = F.RepoFilters()
    assert F.evaluate(repo(), f) == (True, "matched")
    assert F.evaluate(repo(archived=True), f) == (False, "archived")
    assert F.evaluate(repo(archived=True), F.RepoFilters(include_archived=True)) == (True, "matched")
    assert F.evaluate(repo(fork=True), f) == (False, "fork")
    assert F.evaluate(repo(), F.RepoFilters(include_names=["acme/pay*"])) == (True, "matched")
    assert F.evaluate(repo(), F.RepoFilters(include_names=["pay*"])) == (True, "matched")  # bare name also matches
    assert F.evaluate(repo(), F.RepoFilters(include_names=["billing-*"])) == (False, "not_included_name")
    assert F.evaluate(repo(), F.RepoFilters(exclude_names=["*-API"])) == (False, "excluded_name")  # case-insensitive
    assert F.evaluate(repo(), F.RepoFilters(topics_any=["pci", "sox"])) == (True, "matched")
    assert F.evaluate(repo(topics=[]), F.RepoFilters(topics_any=["pci"])) == (False, "missing_topic")
    assert F.evaluate(repo(topics=["pci", "deprecated"]), F.RepoFilters(exclude_topics=["Deprecated"])) == \
        (False, "excluded_topic")
    assert F.evaluate(repo(), F.RepoFilters(languages=["java", "python"])) == (True, "matched")
    assert F.evaluate(repo(language=None), F.RepoFilters(languages=["python"])) == (False, "language")
    assert F.evaluate(repo(), F.RepoFilters(visibility=["public"])) == (False, "visibility")
    assert F.evaluate(repo(size_kb=300 * 1024), F.RepoFilters(max_size_mb=100)) == (False, "too_large")
    # exclude wins over include, and the order of checks is fixed (the first failing rule is the reason)
    both = F.RepoFilters(include_names=["acme/*"], exclude_names=["*payments*"])
    assert F.evaluate(repo(), both) == (False, "excluded_name")
    assert F.evaluate(repo(archived=True, fork=True), both) == (False, "archived")
    # manual overrides win over every filter
    assert F.in_scope(repo(archived=True), f, "include") == (True, "manual_include")
    assert F.in_scope(repo(), f, "exclude") == (False, "manual_exclude")
    assert F.in_scope(repo(), f, None) == (True, "matched")


def test_filters_reject_bad_input_without_echoing_it():
    with pytest.raises(ValueError):
        F.RepoFilters(include_names=["x" * 201])
    with pytest.raises(ValueError):
        F.RepoFilters(include_names=[f"p{i}" for i in range(101)])
    with pytest.raises(ValueError):
        F.RepoFilters(unknown_rule=True)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        F.RepoFilters(max_size_mb=-1)


def test_filters_are_deterministic_over_many_repositories():
    repos = [{**r, "size_kb": r["size"]} for r in make_repos("acme", 500)]
    f = F.RepoFilters(exclude_topics=["deprecated"], languages=["Python", "Go", "Java"], max_size_mb=8)
    first = [F.evaluate(r, f) for r in repos]
    assert first == [F.evaluate(r, f) for r in reversed(repos)][::-1]
    assert {reason for _ok, reason in first} >= {"matched", "archived", "fork", "language", "excluded_topic"}


# ----------------------------------------------------------------------------- API base allow-list (SSRF)
def test_api_base_defaults_and_self_hosted_needs_the_clone_allow_list(monkeypatch):
    monkeypatch.delenv("GIT_ALLOWED_HOSTS", raising=False)
    assert H.check_api_base("github", "") == "https://api.github.com"
    assert H.check_api_base("gitlab", None) == "https://gitlab.com"
    assert H.check_api_base("bitbucket", "") == "https://api.bitbucket.org"
    for bad in ("https://ghe.corp.example/api/v3", "http://api.github.com", "https://169.254.169.254/",
                "https://user:pw@api.github.com", "ftp://x", "https://api.github.com.evil.example"):
        with pytest.raises(ValueError):
            H.check_api_base("github", bad)
    monkeypatch.setenv("GIT_ALLOWED_HOSTS", "ghe.corp.example,http://git.lab:3000")
    assert H.check_api_base("github", "https://ghe.corp.example/api/v3/") == "https://ghe.corp.example/api/v3"
    assert H.check_api_base("gitlab", "http://git.lab:3000") == "http://git.lab:3000"
    with pytest.raises(ValueError):
        H.check_api_base("gitlab", "http://ghe.corp.example")  # listed for https only


# ----------------------------------------------------------------------------- providers against the fake API
@pytest.fixture()
def fake(monkeypatch):
    state = FakeScmState()
    state.add_tokens(TOKEN)
    with FakeScmServer(state) as srv:
        monkeypatch.setenv("GIT_ALLOWED_HOSTS", f"http://127.0.0.1:{srv.port}")
        yield srv


def gh_token(fake, org="acme", scope="org"):
    return build_provider("github", "token", fake.url, scope, org, {}, {"token": TOKEN}, max_wait_s=30)


def test_github_token_org_pagination_and_normalisation(fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 250)
    prov = gh_token(fake)
    repos = list(prov.iter_repos())
    assert len(repos) == 250 and len({r.external_id for r in repos}) == 250
    assert prov.stats["pages"] == 3 and prov.stats["api_calls"] == 3  # 100 per page
    r0 = repos[0]
    assert (r0.full_name, r0.name, r0.owner, r0.default_branch) == ("acme/legacy-00000", "legacy-00000", "acme", "master")
    assert r0.web_url == "https://github.com/acme/legacy-00000" and r0.size_kb == 200
    assert r0.archived is True and r0.visibility == "public" and r0.topics == ["pci", "deprecated"]
    assert "Authorization" not in repr(prov.stats)
    assert prov.clone_token() == TOKEN
    assert "acme" in prov.test()


def test_github_wrong_token_and_unknown_org_are_safe_errors(fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 3)
    bad = build_provider("github", "token", fake.url, "org", "acme", {}, {"token": "wrong"}, max_wait_s=5)
    with pytest.raises(ScmError) as err:
        list(bad.iter_repos())
    assert err.value.kind == "auth" and "wrong" not in str(err.value)
    with pytest.raises(ScmError) as err:
        list(gh_token(fake, org="nope").iter_repos())
    assert err.value.kind == "not_found"


def test_github_app_installation_jwt_token_and_listing(fake):
    pem, public = rsa_keypair()
    fake.state.github_app_keys["4242"] = public
    fake.state.github_installations[99] = {"app_id": 4242, "repos": make_repos("bank", 130)}
    prov = build_provider("github", "github_app", fake.url, "installation", "bank",
                          {"app_id": "4242", "installation_id": 99}, {"private_key": pem}, max_wait_s=30)
    repos = list(prov.iter_repos())
    assert len(repos) == 130
    token = prov.clone_token()
    assert token.startswith("ghs_fake99")
    assert prov.clone_token() == token  # cached until shortly before it expires
    posts = [p for _t, m, p in fake.state.requests if m == "POST"]
    assert posts == ["/app/installations/99/access_tokens"]
    # a key that is not the App's is refused by the server: a safe auth error
    other_pem, _ = rsa_keypair()
    wrong = build_provider("github", "github_app", fake.url, "installation", "bank",
                           {"app_id": "4242", "installation_id": 99}, {"private_key": other_pem}, max_wait_s=5)
    with pytest.raises(ScmError) as err:
        list(wrong.iter_repos())
    assert err.value.kind == "auth"
    with pytest.raises(ScmError):
        build_provider("github", "github_app", fake.url, "installation", "bank",
                       {"app_id": "4242", "installation_id": 99}, {"private_key": "not a pem"}).clone_token()


def test_primary_rate_limit_is_waited_out_and_reported(fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 500)
    fake.state.rate_limit, fake.state.rate_window_s = 3, 1.5
    prov = gh_token(fake)
    t0 = time.monotonic()
    repos = list(prov.iter_repos())
    assert len(repos) == 500
    assert prov.stats["waits"] >= 1 and prov.stats["waited_s"] > 0
    assert time.monotonic() - t0 < 20
    # the client never ran the budget dry: it paused at the reserve instead of collecting 403s
    assert fake.state.responses.get(403, 0) == 0


def test_secondary_limits_and_5xx_are_retried(fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 400)
    fake.state.secondary_every = 3
    fake.state.fail_requests = {2}
    prov = gh_token(fake)
    assert len(list(prov.iter_repos())) == 400
    assert prov.stats["retries"] >= 2
    assert fake.state.responses[403] >= 1 and fake.state.responses[502] == 1


def test_rate_limit_longer_than_the_cap_stops_as_rate_limited(fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 300)
    fake.state.rate_limit, fake.state.rate_window_s = 2, 120
    prov = build_provider("github", "token", fake.url, "org", "acme", {}, {"token": TOKEN}, max_wait_s=2)
    with pytest.raises(ScmError) as err:
        list(prov.iter_repos())
    assert err.value.kind == "rate_limited" and err.value.reset_at is not None


def test_pagination_links_to_another_host_are_not_followed(fake, monkeypatch):
    from backend.utilities.scm.providers import base

    client = base.HttpClient(fake.url, {"Authorization": f"token {TOKEN}"}, flavour="github", max_wait_s=5)
    with pytest.raises(ScmError) as err:
        client.get_json("https://evil.example/steal")
    assert err.value.kind == "refused"


def test_gitlab_group_keyset_pagination(fake):
    fake.state.gitlab_groups["bank/platform"] = gitlab_projects("bank/platform", 230)
    prov = build_provider("gitlab", "token", fake.url, "group", "bank/platform", {"include_subgroups": True},
                          {"token": TOKEN}, max_wait_s=30)
    repos = list(prov.iter_repos())
    assert len(repos) == 230 and prov.stats["pages"] == 3
    r = repos[3]
    assert r.fork is True and r.full_name == "bank/platform/proj-0003" and r.size_kb == 103
    assert r.web_url == "https://gitlab.com/bank/platform/proj-0003"
    assert any(r.archived for r in repos) and prov.clone_token() == TOKEN
    assert "bank/platform" in prov.test()


def test_bitbucket_workspace_next_pagination(fake):
    fake.state.bitbucket_workspaces["bankws"] = bitbucket_repos("bankws", 120)
    prov = build_provider("bitbucket", "token", fake.url, "workspace", "bankws", {}, {"token": TOKEN},
                          max_wait_s=30)
    repos = list(prov.iter_repos())
    assert len(repos) == 120 and prov.stats["pages"] == 2
    assert repos[5].fork is True and repos[0].language == "java" and repos[0].default_branch == "main"
    assert repos[0].web_url == "https://bitbucket.org/bankws/bb-0000" and repos[0].size_kb == 20
    assert "bankws" in prov.test()


# ----------------------------------------------------------------------------- inventory sync (idempotent)
@pytest.fixture()
def engine(tmp_path):
    _get_fernet.cache_clear()
    eng = create_engine(f"sqlite:///{tmp_path / 'scm.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(eng, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        s.add(Team(id=1, name="Bank", credit_balance=1000.0))
        s.commit()
        u = User(email="a@t.test", password="x", first_name="a", last_name="b", profile_photo=None, default_team_id=1)
        s.add(u)
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=u.id, role="admin"))
        s.commit()
    return eng


def add_connection(engine, fake, *, provider="github", scope_kind="org", scope="acme", filters=None, name="acme"):
    with Session(engine) as s:
        c = ScmConnection(team_id=1, owner_user_id=1, provider=provider, auth_kind="token", name=name,
                          name_lower=name.lower(), api_base=fake.url, scope_kind=scope_kind, scope_name=scope,
                          filters=filters or {}, secret_encrypted=encrypt_secrets({"token": TOKEN}),
                          secret_fields=["token"], webhook_uid=os.urandom(16).hex())
        s.add(c)
        s.commit()
        return c.id


def repos_of(engine, cid):
    with Session(engine) as s:
        return {r.external_id: r for r in s.exec(select(ScmRepository).where(ScmRepository.connection_id == cid)).all()}


def test_sync_is_idempotent_tracks_renames_and_removals(engine, fake):
    org = fake.state.github_orgs["acme"] = make_repos("acme", 60)
    cid = add_connection(engine, fake, filters={"exclude_topics": ["deprecated"]})
    first = INV.sync_connection(engine, cid)
    assert first["status"] == "ok" and (first["discovered"], first["added"], first["updated"]) == (60, 60, 0)
    rows = repos_of(engine, cid)
    assert len(rows) == 60
    archived = [r for r in rows.values() if r.archived]
    assert archived and all(not r.in_scope and r.scope_reason == "archived" for r in archived)
    assert all(r.in_scope == (r.scope_reason == "matched") for r in rows.values())
    again = INV.sync_connection(engine, cid)
    assert (again["added"], again["updated"], again["removed"]) == (0, 0, 0) and len(repos_of(engine, cid)) == 60
    # rename (same id) updates in place; a repo gone from the org is marked removed, never deleted
    org[1] = {**org[1], "name": "renamed", "full_name": "acme/renamed"}
    gone = org.pop(2)
    third = INV.sync_connection(engine, cid)
    assert (third["added"], third["updated"], third["removed"]) == (0, 1, 1)
    rows = repos_of(engine, cid)
    assert rows[str(org[1]["id"])].full_name == "acme/renamed" and len(rows) == 60
    assert rows[str(gone["id"])].removed_at is not None and rows[str(gone["id"])].in_scope is False
    # it comes back: un-removed
    org.append(gone)
    assert INV.sync_connection(engine, cid)["restored"] == 1
    assert repos_of(engine, cid)[str(gone["id"])].removed_at is None


def test_a_partial_sync_removes_nothing(engine, fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 250)
    cid = add_connection(engine, fake)
    assert INV.sync_connection(engine, cid)["status"] == "ok"
    fake.state.github_orgs["acme"] = fake.state.github_orgs["acme"][:150]  # a complete sync would remove 100
    fake.state.rate_limit, fake.state.rate_window_s = 1, 300
    fake.state.used = 0
    out = INV.sync_connection(engine, cid, max_wait_s=1)
    assert out["status"] == "partial" and out["removed"] == 0
    with Session(engine) as s:
        conn = s.get(ScmConnection, cid)
        assert conn.sync_status == "partial" and conn.next_sync_at is not None
        assert "rate limit" in (conn.last_sync_error or "").lower()
    assert sum(1 for r in repos_of(engine, cid).values() if r.removed_at) == 0


def test_manual_override_survives_resync_and_filters_reapply(engine, fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 30)
    cid = add_connection(engine, fake)
    INV.sync_connection(engine, cid)
    rows = repos_of(engine, cid)
    archived = next(r for r in rows.values() if r.archived)
    with Session(engine) as s:
        INV.set_manual_state(s, team_id=1, repo_ids=[archived.id], state="include")
        s.commit()
    INV.sync_connection(engine, cid)
    assert repos_of(engine, cid)[archived.external_id].in_scope is True
    with Session(engine) as s:
        changed = INV.apply_filters(s, cid, F.RepoFilters(include_names=["acme/svc-0000*"]))
        s.commit()
    rows = repos_of(engine, cid)
    assert changed > 0
    assert rows[archived.external_id].scope_reason == "manual_include"
    assert {r.full_name for r in rows.values() if r.in_scope and r.manual_state is None} == \
        {r.full_name for r in rows.values() if r.full_name.startswith("acme/svc-0000") and not r.archived
         and not r.fork}


def test_concurrent_sync_lease_lets_one_runner_in(engine, fake):
    fake.state.github_orgs["acme"] = make_repos("acme", 5)
    cid = add_connection(engine, fake)
    now = dt.datetime(2026, 11, 11, 12, 0)
    with Session(engine) as s:
        assert INV.claim_sync(s, cid, now) is True
        s.commit()
    with Session(engine) as s:
        assert INV.claim_sync(s, cid, now + dt.timedelta(seconds=5)) is False
        s.commit()
    with Session(engine) as s:  # an expired lease (crashed runner) can be taken over
        assert INV.claim_sync(s, cid, now + dt.timedelta(minutes=31)) is True
        s.commit()


def test_one_thousand_repositories_import_well_under_five_minutes(engine, fake):
    """The acceptance number (CI-sized): 1,000 repos through the real HTTP client, paginated, with secondary limits,
    a 502 and 5 ms of server latency per call, into the inventory."""
    fake.state.github_orgs["acme"] = make_repos("acme", 1000)
    fake.state.secondary_every, fake.state.fail_requests, fake.state.latency_s = 4, {3}, 0.005
    cid = add_connection(engine, fake, filters={"exclude_topics": ["deprecated"]})
    t0 = time.monotonic()
    out = INV.sync_connection(engine, cid)
    took = time.monotonic() - t0
    assert out["status"] == "ok" and out["discovered"] == 1000 and out["added"] == 1000
    assert len(repos_of(engine, cid)) == 1000
    assert took < 300, took
    print(f"1,000 repos imported in {took:.2f}s, api calls {out['api_calls']}, retries {out['retries']}")
