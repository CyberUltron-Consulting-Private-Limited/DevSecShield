"""The worker builds clone URLs from the checked host (GIT_ALLOWED_HOSTS for self-hosted servers), never by
searching the URL text for a provider name, and never logs the token."""

import pytest
from git import GitCommandError

from helpers.context import scan_context as sc


def test_public_github_with_and_without_token(monkeypatch):
    monkeypatch.delenv("GIT_ALLOWED_HOSTS", raising=False)
    assert sc.GithubContext(repo_url="https://github.com/acme/app", PAT="").repo_url == "https://github.com/acme/app"
    assert sc.GithubContext(repo_url="https://github.com/acme/app", PAT="ghp_x").repo_url == \
        "https://ghp_x@github.com/acme/app"
    # a sub-domain keeps its host (the old text search rewrote it to github.com)
    assert sc.GithubContext(repo_url="https://gist.github.com/acme/app", PAT="t").repo_url == \
        "https://t@gist.github.com/acme/app"
    # a repo URL pasted into the PAT field is ignored, as before
    assert sc.GithubContext(repo_url="https://github.com/a/b", PAT="https://github.com/a/b").repo_url == \
        "https://github.com/a/b"
    # validating an already-built context again keeps one token, not two
    ctx = sc.GithubContext(repo_url="https://github.com/a/b", PAT="tok")
    assert sc.GithubContext(repo_url=ctx.repo_url, PAT="tok").repo_url == "https://tok@github.com/a/b"


def test_github_app_installation_token_clones_as_x_access_token(monkeypatch):
    """F3: repository scans of a GitHub App connection carry a 1-hour installation token (ghs_...); GitHub documents
    https://x-access-token:<token>@github.com/... for it. Personal tokens keep the token-as-user form."""
    monkeypatch.setenv("GIT_ALLOWED_HOSTS", "ghe.corp.example")
    ctx = sc.GithubContext(repo_url="https://github.com/acme/app", PAT="ghs_AbC123")
    assert ctx.repo_url == "https://x-access-token:ghs_AbC123@github.com/acme/app"
    assert sc.GithubContext(repo_url=ctx.repo_url, PAT="ghs_AbC123").repo_url == ctx.repo_url  # re-validated: same
    assert sc.GithubContext(repo_url="https://ghe.corp.example/o/r", PAT="ghs_z").repo_url == \
        "https://x-access-token:ghs_z@ghe.corp.example/o/r"
    assert sc.GithubContext(repo_url="https://github.com/acme/app", PAT="github_pat_x").repo_url == \
        "https://github_pat_x@github.com/acme/app"


def test_plain_http_and_unlisted_hosts_are_refused(monkeypatch):
    monkeypatch.delenv("GIT_ALLOWED_HOSTS", raising=False)
    for ctx_cls, url in ((sc.GithubContext, "http://github.com/a/b"),
                         (sc.GitlabContext, "https://gitlab.corp.example/g/p"),
                         (sc.BitbucketContext, "https://bitbucket.org.evil.tld/w/r")):
        with pytest.raises(ValueError):
            ctx_cls(repo_url=url, PAT="tok")
    assert not sc.is_github_url("https://evil.tld/github.com/a/b")


def test_self_hosted_servers_from_the_operator_list(monkeypatch):
    monkeypatch.setenv("GIT_ALLOWED_HOSTS", "gitlab.corp.example,http://gitea.lab:3000,bb.corp:7990")
    assert sc.GitlabContext(repo_url="https://gitlab.corp.example/g/p.git", PAT="glpat-1").repo_url == \
        "https://oauth2:glpat-1@gitlab.corp.example/g/p.git"
    assert sc.GithubContext(repo_url="http://gitea.lab:3000/o/r", PAT="t").repo_url == "http://t@gitea.lab:3000/o/r"
    assert sc.BitbucketContext(repo_url="https://me@bb.corp:7990/scm/p/r.git", PAT="a/b").repo_url == \
        "https://x-token-auth:a%2Fb@bb.corp:7990/scm/p/r.git"
    with pytest.raises(ValueError, match="plain HTTP"):
        sc.GitlabContext(repo_url="http://gitlab.corp.example/g/p", PAT="glpat-1")
    with pytest.raises(ValueError):
        sc.BitbucketContext(repo_url="https://bb.corp/scm/p/r.git", PAT="t")  # listed with port 7990 only
    assert sc.is_gitlab_url("https://gitlab.corp.example/g/p")
    ctx = sc.validate_dict_with_context({"mode": "gitlab", "repo_url": "https://gitlab.corp.example/g/p", "PAT": "x"})
    assert ctx.repo_url == "https://oauth2:x@gitlab.corp.example/g/p"


def test_clone_failure_never_carries_the_token(monkeypatch, capsys):
    def fail(url, *a, **k):
        raise GitCommandError(["git", "clone", url], 128, stderr=f"fatal: could not read from {url}")

    monkeypatch.setattr(sc.Repo, "clone_from", fail)
    with pytest.raises(RuntimeError) as err:
        sc.clone_repo("https://oauth2:glpat-SECRET@gitlab.com/g/p", "main")
    assert "glpat-SECRET" not in str(err.value) and "***@gitlab.com" in str(err.value)
    assert "glpat-SECRET" not in capsys.readouterr().out
