"""Repository URLs a scan may clone: public providers over https, self-hosted servers listed in GIT_ALLOWED_HOSTS."""
import logging
import pathlib

import pytest
from pydantic import ValidationError

from backend.utilities import git_hosts
from backend.utilities.db.schemas import BitbucketContextSchema, GithubContextSchema, GitlabContextSchema

REPO = pathlib.Path(__file__).resolve().parents[2]


def ok(url, host="github.com", label="GitHub"):
    return git_hosts.check_repo_url(url, host, label)


def bad(url, match, host="github.com", label="GitHub"):
    with pytest.raises(ValueError, match=match):
        git_hosts.check_repo_url(url, host, label)


def test_public_providers_https_only(monkeypatch):
    monkeypatch.delenv("GIT_ALLOWED_HOSTS", raising=False)
    assert ok("https://github.com/acme/app").host == "github.com"
    assert ok("https://gist.github.com/acme/app.git").host == "gist.github.com"
    assert ok("https://GitHub.com:443/acme/app").port is None
    assert ok("https://gitlab.com/g/sub/p", "gitlab.com", "GitLab").path == "/g/sub/p"
    bad("http://github.com/acme/app", "https://")
    bad("https://github.com:8443/acme/app", "standard https port")
    bad("https://github.com.evil.tld/acme/app", "GIT_ALLOWED_HOSTS")
    bad("https://evil.tld/github.com/acme/app", "GIT_ALLOWED_HOSTS")
    bad("ssh://git@github.com/acme/app", "https://")
    bad("https://github.com/", "name a repository")
    bad("https://github.com:99999/acme/app", "not a valid URL")
    bad("", "required")


def test_self_hosted_needs_the_operator_list(monkeypatch):
    monkeypatch.delenv("GIT_ALLOWED_HOSTS", raising=False)
    bad("https://git.corp.example/team/app", "GIT_ALLOWED_HOSTS")
    monkeypatch.setenv("GIT_ALLOWED_HOSTS", " git.corp.example , gitlab.lab:8443,http://gitea.lab:3000, http://[fd00::5] ")
    assert ok("https://git.corp.example/team/app").host == "git.corp.example"
    assert ok("https://GIT.corp.example:443/team/app").host == "git.corp.example"
    bad("http://git.corp.example/team/app", "plain HTTP to git.corp.example is allowed only")
    bad("https://sub.git.corp.example/team/app", "GIT_ALLOWED_HOSTS")  # listed hosts match exactly
    bad("https://git.corp.example:8443/team/app", "GIT_ALLOWED_HOSTS")  # another port
    assert ok("https://gitlab.lab:8443/g/p", "gitlab.com", "GitLab").port == 8443
    bad("https://gitlab.lab/g/p", "GIT_ALLOWED_HOSTS", "gitlab.com", "GitLab")
    assert ok("http://gitea.lab:3000/o/r").scheme == "http"
    assert ok("https://gitea.lab:3000/o/r").scheme == "https"  # http:// listing allows https too
    bad("http://gitea.lab/o/r", "GIT_ALLOWED_HOSTS")
    assert ok("http://[fd00::5]/o/r").host == "fd00::5"


def test_invalid_entries_are_ignored_with_a_warning(monkeypatch, caplog):
    monkeypatch.setenv("GIT_ALLOWED_HOSTS", "ftp://files.lab,git.ok.lab,https://x.lab/path,user@y.lab,z.lab:notaport")
    with caplog.at_level(logging.WARNING, logger=git_hosts.__name__):
        assert ok("https://git.ok.lab/o/r").host == "git.ok.lab"
        for host in ("files.lab", "x.lab", "y.lab", "z.lab"):
            bad(f"https://{host}/o/r", "GIT_ALLOWED_HOSTS")
    ignored = [r.getMessage() for r in caplog.records if "entry_ignored" in r.getMessage()]
    assert len(ignored) == 4


def test_clone_url_is_rebuilt_from_the_parsed_host(monkeypatch):
    monkeypatch.setenv("GIT_ALLOWED_HOSTS", "git.corp.example:8443,http://[fd00::5]:3000")
    # a sub-domain stays a sub-domain (the old text search turned gist.github.com into github.com)
    assert git_hosts.clone_url("https://gist.github.com/a/b", "github.com", "GitHub", user="tok") == \
        "https://tok@gist.github.com/a/b"
    # user info typed into the URL (Bitbucket's clone button adds it) is dropped; query/fragment too
    assert git_hosts.clone_url("https://me@bitbucket.org/w/r.git?x=1#f", "bitbucket.org", "Bitbucket",
                               user="x-token-auth", secret="s/e@c:r t") == \
        "https://x-token-auth:s%2Fe%40c%3Ar%20t@bitbucket.org/w/r.git"
    assert git_hosts.clone_url("https://git.corp.example:8443/t/a", "gitlab.com", "GitLab", user="oauth2",
                               secret="glpat") == "https://oauth2:glpat@git.corp.example:8443/t/a"
    assert git_hosts.clone_url("http://[fd00::5]:3000/o/r", "github.com", "GitHub") == "http://[fd00::5]:3000/o/r"
    assert git_hosts.clone_url("https://github.com/a/b", "github.com", "GitHub") == "https://github.com/a/b"


def test_redact_removes_credentials_from_messages():
    msg = "Clone failed: cmdline: git clone https://ghp_secret@github.com/a/b /tmp/x; https://u:p@h/x"
    out = git_hosts.redact(msg)
    assert "ghp_secret" not in out and "u:p" not in out and "https://***@github.com/a/b" in out


def test_start_scan_schemas_apply_the_allowlist(monkeypatch):
    monkeypatch.delenv("GIT_ALLOWED_HOSTS", raising=False)
    GithubContextSchema(repo_url="https://github.com/a/b", PAT="x")
    with pytest.raises(ValidationError, match="GIT_ALLOWED_HOSTS"):
        GitlabContextSchema(repo_url="https://gitlab.corp/a/b", PAT="x")
    with pytest.raises(ValidationError, match="https://"):
        BitbucketContextSchema(repo_url="http://bitbucket.org/a/b", PAT="x")
    monkeypatch.setenv("GIT_ALLOWED_HOSTS", "gitlab.corp")
    GitlabContextSchema(repo_url="https://gitlab.corp/a/b", PAT="x")


def test_backend_and_worker_copies_are_identical():
    backend = (REPO / "backend/utilities/git_hosts.py").read_bytes()
    worker = (REPO / "RabbitMQ/worker/helpers/context/git_hosts.py").read_bytes()
    assert backend == worker, "keep backend/utilities/git_hosts.py and the worker copy byte-identical"
