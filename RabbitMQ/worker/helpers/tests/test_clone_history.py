"""Scan option "scan git history for keys" (CBOM repository scans, WP13).

Off (default): the depth-1 clone as before, whose shallow history the engine does not read. On: a deeper clone,
capped at HISTORY_CLONE_DEPTH commits with blobs over 2 MB filtered out, and the engine reads the history
(``scan_history=True``), so a key committed and later deleted is found.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from helpers.context import scan_context
from helpers.context.scan_context import HISTORY_BLOB_FILTER, HISTORY_CLONE_DEPTH, GithubContext, clone_repo

_VCS = shutil.which("git")
_KEY = "00112233445566778899aabbccddeeff"
needs_vcs = pytest.mark.skipif(_VCS is None, reason="git binary not installed")


def _vcs(*args: str, cwd: Path) -> str:
    return subprocess.run([_VCS, *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}).stdout


def _source_with_deleted_key(base: Path) -> Path:
    src = base / "src"
    (src / "config").mkdir(parents=True)
    _vcs("init", "-q", "-b", "main", cwd=src)
    (src / "config" / "old_deploy.key").write_text(f"{_KEY}\n")
    (src / "app.py").write_text("x = 1\n")
    _vcs("add", "-A", cwd=src)
    _vcs("commit", "-q", "-m", "add", cwd=src)
    _vcs("rm", "-q", "config/old_deploy.key", cwd=src)
    _vcs("commit", "-q", "-m", "remove", cwd=src)
    (src / "app.py").write_text("x = 2\n")
    _vcs("commit", "-q", "-am", "edit", cwd=src)
    return src


@needs_vcs
def test_default_clone_is_depth_one_and_the_option_clones_history(tmp_path: Path) -> None:
    src = _source_with_deleted_key(tmp_path)
    shallow = clone_repo(f"file://{src}", branch="main")
    deep = clone_repo(f"file://{src}", branch="main", history_depth=HISTORY_CLONE_DEPTH)
    try:
        assert _vcs("rev-list", "--count", "HEAD", cwd=shallow).strip() == "1"
        assert (shallow / ".git" / "shallow").exists()
        assert _vcs("rev-list", "--count", "HEAD", cwd=deep).strip() == "3"
        assert not (deep / "config" / "old_deploy.key").exists()  # deleted at HEAD: only in history
    finally:
        shutil.rmtree(shallow, ignore_errors=True)
        shutil.rmtree(deep, ignore_errors=True)


def test_history_clone_is_capped_and_filters_large_blobs(monkeypatch) -> None:
    calls: list[dict] = []
    monkeypatch.setattr(scan_context.Repo, "clone_from", lambda url, to, **kw: calls.append(kw))
    for asked in (10**6, 5, None):
        out = clone_repo("https://github.com/o/r", branch="main", history_depth=asked)
        shutil.rmtree(out, ignore_errors=True)
    assert [(c["depth"], c.get("filter")) for c in calls] == [
        (HISTORY_CLONE_DEPTH, HISTORY_BLOB_FILTER), (5, HISTORY_BLOB_FILTER), (1, None)]
    assert all(c["env"] == scan_context.CLONE_GIT_ENV for c in calls)  # links stay plain files either way


def test_engine_caps_match_the_clone_caps() -> None:
    githistory = pytest.importorskip("aibom.cbom.githistory")
    assert HISTORY_CLONE_DEPTH == githistory.MAX_COMMITS
    assert HISTORY_BLOB_FILTER == f"blob:limit={githistory.MAX_BLOB_BYTES // 1_000_000}m"


@needs_vcs
def test_the_option_finds_a_key_that_exists_only_in_history(tmp_path: Path, monkeypatch) -> None:
    pytest.importorskip("aibom.integrations.cbom_devsecshield")
    from helpers.tools.cbom_agent import main as cbom_main

    src = _source_with_deleted_key(tmp_path)
    monkeypatch.setattr(
        cbom_main, "clone_repo_from_context",
        lambda ctx, history_depth=None: clone_repo(f"file://{src}", "main", history_depth),
    )
    context = GithubContext(repo_url="https://github.com/o/r")

    def history_rows(**option) -> list[dict]:
        run = cbom_main.CBOMAgent(context=context, **option).run_agent()  # always removes the clone
        return [r for r in run["results"] if r.get("location") == "config/old_deploy.key"]

    assert history_rows() == []  # default: depth-1 clone, history not read
    found = history_rows(scan_history=True)
    assert len(found) == 1 and found[0]["asset_type"] == "related-crypto-material"
