"""CB-07 review 5878689101 [minor]: the pin checks of lane.fetch, on a throwaway git repository (no network).

Each check fails closed with LaneError (the lane's exit 2, NOT JUDGED): HEAD not at the pinned commit, a work tree
that differs from it, a label file whose sha256 is not the pinned one, a scanned tree whose digest is not the pinned
one. The positive control passes every check on the untouched checkout.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from lane import fetch
from lane.labels import LaneError


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "t",
                               "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                               "GIT_COMMITTER_EMAIL": "t@t"}).stdout.strip()


@pytest.fixture
def pinned(tmp_path):
    """A checkout like `fetch.fetch` leaves it, and the spec that pins it."""
    repo = tmp_path / "bench"
    (repo / "src/a").mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    (repo / "labels.csv").write_text("case,vulnerable\nA,true\n")
    (repo / "src/a/A.java").write_text("class A { String h = \"MD5\"; }\n")
    (repo / "build.gradle").write_text("// build\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "pin")
    spec = {"commit": git(repo, "rev-parse", "HEAD"),
            "labels": {"path": "labels.csv", "sha256": fetch.sha256_file(repo / "labels.csv")},
            "scan_paths": ["build.gradle", "src"]}
    tree = tmp_path / "expected-tree"
    for rel in ("build.gradle", "src/a/A.java"):
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes((repo / rel).read_bytes())
    spec["scan_tree_sha256"] = fetch.tree_digest(tree)[0]
    return repo, spec, tmp_path / "scan"


def test_positive_control_passes_every_check(pinned):
    repo, spec, out = pinned
    fetch.verify("b", spec, repo)
    got = fetch.scan_tree("b", spec, repo, out)
    assert got == {"files": 2, "sha256": spec["scan_tree_sha256"]}
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()) == [
        "build.gradle", "src/a/A.java"]                                  # no .git, no label file


def test_a_wrong_label_sha256_is_refused(pinned):
    repo, spec, _ = pinned
    spec["labels"]["sha256"] = "0" * 64
    with pytest.raises(LaneError, match="labels.csv sha256 .* pinned 0000"):
        fetch.verify("b", spec, repo)


def test_a_label_file_edited_and_committed_is_refused(pinned):
    repo, spec, _ = pinned
    (repo / "labels.csv").write_text("case,vulnerable\nA,false\n")
    git(repo, "commit", "-qam", "relabel")
    spec["commit"] = git(repo, "rev-parse", "HEAD")                     # even at a matching commit pin
    with pytest.raises(LaneError, match="labels.csv sha256"):
        fetch.verify("b", spec, repo)


def test_head_not_at_the_pin_is_refused(pinned):
    repo, spec, _ = pinned
    (repo / "NEWS").write_text("x\n")
    git(repo, "add", "NEWS")
    git(repo, "commit", "-qm", "later")
    with pytest.raises(LaneError, match="checkout is at .* pinned " + spec["commit"]):
        fetch.verify("b", spec, repo)


def test_a_dirty_work_tree_is_refused(pinned):
    repo, spec, _ = pinned
    (repo / "src/a/A.java").write_text("class A { String h = \"SHA-256\"; }\n")
    with pytest.raises(LaneError, match="differs from the pinned commit"):
        fetch.verify("b", spec, repo)


def test_a_wrong_scan_tree_digest_is_refused(pinned):
    repo, spec, out = pinned
    spec["scan_tree_sha256"] = "f" * 64
    with pytest.raises(LaneError, match="scan tree digest .* pinned ffff"):
        fetch.scan_tree("b", spec, repo, out)


def test_an_untracked_file_in_a_scanned_directory_changes_the_digest(pinned):
    """verify() ignores untracked files (`--untracked-files=no`); the scan-tree digest is what catches one."""
    repo, spec, out = pinned
    (repo / "src/a/Planted.java").write_text("class P {}\n")
    fetch.verify("b", spec, repo)
    with pytest.raises(LaneError, match="scan tree digest"):
        fetch.scan_tree("b", spec, repo, out)
