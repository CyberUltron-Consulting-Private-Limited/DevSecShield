#!/usr/bin/env python3
"""The scan node release version of a commit on a release branch (issue #361): derived from the branch's history, so
every promotion that ships node changes gets the next patch version without anyone editing a file.

    node_version.py [--repo DIR] [--rev REV] [--explain]

prints the version (``1.0.N``), or nothing when no promotion after the anchor changed the node yet; ``--explain``
prints JSON with the counted promotions instead. Exit 1 (with the reason on stderr) when the history cannot say.

Rule (``scan_node/release.json`` at REV: ``{"after": "<40-hex commit>", "first": "X.Y.Z"}``):

* walk REV's first-parent history (on ``staging`` every first-parent commit is a promotion merge, or a direct push)
  back to ``after``, which must be on it;
* a promotion **ships node changes** when its diff against its first parent touches ``NODE_PATHS``: the node's code
  and image (``scan_node/``), the Helm chart, and the scripts that package what is published
  (``scripts/release/``); only promotions that carry ``release.json`` count (the rule is in force from the promotion
  that brings it, so promotions that land between the anchor and that one never shift the first version);
* the first such promotion after ``after`` is released as ``first``; each later one adds 1 to the patch;
* a promotion that ships no node change keeps the version of the last one that did: its node is the same, so the
  release job finds that version published and keeps it (and refuses if the published one differs: never two
  contents under one version).

The same commit always gets the same version (re-runs, the publish workflow and the staging deploy all agree), and
the version only grows along the branch. A minor or major release is an edit of ``release.json`` (``first: 1.1.0``,
``after``: the release branch's head at the time).

Only git is used (``rev-list``, ``diff-tree`` on trees, ``show`` of one small file), so a clone with
``filter: blob:none`` and full history is enough.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

ANCHOR_FILE = "scan_node/release.json"
NODE_PATHS = ("scan_node", "deploy/helm/cbom-scan-node", "scripts/release")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REV_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")


class VersionError(Exception):
    pass


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=120)


def _out(repo: str, *args: str) -> str:
    p = _git(repo, *args)
    if p.returncode != 0:
        raise VersionError(f"git {' '.join(args[:2])} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p.stdout


def anchor(repo: str, rev: str) -> tuple[str, tuple[int, int, int]]:
    """(after, (major, minor, patch) of first) from REV's release.json."""
    try:
        data = json.loads(_out(repo, "show", f"{rev}:{ANCHOR_FILE}"))
    except ValueError as exc:
        raise VersionError(f"{ANCHOR_FILE} at {rev} is not JSON: {exc}") from None
    after, first = (data.get("after"), data.get("first")) if isinstance(data, dict) else (None, None)
    if not isinstance(after, str) or not SHA_RE.match(after):
        raise VersionError(f"{ANCHOR_FILE}: after must be a 40-character commit, not {str(after)[:60]!r}")
    m = SEMVER_RE.match(first) if isinstance(first, str) else None
    if not m:
        raise VersionError(f"{ANCHOR_FILE}: first must be X.Y.Z, not {str(first)[:60]!r}")
    return after, (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def ships_node_changes(repo: str, commit: str) -> bool:
    """Whether ``commit`` changes NODE_PATHS against its first parent (trees only; no file content is read)."""
    p = _git(repo, "diff-tree", "--quiet", "--no-commit-id", "-r", f"{commit}^1", commit, "--", *NODE_PATHS)
    if p.returncode not in (0, 1):
        raise VersionError(f"git diff-tree {commit[:12]} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return p.returncode == 1


def has_anchor_file(repo: str, commit: str) -> bool:
    """Whether ``commit`` carries ANCHOR_FILE (a tree lookup: no file content is read)."""
    return bool(_out(repo, "ls-tree", "--name-only", commit, "--", ANCHOR_FILE).strip())


def derive(repo: str, rev: str) -> dict:
    """{"version", "commit", "after", "first", "releases": [the counted promotions, oldest first]}."""
    if not REV_RE.match(rev):
        raise VersionError(f"not a revision: {rev[:60]!r}")
    commit = _out(repo, "rev-parse", "--verify", f"{rev}^{{commit}}").strip()
    after, (major, minor, patch) = anchor(repo, commit)
    chain = _out(repo, "rev-list", "--first-parent", commit).split()
    if after not in chain:
        shallow = _out(repo, "rev-parse", "--is-shallow-repository").strip() == "true"
        raise VersionError(f"{ANCHOR_FILE}: {after[:12]} is not on the first-parent history of {commit[:12]}"
                           + (" (the clone is shallow: fetch the full history)" if shallow else ""))
    since = list(reversed(chain[:chain.index(after)]))  # oldest first, the anchor itself excluded
    releases = [c for c in since if has_anchor_file(repo, c) and ships_node_changes(repo, c)]
    version = f"{major}.{minor}.{patch + len(releases) - 1}" if releases else ""
    return {"version": version, "commit": commit, "after": after, "first": f"{major}.{minor}.{patch}",
            "releases": releases}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", default=".")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--explain", action="store_true")
    args = ap.parse_args(argv[1:])
    try:
        out = derive(args.repo, args.rev)
    except VersionError as exc:
        print(f"node_version: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2) if args.explain else out["version"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
