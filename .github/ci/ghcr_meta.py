#!/usr/bin/env python3
"""Decide what .github/workflows/publish-ghcr.yml publishes, and under which tags (docs/ci/README.md, "Publish images").

    ghcr_meta.py decide   reads the event from the environment, writes key=value lines (for $GITHUB_OUTPUT):
                          publish (true/false), reason, ref (what to check out), prefix, moving, api_url, release
                          (true on a release branch: staging, main), owner, registry, source
    ghcr_meta.py tags     reads PREFIX, SHA (the commit actually checked out), API_URL, RELEASE and NODE_VERSION_FILE
                          (the checked-out scan_node/zs_scan_node/__init__.py), writes sha,
                          tag=<prefix>-<sha12> (manual runs with another api_url: manual-<sha12>-<8 hex of its sha256>),
                          node_version (the scan node's VERSION) and node_release_tags (RELEASE only: "1.0.0 1.0 latest"
                          for a X.Y.Z version, just the version otherwise)

Tag scheme:
    push to dev / staging                 <branch>-<sha12>, moving <branch>
    pull_request (labeled, synchronize, reopened) from THIS repository carrying the label publish-preview
                                          pr-<n>-<head sha12>, moving pr-<n>   (forks: never)
    workflow_dispatch (inputs ref, api_url)
                                          manual-<sha12>, or manual-<sha12>-<hash8> when api_url is not the default
                                          (the frontend differs by api_url), no moving tag
Immutable tags are written once: publish-ghcr.yml reuses an existing one and never overwrites it.
Release tags (scan-node only, push to a release branch): <version>, <major.minor> and latest move with the release
branch like the moving tag (devsecshield-scan-node:1.0.0 = :staging), and the Helm chart is pushed as an OCI artifact
to <registry>/charts/cbom-scan-node:<version> (deploy/staging/README.md, "Public registry").

Environment (set by the workflow from the event; never pasted into a shell script):
    EVENT, ACTION, REPO, OWNER, REF_NAME, SHA, PR_NUMBER, PR_HEAD_SHA, PR_HEAD_REPO, PR_LABELS (JSON list of names),
    LABEL (the label of a `labeled` event), INPUT_REF, INPUT_API_URL, SERVER_URL.
A refusal (fork, missing label, other branch) is publish=false with the reason, exit 0. A malformed dispatch input
is an error (exit 1): the person who started the run should see it fail.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

PREVIEW_LABEL = "publish-preview"
BRANCHES = ("dev", "staging")
RELEASE_BRANCHES = ("staging", "main")  # only those that also publish (BRANCHES) ever release
NODE_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.-]{0,18}$")  # scripts/release/scan_node_image.sh NODE_VERSION_RE
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
DEFAULT_API_URL = "http://localhost:8000"
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
API_URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHORT_SHA_RE = re.compile(r"^[0-9a-f]{7,39}$")
OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}$")


class InputError(Exception):
    pass


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def common() -> dict[str, str]:
    owner = env("OWNER").lower()
    if not OWNER_RE.match(owner):
        raise InputError(f"unexpected repository owner {env('OWNER')!r}")
    repo = env("REPO")
    server = env("SERVER_URL") or "https://github.com"
    return {"owner": owner, "registry": f"ghcr.io/{owner}", "source": f"{server}/{repo}"}


def refuse(reason: str) -> dict[str, str]:
    return {"publish": "false", "reason": reason, "ref": "", "prefix": "", "moving": "", "api_url": "", "release": "false"}


def decide() -> dict[str, str]:
    event = env("EVENT")
    out = common()
    if event == "push":
        branch = env("REF_NAME")
        sha = env("SHA")
        if branch not in BRANCHES:
            return out | refuse(f"push to {branch!r}: only {', '.join(BRANCHES)} publish")
        if not SHA_RE.match(sha):
            raise InputError(f"unexpected commit {sha!r}")
        return out | {"publish": "true", "reason": f"push to {branch}", "ref": sha, "prefix": branch,
                      "moving": branch, "api_url": DEFAULT_API_URL,
                      "release": "true" if branch in RELEASE_BRANCHES else "false"}
    if event == "pull_request":
        number = env("PR_NUMBER")
        head_repo = env("PR_HEAD_REPO")
        if head_repo != env("REPO"):
            return out | refuse(f"PR #{number} comes from {head_repo or 'an unknown repository'} (a fork): never published")
        try:
            labels = json.loads(env("PR_LABELS") or "[]")
        except json.JSONDecodeError as exc:
            raise InputError(f"PR_LABELS is not JSON: {exc}") from exc
        action = env("ACTION")
        if action == "labeled":
            if env("LABEL") != PREVIEW_LABEL:
                return out | refuse(f"label {env('LABEL')!r} added: only {PREVIEW_LABEL!r} starts a preview")
        elif action in ("synchronize", "reopened"):
            if PREVIEW_LABEL not in labels:
                return out | refuse(f"PR #{number} does not carry {PREVIEW_LABEL!r}")
        else:
            return out | refuse(f"pull_request action {action!r} does not publish")
        if not re.fullmatch(r"[1-9][0-9]{0,6}", number):
            raise InputError(f"unexpected PR number {number!r}")
        head = env("PR_HEAD_SHA")
        if not SHA_RE.match(head):
            raise InputError(f"unexpected PR head {head!r}")
        return out | {"publish": "true", "reason": f"PR #{number} ({action}, {PREVIEW_LABEL})", "ref": head,
                      "prefix": f"pr-{number}", "moving": f"pr-{number}", "api_url": DEFAULT_API_URL, "release": "false"}
    if event == "workflow_dispatch":
        ref = env("INPUT_REF")
        api_url = env("INPUT_API_URL") or DEFAULT_API_URL
        if not REF_RE.match(ref) or ".." in ref:
            raise InputError(f"input ref {ref!r}: a branch, tag or commit (letters, digits, . _ / -)")
        if SHORT_SHA_RE.match(ref):
            # actions/checkout takes anything but 40 hex characters as a branch or tag name.
            raise InputError(f"input ref {ref!r} looks like an abbreviated commit: give the full 40-character commit")
        if not API_URL_RE.match(api_url):
            raise InputError(f"input api_url {api_url!r}: http(s)://host[:port], nothing else")
        return out | {"publish": "true", "reason": f"workflow_dispatch of {ref}", "ref": ref, "prefix": "manual",
                      "moving": "", "api_url": api_url, "release": "false"}
    return out | refuse(f"event {event!r} does not publish")


def tags() -> dict[str, str]:
    prefix = env("PREFIX")
    sha = env("SHA")
    api_url = env("API_URL") or DEFAULT_API_URL
    if not re.fullmatch(r"(dev|staging|manual|pr-[1-9][0-9]{0,6})", prefix):
        raise InputError(f"unexpected tag prefix {prefix!r}")
    if not SHA_RE.match(sha):
        raise InputError(f"unexpected commit {sha!r}")
    if not API_URL_RE.match(api_url):
        raise InputError(f"unexpected api_url {api_url!r}")
    tag = f"{prefix}-{sha[:12]}"
    if api_url != DEFAULT_API_URL:
        if prefix != "manual":
            raise InputError(f"only manual runs take another api_url ({prefix}, {api_url!r})")
        # The frontend inlines the API URL: one tag per (commit, api_url), so two hosts never share a tag.
        tag += "-" + hashlib.sha256(api_url.encode()).hexdigest()[:8]
    node_version = read_node_version(env("NODE_VERSION_FILE"))
    release = env("RELEASE") == "true"
    if release and prefix not in RELEASE_BRANCHES:
        raise InputError(f"only a release branch ({', '.join(RELEASE_BRANCHES)}) gets release tags, not {prefix!r}")
    if release and not node_version:
        raise InputError(f"no scan-node VERSION in {env('NODE_VERSION_FILE') or 'NODE_VERSION_FILE (unset)'}")
    return {"sha": sha, "tag": tag, "node_version": node_version,
            "node_release_tags": " ".join(release_tags(node_version)) if release else ""}


def read_node_version(path: str) -> str:
    """VERSION = "<v>" from the scan node's __init__.py (what staging.sh node-artifacts uses); "" when absent."""
    if not path:
        return ""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return ""
    m = re.search(r'(?m)^VERSION = "([^"\n]*)"$', text)
    if not m:
        return ""
    if not NODE_VERSION_RE.match(m.group(1)):
        raise InputError(f"scan-node VERSION {m.group(1)!r} is not a release version")
    return m.group(1)


def release_tags(version: str) -> list[str]:
    """1.2.3 -> [1.2.3, 1.2, latest]; a pre-release or other version (2.0.0-rc.1) only names itself."""
    m = SEMVER_RE.match(version)
    return [version, f"{m.group(1)}.{m.group(2)}", "latest"] if m else [version]


def main(argv: list[str]) -> int:
    commands = {"decide": decide, "tags": tags}
    if len(argv) != 2 or argv[1] not in commands:
        print(f"usage: {argv[0]} {{decide|tags}}", file=sys.stderr)
        return 2
    try:
        values = commands[argv[1]]()
    except InputError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    for key, value in values.items():
        if "\n" in value or "\r" in value:
            print(f"::error::{key} contains a line break", file=sys.stderr)
            return 1
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
