#!/usr/bin/env python3
"""Decide what .github/workflows/publish-ghcr.yml publishes, and under which tags (docs/ci/README.md, "Publish images").

    ghcr_meta.py decide   reads the event from the environment, writes key=value lines (for $GITHUB_OUTPUT):
                          publish (true/false), reason, ref (what to check out), prefix, moving, api_url, owner,
                          registry, source
    ghcr_meta.py tags     reads PREFIX and SHA (the commit actually checked out), writes sha and tag=<prefix>-<sha12>

Tag scheme:
    push to dev / staging                 <branch>-<sha12>, moving <branch>
    pull_request (labeled, synchronize, reopened) from THIS repository carrying the label publish-preview
                                          pr-<n>-<head sha12>, moving pr-<n>   (forks: never)
    workflow_dispatch (inputs ref, api_url)
                                          manual-<sha12>, no moving tag

Environment (set by the workflow from the event; never pasted into a shell script):
    EVENT, ACTION, REPO, OWNER, REF_NAME, SHA, PR_NUMBER, PR_HEAD_SHA, PR_HEAD_REPO, PR_LABELS (JSON list of names),
    LABEL (the label of a `labeled` event), INPUT_REF, INPUT_API_URL, SERVER_URL.
A refusal (fork, missing label, other branch) is publish=false with the reason, exit 0. A malformed dispatch input
is an error (exit 1): the person who started the run should see it fail.
"""
from __future__ import annotations

import json
import os
import re
import sys

PREVIEW_LABEL = "publish-preview"
BRANCHES = ("dev", "staging")
DEFAULT_API_URL = "http://localhost:8000"
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
API_URL_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
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
    return {"publish": "false", "reason": reason, "ref": "", "prefix": "", "moving": "", "api_url": ""}


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
                      "moving": branch, "api_url": DEFAULT_API_URL}
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
                      "prefix": f"pr-{number}", "moving": f"pr-{number}", "api_url": DEFAULT_API_URL}
    if event == "workflow_dispatch":
        ref = env("INPUT_REF")
        api_url = env("INPUT_API_URL") or DEFAULT_API_URL
        if not REF_RE.match(ref) or ".." in ref:
            raise InputError(f"input ref {ref!r}: a branch, tag or commit (letters, digits, . _ / -)")
        if not API_URL_RE.match(api_url):
            raise InputError(f"input api_url {api_url!r}: http(s)://host[:port], nothing else")
        return out | {"publish": "true", "reason": f"workflow_dispatch of {ref}", "ref": ref, "prefix": "manual",
                      "moving": "", "api_url": api_url}
    return out | refuse(f"event {event!r} does not publish")


def tags() -> dict[str, str]:
    prefix = env("PREFIX")
    sha = env("SHA")
    if not re.fullmatch(r"(dev|staging|manual|pr-[1-9][0-9]{0,6})", prefix):
        raise InputError(f"unexpected tag prefix {prefix!r}")
    if not SHA_RE.match(sha):
        raise InputError(f"unexpected commit {sha!r}")
    return {"sha": sha, "tag": f"{prefix}-{sha[:12]}"}


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
