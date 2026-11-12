"""Review coverage of gate files in a promotion PR (pr-hygiene, .github/workflows/reusable-pr-checks.yml).

Owner decision 2026-11-12, "Exempt reviewed CI files": in a promotion (dev -> staging, staging -> main), a file that
configures the CI or security gates needs no `security-config-reviewed` label of its own when EVERY commit in
base..head that changes it came in through a merged pull request that carried the label when it merged.

pr-hygiene never runs the promotion head's copy of this file: it fetches the copy from the base commit, or from the
head commit only when the head branch is protected (as the gitleaks step chooses its config). It runs it with
`python3 -I` against a blobless full-history checkout; only git plumbing and `gh api` (read-only) are used.

A commit C that changes path p is covered by a pull request P when all of these hold:
  * P is one of: the merged PR the API says introduced C (`commits/C/pulls`), or the PR whose merge commit brought C
    into the head branch (the head's first-parent merge M with C reachable from M but not from M^1). The second is how
    a commit that arrived through an earlier promotion is found: the API names only the PR that introduced a commit.
  * P is merged into this repository, and its merge commit is in the head's history.
  * P brought C in: C is P's merge commit, or C is reachable from it and NOT from its first parent (the base branch
    when P merged). A direct push that a later labelled branch merely contains is not covered by that branch's PR.
  * If C is P's merge commit and a merge: GitHub made it (signature valid, committer noreply@github.com), so a merge
    crafted locally and pushed directly cannot borrow P's review.
  * P carried the label when it merged (labeled/unlabeled events replayed up to merged_at). Or, only for the merge
    commit of an earlier promotion that merged without the label: every commit that promotion brought in which
    changes p is itself covered ("an earlier promotion which passed this same rule").

"Changes p": a non-merge commit whose diff to its parent names p; a merge whose result for p differs from EVERY parent
(git's combined diff), i.e. what the merge itself introduced. Renames count under both names.

Exit 0: every path covered. 1: at least one path not covered. 2: a GitHub API or git error (fail closed).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

GITHUB_COMMITTER = "noreply@github.com"
MAX_DEPTH = 4  # earlier promotions nested inside each other
MAX_PAGES = 50


class RuleError(Exception):
    """A GitHub API or git failure: the rule cannot decide, so it fails closed."""


class Api:
    def __init__(self, repo: str):
        self.repo = repo
        self.cache: dict[str, object] = {}

    def get(self, path: str) -> object:
        if path not in self.cache:
            try:
                r = subprocess.run(["gh", "api", f"repos/{self.repo}/{path}"], capture_output=True, text=True,
                                   timeout=120, check=False)
            except (OSError, subprocess.TimeoutExpired) as e:
                raise RuleError(f"GitHub API GET {path}: {e}") from None
            if r.returncode != 0:
                raise RuleError(f"GitHub API GET {path}: {(r.stderr or r.stdout).strip()[:300]}")
            try:
                self.cache[path] = json.loads(r.stdout)
            except ValueError:
                raise RuleError(f"GitHub API GET {path}: the response is not JSON") from None
        return self.cache[path]

    def pages(self, path: str) -> list:
        out: list = []
        for page in range(1, MAX_PAGES + 1):
            chunk = self.get(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
            if not isinstance(chunk, list):
                raise RuleError(f"GitHub API GET {path}: expected a list")
            out += chunk
            if len(chunk) < 100:
                return out
        raise RuleError(f"GitHub API GET {path}: more than {MAX_PAGES} pages")


class Git:
    def __init__(self, git_dir: str):
        self.dir = git_dir
        self.parent_cache: dict[str, list[str]] = {}

    def run(self, *args: str, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
        # GIT_NO_LAZY_FETCH: the checkout is blobless and has no credentials; nothing here needs a blob.
        r = subprocess.run(["git", "-C", self.dir, "-c", "core.quotePath=false", *args], capture_output=True,
                           text=True, check=False, env={"GIT_NO_LAZY_FETCH": "1", "PATH": "/usr/bin:/bin:/usr/local/bin",
                                           "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1"})
        if r.returncode not in ok:
            raise RuleError(f"git {' '.join(args)}: {r.stderr.strip()[:300]}")
        return r

    def has_commit(self, sha: str) -> bool:
        return self.run("cat-file", "-e", f"{sha}^{{commit}}", ok=(0, 1, 128)).returncode == 0

    def is_ancestor(self, a: str, b: str) -> bool:
        return self.run("merge-base", "--is-ancestor", a, b, ok=(0, 1)).returncode == 0

    def parents(self, sha: str) -> list[str]:
        if sha not in self.parent_cache:
            self.parent_cache[sha] = self.run("rev-list", "--parents", "-n", "1", sha).stdout.split()[1:]
        return self.parent_cache[sha]

    def changes(self, tip: str, exclude: str) -> dict[str, list[str]]:
        """path -> commits (oldest first) in exclude..tip that change it (combined diff for merges, no renames)."""
        out = self.run("log", "--reverse", "--no-renames", "-c", "--name-only", "-z", "--format=%x01%H", tip,
                       f"^{exclude}").stdout
        # -z layout: \x01<sha>\0\n<path>\0<path>\0 ... per commit (a commit that changes nothing has no paths)
        touched: dict[str, list[str]] = {}
        for record in out.split("\x01")[1:]:
            sha, *names = record.split("\x00")
            for name in names:
                name = name.removeprefix("\n")
                if name:
                    touched.setdefault(name, []).append(sha.strip())
        return touched

    def first_parent_introductions(self, head: str, base: str) -> dict[str, str]:
        """commit -> the head's first-parent merge that brought it into the head branch."""
        intro: dict[str, str] = {}
        for line in self.run("rev-list", "--first-parent", "--parents", head, f"^{base}").stdout.splitlines():
            m, *ps = line.split()
            if len(ps) < 2:
                continue
            for c in self.run("rev-list", m, f"^{ps[0]}", f"^{base}").stdout.split():
                if c != m:
                    intro.setdefault(c, m)
        return intro


class Coverage:
    def __init__(self, api: Api, git: Git, args: argparse.Namespace):
        self.api, self.git, self.a = api, git, args
        self.repo = args.repo
        self.intro = git.first_parent_introductions(args.head, args.base)
        self.verdicts: dict[tuple[str, str], tuple[int | None, str]] = {}

    def candidates(self, c: str) -> list[dict]:
        found: dict[int, dict] = {}
        for p in self.api.pages(f"commits/{c}/pulls"):
            found.setdefault(p["number"], p)
        m = self.intro.get(c)
        if m:
            for p in self.api.pages(f"commits/{m}/pulls"):
                if p.get("merge_commit_sha") == m:
                    found.setdefault(p["number"], p)
        return [found[n] for n in sorted(found)]

    def labelled_at_merge(self, p: dict) -> bool:
        merged_at, state = p["merged_at"], False
        evs = sorted(self.api.pages(f"issues/{p['number']}/events"), key=lambda e: (e.get("created_at") or "", e.get("id") or 0))
        for e in evs:
            if (e.get("created_at") or "") > merged_at:
                break
            if e.get("event") in ("labeled", "unlabeled") and (e.get("label") or {}).get("name") == self.a.label:
                state = e["event"] == "labeled"
        return state

    def github_made(self, sha: str) -> bool:
        c = (self.api.get(f"commits/{sha}") or {}).get("commit") or {}
        v = c.get("verification") or {}
        return (v.get("verified") is True and v.get("reason") == "valid"
                and (c.get("committer") or {}).get("email") == GITHUB_COMMITTER)

    def is_promotion(self, p: dict) -> bool:
        head = p.get("head") or {}
        return ((p.get("base") or {}).get("ref") in self.a.promotion_bases.split()
                and head.get("ref") in self.a.promotion_heads.split()
                and (head.get("repo") or {}).get("full_name") == self.repo)

    def covered(self, c: str, path: str, depth: int = 0) -> tuple[int | None, str]:
        """(PR number, '') when covered; (None, why not) otherwise."""
        key = (c, path)
        if key in self.verdicts:
            return self.verdicts[key]
        why: list[str] = []
        unmerged: list[int] = []
        verdict: tuple[int | None, str] | None = None
        for p in self.candidates(c):
            n = p["number"]
            if not p.get("merged_at"):
                unmerged.append(n)
                continue
            if ((p.get("base") or {}).get("repo") or {}).get("full_name") != self.repo:
                why.append(f"#{n} merged into another repository")
                continue
            m = p.get("merge_commit_sha") or ""
            if not m or not self.git.has_commit(m) or not self.git.is_ancestor(m, self.a.head):
                why.append(f"#{n} merged into a branch outside this promotion")
                continue
            parents = self.git.parents(m)
            if c != m:
                if not self.git.is_ancestor(c, m):
                    why.append(f"#{n} does not contain it")
                    continue
                if parents and self.git.is_ancestor(c, parents[0]):
                    why.append(f"#{n} did not bring it in (it was already on {(p.get('base') or {}).get('ref')} "
                               f"when #{n} merged)")
                    continue
            elif len(parents) > 1 and not self.github_made(m):
                why.append(f"#{n}'s merge commit was not made by GitHub")
                continue
            if self.labelled_at_merge(p):
                verdict = (n, "")
                break
            if c == m and len(parents) > 1 and self.is_promotion(p) and depth < MAX_DEPTH:
                inner = self.git.changes(m, parents[0]).get(path, [])
                inner = [x for x in inner if x != m]
                results = [self.covered(x, path, depth + 1) for x in inner]
                if inner and all(r[0] is not None for r in results):
                    verdict = (n, "")
                    break
                why.append(f"#{n} merged without the '{self.a.label}' label, and not every commit it brought in is covered")
                continue
            why.append(f"#{n} merged without the '{self.a.label}' label")
        if verdict is None:
            # `why` holds one reason per MERGED candidate; open PRs that merely contain the commit are only counted
            reasons = why or ["no merged PR brought it in (a direct push)"]
            if unmerged:
                more = ", ..." if len(unmerged) > 5 else ""
                reasons.append(f"{len(unmerged)} unmerged PR(s) contain it ({', '.join(f'#{n}' for n in unmerged[:5])}{more})")
            verdict = (None, "; ".join(reasons))
        self.verdicts[key] = verdict
        return verdict


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--git-dir", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--promotion-bases", required=True)
    ap.add_argument("--promotion-heads", required=True)
    ap.add_argument("--paths", required=True, help="file with one gate path per line")
    ap.add_argument("--summary", help="markdown file to append the result to (GITHUB_STEP_SUMMARY)")
    a = ap.parse_args()
    with open(a.paths, encoding="utf-8") as f:
        paths = [p for p in dict.fromkeys(line.rstrip("\n") for line in f) if p]
    print(f"review coverage: {a.base[:12]}..{a.head[:12]} in {a.repo}, label '{a.label}', {len(paths)} gate file(s)")
    rows, uncovered = [], []
    try:
        git = Git(a.git_dir)
        for sha in (a.base, a.head):
            if not git.has_commit(sha):
                raise RuleError(f"commit {sha} is not in the checked-out history")
        cov = Coverage(Api(a.repo), git, a)
        touched = git.changes(a.head, a.base)
        for path in paths:
            commits = touched.get(path, [])
            if not commits:
                why = f"no commit in {a.base[:12]}..{a.head[:12]} changes it, so it cannot be attributed"
                uncovered.append((path, "-", why))
                continue
            by_pr: dict[int, list[str]] = {}
            bad = None
            for c in commits:
                n, why = cov.covered(c, path)
                if n is None:
                    bad = (path, c, why)
                    break
                by_pr.setdefault(n, []).append(c[:7])
            if bad:
                uncovered.append(bad)
            else:
                rows.append((path, ", ".join(f"#{n} ({', '.join(cs)})" for n, cs in sorted(by_pr.items()))))
    except RuleError as e:
        print(f"::error title=Review coverage::{e}. Failing closed: the '{a.label}' label is required.")
        if a.summary:
            with open(a.summary, "a", encoding="utf-8") as s:
                s.write(f"\n### Review coverage (promotion)\n\nCould not decide ({e}); the `{a.label}` label is required.\n")
        return 2
    for path, by in rows:
        print(f"  covered      {path} <- {by}")
    for path, c, why in uncovered:
        print(f"  NOT covered  {path}: {c[:12]} {why}")
        print(f"::error file={path}::{path} needs the '{a.label}' label: commit {c[:12]} {why}.")
    if a.summary:
        with open(a.summary, "a", encoding="utf-8") as s:
            s.write("\n### Review coverage (promotion)\n\n"
                    f"Gate files in {a.base[:12]}..{a.head[:12]}: a file passes without the `{a.label}` label when "
                    "every commit that changes it came in through a merged PR that carried the label.\n\n"
                    "| Gate file | Covered by (commits) |\n|---|---|\n")
            for path, by in rows:
                s.write(f"| `{path}` | {by} |\n")
            for path, c, why in uncovered:
                s.write(f"| `{path}` | **not covered**: `{c[:12]}` {why} |\n")
    if uncovered:
        print(f"::error title=Review coverage::{len(uncovered)} of {len(paths)} gate file(s) are not covered by reviewed "
              f"PRs. A security reviewer must check them and add the '{a.label}' label, then re-run this job.")
        return 1
    print(f"all {len(paths)} gate file(s) came in through PRs that carried the '{a.label}' label")
    return 0


if __name__ == "__main__":
    sys.exit(main())
