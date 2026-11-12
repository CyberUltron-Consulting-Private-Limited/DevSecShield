"""Self-tests for reusable-pr-checks.yml: the branch-flow script and the pr-hygiene default regexes.

Both are read straight from the workflow file, so the test exercises exactly what CI runs.
Run: python3 -m unittest discover -s .github/tests -v
"""

import os
import re
import subprocess
import textwrap
import unittest
from pathlib import Path

WF = Path(__file__).resolve().parents[1] / "workflows" / "reusable-pr-checks.yml"
TEXT = WF.read_text(encoding="utf-8")


def step_script(step_name: str) -> str:
    """The `run: |` block of the named step."""
    m = re.search(rf"- name: {re.escape(step_name)}\n(?:.*\n)*?\s+run: \|\n((?:(?:\s{{10}}.*)?\n)+)", TEXT)
    assert m, step_name
    return textwrap.dedent(m.group(1))


def input_default(name: str) -> str:
    """The default of a workflow_call input (single-quoted or folded `>-` scalar)."""
    m = re.search(rf"\n      {re.escape(name)}:\n(?:        (?!default).*\n)*        default: (.*)\n((?:          .*\n)*)", TEXT)
    assert m, name
    first, rest = m.group(1), m.group(2)
    if first.strip() == ">-":
        return " ".join(line.strip() for line in rest.splitlines())
    first = first.strip()
    return first[1:-1] if first[:1] in "'\"" else first


class BranchFlow(unittest.TestCase):
    def flow(self, base: str, head: str, head_repo: str = "o/r") -> int:
        env = dict(os.environ, FLOWS=input_default("flows"), BASE=base, HEAD=head, HEAD_REPO=head_repo, REPO="o/r")
        return subprocess.run(["bash", "-c", step_script("Promotion order")], env=env, capture_output=True).returncode

    def test_promotion_order(self):
        self.assertEqual(self.flow("staging", "dev"), 0)
        self.assertEqual(self.flow("main", "staging"), 0)
        self.assertEqual(self.flow("dev", "feature/ci-pipelines"), 0)
        self.assertEqual(self.flow("dev", "main"), 0)  # back-merge after a hotfix

    def test_hotfix_route_into_main_only(self):
        self.assertEqual(self.flow("main", "hotfix/cert-expiry"), 0)
        self.assertNotEqual(self.flow("staging", "hotfix/cert-expiry"), 0)
        self.assertNotEqual(self.flow("main", "hotfixes"), 0)

    def test_skipping_a_stage_or_a_fork_is_refused(self):
        self.assertNotEqual(self.flow("staging", "feature/x"), 0)
        self.assertNotEqual(self.flow("main", "dev"), 0)
        self.assertNotEqual(self.flow("main", "staging", head_repo="fork/r"), 0)


class HygieneRegexes(unittest.TestCase):
    """The security review's path list (PR #16, review 5855812689)."""

    forbid = re.compile(input_default("forbidden-files-regex"), re.I)
    allow = re.compile(input_default("allowed-files-regex"), re.I)
    config = re.compile(input_default("security-config-regex"))

    def blocked(self, path: str) -> bool:
        return bool(self.forbid.search(path)) and not self.allow.search(path)

    def test_secret_files_are_blocked_in_any_case_and_name(self):
        for p in [".env", "backend/.env.local", "x.ENV", "backend/.ENV", "cu-devsecshield-key.PEM", "deploy/tls/server.Key",
                  "ID_RSA", ".ssh/id_rsa_prod", ".ssh/id_ed25519_sk", "keys/id_rsa.old", "secrets/aws-dev.env",
                  "compose/prod.env", ".envrc", ".aws/credentials", ".npmrc", ".pypirc", ".netrc", ".git-credentials",
                  "infra/prod.tfvars", "deploy/kubeconfig", "gcp/service-account.json", "apple/AuthKey_ABC123.p8",
                  "aibom/tests/fixtures/leak/.env", "backend/tests/fixtures/real.pem",
                  # security re-review 5856745968
                  "infra/terraform.tfstate.backup", "Downloads/accessKeys.csv", "aws/credentials.csv", ".pgpass",
                  "deploy/.htpasswd", ".s3cfg", "vpn/office.ovpn", "krb/svc.keytab", ".docker/config.json",
                  "home/ci/.docker/config.json"]:
            with self.subTest(p):
                self.assertTrue(self.blocked(p))

    def test_templates_public_keys_and_code_pass(self):
        for p in [".env.example", "backend/.env.sample", "keys/deploy.pub", "frontend/app/page.tsx", "docs/ci/README.md",
                  "docker/config.json", "docs/credentials-rotation.md"]:
            with self.subTest(p):
                self.assertFalse(self.blocked(p))

    def test_gate_files_need_the_security_label(self):
        for p in [".github/workflows/ci.yml", ".gitleaks.toml", ".gitleaksignore", "backend/.semgrepignore", ".gitattributes"]:
            with self.subTest(p):
                self.assertTrue(self.config.search(p))
        self.assertFalse(self.config.search("backend/main.py"))


def hygiene_script() -> str:
    blocks = [textwrap.dedent(b) for b in re.findall(r"<<'PY'\n(.*?)\n[ \t]*PY\n", TEXT, re.S) if "TITLE_RE" in b]
    assert len(blocks) == 1
    return blocks[0]


TEMPLATE = (Path(__file__).resolve().parents[1] / "pull_request_template.md").read_text(encoding="utf-8")
PROMOTION = (Path(__file__).resolve().parents[1] / "PULL_REQUEST_TEMPLATE" / "promotion.md").read_text(encoding="utf-8")


# A stand-in for the `gh` CLI: `gh api [-H h] [--jq .a.b] <path>` answers from a JSON fixture (FAKE_GH), keyed by the
# path without per_page/page (lists are paged as the API does). {"__status__": N} answers HTTP N; a path that is not
# in the fixture answers HTTP 500, so a test never reaches the real API. Every request is appended to FAKE_GH.log.
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys, urllib.parse
args, path, jq = sys.argv[2:], None, None
i = 0
while i < len(args):
    if args[i] in ("-H", "--header", "--jq", "-X", "--method"):
        if args[i] == "--jq":
            jq = args[i + 1]
        i += 2
        continue
    if not args[i].startswith("-"):
        path = args[i]
    i += 1
with open(os.environ["FAKE_GH"] + ".log", "a") as log:
    log.write(path + "\n")
data = json.load(open(os.environ["FAKE_GH"]))
u = urllib.parse.urlsplit(path)
q = dict(urllib.parse.parse_qsl(u.query))
page, per = int(q.pop("page", 1)), int(q.pop("per_page", 30))
key = u.path + ("?" + urllib.parse.urlencode(sorted(q.items())) if q else "")
v = data.get(key, {"__status__": 500})
if isinstance(v, dict) and "__status__" in v:
    print(f"gh: {'Not Found' if v['__status__'] == 404 else 'Server Error'} (HTTP {v['__status__']})", file=sys.stderr)
    sys.exit(1)
if isinstance(v, str):
    sys.stdout.write(v)
    sys.exit(0)
if isinstance(v, list):
    v = v[(page - 1) * per:page * per]
for part in (jq or ".").strip(".").split(".") if jq and jq != "." else []:
    v = v[part]
print(str(v).lower() if isinstance(v, bool) else v if isinstance(v, str) else json.dumps(v))
'''


def fake_gh(d: Path, fixture: dict) -> dict:
    """Install the fake gh in d/bin; returns the env entries that make every `gh` call use it."""
    import json
    (d / "bin").mkdir(exist_ok=True)
    (d / "bin" / "gh").write_text(FAKE_GH)
    (d / "bin" / "gh").chmod(0o755)
    (d / "gh.json").write_text(json.dumps(fixture))
    return {"PATH": f"{d / 'bin'}:{os.environ['PATH']}", "FAKE_GH": str(d / "gh.json")}


def gh_requests(env: dict) -> list[str]:
    p = Path(env["FAKE_GH"] + ".log")
    return p.read_text().splitlines() if p.exists() else []


class HygieneCase(unittest.TestCase):
    """Runs the pr-hygiene script on PR data as the API returns it."""

    def check(self, title: str, body: str, files: list = (), labels: list[str] = (), base: str = "dev",
              bot: bool = False, head: str = "feature/x", head_repo: str = "o/r",
              gh: dict | None = None) -> subprocess.CompletedProcess:
        """files: paths (status "modified", a one-line patch) or dicts as the pulls/<n>/files API returns them.
        gh: the fake API's fixture (default: empty, every call fails). The result also carries .outputs (GITHUB_OUTPUT)
        and .paths (the gate files handed to the review-coverage step)."""
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            pr = {"title": title, "body": body, "labels": [{"name": n} for n in labels], "base": {"ref": base},
                  "head": {"ref": head, "repo": {"full_name": head_repo}}, "user": {"type": "Bot" if bot else "User"}}
            (Path(d) / "pr.json").write_text(json.dumps(pr))
            entries = [f if isinstance(f, dict) else {"status": "modified", "filename": f, "patch": "@@ -1 +1 @@\n+x"}
                       for f in files]
            (Path(d) / "files.txt").write_text("".join(json.dumps(e) + "\n" for e in entries))
            (Path(d) / "tmp").mkdir()
            env = dict(os.environ, GITHUB_STEP_SUMMARY=str(Path(d) / "s.md"), NEED_AC="true", GITHUB_REPOSITORY="o/r",
                       GITHUB_OUTPUT=str(Path(d) / "out"), RUNNER_TEMP=str(Path(d) / "tmp"),
                       **fake_gh(Path(d), gh or {}),
                       **{k: input_default(v) for k, v in [
                           ("TITLE_RE", "title-regex"), ("TITLE_MAX", "title-max-length"),
                           ("AC_RE", "acceptance-heading-regex"), ("FORBID_RE", "forbidden-files-regex"),
                           ("ALLOW_RE", "allowed-files-regex"), ("FIXTURE_LABEL", "secret-fixture-label"),
                           ("FIXTURE_RE", "secret-fixture-regex"), ("CONFIG_RE", "security-config-regex"),
                           ("CONFIG_LABEL", "security-config-label"), ("SUPPRESS_RE", "suppression-regex"),
                           ("TRUSTED_HEADS", "trusted-heads"), ("PROMOTION_BASES", "promotion-bases"),
                           ("PRODUCTION_BRANCH", "production-branch")]})
            out = subprocess.run(["python3", "-c", hygiene_script(), str(Path(d) / "pr.json"), str(Path(d) / "files.txt")],
                                 env=env, capture_output=True, text=True)
            o = Path(d) / "out"
            out.outputs = dict(l.split("=", 1) for l in o.read_text().splitlines() if "=" in l) if o.exists() else {}
            p = Path(d) / "tmp" / "review-coverage" / "paths.txt"
            out.paths = p.read_text().splitlines() if p.exists() else []
            out.requests = gh_requests(env)
            return out

    @staticmethod
    def body(*evidence: str) -> str:
        rows = "".join(f"| {i} | criterion {i} | {e} |\n" for i, e in enumerate(evidence, 1))
        return f"## Summary\n\nx\n\n## Acceptance criteria → evidence\n\n| # | Criterion | Evidence |\n|---|---|---|\n{rows}\n## Risk\n"


class Hygiene(HygieneCase):
    """The pr-hygiene script, on PR data as the API returns it (QA review 5856030118)."""

    def test_filled_table_passes(self):
        out = self.check("feat(cbom): add a thing", self.body("test_x passes", "run https://example.invalid/1",
                                                                 "test_pending_invites_are_listed passes"))
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_pending_tbd_placeholder_or_empty_rows_fail(self):
        for bad in ("pending", "Pending: run link after CI", "TBD", "wip", "N/A", "_test name_", " ", "**pending**",
                    "Run on this PR: pending first run (link added below when complete)", "Throwaway draft PR: pending",
                    "screenshot TODO"):
            with self.subTest(bad):
                out = self.check("feat(cbom): add a thing", self.body("test_x passes", bad))
                self.assertEqual(out.returncode, 1, out.stdout)

    def test_unfilled_templates_fail(self):
        self.assertEqual(self.check("feat(cbom): add a thing", TEMPLATE).returncode, 1)
        self.assertEqual(self.check("release: promote dev to staging", PROMOTION, base="staging").returncode, 1)

    def test_promotion_without_a_table_points_at_the_promotion_template(self):
        out = self.check("release: promote dev to staging", "Promote.", base="staging")
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("template=promotion.md", out.stdout)

    def test_filled_promotion_template_passes(self):
        body = re.sub(r"\| _[^|]*_ \|", "| see https://example.invalid/run/1 |", PROMOTION)
        out = self.check("release: promote dev to staging (2026-11-12)", body, base="staging")
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_github_revert_button_title_passes(self):
        title = 'Revert "feat(cbom): add scan-node heartbeat with a rather long description of the change"'
        self.assertEqual(self.check(title, self.body("ci-gate run https://example.invalid/2")).returncode, 0)
        self.assertEqual(self.check('Revert something', self.body("x")).returncode, 1)

    def test_dependabot_actions_bump_needs_the_security_label(self):
        files = [".github/workflows/ci.yml"]
        out = self.check("chore(deps): bump actions/checkout from 7.0.1 to 7.0.2", "Bumps ...", files, bot=True)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("security-config-reviewed", out.stdout)
        out = self.check("chore(deps): bump actions/checkout from 7.0.1 to 7.0.2", "Bumps ...", files,
                         labels=["security-config-reviewed"], bot=True)
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_deleting_a_gate_file_needs_the_security_label(self):
        # security re-review 5856745968: removed files were dropped before the config rule saw them
        removed = [{"status": "removed", "filename": f} for f in
                   (".github/CODEOWNERS", ".github/workflows/security-scheduled.yml", ".github/dependabot.yml")]
        out = self.check("chore: tidy", self.body("x"), removed)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("3 file(s) that configure the CI or security gates", out.stdout)
        self.assertEqual(self.check("chore: tidy", self.body("x"), removed, labels=["security-config-reviewed"]).returncode, 0)

    def test_renaming_a_gate_file_away_needs_the_security_label(self):
        moved = [{"status": "renamed", "filename": "docs/old-ci.yml", "previous_filename": ".github/workflows/ci.yml",
                  "patch": ""}]
        self.assertEqual(self.check("chore: tidy", self.body("x"), moved).returncode, 1)

    def test_deleting_a_secret_file_is_allowed(self):
        out = self.check("fix(backend): stop tracking .env", self.body("x"), [{"status": "removed", "filename": "backend/.env"}])
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_added_inline_suppressions_need_the_security_label(self):
        for line in ("+    eval(x)  # nosemgrep", "+# checkov:skip=CKV_K8S_20: reason", "+# hadolint ignore=DL3008",
                     "+# shellcheck disable=SC2086", "+  #trivy:ignore:AVD-DS-0002"):
            with self.subTest(line):
                f = [{"status": "modified", "filename": "backend/app.py", "patch": f"@@ -1,2 +1,3 @@\n a\n{line}\n b"}]
                out = self.check("feat(api): add an endpoint", self.body("x"), f)
                self.assertEqual(out.returncode, 1, out.stdout)
                self.assertIn("inline scanner suppression", out.stdout)
                self.assertEqual(self.check("feat(api): add an endpoint", self.body("x"), f, labels=["security-config-reviewed"]).returncode, 0)
        # removing a suppression, or one that was already there (context line), needs nothing
        f = [{"status": "modified", "filename": "backend/app.py", "patch": "@@ -1,2 +1,2 @@\n x  # nosemgrep\n-y  # nosemgrep\n+y"}]
        self.assertEqual(self.check("feat(api): add an endpoint", self.body("x"), f).returncode, 0)

    def test_modified_env_file_blocks_a_promotion(self):
        out = self.check("release: promote staging to main", self.body("run 1"), ["backend/.env"], base="main")
        self.assertEqual(out.returncode, 1, out.stdout)


GATE_FILES = [".github/workflows/ci.yml", ".github/workflows/reusable-image-build.yml", ".github/tests/test_ci.py"]


class PromotionGateFiles(HygieneCase):
    """Owner decision 1 (2026-11-12): in a promotion, gate files go to the review-coverage step instead of failing
    on the missing label; every other PR still needs the label."""

    PROMO = {"title": "release: promote dev to staging (2026-11-12)", "base": "staging", "head": "dev"}

    def test_a_promotion_without_the_label_hands_its_gate_files_to_the_coverage_step(self):
        out = self.check(body=self.body("run 1"), files=GATE_FILES, **self.PROMO)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertEqual(out.outputs.get("coverage"), "needed")
        self.assertEqual(out.paths, GATE_FILES)
        self.assertIn("review-coverage", out.stdout)

    def test_staging_to_main_is_a_promotion_too(self):
        out = self.check("release: promote staging to main", self.body("run 1"), GATE_FILES, base="main", head="staging")
        self.assertEqual((out.returncode, out.outputs.get("coverage")), (0, "needed"), out.stdout)

    def test_renamed_and_deleted_gate_files_are_handed_over_by_both_names(self):
        files = [{"status": "renamed", "filename": ".github/workflows/b.yml", "previous_filename": ".github/workflows/a.yml",
                  "patch": ""}, {"status": "removed", "filename": ".github/dependabot.yml"}]
        out = self.check(body=self.body("run 1"), files=files, **self.PROMO)
        self.assertEqual(sorted(out.paths), [".github/dependabot.yml", ".github/workflows/a.yml", ".github/workflows/b.yml"])

    def test_with_the_label_nothing_is_handed_over(self):
        out = self.check(body=self.body("run 1"), files=GATE_FILES, labels=["security-config-reviewed"], **self.PROMO)
        self.assertEqual((out.returncode, out.outputs.get("coverage")), (0, "none"), out.stdout)
        self.assertEqual(out.paths, [])

    def test_a_non_promotion_pr_still_needs_the_label(self):
        out = self.check("ci: tweak", self.body("run 1"), GATE_FILES, base="dev", head="ci/tweak")
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("security-config-reviewed", out.stdout)
        self.assertNotEqual(out.outputs.get("coverage"), "needed")
        # a branch merely named like a promotion head, into dev, is not a promotion either
        self.assertEqual(self.check("ci: x", self.body("run 1"), GATE_FILES, base="dev", head="staging").returncode, 1)

    def test_a_fork_or_a_hotfix_into_main_still_needs_the_label(self):
        fork = self.check(body=self.body("run 1"), files=GATE_FILES, head_repo="someone/fork", **self.PROMO)
        self.assertEqual((fork.returncode, fork.outputs.get("coverage")), (1, "none"), fork.stdout)
        hotfix = self.check("fix: cert expiry", self.body("run 1"), GATE_FILES, base="main", head="hotfix/cert")
        self.assertEqual((hotfix.returncode, hotfix.outputs.get("coverage")), (1, "none"), hotfix.stdout)

    def test_an_added_suppression_in_a_promotion_still_needs_the_label(self):
        f = [{"status": "modified", "filename": "backend/app.py", "patch": "@@ -1 +1,2 @@\n x\n+eval(y)  # nosemgrep"}]
        out = self.check(body=self.body("run 1"), files=f + GATE_FILES[:1], **self.PROMO)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("inline scanner suppression", out.stdout)
        self.assertNotIn("file(s) that configure", out.stdout)  # the gate file itself went to the coverage step
        self.assertEqual(out.paths, GATE_FILES[:1])


MAIN_BLOB = "f60f18bb37110000000000000000000000000000"
DEV_BLOB = "0c7b4b831a100000000000000000000000000000"


class RestoredSecretFile(HygieneCase):
    """Owner decision 2 (2026-11-12): a tracked secret-bearing file may be MODIFIED only back to main's exact blob."""

    MAIN = {"repos/o/r/contents/backend/.env?ref=main": {"type": "file", "path": "backend/.env", "sha": MAIN_BLOB}}

    def env_change(self, status: str = "modified", sha: str = MAIN_BLOB, **kw) -> dict:
        return {"status": status, "filename": "backend/.env", "sha": sha, "patch": "@@ -1 +1 @@\n-A=1\n+A=2", **kw}

    def test_restoring_mains_blob_passes_with_a_notice(self):
        for base, head in (("dev", "fix/env-restore"), ("staging", "dev")):
            with self.subTest(base):
                out = self.check("fix(config): restore main's env files", self.body("x"), [self.env_change()],
                                 base=base, head=head, gh=self.MAIN)
                self.assertEqual(out.returncode, 0, out.stdout)
                self.assertRegex(out.stdout, r"::notice file=backend/\.env::.*main")
                self.assertIn("repos/o/r/contents/backend/.env?ref=main", out.requests)

    def test_any_other_blob_fails(self):
        out = self.check("fix: x", self.body("x"), [self.env_change(sha=DEV_BLOB)], gh=self.MAIN)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("forbidden file", out.stdout)

    def test_adding_renaming_or_copying_never_passes(self):
        for status, extra in (("added", {}), ("renamed", {"previous_filename": "backend/env.txt"}), ("copied", {}),
                              ("changed", {})):
            with self.subTest(status):
                out = self.check("fix: x", self.body("x"), [self.env_change(status=status, **extra)], gh=self.MAIN)
                self.assertEqual(out.returncode, 1, out.stdout)

    def test_a_file_main_does_not_have_fails(self):
        out = self.check("fix: x", self.body("x"), [self.env_change()],
                         gh={"repos/o/r/contents/backend/.env?ref=main": {"__status__": 404}})
        self.assertEqual(out.returncode, 1, out.stdout)

    def test_an_api_error_fails_closed(self):
        out = self.check("fix: x", self.body("x"), [self.env_change()],
                         gh={"repos/o/r/contents/backend/.env?ref=main": {"__status__": 502}})
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("API", out.stdout)

    def test_only_the_restored_file_passes(self):
        other = {"status": "modified", "filename": "RabbitMQ/worker/.env", "sha": DEV_BLOB, "patch": "@@ -1 +1 @@\n+B=1"}
        gh = dict(self.MAIN, **{"repos/o/r/contents/RabbitMQ/worker/.env?ref=main": {"type": "file", "sha": MAIN_BLOB}})
        out = self.check("fix: x", self.body("x"), [self.env_change(), other], gh=gh)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("1 forbidden file(s) added or modified: RabbitMQ/worker/.env", out.stdout)


RULE = Path(__file__).resolve().parents[1] / "ci" / "review_coverage.py"
LABEL = "security-config-reviewed"
CI_YML = ".github/workflows/ci.yml"


class History:
    """A throwaway git repository to build promotion histories in."""

    def __init__(self, d: Path, first_branch: str = "staging"):
        self.d = d
        self.git("init", "-q", "-b", first_branch)

    def git(self, *args: str) -> str:
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@invalid", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@invalid", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        return subprocess.run(["git", "-C", str(self.d), *args], check=True, capture_output=True, text=True,
                              env=env).stdout.strip()

    def commit(self, msg: str, files: dict[str, str]) -> str:
        for name, text in files.items():
            (self.d / name).parent.mkdir(parents=True, exist_ok=True)
            (self.d / name).write_text(text)
        self.git("add", "--", *files)
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def on(self, branch: str, at: str | None = None) -> "History":
        self.git("checkout", "-q", *(["-b", branch, at] if at else [branch]))
        return self

    def merge(self, branch: str, msg: str) -> str:
        self.git("merge", "-q", "--no-ff", "-m", msg, branch)
        return self.git("rev-parse", "HEAD")


def pr(n: int, merge_sha: str | None, *, base: str = "dev", head: str = "feature/x", merged: bool = True,
       merged_at: str = "2026-11-12T08:00:00Z", head_repo: str = "o/r") -> dict:
    return {"number": n, "state": "closed" if merged else "open", "merged_at": merged_at if merged else None,
            "merge_commit_sha": merge_sha, "base": {"ref": base, "repo": {"full_name": "o/r"}},
            "head": {"ref": head, "repo": {"full_name": head_repo}}, "labels": [{"name": "size/S"}]}


def events(*evs: tuple) -> list[dict]:
    return [{"id": i, "event": e, "created_at": t, **({"label": {"name": l}} if l else {})}
            for i, (e, l, t) in enumerate(evs)]


LABELLED = events(("labeled", "size/S", "2026-11-12T06:00:00Z"), ("labeled", LABEL, "2026-11-12T07:00:00Z"),
                  ("merged", None, "2026-11-12T08:00:00Z"), ("closed", None, "2026-11-12T08:00:00Z"))
UNLABELLED = events(("labeled", "size/S", "2026-11-12T06:00:00Z"), ("merged", None, "2026-11-12T08:00:00Z"))
GITHUB_MADE = {"sha": "x", "commit": {"committer": {"name": "GitHub", "email": "noreply@github.com"},
                                      "verification": {"verified": True, "reason": "valid"}}}
LOCAL_MERGE = {"sha": "x", "commit": {"committer": {"name": "t", "email": "t@invalid"},
                                      "verification": {"verified": False, "reason": "unsigned"}}}


class ReviewCoverage(unittest.TestCase):
    """.github/ci/review_coverage.py: a gate file in a promotion needs no label when every commit in base..head that
    touches it came in through a merged PR that carried the label when it merged (owner decision 1, 2026-11-12)."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "repo").mkdir()
        self.h = History(self.root / "repo")

    def run_rule(self, base: str, head: str, api: dict, paths: list[str] = (CI_YML,)) -> subprocess.CompletedProcess:
        api = {f"repos/o/r/{k}": v for k, v in api.items()}
        env = dict(os.environ, **fake_gh(self.root, api))
        (self.root / "paths.txt").write_text("".join(p + "\n" for p in paths))
        out = subprocess.run(["python3", "-I", str(RULE), "--git-dir", str(self.h.d), "--repo", "o/r", "--base", base,
                              "--head", head, "--label", LABEL, "--promotion-bases", "staging main",
                              "--promotion-heads", "dev staging", "--paths", str(self.root / "paths.txt"),
                              "--summary", str(self.root / "summary.md")], env=env, capture_output=True, text=True)
        out.summary = (self.root / "summary.md").read_text() if (self.root / "summary.md").exists() else ""
        out.requests = gh_requests(env)
        return out

    def dev_with_labelled_pr(self):
        """staging A; dev = A + feature PR #55 (commit F touches ci.yml), merged as M."""
        h = self.h
        a = h.commit("base", {CI_YML: "v1\n", "app.py": "1\n"})
        h.on("dev", a)
        h.on("ci/x", a)
        f = h.commit("ci change", {CI_YML: "v2\n"})
        h.on("dev")
        m = h.merge("ci/x", "Merge PR #55")
        api = {f"commits/{f}/pulls": [pr(55, m, head="ci/x"), pr(82, None, base="staging", head="dev", merged=False)],
               f"commits/{m}/pulls": [pr(55, m, head="ci/x")], "issues/55/events": LABELLED}
        return a, f, m, api

    def test_every_commit_from_a_labelled_merged_pr_passes_and_names_the_pr(self):
        a, f, m, api = self.dev_with_labelled_pr()
        out = self.run_rule(a, m, api)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertRegex(out.stdout, rf"covered\s+{re.escape(CI_YML)} <- #55 \({f[:7]}")
        self.assertIn("#55", out.summary)

    def test_an_unlabelled_direct_push_fails(self):
        a, _f, _m, api = self.dev_with_labelled_pr()
        d = self.h.commit("direct push to dev", {CI_YML: "v3\n"})
        out = self.run_rule(a, d, dict(api, **{f"commits/{d}/pulls": []}))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertRegex(out.stdout, rf"NOT covered\s+{re.escape(CI_YML)}: {d[:12]}")
        self.assertIn(f"::error file={CI_YML}::", out.stdout)

    def test_a_direct_push_swept_into_a_labelled_branch_is_not_covered_by_it(self):
        h = self.h
        a = h.commit("base", {CI_YML: "v1\n", "app.py": "1\n"})
        h.on("dev", a)
        d = h.commit("direct push to dev", {CI_YML: "evil\n"})
        h.on("feat/y", d)
        g = h.commit("app change", {"app.py": "2\n"})
        h.on("dev")
        m = h.merge("feat/y", "Merge PR #56")
        api = {f"commits/{d}/pulls": [pr(56, m, head="feat/y")], f"commits/{g}/pulls": [pr(56, m, head="feat/y")],
               f"commits/{m}/pulls": [pr(56, m, head="feat/y")], "issues/56/events": LABELLED}
        out = self.run_rule(a, m, api)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("already on dev when #56 merged", out.stdout)

    def test_a_label_added_after_the_merge_or_removed_before_it_does_not_count(self):
        a, _f, m, api = self.dev_with_labelled_pr()
        late = events(("merged", None, "2026-11-12T08:00:00Z"), ("labeled", LABEL, "2026-11-12T08:05:00Z"))
        removed = events(("labeled", LABEL, "2026-11-12T07:00:00Z"), ("unlabeled", LABEL, "2026-11-12T07:30:00Z"),
                         ("merged", None, "2026-11-12T08:00:00Z"))
        for evs in (late, removed, UNLABELLED):
            with self.subTest(evs=[e["event"] for e in evs]):
                out = self.run_rule(a, m, dict(api, **{"issues/55/events": evs}))
                self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
                self.assertIn("#55 merged without", out.stdout)

    def test_an_open_or_unmerged_pr_does_not_count(self):
        a, f, m, api = self.dev_with_labelled_pr()
        api.update({f"commits/{f}/pulls": [pr(55, None, merged=False)], f"commits/{m}/pulls": []})
        out = self.run_rule(a, m, api)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("no merged PR brought it in (a direct push); 1 unmerged PR(s) contain it (#55)", out.stdout)

    def test_staging_to_main_counts_commits_a_labelled_promotion_brought_in(self):
        h = self.h
        b0 = h.commit("main", {CI_YML: "v1\n"})
        h.git("branch", "-m", "main")
        h.on("staging", b0)
        h.on("dev", b0)
        d = h.commit("direct push to dev", {CI_YML: "v2\n"})
        h.on("staging")
        ms = h.merge("dev", "Merge PR #26: promote dev to staging")
        api = {f"commits/{d}/pulls": [], f"commits/{ms}/pulls": [pr(26, ms, base="staging", head="dev")],
               "issues/26/events": LABELLED}
        out = self.run_rule(b0, ms, api)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("<- #26", out.stdout)
        out = self.run_rule(b0, ms, dict(api, **{"issues/26/events": UNLABELLED}))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)

    def promotion_merge_that_changes_the_file_itself(self):
        """main B0; staging gets PR #30 (S1 edits line 1); dev gets PR #31 (F edits line 5); promotion #40 merges dev
        into staging without the label, and its merge commit MP carries both edits (it differs from both parents)."""
        h = self.h
        b0 = h.commit("main", {CI_YML: "l1\nl2\nl3\nl4\nl5\n"})
        h.git("branch", "-m", "main")
        h.on("staging", b0)
        h.on("fix/s1", b0)
        s1 = h.commit("staging fix", {CI_YML: "L1\nl2\nl3\nl4\nl5\n"})
        h.on("staging")
        ms1 = h.merge("fix/s1", "Merge PR #30")
        h.on("dev", b0)
        h.on("ci/f", b0)
        f = h.commit("dev change", {CI_YML: "l1\nl2\nl3\nl4\nL5\n"})
        h.on("dev")
        md = h.merge("ci/f", "Merge PR #31")
        h.on("staging")
        mp = h.merge("dev", "Merge PR #40: promote dev to staging")
        self.assertEqual((self.h.d / CI_YML).read_text(), "L1\nl2\nl3\nl4\nL5\n")
        api = {f"commits/{s1}/pulls": [pr(30, ms1, base="staging", head="fix/s1")],
               f"commits/{ms1}/pulls": [pr(30, ms1, base="staging", head="fix/s1")], "issues/30/events": LABELLED,
               f"commits/{f}/pulls": [pr(31, md, head="ci/f")], f"commits/{md}/pulls": [pr(31, md, head="ci/f")],
               "issues/31/events": LABELLED,
               f"commits/{mp}/pulls": [pr(40, mp, base="staging", head="dev")], "issues/40/events": UNLABELLED,
               f"commits/{mp}": GITHUB_MADE}
        return b0, mp, api

    def test_an_earlier_promotion_that_passed_this_rule_counts_for_its_own_merge_commit(self):
        b0, mp, api = self.promotion_merge_that_changes_the_file_itself()
        out = self.run_rule(b0, mp, api)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        for n in ("#30", "#31", "#40"):
            self.assertIn(n, out.stdout)

    def test_a_merge_commit_github_did_not_make_borrows_no_review(self):
        b0, mp, api = self.promotion_merge_that_changes_the_file_itself()
        out = self.run_rule(b0, mp, dict(api, **{f"commits/{mp}": LOCAL_MERGE}))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("not made by GitHub", out.stdout)

    def test_an_api_error_fails_closed(self):
        a, f, m, api = self.dev_with_labelled_pr()
        for broken in (f"commits/{f}/pulls", "issues/55/events"):
            with self.subTest(broken):
                out = self.run_rule(a, m, dict(api, **{broken: {"__status__": 502}}))
                self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
                self.assertIn("API", out.stdout)

    def test_a_listed_path_that_no_commit_changes_is_not_covered(self):
        a, _f, m, api = self.dev_with_labelled_pr()
        out = self.run_rule(a, m, api, paths=[CI_YML, ".github/other.yml"])
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("NOT covered", out.stdout)
        self.assertIn(".github/other.yml", out.stdout)

    def test_long_pr_lists_are_read_page_by_page(self):
        a, f, m, api = self.dev_with_labelled_pr()
        many = [pr(1000 + i, None, merged=False) for i in range(150)] + [pr(55, m, head="ci/x")]
        out = self.run_rule(a, m, dict(api, **{f"commits/{f}/pulls": many}))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f"repos/o/r/commits/{f}/pulls?per_page=100&page=2", out.requests)


def coverage_step() -> str:
    return step_script("Review coverage of gate files in a promotion")


class ReviewCoverageSource(unittest.TestCase):
    """The step that runs the rule: the copy comes from the base, or from a protected trusted head, never from an
    unprotected head (mirrors the gitleaks config source in reusable-security.yml)."""

    BASE, HEAD = "b" * 40, "h" * 40
    RULE_PATH = ".github/ci/review_coverage.py"

    def run_step(self, fixture: dict, head_ref: str = "dev", head_repo: str = "o/r") -> subprocess.CompletedProcess:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "tmp" / "review-coverage").mkdir(parents=True)
            (Path(d) / "tmp" / "review-coverage" / "paths.txt").write_text(CI_YML + "\n")
            env = dict(os.environ, GITHUB_REPOSITORY="o/r", GH_TOKEN="x", RUNNER_TEMP=str(Path(d) / "tmp"),
                       GITHUB_WORKSPACE=d, GITHUB_STEP_SUMMARY=str(Path(d) / "s.md"), BASE_SHA=self.BASE,
                       HEAD_SHA=self.HEAD, BASE_REF="staging", HEAD_REF=head_ref, HEAD_REPO=head_repo,
                       TRUSTED_HEADS=input_default("trusted-heads"), PROMOTION_BASES=input_default("promotion-bases"),
                       CONFIG_LABEL=LABEL, RULE_PATH=self.RULE_PATH, **fake_gh(Path(d), fixture))
            out = subprocess.run(["bash", "-c", coverage_step()], env=env, capture_output=True, text=True)
            out.requests = gh_requests(env)
            out.summary = (Path(d) / "s.md").read_text() if (Path(d) / "s.md").exists() else ""
            return out

    def fixture(self, protected: bool, base_rule: object = None, head_rule: object = None) -> dict:
        stub = 'import sys\nprint("RULE FROM {}", " ".join(sys.argv[1:]))\nsys.exit({})\n'
        return {"repos/o/r/branches/dev": {"name": "dev", "protected": protected},
                f"repos/o/r/contents/{self.RULE_PATH}?ref={self.BASE}": base_rule or stub.format("BASE", 0),
                f"repos/o/r/contents/{self.RULE_PATH}?ref={self.HEAD}": head_rule or stub.format("HEAD", 0)}

    def test_an_unprotected_head_is_judged_by_the_bases_copy(self):
        out = self.run_step(self.fixture(protected=False))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("RULE FROM BASE", out.stdout)
        self.assertNotIn(f"ref={self.HEAD}", "\n".join(out.requests))
        self.assertIn(f"--base {self.BASE} --head {self.HEAD}", out.stdout)

    def test_a_protected_trusted_head_uses_its_own_copy(self):
        out = self.run_step(self.fixture(protected=True))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("RULE FROM HEAD", out.stdout)

    def test_a_fork_or_an_untrusted_head_never_uses_its_own_copy(self):
        fork = self.run_step(self.fixture(protected=True), head_repo="someone/fork")
        self.assertIn("RULE FROM BASE", fork.stdout)
        fx = self.fixture(protected=True)
        fx["repos/o/r/branches/release-x"] = {"protected": True}
        self.assertIn("RULE FROM BASE", self.run_step(fx, head_ref="release-x").stdout)

    def test_a_base_without_the_rule_needs_the_label(self):
        out = self.run_step(self.fixture(protected=False, base_rule={"__status__": 404}))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("has no .github/ci/review_coverage.py", out.stdout)
        self.assertIn(LABEL, out.stdout)
        self.assertIn(LABEL, out.summary)

    def test_api_errors_fail_closed(self):
        out = self.run_step(self.fixture(protected=False, base_rule={"__status__": 502}))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("API", out.stdout)
        # the branch lookup failing means "not protected": the base's copy, never the head's
        fx = self.fixture(protected=True)
        fx["repos/o/r/branches/dev"] = {"__status__": 502}
        self.assertIn("RULE FROM BASE", self.run_step(fx).stdout)

    def test_the_rules_verdict_is_the_steps_verdict(self):
        stub = 'import sys\nprint("uncovered")\nsys.exit(1)\n'
        self.assertEqual(self.run_step(self.fixture(protected=False, base_rule=stub)).returncode, 1)


def review_labels_script() -> str:
    blocks = [textwrap.dedent(b) for b in re.findall(r"<<'PY'\n(.*?)\n[ \t]*PY\n", TEXT, re.S) if "review = [" in b]
    assert len(blocks) == 1
    return blocks[0]


class ReviewLabels(unittest.TestCase):
    """review-labels: which review labels a new push outdates (security re-review 5856745968)."""

    def drop(self, labels: list[str], files: list[dict] | None) -> list[str]:
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "labels.txt").write_text("\n".join(labels) + "\n")
            if files is not None:
                (Path(d) / "new.jsonl").write_text("".join(json.dumps(f) + "\n" for f in files))
            env = dict(os.environ, CONFIG_LABEL="security-config-reviewed", FIXTURE_LABEL="secret-fixtures-reviewed",
                       CONFIG_RE=input_default("security-config-regex"), FIXTURE_RE=input_default("secret-fixture-regex"),
                       SUPPRESS_RE=input_default("suppression-regex"))
            out = subprocess.run(["python3", "-c", review_labels_script(), str(Path(d) / "labels.txt"),
                                  str(Path(d) / "new.jsonl")], env=env, capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            return [l for l in out.stdout.split("\n") if l]

    BOTH = ["security-config-reviewed", "secret-fixtures-reviewed", "size/S"]

    def test_a_new_gate_change_drops_the_config_label(self):
        self.assertEqual(self.drop(self.BOTH, [{"filename": ".gitleaksignore", "patch": "+x"}]), ["security-config-reviewed"])
        self.assertEqual(self.drop(self.BOTH, [{"filename": "docs/x.yml", "previous_filename": ".github/workflows/a.yml"}]),
                         ["security-config-reviewed"])

    def test_a_new_fixture_drops_the_fixture_label(self):
        self.assertEqual(self.drop(self.BOTH, [{"filename": "backend/tests/fixtures/k.env", "patch": "+A=1"}]),
                         ["secret-fixtures-reviewed"])

    def test_a_new_suppression_drops_the_config_label(self):
        self.assertEqual(self.drop(self.BOTH, [{"filename": "a.py", "patch": "@@ -1 +1 @@\n+x()  # nosemgrep"}]),
                         ["security-config-reviewed"])

    def test_ordinary_code_keeps_the_labels(self):
        self.assertEqual(self.drop(self.BOTH, [{"filename": "backend/app.py", "patch": "+x = 1"}]), [])

    def test_an_unreadable_comparison_drops_both(self):
        self.assertEqual(sorted(self.drop(self.BOTH, None)), ["secret-fixtures-reviewed", "security-config-reviewed"])

    def test_only_labels_that_are_present_are_dropped(self):
        self.assertEqual(self.drop(["size/S"], None), [])


if __name__ == "__main__":
    unittest.main()
