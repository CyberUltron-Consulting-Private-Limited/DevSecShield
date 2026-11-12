"""Self-tests for reusable-pr-checks.yml: the branch-flow script and the pr-hygiene step.

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


def hygiene_script() -> str:
    blocks = [textwrap.dedent(b) for b in re.findall(r"<<'PY'\n(.*?)\n[ \t]*PY\n", TEXT, re.S) if "TITLE_RE" in b]
    assert len(blocks) == 1
    return blocks[0]


TEMPLATE = (Path(__file__).resolve().parents[1] / "pull_request_template.md").read_text(encoding="utf-8")
PROMOTION = (Path(__file__).resolve().parents[1] / "PULL_REQUEST_TEMPLATE" / "promotion.md").read_text(encoding="utf-8")


class Hygiene(unittest.TestCase):
    """The pr-hygiene script, on PR data as the API returns it (QA review 5856030118)."""

    def check(self, title: str, body: str, base: str = "dev", bot: bool = False) -> subprocess.CompletedProcess:
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            pr = {"title": title, "body": body, "base": {"ref": base}, "user": {"type": "Bot" if bot else "User"}}
            (Path(d) / "pr.json").write_text(json.dumps(pr))
            env = dict(os.environ, GITHUB_STEP_SUMMARY=str(Path(d) / "s.md"), NEED_AC="true",
                       **{k: input_default(v) for k, v in [
                           ("TITLE_RE", "title-regex"), ("TITLE_MAX", "title-max-length"),
                           ("AC_RE", "acceptance-heading-regex")]})
            return subprocess.run(["python3", "-c", hygiene_script(), str(Path(d) / "pr.json")],
                                  env=env, capture_output=True, text=True)

    @staticmethod
    def body(*evidence: str) -> str:
        rows = "".join(f"| {i} | criterion {i} | {e} |\n" for i, e in enumerate(evidence, 1))
        return f"## Summary\n\nx\n\n## Acceptance criteria → evidence\n\n| # | Criterion | Evidence |\n|---|---|---|\n{rows}\n## Risk\n"

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


# A stand-in for `gh api <path>`: answers from the JSON fixture in FAKE_GH; any other path fails (HTTP 500).
FAKE_GH = """#!/usr/bin/env python3
import json, os, sys
path = [a for a in sys.argv[2:] if not a.startswith("-")][-1].split("?")[0]
data = json.load(open(os.environ["FAKE_GH"]))
if path not in data:
    print("gh: Server Error (HTTP 500)", file=sys.stderr)
    sys.exit(1)
print(json.dumps(data[path]))
"""


class NoReviewGates(unittest.TestCase):
    """Owner decision 2026-11-12 (~11:40Z): no secret-bearing-file rule and no review label. A PR that touches
    .github/**, scanner configs or .env files, or adds an inline suppression, passes pr-hygiene with no label."""

    WF = TEXT

    def run_step(self, files: list[dict], labels: list[str] = ()) -> subprocess.CompletedProcess:
        """The whole pr-hygiene step (bash + Python) against a fake API, as CI runs it."""
        import json
        import tempfile
        body = Hygiene.body("test_x passes", "run https://example.invalid/1")
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "bin").mkdir()
            (Path(d) / "bin" / "gh").write_text(FAKE_GH)
            (Path(d) / "bin" / "gh").chmod(0o755)
            pr = {"title": "ci: drop the review gates", "body": body, "base": {"ref": "dev"},
                  "user": {"type": "User"}, "labels": [{"name": n} for n in labels]}
            (Path(d) / "api.json").write_text(json.dumps({"repos/o/r/pulls/7": pr, "repos/o/r/pulls/7/files": files}))
            env = dict(os.environ, PATH=f"{Path(d) / 'bin'}:{os.environ['PATH']}", FAKE_GH=str(Path(d) / "api.json"),
                       GITHUB_REPOSITORY="o/r", RUNNER_TEMP=d, GITHUB_STEP_SUMMARY=str(Path(d) / "s.md"), PR="7",
                       GH_TOKEN="x", NEED_AC="true", TITLE_RE=input_default("title-regex"),
                       TITLE_MAX=input_default("title-max-length"), AC_RE=input_default("acceptance-heading-regex"))
            return subprocess.run(["bash", "-c", step_script("Title and acceptance criteria")], env=env,
                                  capture_output=True, text=True)

    def test_gate_files_secret_files_and_suppressions_pass_without_a_label(self):
        files = [{"status": "modified", "filename": ".github/workflows/ci.yml", "patch": "@@ -1 +1 @@\n+x"},
                 {"status": "removed", "filename": ".github/CODEOWNERS"},
                 {"status": "modified", "filename": ".gitleaksignore", "patch": "@@ -1 +1 @@\n+x"},
                 {"status": "added", "filename": "backend/.env", "patch": "@@ -0,0 +1 @@\n+A=1"},
                 {"status": "modified", "filename": "RabbitMQ/worker/.env", "patch": "@@ -1 +1 @@\n-A=1\n+A=2"},
                 {"status": "added", "filename": "deploy/tls/server.key", "patch": ""},
                 {"status": "modified", "filename": "backend/app.py", "patch": "@@ -1 +1 @@\n+eval(x)  # nosemgrep"}]
        out = self.run_step(files)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotIn("::error", out.stdout)

    def test_the_title_and_acceptance_table_still_fail(self):
        self.assertEqual(Hygiene().check("tidy things", Hygiene.body("x")).returncode, 1)
        self.assertEqual(Hygiene().check("ci: tidy", Hygiene.body("pending")).returncode, 1)

    def test_no_label_logic_or_secret_file_rule_is_left_in_the_workflow(self):
        jobs = self.WF[self.WF.index("\njobs:\n"):]
        self.assertNotIn("review-labels", jobs)
        for gone in ("forbidden-files-regex", "allowed-files-regex", "secret-fixture-label", "secret-fixture-regex",
                     "security-config-regex", "security-config-label", "suppression-regex"):
            with self.subTest(gone):
                self.assertNotIn(gone, self.WF)
        self.assertNotIn("pull-requests: write", self.WF)  # nothing removes labels any more
        self.assertNotIn("/files", jobs)  # pr-hygiene no longer reads the changed files


if __name__ == "__main__":
    unittest.main()
