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
                  "aibom/tests/fixtures/leak/.env", "backend/tests/fixtures/real.pem"]:
            with self.subTest(p):
                self.assertTrue(self.blocked(p))

    def test_templates_public_keys_and_code_pass(self):
        for p in [".env.example", "backend/.env.sample", "keys/deploy.pub", "frontend/app/page.tsx", "docs/ci/README.md"]:
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


class Hygiene(unittest.TestCase):
    """The pr-hygiene script, on PR data as the API returns it (QA review 5856030118)."""

    def check(self, title: str, body: str, files: list[str] = (), labels: list[str] = (), base: str = "dev",
              bot: bool = False) -> subprocess.CompletedProcess:
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            pr = {"title": title, "body": body, "labels": [{"name": n} for n in labels], "base": {"ref": base},
                  "user": {"type": "Bot" if bot else "User"}}
            (Path(d) / "pr.json").write_text(json.dumps(pr))
            (Path(d) / "files.txt").write_text("\n".join(files) + "\n")
            env = dict(os.environ, GITHUB_STEP_SUMMARY=str(Path(d) / "s.md"), NEED_AC="true",
                       **{k: input_default(v) for k, v in [
                           ("TITLE_RE", "title-regex"), ("TITLE_MAX", "title-max-length"),
                           ("AC_RE", "acceptance-heading-regex"), ("FORBID_RE", "forbidden-files-regex"),
                           ("ALLOW_RE", "allowed-files-regex"), ("FIXTURE_LABEL", "secret-fixture-label"),
                           ("FIXTURE_RE", "secret-fixture-regex"), ("CONFIG_RE", "security-config-regex"),
                           ("CONFIG_LABEL", "security-config-label")]})
            return subprocess.run(["python3", "-c", hygiene_script(), str(Path(d) / "pr.json"), str(Path(d) / "files.txt")],
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

    def test_dependabot_actions_bump_needs_the_security_label(self):
        files = [".github/workflows/ci.yml"]
        out = self.check("chore(deps): bump actions/checkout from 7.0.1 to 7.0.2", "Bumps ...", files, bot=True)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("security-config-reviewed", out.stdout)
        out = self.check("chore(deps): bump actions/checkout from 7.0.1 to 7.0.2", "Bumps ...", files,
                         labels=["security-config-reviewed"], bot=True)
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_modified_env_file_blocks_a_promotion(self):
        out = self.check("release: promote staging to main", self.body("run 1"), ["backend/.env"], base="main")
        self.assertEqual(out.returncode, 1, out.stdout)


if __name__ == "__main__":
    unittest.main()
