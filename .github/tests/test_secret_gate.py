"""Self-tests for the gitleaks step of reusable-security.yml (security re-review 5856745968).

* A promotion head's gitleaks config and .gitleaksignore are used only for a PROTECTED, same-repository head listed
  in trusted-heads; otherwise the base commit's. An unprotected dev can take a direct push that allowlists its own
  secret.
* Only 4-field fingerprints (commit:file:rule:line) survive in .gitleaksignore; a 3-field line would apply to every
  commit.
* Semgrep runs with --disable-nosem.
Run: python3 -m unittest discover -s .github/tests -v
"""

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

TEXT = (Path(__file__).resolve().parents[1] / "workflows" / "reusable-security.yml").read_text(encoding="utf-8")


def heredoc(marker: str) -> str:
    blocks = [textwrap.dedent(b) for b in re.findall(r"<<'PY'\n(.*?)\n[ \t]*PY\n", TEXT, re.S) if marker in b]
    assert len(blocks) == 1, marker
    return blocks[0]


class TrustedHead(unittest.TestCase):
    def source(self, head_ref: str, protected: str, head_repo: str = "o/r", pr: str = "16") -> str:
        env = dict(os.environ, PR_NUMBER=pr, HEAD_REF=head_ref, HEAD_REPO=head_repo, GITHUB_REPOSITORY="o/r",
                   TRUSTED_HEADS="dev staging", PROTECTED=protected)
        out = subprocess.run([sys.executable, "-c", heredoc("gitleaks config source")], env=env, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip()

    def test_a_protected_promotion_head_is_trusted(self):
        self.assertEqual(self.source("dev", "true"), "head")
        self.assertEqual(self.source("staging", "true"), "head")

    def test_an_unprotected_promotion_head_is_not(self):
        # the review's repro: a direct push to an unprotected dev that allowlists its own secret
        self.assertEqual(self.source("dev", "false"), "base")
        self.assertEqual(self.source("dev", ""), "base")  # the API call failed

    def test_forks_unlisted_heads_and_pushes_are_not(self):
        self.assertEqual(self.source("dev", "true", head_repo="fork/r"), "base")
        self.assertEqual(self.source("feature/x", "true"), "base")
        self.assertEqual(self.source("hotfix/y", "true"), "base")
        self.assertEqual(self.source("dev", "true", pr=""), "base")


class IgnoreFile(unittest.TestCase):
    def test_only_commit_fingerprints_survive(self):
        sha = "8314739da8e6c09d9825c570faaccbf35056d5b6"
        lines = ["# baseline", "", f"{sha}:backend/.env:generic-api-key:3",
                 "backend/config.py:github-pat:2",            # 3-field: matches that line in every commit
                 "github-pat", f"{sha[:12]}:a.py:github-pat:1"]  # short SHA: not a gitleaks commit fingerprint
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".gitleaksignore"
            p.write_text("\n".join(lines) + "\n")
            out = subprocess.run([sys.executable, "-c", heredoc("without a commit SHA"), str(p)], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(p.read_text().splitlines(), ["# baseline", "", f"{sha}:backend/.env:generic-api-key:3"])
            self.assertIn("3 without a commit SHA dropped", out.stdout)
            self.assertIn("::warning file=.gitleaksignore::", out.stdout)

    def test_the_committed_baseline_is_all_commit_fingerprints(self):
        path = Path(__file__).resolve().parents[2] / ".gitleaksignore"
        bad = [l for l in path.read_text().splitlines()
               if l.strip() and not l.startswith("#") and not re.match(r"[0-9a-f]{40}:[^:]+:[\w-]+:\d+$", l.strip())]
        self.assertEqual(bad, [])


class Semgrep(unittest.TestCase):
    def test_inline_nosemgrep_is_not_honoured(self):
        self.assertRegex(TEXT, r"args=\(scan [^)]*--disable-nosem")


if __name__ == "__main__":
    unittest.main()
