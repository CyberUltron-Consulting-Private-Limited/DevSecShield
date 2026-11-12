"""Self-tests for reusable-security.yml and its callers.

* Semgrep runs with --disable-nosem.
* No secret scanning (owner decision 2026-11-12, ~11:40Z): no gitleaks / ggshield job, no GitGuardian secret passed,
  and the security job's result is the scanners job's. .gitleaks.toml and .gitleaksignore may stay as files; no
  workflow runs them.
Run: python3 -m unittest discover -s .github/tests -v
"""

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / "workflows"
TEXT = (WORKFLOWS / "reusable-security.yml").read_text(encoding="utf-8")


def jobs(text: str) -> list[str]:
    """Top-level job ids under `jobs:`."""
    return re.findall(r"^  ([a-z][\w-]*):\n", text[text.index("\njobs:\n"):], re.M)


class Semgrep(unittest.TestCase):
    def test_inline_nosemgrep_is_not_honoured(self):
        self.assertRegex(TEXT, r"args=\(scan [^)]*--disable-nosem")


class NoSecretScanning(unittest.TestCase):
    def test_the_security_workflow_has_only_the_scanners_and_the_optional_sarif_upload(self):
        self.assertEqual(jobs(TEXT), ["scanners", "upload-sarif"])
        self.assertIn("needs: [scanners]", TEXT)

    def test_no_workflow_runs_gitleaks_or_ggshield(self):
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            body = "\n".join(l for l in wf.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#"))
            with self.subTest(wf.name):
                self.assertIsNone(re.search(r"\bgitleaks\s+(git|dir|detect|protect)\b|ggshield\s+secret", body))
                self.assertNotIn("GITGUARDIAN_API_KEY", body)

    def test_callers_grant_read_only_contents(self):
        for name in ("ci.yml", "security-scheduled.yml"):
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            block = text[text.index("\n  security:\n"):]
            block = block[:block.index("    uses: ./.github/workflows/reusable-security.yml")]
            with self.subTest(name):
                self.assertIn("contents: read", block)
                self.assertNotIn("pull-requests", block)


if __name__ == "__main__":
    unittest.main()
