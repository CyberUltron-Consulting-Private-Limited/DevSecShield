"""Self-tests for reusable-security.yml and its callers.

* Semgrep runs with --disable-nosem.
* No secret scanning (owner decision 2026-11-12, ~11:40Z): no gitleaks / ggshield job, no GitGuardian secret passed,
  and the security job's result is the scanners job's. .gitleaks.toml and .gitleaksignore may stay as files; no
  workflow runs them.
* No credential-detection rules in the scanners job either (coordinator, same day: "no security, no credential
  exposure issues"): no p/secrets, credential-rule findings are dropped from Semgrep's SARIF before the gate, Trivy
  never runs its secret scanner and Checkov no secrets framework. A PR that adds a secret-shaped literal passes.
Run: python3 -m unittest discover -s .github/tests -v
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / "workflows"
TEXT = (WORKFLOWS / "reusable-security.yml").read_text(encoding="utf-8")


def heredoc(marker: str) -> str:
    blocks = [textwrap.dedent(b) for b in re.findall(r"<<'PY'[^\n]*\n(.*?)\n[ \t]*PY\n", TEXT, re.S) if marker in b]
    assert len(blocks) == 1, marker
    return blocks[0]


def input_default(name: str) -> str:
    m = re.search(rf"\n      {re.escape(name)}:\n(?:        (?!default).*\n)*        default: (.*)\n", TEXT)
    assert m, name
    v = m.group(1).strip()
    return v[1:-1] if v[:1] in "'\"" else v


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


def result(rule: str, uri: str = "backend/app.py", line: int = 3) -> dict:
    return {"ruleId": rule, "level": "error", "message": {"text": f"{rule.rsplit('.', 1)[-1]} found"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}


# Rule ids and CWE tags as Semgrep 1.181.1 reports them (p/ci p/python p/typescript p/secrets, run on generated
# secret-shaped literals and on code-analysis cases on 2026-11-12).
CREDENTIAL_RULES = {
    "generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value": "CWE-798",
    "generic.secrets.security.detected-private-key.detected-private-key": "CWE-798",
    "generic.secrets.security.detected-onfido-live-api-token.detected-onfido-live-api-token": "CWE-798",
    "python.boto3.security.hardcoded-token.hardcoded-token": "CWE-798",
    "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret": "CWE-798",
    "python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret": "CWE-522",
    "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure": "CWE-532",
}
CODE_RULES = {
    "python.lang.security.audit.eval-detected.eval-detected": "CWE-95",
    "javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-secure.express-cookie-session-no-secure": "CWE-522",
    "python.django.security.passwords.password-empty-string.password-empty-string": "CWE-521",
    "python.lang.security.audit.md5-used-as-password.md5-used-as-password": "CWE-327",
    "yaml.github-actions.security.secrets-inherit.secrets-inherit": "CWE-250",
}


class SecretShapedLiteralPassesScanners(unittest.TestCase):
    """A PR that adds secret-shaped literals passes `security / scanners`; every other rule still gates."""

    def gate(self, rules: dict[str, str]) -> tuple[subprocess.CompletedProcess, list[str]]:
        """Semgrep's SARIF for `rules` -> the step's credential filter -> findings.py in diff mode (--all-new: in a
        PR, Semgrep's --baseline-commit has already removed what the base had), exactly as the Semgrep step runs."""
        sarif = {"runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": [
            {"id": r, "properties": {"tags": [f"{c}: description"]}} for r, c in rules.items()]}},
            "results": [result(r, line=i + 1) for i, r in enumerate(rules)]}]}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "semgrep.sarif"
            path.write_text(json.dumps(sarif))
            env = dict(os.environ, CRED_CWES=input_default("semgrep-credential-cwes"),
                       CRED_RE=input_default("semgrep-credential-rule-regex"), GITHUB_STEP_SUMMARY=str(Path(d) / "s.md"),
                       GITHUB_WORKSPACE=d, BASE_DIR=d, EXCLUDE_RE=input_default("exclude-regex"), RUNNER_TEMP=d)
            filt = subprocess.run([sys.executable, "-c", heredoc("CRED_CWES"), str(path)], env=env,
                                  capture_output=True, text=True)
            self.assertEqual(filt.returncode, 0, filt.stderr)
            left = [x["ruleId"] for x in json.loads(path.read_text())["runs"][0]["results"]]
            (Path(d) / "findings.py").write_text(heredoc("argparse.ArgumentParser"))
            out = subprocess.run([sys.executable, str(Path(d) / "findings.py"), "--tool", "semgrep", "--head", str(path),
                                  "--all-new", "--min-level", input_default("semgrep-min-level"), "--gate", "diff"],
                                 env=env, capture_output=True, text=True)
            return out, left

    def test_a_pr_that_adds_secret_shaped_literals_passes(self):
        out, left = self.gate(CREDENTIAL_RULES)
        self.assertEqual(left, [])
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_every_other_rule_still_gates(self):
        out, left = self.gate({**CREDENTIAL_RULES, **CODE_RULES})
        self.assertEqual(sorted(left), sorted(CODE_RULES))  # cookie settings, password policy, md5, secrets: inherit
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)

    def test_no_secret_detection_ruleset_is_configured(self):
        configs = input_default("semgrep-configs").split()
        self.assertEqual(configs, ["p/ci", "p/python", "p/typescript", "p/dockerfile"])
        for name in ("ci.yml", "security-scheduled.yml"):  # the callers keep the default rulesets
            with self.subTest(name):
                self.assertNotIn("semgrep-configs", (WORKFLOWS / name).read_text(encoding="utf-8"))

    def test_trivy_never_runs_its_secret_scanner(self):
        self.assertNotIn("secret", input_default("trivy-scanners"))
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            text = wf.read_text(encoding="utf-8")
            for call in re.findall(r"trivy (?:fs|image|repo|rootfs|config)\b[^\n]*", text):
                with self.subTest(wf.name, call=call[:60]):
                    self.assertIn("--scanners", call)  # trivy fs and image scan secrets by default
                    self.assertNotIn("secret", call)
            with self.subTest(wf.name, check="callers"):
                self.assertNotRegex(text, r"trivy-scanners:.*secret")

    def test_checkov_runs_no_secrets_framework(self):
        self.assertNotIn("secrets", input_default("checkov-frameworks").split())
        self.assertRegex(TEXT, r"checkov -d \. --framework \$FRAMEWORKS")


if __name__ == "__main__":
    unittest.main()
