"""Self-tests for reusable-security.yml and its callers.

* Semgrep runs with --disable-nosem.
* No secret scanning (owner decision 2026-11-12, ~11:40Z): no gitleaks / ggshield job, no GitGuardian secret passed,
  and the security job's result is the scanners job's. .gitleaks.toml and .gitleaksignore may stay as files; no
  workflow runs them.
* No credential-detection rules in the scanners job either (coordinator, same day: "no security, no credential
  exposure issues"): no p/secrets, credential-rule findings are dropped from Semgrep's SARIF before the gate, Trivy
  never runs its secret scanner and Checkov no secrets framework. A PR that adds a secret-shaped literal passes.
* A merge-queue entry (merge_group) is gated in diff mode against merge_group.base_sha, as a pull request is against
  its base branch and a push against the commit before it. A queue or PR run without its base still scans the tree
  in full mode for the reports, then fails at the job's last step instead of passing report-only (#70).
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


# ----------------------------------------------------------------------------------------------------------------
# #70: the merge queue


def expression(env: str) -> str:
    """The `${{ }}` expression of a workflow-level env variable."""
    m = re.search(rf"^  {re.escape(env)}: \$\{{\{{ (.*) \}}\}}$", TEXT, re.M)
    assert m, env
    return m.group(1)


def evaluate(expr: str, context: dict) -> str:
    """Evaluate a `${{ }}` expression made of context paths, 'strings', ==, &&, || and parentheses as the runner does:
    `a && b` is b when a is truthy, else a; `a || b` is a when a is truthy, else b; null, '' and false are falsy;
    strings compare case-insensitively; the result becomes a string (null -> ''). Anything else fails the test."""
    tokens = re.findall(r"\(|\)|==|&&|\|\||'[^']*'|[A-Za-z_][\w.-]*|\S", expr)
    pos = 0

    def at(op: str) -> bool:
        return pos < len(tokens) and tokens[pos] == op

    def take() -> str:
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def primary():
        t = take()
        if t == "(":
            v = either()
            assert take() == ")", expr
            return v
        if t.startswith("'"):
            return t[1:-1]
        assert re.fullmatch(r"[A-Za-z_][\w.-]*", t), f"unsupported {t!r} in {expr}"
        v = context
        for part in t.split("."):
            v = v.get(part) if isinstance(v, dict) else None
        return v

    def equal():
        v = primary()
        while at("=="):
            take()
            r = primary()
            v = v.lower() == r.lower() if isinstance(v, str) and isinstance(r, str) else v == r
        return v

    def both():
        v = equal()
        while at("&&"):
            take()
            r = equal()
            v = r if v else v
        return v

    def either():
        v = both()
        while at("||"):
            take()
            r = both()
            v = v if v else r
        return v

    value = either()
    assert pos == len(tokens), expr
    return "" if value is None else str(value).lower() if isinstance(value, bool) else str(value)


def github(event: str, base: str, head: str) -> dict:
    """The caller's `github` context for `event` (a called workflow sees its caller's), the parts these tests read."""
    payload = {"pull_request": {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}},
               "merge_group": {"merge_group": {"base_sha": base, "head_sha": head, "base_ref": "refs/heads/dev",
                                               "head_ref": f"refs/heads/gh-readonly-queue/dev/pr-70-{head}"}},
               "push": {"before": base, "after": head}}.get(event, {})
    return {"github": {"event_name": event, "event": payload, "sha": head}}


def step(name: str) -> str:
    """The `run: |` script of the scanners job's step `name`."""
    m = re.search(rf"\n      - name: {re.escape(name)}\n(?:        (?!run:).*\n)*        run: \|\n((?:(?: {{10}}.*)?\n)+)",
                  TEXT)
    assert m, name
    return textwrap.dedent(m.group(1))


GIT_ENV = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG")} | {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

# `shellcheck -f json1 -S <severity> <file>...`: SC2164 (a warning) on each bare `cd <dir>` line; exit 1 if it reports
FAKE_SHELLCHECK = r"""#!/usr/bin/env python3
import json, re, sys
args, files = sys.argv[1:], []
while args:
    a = args.pop(0)
    if a in ("-f", "-S"):
        args.pop(0)
    else:
        files.append(a)
out = [{"file": f, "line": n, "column": 1, "level": "warning", "code": 2164,
        "message": "Use 'cd ... || exit' or 'cd ... || return' in case cd fails."}
       for f in files for n, line in enumerate(open(f, encoding="utf-8"), 1) if re.fullmatch(r"cd [^|;&]+", line.strip())]
print(json.dumps({"comments": out}))
sys.exit(1 if out else 0)
"""

SCAN = ("Scope and base checkout", "Findings helper", "ShellCheck (shell scripts)")
FINAL = "Fail without a base commit"  # the scanners job's last step


class MergeQueue(unittest.TestCase):
    """#70: a merge-queue entry is gated against merge_group.base_sha, as a pull request is against its base branch
    and a push against the commit before it. The tests run the scanners job's own steps, in order, on a real queue
    commit: the Scope step, the Findings helper, the ShellCheck step (a fake shellcheck sits where the Install step
    puts the real one) and the job's last step."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.repo, self.temp = root / "work" / "repo" / "repo", root / "_temp"  # $GITHUB_WORKSPACE, $RUNNER_TEMP
        self.repo.mkdir(parents=True)
        (self.temp / "bin").mkdir(parents=True)
        (self.temp / "bin" / "shellcheck").write_text(FAKE_SHELLCHECK, encoding="utf-8")
        (self.temp / "bin" / "shellcheck").chmod(0o755)
        self.git("init", "-q")
        # the target branch already has a finding; it is debt, not something the queue commit adds
        self.base = self.commit({"scripts/build.sh": "#!/bin/sh\ncd /tmp\nmake\n"})

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=self.repo, env=GIT_ENV, check=True, capture_output=True,
                              text=True).stdout.strip()

    def commit(self, files: dict[str, str]) -> str:
        for name, body in files.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(body, encoding="utf-8")
        self.git("add", "--", *files)
        self.git("commit", "-q", "-m", "change")
        return self.git("rev-parse", "HEAD")

    def run_steps(self, event: str, base: str, head: str, *names: str) -> tuple[subprocess.CompletedProcess, dict]:
        """Run the steps as the runner does: workflow, job and step env, each script under `bash -e` (the default
        shell when a step names none), and what a step writes to $GITHUB_ENV / $GITHUB_PATH passed to the later
        steps. Stops at the first step that fails. Returns the steps' output, in order (like the job log), with the
        exit code of the last step run, and the env after the last step that passed."""
        ctx = github(event, base, head)
        env_file, path_file = self.temp / "github_env", self.temp / "github_path"
        env_file.write_text("")
        path_file.write_text("")
        env = GIT_ENV | {
            "BASE_SHA": evaluate(expression("BASE_SHA"), ctx), "HEAD_SHA": evaluate(expression("HEAD_SHA"), ctx),
            "REQUESTED_MODE": input_default("mode"),
            "EXCLUDE_RE": input_default("exclude-regex"), "R": "security-reports",
            "SEVERITY": input_default("shellcheck-severity"),
            "GITHUB_EVENT_NAME": event, "GITHUB_WORKSPACE": str(self.repo), "RUNNER_TEMP": str(self.temp),
            "GITHUB_ENV": str(env_file), "GITHUB_PATH": str(path_file),
            "GITHUB_STEP_SUMMARY": str(self.temp / "summary.md")}
        out, err = [], []
        for name in names:
            res = subprocess.run(["bash", "-e", "-c", step(name)], cwd=self.repo, env=env, capture_output=True,
                                 text=True, timeout=120)
            out.append(res.stdout)
            err.append(res.stderr)
            if res.returncode:
                break
            env |= dict(line.split("=", 1) for line in env_file.read_text().splitlines() if line)
            env["PATH"] = os.pathsep.join([*reversed(path_file.read_text().splitlines()), GIT_ENV["PATH"]])
        return subprocess.CompletedProcess(res.args, res.returncode, "".join(out), "".join(err)), env

    def test_the_base_commit_of_each_event(self):
        # the PR's base branch, the queue's base, the commit before a push; nothing for a dispatch or a schedule
        base, head = "b" * 40, "c" * 40
        for event, want in {"pull_request": base, "merge_group": base, "push": base,
                            "workflow_dispatch": "", "schedule": ""}.items():
            with self.subTest(event):
                self.assertEqual(evaluate(expression("BASE_SHA"), github(event, base, head)), want)
                self.assertEqual(evaluate(expression("HEAD_SHA"), github(event, base, head)), head)

    def test_a_queue_commit_is_scanned_in_diff_mode_against_the_queue_base(self):
        head = self.commit({"scripts/deploy.sh": "#!/bin/sh\necho deploy\n"})
        res, env = self.run_steps("merge_group", self.base, head, SCAN[0])
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(env.get("MODE"), "diff", res.stdout)
        self.assertIn(f"mode=diff base={self.base} head={head}", res.stdout)
        # the base checkout is the queue's base commit, and the diff runs from there to the queue commit
        self.assertTrue((Path(env["BASE_DIR"]) / "scripts" / "build.sh").is_file())
        self.assertFalse((Path(env["BASE_DIR"]) / "scripts" / "deploy.sh").exists())
        self.assertIn("+++ b/scripts/deploy.sh", (self.temp / "diff.txt").read_text())

    def test_a_finding_the_queue_commit_adds_fails(self):
        head = self.commit({"scripts/deploy.sh": "#!/bin/sh\ncd /srv/app\n./deploy\n"})
        res, _ = self.run_steps("merge_group", self.base, head, *SCAN)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("::error file=scripts/deploy.sh,line=2::shellcheck SC2164", res.stdout)
        self.assertIn("new in this change: 1 -> FAIL", res.stdout)
        self.assertNotIn("scripts/build.sh", res.stdout)

    def test_a_queue_commit_that_adds_no_finding_passes(self):
        # the target branch's own finding (scripts/build.sh) does not block the queue
        head = self.commit({"scripts/deploy.sh": "#!/bin/sh\ncd /srv/app || exit 1\n./deploy\n"})
        res, _ = self.run_steps("merge_group", self.base, head, *SCAN, FINAL)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("new in this change: 0 -> pass", res.stdout)

    def test_a_queue_or_pr_run_without_its_base_commit_scans_in_full_mode_then_fails(self):
        # merge_group.base_sha, like a PR's base, always exists. A run that cannot find it still scans the whole tree
        # for the reports (the upload step sends security-reports/), but must not pass: the last step fails the job.
        head = self.commit({"scripts/deploy.sh": "#!/bin/sh\ncd /srv/app\n"})
        missing = "f" * 40
        for event in ("merge_group", "pull_request"):
            with self.subTest(event):
                res, env = self.run_steps(event, missing, head, *SCAN, FINAL)
                self.assertEqual(env.get("MODE"), "full", res.stdout + res.stderr)
                self.assertIn(f"::error::the {event} event's base commit {missing} is not in the checkout", res.stdout)
                # the scanner ran on the whole tree, the target branch's finding included, and only reported
                self.assertIn("shellcheck: 2 finding(s) at >= note; new in this change: n/a -> report only", res.stdout)
                report = json.loads((self.repo / "security-reports" / "shellcheck.json").read_text(encoding="utf-8"))
                self.assertEqual(sorted(c["file"] for c in report["comments"]), ["scripts/build.sh", "scripts/deploy.sh"])
                # ... and the job still fails, at its last step
                self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
                self.assertIn(f"::error::the {event} event's base commit {missing} was not in the checkout, so nothing "
                              "was gated and this run fails", res.stdout)

    def test_a_push_or_dispatch_without_a_base_still_scans_in_full_mode(self):
        # a push that creates a branch has before = 000..., a dispatch has no base: report only, and the job passes
        head = self.commit({"scripts/deploy.sh": "#!/bin/sh\ncd /srv/app\n"})
        for event, base in (("push", "0" * 40), ("workflow_dispatch", "")):
            with self.subTest(event):
                res, env = self.run_steps(event, base, head, *SCAN, FINAL)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual(env.get("MODE"), "full", res.stdout)
                self.assertIn("new in this change: n/a -> report only", res.stdout)
                self.assertNotIn("::error::", res.stdout)


if __name__ == "__main__":
    unittest.main()
