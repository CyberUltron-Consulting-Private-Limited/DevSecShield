"""Self-tests for the "no new findings" gates embedded in the reusable workflows.

The gates are Python heredocs inside the workflow files (so a workflow called from another repository needs no extra
checkout). These tests extract each heredoc from the YAML and run it on synthetic tool output, so a change to the gate
logic is tested before it can block, or wave through, anyone's pull request.

Properties covered:
* the SAME findings from two checkouts at DIFFERENT paths give "0 new", even when tools embed absolute paths, line
  numbers, code frames, ruff's "(130 > 88)" or a package version in their messages, and when code moved or a file
  was renamed;
* an added finding is new;
* failure modes never pass silently: a linter that did not run (exit > 1, or exit 1 with nothing readable), a base
  commit that could not be checked out on a pull request, and a linter that failed on the base commit (then every
  finding in a changed file counts as new, never every finding in the repository).

Run: python3 -m unittest discover -s .github/tests -v
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / "workflows"


def heredoc(workflow: str, marker: str) -> str:
    """The Python heredoc (<<'PY' ... PY) of the step whose script contains `marker`."""
    text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    blocks = re.findall(r"<<'PY'\n(.*?)\n[ \t]*PY\n", text, re.S)
    found = [textwrap.dedent(b) for b in blocks if marker in b]
    assert len(found) == 1, f"{workflow}: expected one heredoc containing {marker!r}, found {len(found)}"
    return found[0]


class _Run:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.summary = self.dir / "summary.md"
        self.env = dict(os.environ, GITHUB_STEP_SUMMARY=str(self.summary), RUNNER_TEMP=str(self.dir))

    def tearDown(self):
        self.tmp.cleanup()

    def run_py(self, source: str, args: list[str], env: dict | None = None, cwd: Path | None = None):
        script = self.dir / "gate.py"
        script.write_text(source, encoding="utf-8")
        return subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True,
                              env={**self.env, **(env or {})}, cwd=cwd)

    def checkouts(self, wd: str) -> tuple[Path, Path]:
        """Head checkout (the job's working directory) and base worktree, at different absolute paths."""
        head, base = self.dir / "work" / "repo" / wd, self.dir / "base" / wd
        head.mkdir(parents=True)
        base.mkdir(parents=True)
        return head, base


# --------------------------------------------------------------------------------------------------------------
# reusable-python-tests.yml, "Lint (no new findings)": `path:line[:col]: message` lines (ruff, mypy)


class LintDiff(_Run, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.head, self.base = self.checkouts("aibom")

    @staticmethod
    def tool(root: Path, i: int, out: str, rc: int):
        (root / f"out{i}.txt").write_text(out)
        (root / f"rc{i}").write_text(str(rc))

    def gate(self, head: list[tuple[str, int]], base: list[tuple[str, int]] | None = None, *, is_pr: bool = True,
             base_status: str = "ok", renames: str = "", changed: str = "", base_exists: bool = True):
        """head / base: (output, exit code) of each lint command, in order."""
        for i, (out, rc) in enumerate(head):
            self.tool(self.head, i, out, rc)
        for i, (out, rc) in enumerate(base or [("", 0)] * len(head)):
            self.tool(self.base, i, out, rc)
        if not base_exists:
            shutil.rmtree(self.base)
        (self.dir / "renames.tsv").write_text(renames)
        (self.dir / "changed.txt").write_text(changed)
        env = {"LINT_CMD": "\n".join(f'cat out{i}.txt; exit "$(cat rc{i})"' for i in range(len(head))),
               "WD": "aibom", "SUITE": "aibom", "IS_PR": "true" if is_pr else "false", "BASE_STATUS": base_status,
               "BASE_DIR": str(self.dir / "base") if base_status == "ok" else ""}
        return self.run_py(heredoc("reusable-python-tests.yml", "findings now"), [], env, cwd=self.head)

    @staticmethod
    def output(root: Path, shift: int = 0) -> str:
        return (f"src/aibom/cbom/x.py:{10 + shift}:89: E501 Line too long (112 > 88)\n"
                f"src/aibom/cbom/x.py:{30 + shift}:5: F811 Redefinition of unused `scan` from line {3 + shift}\n"
                f"src/aibom/cbom/pipeline.py:{161 + shift}: error: Argument \"seed\" has incompatible type [arg-type]\n"
                f"src/aibom/cbom/pipeline.py:{161 + shift}: note: \"list\" is invariant\n"
                f"{root}/src/aibom/cbom/abs.py:{5 + shift}:1: F401 `os` imported but unused\n"
                "Found 5 errors.\n")

    def ok(self, out, new: int):
        self.assertEqual(out.returncode, 1 if new else 0, out.stdout + out.stderr)
        self.assertRegex(out.stdout, rf"\b{new} new\b")

    # happy paths
    def test_identical_output_from_different_roots_has_no_new_findings(self):
        out = self.gate([(self.output(self.head), 1)], [(self.output(self.base), 1)])
        self.ok(out, 0)
        self.assertIn("5 findings, 0 new", out.stdout)

    def test_moved_code_and_line_references_are_not_new(self):
        self.ok(self.gate([(self.output(self.head, shift=4), 1)], [(self.output(self.base), 1)]), 0)

    def test_an_added_finding_is_new(self):
        out = self.gate([(self.output(self.head) + "src/aibom/new.py:1:1: F401 `re` imported but unused\n", 1)],
                        [(self.output(self.base), 1)])
        self.ok(out, 1)
        self.assertIn("file=aibom/src/aibom/new.py,line=1", out.stdout)

    # false reds (QA review 5856030118)
    def test_editing_a_long_line_that_stays_too_long_is_not_new(self):
        out = self.gate([("src/edit.py:1:89: E501 Line too long (125 > 88)\n", 1)],
                        [("src/edit.py:1:89: E501 Line too long (130 > 88)\n", 1)])
        self.ok(out, 0)

    def test_a_renamed_file_keeps_its_findings(self):
        body = "{p}:3:1: F401 `os` imported but unused\n{p}:9:89: E501 Line too long (130 > 88)\n"
        out = self.gate([(body.format(p="src/new_name.py"), 1)], [(body.format(p="src/old.py"), 1)],
                        renames="R100\taibom/src/old.py\taibom/src/new_name.py\n")
        self.ok(out, 0)

    # false greens: a tool that did not run is never "0 findings"
    def test_a_crashed_linter_fails(self):
        out = self.gate([("error: Failed to spawn: `ruff`\n  Caused by: No such file or directory (os error 2)\n", 2)],
                        [(self.output(self.base), 1)])
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("did not run (exit 2)", out.stdout)

    def test_exit_1_without_a_readable_finding_fails(self):
        out = self.gate([("mypy: error: Cannot find implementation or library stub for module named 'x'\n", 1)])
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("printed no `path:line: message` finding", out.stdout)

    def test_each_command_keeps_its_own_exit_code(self):
        # aibom runs ruff, then mypy: a crashed ruff must fail even when mypy is clean afterwards
        out = self.gate([("ruff: error: unknown rule selector\n", 2), ("Success: no issues found\n", 0)])
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("did not run (exit 2)", out.stdout)

    def test_a_base_that_could_not_be_checked_out_fails_on_a_pull_request(self):
        out = self.gate([(self.output(self.head), 1)], base_status="failed")
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("base commit could not be checked out", out.stdout)

    def test_a_linter_failing_on_the_base_does_not_make_every_finding_new(self):
        # only findings in files the change adds or modifies count; here the change touched no file with a finding
        crashed_base = [("ruff failed: invalid configuration\n", 2)]
        out = self.gate([(self.output(self.head), 1)], crashed_base, changed="aibom/README.md\n")
        self.ok(out, 0)
        self.assertIn("lint failed on the base commit", out.stdout)
        # ... but a finding in a changed file blocks
        out = self.gate([(self.output(self.head), 1)], crashed_base, changed="aibom/src/aibom/cbom/abs.py\n")
        self.ok(out, 1)

    def test_outside_a_pull_request_it_reports_but_a_crash_still_fails(self):
        self.ok(self.gate([(self.output(self.head), 1)], is_pr=False, base_status=""), 0)
        crash = self.gate([("Traceback (most recent call last):\n", 2)], is_pr=False, base_status="")
        self.assertEqual(crash.returncode, 1, crash.stdout)

    def test_a_project_new_in_this_change_has_every_finding_new(self):
        self.ok(self.gate([(self.output(self.head), 1)], base_exists=False), 5)

    def test_annotations_point_at_the_added_lines_with_the_tools_message(self):
        # canary PR #23: a 102-column docstring and an unused variable appended to a file that already has E501s.
        # All E501s of a file share one key, so the annotation must come from the added lines, not the first one.
        base = "src/aibom/cbom/redact.py:1:89: E501 Line too long (90 > 88)\n"
        head = base + ("src/aibom/cbom/redact.py:245:89: E501 Line too long (102 > 88)\n"
                       "src/aibom/cbom/redact.py:246:5: F841 Local variable `unused` is assigned to but never used\n")
        (self.dir / "diff.txt").write_text(
            "diff --git a/aibom/src/aibom/cbom/redact.py b/aibom/src/aibom/cbom/redact.py\n"
            "--- a/aibom/src/aibom/cbom/redact.py\n+++ b/aibom/src/aibom/cbom/redact.py\n"
            "@@ -242,0 +243,4 @@ def x():\n+\n+\n+def _ci_canary() -> None:\n+    unused = 1\n")
        out = self.gate([(head, 1)], [(base, 1)])
        self.ok(out, 2)
        self.assertIn("file=aibom/src/aibom/cbom/redact.py,line=245::aibom lint: E501 Line too long (102 > 88)", out.stdout)
        self.assertIn("line=246::aibom lint: F841", out.stdout)
        self.assertNotIn("line=1::", out.stdout)


# --------------------------------------------------------------------------------------------------------------
# reusable-frontend.yml, "ESLint (diff)"


def _eslint_report(root: Path, messages: list[tuple[str, int, str, str]]) -> list[dict]:
    """ESLint JSON: messages = (relative file, line, ruleId, message)."""
    files: dict[str, list] = {}
    for rel, line, rule, msg in messages:
        files.setdefault(rel, []).append({"ruleId": rule, "severity": 2, "message": msg, "line": line, "column": 5})
    return [{"filePath": f"{root}/{rel}", "messages": ms} for rel, ms in files.items()]


def _compiler_message(root: Path, rel: str, line: int) -> str:
    """A React Compiler (react-hooks/*) message: first line, then a code frame with the absolute path and lines."""
    return (f"Error: Calling setState synchronously within an effect can trigger cascading renders\n\n"
            f"Effects are intended to synchronize state.\n\n{root}/{rel}:{line}:5\n"
            f"  {line - 1} |\n> {line} |   setScanStatus(x);\n  {line + 1} | }}, [q]);")


PAGE = "app/[team_id]/cbom/[scan_id]/page.tsx"


class EslintDiff(_Run, unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.head, self.base = self.checkouts("frontend")

    def gate(self, head: list[dict] | None, base: list[dict] | None, *, head_rc: int = 1, base_rc: str = "1",
             is_pr: bool = True, base_status: str = "ok", renames: str = "", changed: str = ""):
        out = self.dir / "eslint"
        out.mkdir(exist_ok=True)
        if head is not None:
            (out / "head.json").write_text(json.dumps(head))
        if base is not None:
            (out / "base.json").write_text(json.dumps(base))
        (self.dir / "renames.tsv").write_text(renames)
        (self.dir / "changed.txt").write_text(changed)
        env = {"WD": "frontend", "IS_PR": "true" if is_pr else "false", "BASE_STATUS": base_status,
               "BASE_DIR": str(self.dir / "base") if base_status == "ok" else ""}
        src = heredoc("reusable-frontend.yml", "errors only; warnings never block")
        return self.run_py(src, [str(out), str(head_rc), base_rc], env, cwd=self.head)

    def findings(self, root: Path, shift: int = 0, page: str = PAGE) -> list[dict]:
        return _eslint_report(root, [
            (page, 45 + shift, "react-hooks/set-state-in-effect", _compiler_message(root, page, 45 + shift)),
            (page, 60 + shift, "react-hooks/set-state-in-effect", _compiler_message(root, page, 60 + shift)),
            ("utils/backend_api.ts", 12 + shift, "@typescript-eslint/no-explicit-any", "Unexpected any. Specify a different type."),
        ])

    def test_identical_trees_at_different_paths_have_no_new_errors(self):
        out = self.gate(self.findings(self.head), self.findings(self.base))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("new: 0", out.stdout)

    def test_moved_code_is_not_new(self):
        out = self.gate(self.findings(self.head, shift=7), self.findings(self.base))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_a_third_occurrence_of_the_same_rule_in_a_file_is_new(self):
        head = self.findings(self.head)
        head[0]["messages"].append({"ruleId": "react-hooks/set-state-in-effect", "severity": 2, "line": 90,
                                    "column": 5, "message": _compiler_message(self.head, PAGE, 90)})
        out = self.gate(head, self.findings(self.base))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("new: 1", out.stdout)

    def test_the_annotation_is_on_the_added_line(self):
        head = self.findings(self.head)
        head[1]["messages"].append({"ruleId": "@typescript-eslint/no-explicit-any", "severity": 2, "line": 40,
                                    "column": 5, "message": "Unexpected any. Specify a different type."})
        (self.dir / "diff.txt").write_text("+++ b/frontend/utils/backend_api.ts\n@@ -39,0 +40 @@\n")
        out = self.gate(head, self.findings(self.base))
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("file=frontend/utils/backend_api.ts,line=40::", out.stdout)

    def test_warnings_never_block(self):
        head = self.findings(self.head)
        head[0]["messages"].append({"ruleId": "no-console", "severity": 1, "line": 3, "column": 1, "message": "x"})
        out = self.gate(head, self.findings(self.base))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_a_renamed_file_keeps_its_errors(self):
        out = self.gate(self.findings(self.head, page="app/scans/page.tsx"), self.findings(self.base),
                        renames=f"R098\tfrontend/{PAGE}\tfrontend/app/scans/page.tsx\n")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("new: 0", out.stdout)

    def test_eslint_that_did_not_run_fails(self):
        out = self.gate(None, self.findings(self.base), head_rc=2)
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("eslint did not run", out.stdout)

    def test_a_base_that_could_not_be_checked_out_fails_on_a_pull_request(self):
        out = self.gate(self.findings(self.head), None, base_rc="none", base_status="failed")
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("base commit could not be checked out", out.stdout)

    def test_eslint_failing_on_the_base_gates_the_changed_files(self):
        # e.g. an ESLint upgrade whose new version cannot load the base's config: exit 2, no report
        out = self.gate(self.findings(self.head), None, base_rc="2", changed="frontend/package.json\n")
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("ESLint failed on the base commit", out.stdout)
        out = self.gate(self.findings(self.head), None, base_rc="2", changed="frontend/utils/backend_api.ts\n")
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("new: 1", out.stdout)

    def test_outside_a_pull_request_it_reports(self):
        out = self.gate(self.findings(self.head), None, base_rc="none", is_pr=False, base_status="")
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertIn("report only", out.stdout)


# --------------------------------------------------------------------------------------------------------------
# reusable-security.yml, findings.py (SARIF, ShellCheck json1, actionlint lines)


class SecurityFindings(_Run, unittest.TestCase):

    HEAD = "/home/runner/work/repo/repo"
    BASE = "/home/runner/work/_temp/base"

    def gate(self, fmt: str, head: str, base: str, tool: str = "t", renames: str = ""):
        (self.dir / "head").write_text(head)
        (self.dir / "base").write_text(base)
        (self.dir / "renames.tsv").write_text(renames)
        src = heredoc("reusable-security.yml", "argparse.ArgumentParser")
        env = {"GITHUB_WORKSPACE": self.HEAD, "BASE_DIR": self.BASE, "EXCLUDE_RE": r"(^|/)tests?/fixtures/",
               "RENAMES": str(self.dir / "renames.tsv")}
        return self.run_py(src, ["--tool", tool, "--format", fmt, "--head", str(self.dir / "head"),
                                 "--base", str(self.dir / "base"), "--gate", "diff"], env)

    @staticmethod
    def sarif(root: str, shift: int = 0, extra: int = 0, pillow: str = "12.1.0", lock: str = "backend/uv.lock") -> str:
        res = [{"ruleId": "CVE-2026-1", "level": "warning",
                "message": {"text": f"Package 'pillow@{pillow}' is vulnerable to 'CVE-2026-1' (also known as 'GHSA-1')"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"file://{root}/{lock}"}}}]},
               {"ruleId": "KSV001", "level": "error",
                "message": {"text": f"Artifact: deploy/helm/x.yaml\nType: helm\nLine {40 + shift}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "deploy/helm/x.yaml"},
                                                    "region": {"startLine": 40 + shift}}}]},
               {"ruleId": "planted", "level": "error", "message": {"text": "fixture"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "aibom/tests/fixtures/a.py"}}}]}]
        res += [{"ruleId": f"R{i}", "level": "error", "message": {"text": "added"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}]} for i in range(extra)]
        return json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": res}]})

    def test_sarif_from_two_roots_has_no_new_findings(self):
        out = self.gate("sarif", self.sarif(self.HEAD), self.sarif(self.BASE))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("new in this change: 0", out.stdout)

    def test_sarif_moved_lines_are_not_new_and_excluded_paths_never_count(self):
        out = self.gate("sarif", self.sarif(self.HEAD, shift=9), self.sarif(self.BASE))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("2 finding(s)", out.stdout)  # the tests/fixtures result is excluded

    def test_sarif_added_findings_are_new(self):
        out = self.gate("sarif", self.sarif(self.HEAD, extra=2), self.sarif(self.BASE))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("new in this change: 2", out.stdout)

    def test_osv_a_bump_that_leaves_the_cve_open_is_not_new(self):
        out = self.gate("sarif", self.sarif(self.HEAD, pillow="12.2.0"), self.sarif(self.BASE), tool="osv-scanner")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("new in this change: 0", out.stdout)

    def test_osv_a_new_vulnerable_package_is_new(self):
        head = json.loads(self.sarif(self.HEAD))
        head["runs"][0]["results"].append({
            "ruleId": "GHSA-462w-v97r-4m45", "level": "warning",
            "message": {"text": "Package 'jinja2@2.10' is vulnerable to 'GHSA-462w-v97r-4m45'"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "canary/requirements.txt"}}}]})
        out = self.gate("sarif", json.dumps(head), self.sarif(self.BASE), tool="osv-scanner")
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("jinja2", out.stdout)

    def test_identical_sarif_results_count_once(self):
        # OSV-Scanner writes many results twice (canary PR #23: every jinja2 advisory showed "(x2)")
        head = json.loads(self.sarif(self.HEAD))
        res = {"ruleId": "CVE-2019-10906", "level": "warning", "partialFingerprints": {"primaryLocationLineHash": "e0a0"},
               "message": {"text": "Package 'jinja2@2.10.0' is vulnerable to 'CVE-2019-10906'"},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": "canary/requirements.txt"}}}]}
        head["runs"][0]["results"] += [res, dict(res)]
        out = self.gate("sarif", json.dumps(head), self.sarif(self.BASE), tool="osv-scanner")
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("new in this change: 1", out.stdout)
        self.assertNotIn("(x2)", out.stdout)

    def test_a_renamed_file_keeps_its_findings(self):
        out = self.gate("sarif", self.sarif(self.HEAD, lock="backend/core/uv.lock"), self.sarif(self.BASE),
                        renames="R100\tbackend/uv.lock\tbackend/core/uv.lock\n")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_the_annotation_is_on_the_added_line(self):
        def sc(lines):
            return json.dumps({"comments": [{"file": "scripts/a.sh", "line": n, "code": 2086, "level": "warning",
                                             "message": "Double quote to prevent globbing."} for n in lines]})
        (self.dir / "diff.txt").write_text("+++ b/scripts/a.sh\n@@ -30,0 +31,2 @@\n")
        out = self.gate("shellcheck", sc([4, 32]), sc([4]))
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("file=scripts/a.sh,line=32::", out.stdout)

    def test_shellcheck_json_from_two_roots(self):
        def sc(root, line):
            return json.dumps({"comments": [{"file": f"{root}/scripts/a.sh", "line": line, "code": 2086,
                                             "level": "warning", "message": "Double quote to prevent globbing."}]})
        out = self.gate("shellcheck", sc(self.HEAD, 9), sc(self.BASE, 4))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_actionlint_lines(self):
        line = ".github/workflows/ci.yml:{n}:9: shellcheck reported issue in this script: SC2086 [shellcheck]\n"
        same = self.gate("lines", line.format(n=20), line.format(n=12))
        self.assertEqual(same.returncode, 0, same.stdout + same.stderr)
        new = self.gate("lines", line.format(n=20) + ".github/workflows/x.yml:1:1: bad [syntax-check]\n", line.format(n=12))
        self.assertEqual(new.returncode, 1, new.stdout + new.stderr)


if __name__ == "__main__":
    unittest.main()
