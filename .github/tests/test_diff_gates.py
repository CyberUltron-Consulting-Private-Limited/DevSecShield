"""Self-tests for the "no new findings" comparators embedded in the reusable workflows.

The comparators are Python heredocs inside the workflow files (so a workflow called from another repository needs
no extra checkout). These tests extract each heredoc from the YAML and run it on synthetic reports, so a change to
the gate logic is tested before it can block anyone's pull request.

The key property: the SAME findings produced from two checkouts at DIFFERENT paths (head in $GITHUB_WORKSPACE, base
in $RUNNER_TEMP/base) must give "0 new", even when tools embed absolute paths, line numbers or code frames in their
messages, and even when code moved. Run: python3 -m unittest discover -s .github/tests -v
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
HEAD_ROOT = "/home/runner/work/repo/repo/frontend"
BASE_ROOT = "/home/runner/work/_temp/base/frontend"


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
        self.env = dict(os.environ, GITHUB_STEP_SUMMARY=str(self.summary), RUNNER_TEMP=str(self.dir), WD="frontend")

    def tearDown(self):
        self.tmp.cleanup()

    def run_py(self, source: str, args: list[str], env: dict | None = None) -> subprocess.CompletedProcess:
        script = self.dir / "gate.py"
        script.write_text(source, encoding="utf-8")
        return subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True,
                              env={**self.env, **(env or {})})


def _eslint_report(root: str, messages: list[tuple[str, int, str, str]]) -> list[dict]:
    """ESLint JSON: messages = (relative file, line, ruleId, message)."""
    files: dict[str, list] = {}
    for rel, line, rule, msg in messages:
        files.setdefault(rel, []).append({"ruleId": rule, "severity": 2, "message": msg, "line": line, "column": 5})
    return [{"filePath": f"{root}/{rel}", "messages": ms} for rel, ms in files.items()]


def _compiler_message(root: str, rel: str, line: int) -> str:
    """A React Compiler (react-hooks/*) message: first line, then a code frame with the absolute path and lines."""
    return (f"Error: Calling setState synchronously within an effect can trigger cascading renders\n\n"
            f"Effects are intended to synchronize state.\n\n{root}/{rel}:{line}:5\n"
            f"  {line - 1} |\n> {line} |   setScanStatus(x);\n  {line + 1} | }}, [q]);")


class EslintDiff(_Run, unittest.TestCase):
    """reusable-frontend.yml, ESLint (diff)."""

    def gate(self, head: list[dict], base: list[dict]) -> subprocess.CompletedProcess:
        (self.dir / "head.json").write_text(json.dumps(head))
        (self.dir / "base.json").write_text(json.dumps(base))
        src = heredoc("reusable-frontend.yml", "errors only; warnings never block")
        return self.run_py(src, [str(self.dir / "head.json"), str(self.dir / "base.json"), "diff", HEAD_ROOT, BASE_ROOT])

    def findings(self, root: str, shift: int = 0) -> list[dict]:
        rel = "app/[team_id]/cbom/[scan_id]/page.tsx"
        return _eslint_report(root, [
            (rel, 45 + shift, "react-hooks/set-state-in-effect", _compiler_message(root, rel, 45 + shift)),
            (rel, 60 + shift, "react-hooks/set-state-in-effect", _compiler_message(root, rel, 60 + shift)),
            ("utils/backend_api.ts", 12 + shift, "@typescript-eslint/no-explicit-any", "Unexpected any. Specify a different type."),
        ])

    def test_identical_trees_at_different_paths_have_no_new_errors(self):
        out = self.gate(self.findings(HEAD_ROOT), self.findings(BASE_ROOT))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("new: 0", out.stdout)

    def test_moved_code_is_not_new(self):
        out = self.gate(self.findings(HEAD_ROOT, shift=7), self.findings(BASE_ROOT))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_a_third_occurrence_of_the_same_rule_in_a_file_is_new(self):
        head = self.findings(HEAD_ROOT)
        rel = "app/[team_id]/cbom/[scan_id]/page.tsx"
        head[0]["messages"].append({"ruleId": "react-hooks/set-state-in-effect", "severity": 2, "line": 90,
                                    "column": 5, "message": _compiler_message(HEAD_ROOT, rel, 90)})
        out = self.gate(head, self.findings(BASE_ROOT))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("new: 1", out.stdout)

    def test_warnings_never_block(self):
        head = self.findings(HEAD_ROOT)
        head[0]["messages"].append({"ruleId": "no-console", "severity": 1, "line": 3, "column": 1, "message": "x"})
        out = self.gate(head, self.findings(BASE_ROOT))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)


class LintDiff(_Run, unittest.TestCase):
    """reusable-python-tests.yml, Lint (no new findings): `path:line[:col]: message` lines (ruff, mypy)."""

    HEAD = "/home/runner/work/repo/repo/aibom"
    BASE = "/home/runner/work/_temp/base/aibom"

    def gate(self, head: str, base: str) -> subprocess.CompletedProcess:
        (self.dir / "head.txt").write_text(head)
        (self.dir / "base.txt").write_text(base)
        src = heredoc("reusable-python-tests.yml", "findings now")
        return self.run_py(src, [str(self.dir / "head.txt"), str(self.dir / "base.txt"), "gate", "aibom lint",
                                 self.HEAD, self.BASE])

    @staticmethod
    def output(root: str, shift: int = 0) -> str:
        return (f"src/aibom/cbom/x.py:{10 + shift}:89: E501 Line too long (112 > 88)\n"
                f"src/aibom/cbom/x.py:{30 + shift}:5: F811 Redefinition of unused `scan` from line {3 + shift}\n"
                f"src/aibom/cbom/pipeline.py:{161 + shift}: error: Argument \"seed\" has incompatible type [arg-type]\n"
                f"src/aibom/cbom/pipeline.py:{161 + shift}: note: \"list\" is invariant\n"
                f"{root}/src/aibom/cbom/abs.py:{5 + shift}:1: F401 `os` imported but unused\n"
                "Found 5 errors.\n")

    def test_identical_output_from_different_roots_has_no_new_findings(self):
        out = self.gate(self.output(self.HEAD), self.output(self.BASE))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("5 findings, 0 new", out.stdout)

    def test_moved_code_and_line_references_are_not_new(self):
        out = self.gate(self.output(self.HEAD, shift=4), self.output(self.BASE))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)

    def test_an_added_finding_is_new(self):
        out = self.gate(self.output(self.HEAD) + "src/aibom/new.py:1:1: F401 `re` imported but unused\n",
                        self.output(self.BASE))
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("1 new", out.stdout)


class SecurityFindings(_Run, unittest.TestCase):
    """reusable-security.yml, findings.py (SARIF, ShellCheck json1, actionlint lines)."""

    HEAD = "/home/runner/work/repo/repo"
    BASE = "/home/runner/work/_temp/base"

    def gate(self, fmt: str, head: str, base: str, extra: list[str] | None = None) -> subprocess.CompletedProcess:
        (self.dir / "head").write_text(head)
        (self.dir / "base").write_text(base)
        src = heredoc("reusable-security.yml", "argparse.ArgumentParser")
        env = {"GITHUB_WORKSPACE": self.HEAD, "BASE_DIR": self.BASE, "EXCLUDE_RE": r"(^|/)tests?/fixtures/"}
        return self.run_py(src, ["--tool", "t", "--format", fmt, "--head", str(self.dir / "head"),
                                 "--base", str(self.dir / "base"), "--gate", "diff", *(extra or [])], env)

    @staticmethod
    def sarif(root: str, shift: int = 0, extra: int = 0) -> str:
        res = [{"ruleId": "CVE-2026-1", "level": "warning",
                "message": {"text": "Package 'pillow@12.1.0' is vulnerable to 'CVE-2026-1'"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"file://{root}/backend/uv.lock"}}}]},
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
