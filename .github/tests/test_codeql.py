"""Self-tests for reusable-codeql.yml: the CodeQL configuration reaches codeql-action without a file.

codeql-action v4.39.1 refuses a `config-file` outside the workspace ("The configuration file
/home/runner/work/_temp/codeql-config.yml is outside of the workspace"); the workflow wrote it to $RUNNER_TEMP, so both
CodeQL jobs failed on every pull request once CODEQL_ENABLED was set (CI run 43236074193, jobs 131243766174 and
131243766285). The configuration now goes through the action's `config` input (a YAML string).
Run: python3 -m unittest discover -s .github/tests -v
"""

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

WF = (Path(__file__).resolve().parents[1] / "workflows" / "reusable-codeql.yml").read_text(encoding="utf-8")


def step(name: str) -> str:
    parts = re.split(r"\n      - ", WF)
    found = [p for p in parts if p.startswith(f"name: {name}\n")]
    assert len(found) == 1, name
    return found[0]


def config_output(ignore: str) -> str:
    script = textwrap.dedent(re.search(r"\n        run: \|\n((?:(?:\s{10}.*)?\n)+)", step("CodeQL config") + "\n").group(1))
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "out"
        env = dict(os.environ, IGNORE=ignore, GITHUB_OUTPUT=str(out), RUNNER_TEMP=d)
        p = subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True, timeout=30)
        assert p.returncode == 0, p.stderr
        text = out.read_text()
    m = re.fullmatch(r"config<<(\S+)\n(.*)\n\1\n", text, re.S)
    assert m, text
    return m.group(2)


class CodeqlConfig(unittest.TestCase):
    def test_no_config_file_outside_the_workspace(self):
        init = step("Initialise CodeQL")
        self.assertNotIn("config-file:", init)
        self.assertIn("config: ${{ steps.config.outputs.config }}", init)
        self.assertIn("\n        id: config\n", step("CodeQL config"))

    def test_the_config_lists_every_ignored_path(self):
        cfg = config_output("**/node_modules\n\naibom/tests/fixtures/**\n")
        self.assertEqual(cfg.splitlines(), ["name: ci", "paths-ignore:", '  - "**/node_modules"',
                                             '  - "aibom/tests/fixtures/**"'])

    def test_no_ignored_paths(self):
        self.assertEqual(config_output("").splitlines(), ["name: ci", "paths-ignore: []"])


if __name__ == "__main__":
    unittest.main()
