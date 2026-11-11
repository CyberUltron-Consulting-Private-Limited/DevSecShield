"""Self-tests for ci.yml: the ci-gate script and the path filters that decide which suites run.

The path-filter test reads the dorny/paths-filter rules straight from ci.yml and matches them the way the action does
(picomatch globs with dot files; the inverted backend rule needs every pattern to match). Each case is a one-file
change and the suites whose TESTS READ that file: a change that an existing test covers must run that test.
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

CI = (Path(__file__).resolve().parents[1] / "workflows" / "ci.yml").read_text(encoding="utf-8")


def gate_script() -> str:
    blocks = [textwrap.dedent(b) for b in re.findall(r"<<'PY'\n(.*?)\n[ \t]*PY\n", CI, re.S) if "expected = {" in b]
    assert len(blocks) == 1
    return blocks[0]


SUITES = ["backend", "aibom", "cbom-action", "scan-node", "worker", "dast-worker", "worker-locks", "frontend"]


class CiGate(unittest.TestCase):
    def run_gate(self, results: dict[str, str], outputs: dict[str, str], event: str = "pull_request",
                 codeql_on: str = "false") -> subprocess.CompletedProcess:
        needs = {job: {"result": r, "outputs": {}} for job, r in results.items()}
        needs["changes"] = {"result": results.get("changes", "success"), "outputs": outputs}
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, NEEDS=json.dumps(needs), EVENT=event, CODEQL_ON=codeql_on,
                       GITHUB_STEP_SUMMARY=str(Path(d) / "s.md"))
            return subprocess.run([sys.executable, "-c", gate_script()], env=env, capture_output=True, text=True)

    @staticmethod
    def outputs(**on: str) -> dict[str, str]:
        out = {k: "false" for k in SUITES + ["code", "pipeline"]}
        out["images"] = "[]"
        out.update({k.replace("_", "-"): v for k, v in on.items()})
        return out

    def base_results(self, **override: str) -> dict[str, str]:
        r = {"ci-selftest": "skipped", "pr-checks": "success", "security": "success", "codeql": "skipped",
             "images": "skipped", **{s: "skipped" for s in SUITES}}
        r.update({k.replace("_", "-"): v for k, v in override.items()})
        return r

    def test_filter_skips_pass(self):
        out = self.run_gate(self.base_results(), self.outputs())
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_a_suite_that_ran_and_passed(self):
        out = self.run_gate(self.base_results(backend="success"), self.outputs(backend="true"))
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_failed_or_cancelled_fails(self):
        for r in ("failure", "cancelled"):
            out = self.run_gate(self.base_results(backend=r), self.outputs(backend="true"))
            self.assertEqual(out.returncode, 1, out.stdout)

    def test_a_skip_although_the_paths_changed_fails(self):
        out = self.run_gate(self.base_results(dast_worker="skipped"), self.outputs(dast_worker="true"))
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("dast-worker: skipped although", out.stdout)

    def test_a_skipped_security_or_pr_check_fails(self):
        self.assertEqual(self.run_gate(self.base_results(security="skipped"), self.outputs()).returncode, 1)
        self.assertEqual(self.run_gate(self.base_results(pr_checks="skipped"), self.outputs()).returncode, 1)
        # on a push there are no PR checks
        push = self.run_gate(self.base_results(pr_checks="skipped"), self.outputs(), event="push")
        self.assertEqual(push.returncode, 0, push.stdout)

    def test_images_and_codeql_and_selftest_cross_checks(self):
        imgs = self.outputs(images='[{"name":"backend"}]')
        self.assertEqual(self.run_gate(self.base_results(), imgs).returncode, 1)
        self.assertEqual(self.run_gate(self.base_results(images="success"), imgs).returncode, 0)
        # CodeQL skipped because it is not licensed here: fine; skipped although enabled: not fine
        code = self.outputs(code="true")
        self.assertEqual(self.run_gate(self.base_results(), code, codeql_on="false").returncode, 0)
        self.assertEqual(self.run_gate(self.base_results(), code, codeql_on="true").returncode, 1)
        self.assertEqual(self.run_gate(self.base_results(), self.outputs(pipeline="true")).returncode, 1)

    def test_a_lost_changes_output_fails(self):
        out = self.outputs()
        del out["worker"]
        res = self.run_gate(self.base_results(), out)
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn("did not report", res.stdout)

    def test_changes_failed(self):
        res = self.run_gate(self.base_results(changes="failure"), {})
        self.assertEqual(res.returncode, 1, res.stdout)


# ----------------------------------------------------------------------------------------------------------------
# path filters


def glob_re(glob: str) -> re.Pattern:
    """picomatch semantics for the patterns ci.yml uses: `**/` = any directories (or none), `/**` at the end = anything
    below, `*` = within one segment; dot files match (dorny/paths-filter sets dot: true)."""
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif glob.startswith("/**", i) and i + 3 == len(glob):
            out, i = out + "(?:/.*)?", i + 3
        elif glob.startswith("**", i):
            out, i = out + ".*", i + 2
        elif glob[i] == "*":
            out, i = out + "[^/]*", i + 1
        else:
            out, i = out + re.escape(glob[i]), i + 1
    return re.compile(out + r"\Z")


def filter_blocks() -> dict[str, dict[str, list[str]]]:
    """step id -> filter name -> patterns, read from the `filters: |` blocks of ci.yml."""
    steps = {}
    for m in re.finditer(r"\n        id: (\S+)\n(?:.*\n)*?          filters: \|\n((?:            .*\n|\s*\n)+)", CI):
        anchors, filters, current = {}, {}, None
        for line in m.group(2).splitlines():
            line = line.split(" #")[0].rstrip()
            head = re.match(r"^            ([\w-]+):(?: &(\w+))?$", line)
            item = re.match(r"^              - (?:'(.+)'|\*(\w+))$", line)
            if head:
                current = head.group(1)
                filters[current] = []
                if head.group(2):
                    anchors[head.group(2)] = current
            elif item and current:
                if item.group(1):
                    filters[current].append(item.group(1))
                else:
                    filters[current].extend(filters[anchors[item.group(2)]])
        steps[m.group(1)] = filters
    return steps


STEPS = filter_blocks()


def suites_for(path: str) -> set[str]:
    some = {name for name, pats in STEPS["filter"].items() if any(glob_re(p).match(path) for p in pats)}
    for name, pats in STEPS["broad"].items():  # predicate-quantifier: every; "!" negates
        if all((not glob_re(p[1:]).match(path)) if p.startswith("!") else glob_re(p).match(path) for p in pats):
            some.add(name.replace("-broad", ""))
    return some & set(SUITES)


class PathFilters(unittest.TestCase):
    # one-file change -> suites that must run (because their tests read the file)
    MUST = {
        # QA review 5856030118: changes that ran no suite, or only their own
        "deploy/staging/docker-compose.yml": {"backend"},                    # test_staging_compose_minio
        "deploy/staging/nginx/http.conf.template": {"backend"},              # test_ratelimit
        "scripts/deploy/build_images.sh": {"backend"},                       # test_image_build_inputs
        "scripts/crypto_kb/build_kb.py": {"backend"},                        # test_crypto_kb
        "e2e/scripts/compose_policy.py": {"backend", "aibom"},               # test_cbom_posture_airgap_policy
        "RabbitMQ/worker/helpers/context/git_hosts.py": {"backend", "worker", "aibom"},
        "RabbitMQ/worker/helpers/context/enums.py": {"backend", "worker", "aibom"},
        "RabbitMQ/worker/scan_worker.py": {"backend", "worker", "aibom"},
        "RabbitMQ/worker/Dockerfile": {"backend", "worker"},                 # test_image_build_inputs
        "RabbitMQ/dast_worker/helpers/net/address_rule.py": {"backend", "dast-worker", "aibom"},
        "compose/worker-compose/docker-compose.yml": {"backend", "dast-worker"},
        "frontend/components/cbom/sources/ServersTab.tsx": {"frontend", "backend"},   # test_cbom_sources_api
        "frontend/components/cbom/sources/logic.ts": {"frontend", "backend", "scan-node"},
        "frontend/utils/scanRerun.ts": {"frontend", "backend"},
        "frontend/app/[team_id]/page.tsx": {"frontend", "backend"},          # test_certin_india_ux_lock
        "scan_node/zs_scan_node/collectors/kubernetes.py": {"scan-node", "backend"},
        "backend/utilities/cbom_sources/node_auth.py": {"backend", "scan-node", "aibom"},
        "backend/utilities/cbom_sources/data/crypto_kb.json": {"backend", "aibom"},
        "aibom/src/aibom/cbom/pkgdb.py": {"aibom", "backend", "scan-node", "worker", "cbom-action"},
        "deploy/node-images/scripts/install.sh": {"backend", "scan-node"},
        "prod_database_migrations/migrations/versions/x.py": {"backend"},
        "bench/certin/repos.tsv": {"backend", "aibom"},
        "docs/cbom-posture/property-dictionary.md": {"aibom"},
        "docs/certin/LEDGER.md": {"aibom"},
        "RabbitMQ/guardrail_worker/uv.lock": {"backend", "worker-locks"},
        ".github/ci/pytest-deselect-worker.txt": {"worker"},
        ".github/workflows/ci.yml": set(SUITES),
        ".github/workflows/reusable-python-tests.yml": set(SUITES),
    }
    # ... and suites that must NOT run (cost)
    MUST_NOT = {
        "docs/ci/README.md": set(SUITES),
        "README.md": set(SUITES),
        "frontend/package.json": set(SUITES) - {"frontend"},
        "frontend/public/logo.svg": set(SUITES) - {"frontend"},
        ".github/labeler.yml": set(SUITES),
        ".coderabbit.yaml": set(SUITES),
    }

    def test_the_filter_rules_were_read(self):
        self.assertIn("backend", STEPS["filter"])
        self.assertIn("backend-broad", STEPS["broad"])
        self.assertIn(".github/workflows/ci.yml", STEPS["filter"]["frontend"])

    def test_glob_semantics(self):
        self.assertTrue(glob_re("**/*.md").match("README.md"))
        self.assertTrue(glob_re("**/*.md").match("docs/a/b.md"))
        self.assertTrue(glob_re("backend/**/*.py").match("backend/x.py"))
        self.assertFalse(glob_re("frontend/app/**").match("frontend/appx/y.ts"))
        self.assertTrue(glob_re("**").match(".coderabbit.yaml"))

    def test_every_tested_file_runs_the_suites_that_test_it(self):
        for path, want in self.MUST.items():
            with self.subTest(path):
                self.assertLessEqual(want, suites_for(path), f"{path} runs {sorted(suites_for(path))}")

    def test_docs_and_ci_config_run_no_suite(self):
        for path, never in self.MUST_NOT.items():
            with self.subTest(path):
                self.assertFalse(never & suites_for(path), f"{path} runs {sorted(suites_for(path))}")


if __name__ == "__main__":
    unittest.main()
