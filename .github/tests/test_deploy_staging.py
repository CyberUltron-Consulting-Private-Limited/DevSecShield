"""Self-tests for deploy-staging.yml.

* Build identity (CB-03, PR #72 re-review): staging is where the merge gate's G0 compares the frontend's
  <meta name="zs-build"> with the API's /health build, without an account. The frontend's meta is compiled in by
  `staging.sh build` only when DSS_EXPOSE_BUILD is on, and a runner's checkout has no deploy/staging/.env (it is
  gitignored), so the workflow passes the switch itself: input `expose_build`, on by default for staging.
  backend/tests/test_build_identity_wiring.py runs staging.sh with that variable.
Run: python3 -m unittest discover -s .github/tests -v
"""

import re
import unittest
from pathlib import Path

TEXT = (Path(__file__).resolve().parents[1] / "workflows" / "deploy-staging.yml").read_text(encoding="utf-8")


def dispatch_input(name: str) -> dict[str, str]:
    """The keys of one workflow_dispatch input (description, type, default), as written."""
    m = re.search(rf"\n      {re.escape(name)}:\n((?:        .*\n)+)", TEXT)
    assert m, f"no workflow_dispatch input {name}"
    return dict(re.findall(r"^        (\w+): (.*)$", m.group(1), re.M))


def step(name: str) -> str:
    """The text of the step called <name>, up to the next step."""
    m = re.search(rf"\n      - name: {re.escape(name)}\n((?:        .*\n|\s*\n)+)", TEXT)
    assert m, f"no step {name}"
    return m.group(1)


class ExposeBuild(unittest.TestCase):
    def test_input_is_a_boolean_on_by_default(self):
        spec = dispatch_input("expose_build")
        self.assertEqual(spec.get("type"), "boolean")
        self.assertEqual(spec.get("default"), "true")

    def test_build_step_passes_it_to_staging_sh(self):
        build = step("Build images")
        self.assertIn("run: scripts/deploy/staging.sh build", build)
        # through the Settings step (#105: a push has no inputs and always exposes; a manual run keeps its input),
        # then "1" / "0": an explicit 0 also wins over any .env the checkout might hold
        self.assertIn("DSS_EXPOSE_BUILD: ${{ steps.settings.outputs.expose_build == 'true' && '1' || '0' }}", build)

    def test_only_the_build_step_reads_it(self):
        # the switch changes what the images contain; save and deploy ship them as built. The input is read once,
        # by the Settings step, and its output only by the build step.
        self.assertEqual(TEXT.count("inputs.expose_build"), 1)
        self.assertIn("INPUT_EXPOSE_BUILD: ${{ inputs.expose_build }}", step("Settings"))
        self.assertEqual(TEXT.count("steps.settings.outputs.expose_build"), 1)
        self.assertIn("steps.settings.outputs.expose_build", step("Build images"))


if __name__ == "__main__":
    unittest.main()
