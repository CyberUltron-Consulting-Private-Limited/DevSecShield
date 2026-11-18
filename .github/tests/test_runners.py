"""Every job runs on the self-hosted runners (label dss-vm) except a fork's pull request, which gets GitHub's
ubuntu-latest, the arm64 image builds, and the Certificate Transparency live proof (deploy/staging/README.md,
"Self-hosted runners").
Run: python3 -m unittest discover -s .github/tests -v
"""

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / "workflows"
FORK_AWARE = ("github.event.pull_request && github.event.pull_request.head.repo.full_name != github.repository"
              " && 'ubuntu-latest' || 'dss-vm'")
ALLOWED = {
    "dss-vm",
    "${{ " + FORK_AWARE + " }}",
    "${{ inputs.runs-on || (" + FORK_AWARE + ") }}",
    "${{ matrix.platform.runner }}",
}


def runs_on() -> list[tuple[str, int, str]]:
    """(file, line, value) of every job's runs-on (input definitions, which end the line, are left out)."""
    out = []
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r"^    runs-on: (.+)$", line)
            if m:
                out.append((wf.name, n, m.group(1)))
    return out


class Runners(unittest.TestCase):
    def test_every_job_runs_on_dss_vm_or_the_fork_expression(self):
        found = runs_on()
        self.assertGreater(len(found), 20)
        for name, n, value in found:
            if name == "cbom-ct-live.yml":
                self.assertEqual(value, "ubuntu-latest", f"{name}:{n} runs-on: {value}")
                continue
            self.assertIn(value, ALLOWED, f"{name}:{n} runs-on: {value}")

    def test_ct_live_stays_off_the_shared_runner_address(self):
        # Cert Spotter counts queries per source address. dss-vm is one address for every job, and the quota job
        # spends it, so a same-repo pull request on dss-vm cannot compare collector rows with the provider.
        text = (WORKFLOWS / "cbom-ct-live.yml").read_text(encoding="utf-8")
        runs = [line.strip() for line in text.splitlines() if line.startswith("    runs-on:")]
        self.assertEqual(runs, ["runs-on: ubuntu-latest"] * 4)

    def test_only_the_arm64_builds_name_a_github_runner(self):
        text = (WORKFLOWS / "publish-ghcr.yml").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"runner: (\S+)\}", text), ["dss-vm", "ubuntu-24.04-arm"])

    def test_the_reusable_runs_on_inputs_default_to_empty(self):
        # An empty input falls back to the expression above; any other default (even a quoted "") is a label no
        # runner has, and the job waits in the queue for ever.
        for name in ("reusable-python-tests.yml", "reusable-frontend.yml"):
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            block = re.search(r"\n      runs-on:\n((?:        .*\n)+)", text)
            self.assertIsNotNone(block, name)
            self.assertIn('        default: ""\n', block.group(1), name)

    def test_the_label_is_declared_for_actionlint(self):
        config = (WORKFLOWS.parent / "actionlint.yaml").read_text(encoding="utf-8")
        self.assertRegex(config, r"self-hosted-runner:\n(?:  .*\n)*    - dss-vm\n")


if __name__ == "__main__":
    unittest.main()
