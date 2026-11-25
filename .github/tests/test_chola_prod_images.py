"""Self-tests for .github/workflows/chola-prod-images.yml (the Chola production images of one commit as artifacts).

What they pin: dispatch with a full commit or a push of chola-prod-images/<commit>, nothing else; read-only token;
every action pinned by commit (the same pins as publish-ghcr.yml); the helpers come from the workflow's own commit;
the frontend is built as the kit builds it; and the contract with scripts/deploy/chola-prod.sh and
deploy/chola-prod/artifacts.py (crane pin, infrastructure pins, API URL, artifact names, retention). The kit's side of
the same contract: backend/tests/test_chola_prod_kit.py::test_workflow_and_kit_agree.
Run: python3 -m unittest discover -s .github/tests -v
"""

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = (ROOT / ".github" / "workflows" / "chola-prod-images.yml").read_text(encoding="utf-8")
PUBLISH = (ROOT / ".github" / "workflows" / "publish-ghcr.yml").read_text(encoding="utf-8")
KIT = (ROOT / "scripts" / "deploy" / "chola-prod.sh").read_text(encoding="utf-8")
ARTIFACTS = (ROOT / "deploy" / "chola-prod" / "artifacts.py").read_text(encoding="utf-8")
SHA = "0123456789abcdef0123456789abcdef01234567"


def steps() -> dict[str, str]:
    """step name -> its text (6-space `- name:` items of the one job)."""
    body = WF.split("\n    steps:\n", 1)[1]
    parts = re.split(r"\n(?=      - (?:name|uses): )", "\n" + body)
    out = {}
    for part in parts:
        m = re.match(r"\n?      - name: (.+)\n", part)
        if m:
            out[m.group(1).strip()] = part
    return out


STEPS = steps()


def run_block(step: str) -> str:
    m = re.search(r"\n        run: \|\n((?:          .*\n|\s*\n)+)", STEPS[step] + "\n")
    assert m, step
    return textwrap.dedent(m.group(1))


def job_env(name: str) -> str:
    m = re.search(rf"\n      {name}: (?:>-\n((?:        .*\n)+)|(\S+)\n)", WF)
    assert m, name
    return (m.group(1) or m.group(2)).strip()


class Triggers(unittest.TestCase):
    def test_dispatch_with_a_required_sha_or_a_push_of_a_commit_branch_only(self):
        on = WF.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(re.findall(r"^  ([a-z_]+):", on, re.MULTILINE), ["workflow_dispatch", "push"])
        self.assertIn("      sha:\n", on)
        self.assertRegex(on, r"sha:\n(?:        .*\n)*        required: true")
        self.assertIn('    branches: ["chola-prod-images/**"]', on)
        self.assertNotIn("pull_request", WF)

    def test_runs_queue_never_cancel(self):
        self.assertIn("cancel-in-progress: false", WF)


class Privilege(unittest.TestCase):
    def test_read_only_token_and_no_secret(self):
        self.assertIn("\npermissions: {}\n", WF)
        perms = re.findall(r"\n    permissions:\n((?:      .*\n)+)", WF)
        self.assertEqual(perms, ["      contents: read\n      packages: read\n"])
        self.assertNotIn("secrets.", WF)
        self.assertNotRegex(WF, r":\s*write\b")

    def test_every_action_is_pinned_by_commit_like_publish_ghcr(self):
        uses = re.findall(r"uses: ([\w./-]+)@(\S+)( # v\S+)?", WF)
        self.assertTrue(uses)
        pinned = dict(re.findall(r"uses: ([\w./-]+)@([0-9a-f]{40}) #", PUBLISH))
        for action, ref, comment in uses:
            with self.subTest(action):
                self.assertRegex(ref, r"^[0-9a-f]{40}$")
                self.assertTrue(comment)
                self.assertEqual(ref, pinned[action], f"{action}: not the pin publish-ghcr.yml uses")

    def test_helpers_come_from_the_workflows_own_commit(self):
        # the target commit is only the frontend's build context: no script of it runs with the token
        self.assertEqual(re.findall(r"python3 -I (\S+)", WF), ["tools/deploy/chola-prod/artifacts.py"] * 5)
        self.assertNotRegex(WF, r"target/(?!frontend)")
        self.assertRegex(STEPS["Checkout (this workflow's commit, for the kit's helpers)"], r"sparse-checkout: deploy/chola-prod")
        target = STEPS["Checkout the commit (the frontend's build context)"]
        self.assertIn("ref: ${{ steps.commit.outputs.sha }}", target)
        self.assertIn("sparse-checkout: frontend", target)
        for step in STEPS.values():
            if "actions/checkout@" in step:
                self.assertIn("persist-credentials: false", step)

    def test_registry_login_stays_in_the_runs_own_config(self):
        self.assertIn('DOCKER_CONFIG="$OUT/crane-config" crane auth login ghcr.io', WF)
        self.assertNotIn("docker/login-action", WF)
        self.assertIn('rm -rf "${OUT:?}"', run_block("Clean up"))
        self.assertIn("if: always()", STEPS["Clean up"])


class CommitStep(unittest.TestCase):
    def commit(self, **env: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out"
            full = {"PATH": os.environ["PATH"], "RUNNER_TEMP": d, "GITHUB_OUTPUT": str(out), **env}
            p = subprocess.run(["bash", "-c", run_block("Commit")], env=full, capture_output=True, text=True, timeout=30,
                               check=False)
            return p.returncode, (out.read_text() if out.exists() else "") + p.stdout

    def test_dispatch_and_push_give_the_commit(self):
        rc, out = self.commit(EVENT="workflow_dispatch", INPUT_SHA=SHA)
        self.assertEqual(rc, 0)
        self.assertIn(f"sha={SHA}\nsha12={SHA[:12]}\n", out)
        rc, out = self.commit(EVENT="push", REF_NAME=f"chola-prod-images/{SHA}")
        self.assertEqual(rc, 0)
        self.assertIn(f"sha={SHA}\n", out)

    def test_anything_else_is_refused(self):
        for env in ({"EVENT": "workflow_dispatch", "INPUT_SHA": SHA[:12]},
                    {"EVENT": "workflow_dispatch", "INPUT_SHA": SHA.upper()},
                    {"EVENT": "workflow_dispatch", "INPUT_SHA": "dev"},
                    {"EVENT": "workflow_dispatch", "INPUT_SHA": SHA + "\nfoo=bar"},
                    {"EVENT": "workflow_dispatch", "INPUT_SHA": "$(id)"},
                    {"EVENT": "push", "REF_NAME": "chola-prod-images/main"},
                    {"EVENT": "push", "REF_NAME": f"chola-prod-images/{SHA}/x"},
                    {"EVENT": "pull_request", "INPUT_SHA": SHA}):
            with self.subTest(env):
                rc, out = self.commit(**env)
                self.assertEqual(rc, 1, out)
                self.assertNotIn("sha=", out)


class Images(unittest.TestCase):
    def test_ghcr_images_are_copied_for_linux_amd64_with_the_kits_tags(self):
        block = run_block("Backend and workers from GHCR (linux/amd64, byte for byte)")
        self.assertIn('for t in "dev-$SHA12" "staging-$SHA12" "manual-$SHA12"; do', block)
        self.assertIn('for t in "dev-${SHA12}" "staging-${SHA12}" "manual-${SHA12}"; do', KIT)  # the kit's GHCR path
        self.assertIn('crane pull --format=oci --platform linux/amd64 "$ref" "$OUT/image-$c"', block)
        self.assertIn("for c in backend scan-worker dast-worker; do", block)
        self.assertIn('--artifact "chola-image-$c"', block)

    def test_the_frontend_is_built_as_the_kit_builds_it(self):
        block = run_block("Frontend for the Chola API (linux/amd64, as the kit builds it)")
        for arg in ('--platform linux/amd64', '--build-arg "NEXT_PUBLIC_BACKEND_URL=$API_URL"',
                    '--label "org.opencontainers.image.revision=$SHA"',
                    '--label "com.zeroshield.devsecshield.api-url=$API_URL"', "--provenance=false"):
            self.assertIn(arg, block)
        kit_build = KIT.rsplit("docker buildx build --platform linux/amd64", 1)[1].split("|| die", 1)[0]
        for arg in ('--build-arg "NEXT_PUBLIC_BACKEND_URL=https://${API_HOST}"',
                    '--label "org.opencontainers.image.revision=${SHA}"',
                    '--label "com.zeroshield.devsecshield.api-url=https://${API_HOST}"', "--provenance=false"):
            self.assertIn(arg, kit_build)
        self.assertIn("oci-check --normalize", block)
        self.assertIn("grep -acF \"$API_URL\"", block)

    def test_contract_with_the_kit(self):
        self.assertEqual(job_env("API_URL"), "https://" + re.search(r"\nAPI_HOST=(\S+)", KIT).group(1))
        self.assertEqual(job_env("CRANE_VERSION"), re.search(r"\nCRANE_VERSION=(\S+)", KIT).group(1))
        self.assertEqual(job_env("CRANE_SHA256"), re.search(r"Linux_x86_64\) printf '%s\\n' ([0-9a-f]{64})", KIT).group(1))
        kit_pins = re.search(r"\nINFRA_IMAGES=\(\n(.*?)\n\)", KIT, re.DOTALL).group(1).split()
        self.assertEqual(job_env("INFRA_IMAGES").split(), kit_pins)
        self.assertIn("IMAGES_WORKFLOW=.github/workflows/chola-prod-images.yml", KIT)
        self.assertIn('artifact_fetch chola-manifest "${RUN_DIR}/manifest" --file manifest.json', KIT)
        self.assertIn('COMPONENTS = ("backend", "frontend", "scan-worker", "dast-worker")', ARTIFACTS)

    def test_uploads(self):
        uploads = {m.group(1): m.group(0) for m in re.finditer(
            r"uses: actions/upload-artifact@\S+ # v\S+\n        with:\n          name: (\S+)\n((?:          .*\n)+)", WF)}
        self.assertEqual(set(uploads), {"chola-manifest", "chola-infra", "chola-image-backend", "chola-image-frontend",
                                        "chola-image-scan-worker", "chola-image-dast-worker"})
        for name, text in uploads.items():
            with self.subTest(name):
                self.assertIn("retention-days: 3\n", text)
                self.assertIn("if-no-files-found: error\n", text)
                if name != "chola-manifest":  # layers and the archive are compressed already
                    self.assertIn("compression-level: 0\n", text)
        self.assertIn("/infra/release.tar.gz\n", uploads["chola-infra"])
        self.assertIn("/manifest/manifest.json\n", uploads["chola-manifest"])
        self.assertIn('MAX_BYTES: "4294967296"', WF)  # each artifact stays well under GitHub's limits


if __name__ == "__main__":
    unittest.main()
