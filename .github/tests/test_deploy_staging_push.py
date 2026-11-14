"""Self-tests for .github/workflows/deploy-staging.yml: every push to `staging` builds and deploys that commit to the
staging host, one run at a time, in order, and touches nothing but staging.

Why: a workflow_dispatch workflow can only be started from the default branch (`main`), which is behind, so the
release manager could not dispatch it. The owner wants CI/CD deploys to go to staging; production stays untouched.
Run: python3 -m unittest discover -s .github/tests -v
"""

import base64
import os
import re
import secrets
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

WF = (Path(__file__).resolve().parents[1] / "workflows" / "deploy-staging.yml").read_text(encoding="utf-8")
STAGING_API = "https://devsec-staging-api.zeroshield.ai"


def section(name: str) -> str:
    """A top-level key's block (`on:`, `concurrency:`, ...)."""
    m = re.search(rf"(?m)^{name}:\n((?:(?:  .*)?\n)+)", WF)
    assert m, name
    return m.group(1)


def jobs() -> dict[str, str]:
    body = WF.split("\njobs:\n", 1)[1]
    parts = re.split(r"\n(?=  [a-z][a-z0-9-]*:\n)", "\n" + body)
    return {m.group(1): part for part in parts if (m := re.match(r"\n?  ([a-z][a-z0-9-]*):\n", part))}


JOBS = jobs()


def steps(job: str) -> list[str]:
    return re.split(r"\n      - ", JOBS[job])


def run_block(step: str) -> str:
    m = re.search(r"\n        run: \|\n((?:(?:\s{10}.*)?\n)+)", step + "\n")
    assert m, step[:80]
    return textwrap.dedent(m.group(1))


def settings(**env: str) -> tuple[int, dict[str, str], str]:
    found = [p for p in steps("build") if p.startswith("name: Settings\n")]
    assert len(found) == 1, "no Settings step"
    script = run_block(found[0])
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "out"
        full = {"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(out), "EVENT": "", "REF": "", "INPUT_DEPLOY": "",
                "INPUT_API_URL": "", "INPUT_EXPOSE_BUILD": ""} | env
        p = subprocess.run(["bash", "-e", "-c", script], env=full, capture_output=True, text=True, timeout=30)
        values = dict(line.split("=", 1) for line in out.read_text().splitlines()) if out.exists() else {}
    return p.returncode, values, p.stdout + p.stderr


class Triggers(unittest.TestCase):
    def test_every_push_to_staging_and_only_staging(self):
        on = section("on")
        self.assertRegex(on, r"(?m)^  push:\n    branches: \[staging\]\n")
        self.assertNotRegex(on, r"paths(-ignore)?:")
        self.assertNotIn("pull_request", on)
        self.assertNotIn("schedule", on)

    def test_manual_runs_are_kept(self):
        on = section("on")
        self.assertIn("\n  workflow_dispatch:\n", "\n" + on)
        for name in ("deploy", "api_url", "expose_build"):
            self.assertRegex(on, rf"(?m)^      {name}:\n", name)


class Concurrency(unittest.TestCase):
    def test_one_run_at_a_time_in_order_never_cancelling_a_deploy(self):
        c = section("concurrency")
        self.assertRegex(c, r"(?m)^  group: deploy-staging$")  # one group for every ref and event
        self.assertRegex(c, r"(?m)^  cancel-in-progress: false$")
        for name, text in JOBS.items():
            self.assertNotIn("cancel-in-progress: true", text, name)


class PushSettings(unittest.TestCase):
    def test_a_push_to_staging_deploys_with_the_build_exposed(self):
        rc, out, log = settings(EVENT="push", REF="refs/heads/staging")
        self.assertEqual(rc, 0, log)
        self.assertEqual(out, {"deploy": "true", "api_url": STAGING_API, "expose_build": "true"})

    def test_a_push_elsewhere_is_refused(self):
        for ref in ("refs/heads/main", "refs/heads/dev", "refs/tags/v1"):
            rc, out, _ = settings(EVENT="push", REF=ref)
            self.assertEqual((rc, out), (1, {}), ref)

    def test_a_manual_run_keeps_its_inputs(self):
        rc, out, log = settings(EVENT="workflow_dispatch", REF="refs/heads/main", INPUT_DEPLOY="false",
                                INPUT_API_URL="https://api.example.test", INPUT_EXPOSE_BUILD="false")
        self.assertEqual(rc, 0, log)
        self.assertEqual(out, {"deploy": "false", "api_url": "https://api.example.test", "expose_build": "false"})
        rc, out, _ = settings(EVENT="workflow_dispatch", REF="refs/heads/main", INPUT_DEPLOY="true",
                              INPUT_API_URL=STAGING_API, INPUT_EXPOSE_BUILD="true")
        self.assertEqual(out["deploy"], "true")

    def test_a_bad_api_url_or_another_event_fails(self):
        self.assertEqual(settings(EVENT="workflow_dispatch", INPUT_DEPLOY="true", INPUT_API_URL="javascript:x")[0], 1)
        self.assertEqual(settings(EVENT="pull_request", REF="refs/pull/1/merge")[0], 1)

    def test_the_api_url_is_a_bare_origin(self):
        # A path, a trailing slash, a bad port, a space or an embedded newline (which would add a line such as
        # deploy=true to $GITHUB_OUTPUT) is refused before anything is written.
        for bad in ("https://h/path", "https://h/", "https://h:123456", "https://h x", "https://h\ndeploy=true",
                    "ftp://h", "https://", ""):
            rc, out, _ = settings(EVENT="workflow_dispatch", INPUT_DEPLOY="false", INPUT_API_URL=bad)
            self.assertEqual((rc, out), (1, {}), repr(bad))
        for good in ("https://h", "http://localhost:8000", STAGING_API, "https://devsec-staging-api.zeroshield.ai:443"):
            rc, out, log = settings(EVENT="workflow_dispatch", INPUT_DEPLOY="false", INPUT_API_URL=good)
            self.assertEqual(rc, 0, log)
            self.assertEqual(out["api_url"], good)


class Wiring(unittest.TestCase):
    def test_deploy_runs_when_settings_say_so(self):
        self.assertIn("deploy: ${{ steps.settings.outputs.deploy }}", JOBS["build"])
        self.assertRegex(JOBS["deploy"], r"\n    if: needs\.build\.outputs\.deploy == 'true'\n")
        self.assertNotIn("inputs.", JOBS["deploy"])

    def test_the_build_uses_the_settings_and_the_pushed_commit(self):
        build = JOBS["build"]
        self.assertIn("NEXT_PUBLIC_BACKEND_URL: ${{ steps.settings.outputs.api_url }}", build)
        self.assertIn("DSS_EXPOSE_BUILD: ${{ steps.settings.outputs.expose_build == 'true' && '1' || '0' }}", build)
        # Inputs reach the build only through the Settings step (they are empty on a push).
        for line in build.splitlines():
            if "${{ inputs." in line:
                self.assertRegex(line.strip(), r"^INPUT_[A-Z_]+: \$\{\{ inputs\.[a-z_]+ \}\}$", line)
        for job in ("build", "deploy"):
            self.assertIn("ref: ${{ github.sha }}", JOBS[job], job)
        # The tag (so the artifact name and the deployed images) is the checked-out commit itself.
        tag = [p for p in steps("build") if p.startswith("name: Image tag\n")]
        self.assertEqual(len(tag), 1)
        self.assertIn('run: echo "tag=$(git rev-parse --short=12 HEAD)" >> "$GITHUB_OUTPUT"', tag[0])
        self.assertEqual(WF.count("git rev-parse"), 1)


def tip_check(mode: str, tip: str = "", sha: str = "") -> tuple[int, str, list[str], dict[str, str], str]:
    """Run the deploy job's "Still the tip of staging" script with a stubbed git."""
    found = [p for p in steps("deploy") if p.startswith("name: Still the tip of staging\n")]
    assert len(found) == 1, "no tip check"
    token = secrets.token_hex(12)
    with tempfile.TemporaryDirectory() as d:
        stub = Path(d) / "git"
        stub.write_text(textwrap.dedent("""\
            #!/bin/sh
            printf '%s\\n' "$@" > "$STUB_DIR/argv"
            env > "$STUB_DIR/env"
            case "$STUB_MODE" in
              fail) echo "fatal: unable to access" >&2; exit 128 ;;
              empty) exit 0 ;;
              *) printf '%s\\trefs/heads/staging\\n' "$STUB_TIP" ;;
            esac
            """))
        stub.chmod(0o755)
        env = {"PATH": f"{d}:{os.environ['PATH']}", "STUB_DIR": d, "STUB_MODE": mode, "STUB_TIP": tip, "SHA": sha,
               "GH_TOKEN": token, "GITHUB_REPOSITORY": "owner/repo"}
        p = subprocess.run(["bash", "-e", "-c", run_block(found[0])], env=env, capture_output=True, text=True,
                           timeout=30)
        argv = (Path(d) / "argv").read_text().splitlines() if (Path(d) / "argv").exists() else []
        genv = dict(line.split("=", 1) for line in (Path(d) / "env").read_text().splitlines() if "=" in line) \
            if (Path(d) / "env").exists() else {}
    return p.returncode, p.stdout + p.stderr, argv, genv, token


class SupersededPush(unittest.TestCase):
    """A re-run keeps its original GITHUB_SHA: a push run deploys only while its commit is still the tip of staging."""

    A = "a" * 40
    B = "b" * 40

    def test_the_check_runs_first_in_the_deploy_job_for_pushes_only(self):
        names = [p.split("\n", 1)[0] for p in steps("deploy")[1:]]
        self.assertEqual(names[0], "name: Still the tip of staging")
        guard = steps("deploy")[1]
        self.assertIn("\n        if: github.event_name == 'push'\n", guard)
        self.assertIn("SHA: ${{ github.sha }}", guard)
        push = [i for i, p in enumerate(steps("deploy")) if "scripts/deploy/staging.sh push" in p]
        ssh = [i for i, p in enumerate(steps("deploy")) if p.startswith("name: SSH identity\n")]
        self.assertEqual(len(push), 1)
        self.assertLess(1, ssh[0])
        self.assertLess(ssh[0], push[0])

    def test_the_tip_deploys(self):
        rc, log, argv, genv, token = tip_check("ok", tip=self.A, sha=self.A)
        self.assertEqual(rc, 0, log)
        self.assertEqual(argv, ["ls-remote", "https://github.com/owner/repo.git", "refs/heads/staging"])
        # The token reaches git only through its environment config, never argv or the log.
        self.assertEqual(genv.get("GIT_CONFIG_COUNT"), "1")
        self.assertEqual(genv.get("GIT_CONFIG_KEY_0"), "http.https://github.com/.extraheader")
        self.assertEqual(genv.get("GIT_CONFIG_VALUE_0"),
                         "AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{token}".encode()).decode())
        self.assertNotIn(token, " ".join(argv) + log)

    def test_a_superseded_commit_is_refused(self):
        rc, log, _, _, _ = tip_check("ok", tip=self.B, sha=self.A)
        self.assertEqual(rc, 1)
        self.assertIn(f"::error::superseded: staging is at {self.B}; this run built {self.A}", log)

    def test_an_unreadable_or_empty_tip_is_refused(self):
        rc, log, _, _, _ = tip_check("fail", sha=self.A)
        self.assertEqual(rc, 1)
        self.assertIn("::error::could not read the tip of staging", log)
        rc, log, _, _, _ = tip_check("empty", sha=self.A)
        self.assertEqual(rc, 1)
        self.assertIn("::error::staging has no tip", log)


class OnlyStaging(unittest.TestCase):
    def test_nothing_but_the_staging_environment_and_its_secrets(self):
        self.assertEqual(re.findall(r"\n    environment: (\S+)", WF), ["staging"])
        self.assertEqual(sorted(set(re.findall(r"secrets\.([A-Z_]+)", WF))),
                         ["STAGING_SSH_KEY", "STAGING_SSH_KNOWN_HOSTS", "STAGING_SSH_TARGET"])
        self.assertEqual(sorted(set(re.findall(r"vars\.([A-Z_]+)", WF))), ["STAGING_DIR"])
        # What runs (comments and input descriptions are text, not actions).
        code = "\n".join(line for line in WF.splitlines()
                         if not line.lstrip().startswith(("#", "description:")))
        self.assertNotRegex(code, r"(?i)\bprod(uction)?\b|rollback")
        self.assertEqual(re.findall(r"scripts/deploy/staging\.sh ([\w-]+)", code),
                         ["build", "save", "node-artifacts", "push"])

    def test_the_scan_node_downloads_are_built_and_shipped_with_the_release(self):
        build = JOBS["build"]
        self.assertIn("run: scripts/deploy/staging.sh node-artifacts", build)
        # uploaded with the images (same artifact, so the deploy job downloads them next to the archive)
        upload = [p for p in steps("build") if "actions/upload-artifact" in p]
        self.assertEqual(len(upload), 1)
        self.assertIn("deploy/staging/images/node-artifacts/*", upload[0])

    def test_the_job_set_is_build_and_deploy(self):
        self.assertEqual(sorted(JOBS), ["build", "deploy"])


if __name__ == "__main__":
    unittest.main()
