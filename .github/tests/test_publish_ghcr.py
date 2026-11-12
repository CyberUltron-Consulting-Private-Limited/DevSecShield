"""Self-tests for .github/workflows/publish-ghcr.yml, .github/ci/ghcr_meta.py and deploy/local/ (GHCR publishing).

What they pin: forks never publish and every job that can write packages checks that itself; previews need the
publish-preview label; the tag scheme; no secret but GITHUB_TOKEN; the write jobs run no repository script; every
action is pinned by commit; both architectures; the local compose file runs exactly the published images.
Run: python3 -m unittest discover -s .github/tests -v
"""

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF_PATH = ROOT / ".github" / "workflows" / "publish-ghcr.yml"
WF = WF_PATH.read_text(encoding="utf-8")
META = ROOT / ".github" / "ci" / "ghcr_meta.py"
COMPOSE = (ROOT / "deploy" / "local" / "docker-compose.yml").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / "deploy" / "local" / ".env.example").read_text(encoding="utf-8")
MINIO = (ROOT / "deploy" / "local" / "minio" / "Dockerfile").read_text(encoding="utf-8")

REPO = "Acme-Org/DevSecShield"
SHA = "0123456789abcdef0123456789abcdef01234567"
HEAD = "fedcba9876543210fedcba9876543210fedcba98"
COMPONENTS = ["backend", "frontend", "scan-worker", "dast-worker", "scan-node", "minio"]


def meta(command: str, **env: str) -> tuple[int, dict[str, str], str]:
    base = {"REPO": REPO, "OWNER": "Acme-Org", "SERVER_URL": "https://github.com"}
    full = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT")} | base | env
    p = subprocess.run([sys.executable, str(META), command], env=full, capture_output=True, text=True, timeout=30)
    out = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
    return p.returncode, out, p.stderr


def pr(action: str, labels: list[str], label: str = "", head_repo: str = REPO, number: str = "93") -> dict[str, str]:
    return {"EVENT": "pull_request", "ACTION": action, "PR_NUMBER": number, "PR_HEAD_SHA": HEAD,
            "PR_HEAD_REPO": head_repo, "PR_LABELS": json.dumps(labels), "LABEL": label}


def jobs() -> dict[str, str]:
    """name -> text of each job under `jobs:` (2-space indented keys)."""
    body = WF.split("\njobs:\n", 1)[1]
    parts = re.split(r"\n(?=  [a-z][a-z0-9-]*:\n)", "\n" + body)
    return {m.group(1): part for part in parts if (m := re.match(r"\n?  ([a-z][a-z0-9-]*):\n", part))}


JOBS = jobs()
FORK_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"


class Decide(unittest.TestCase):
    def test_push_to_dev_and_staging_publish_with_a_moving_tag(self):
        for branch in ("dev", "staging"):
            rc, out, _ = meta("decide", EVENT="push", REF_NAME=branch, SHA=SHA)
            self.assertEqual(rc, 0)
            self.assertEqual((out["publish"], out["prefix"], out["moving"], out["ref"]), ("true", branch, branch, SHA))
            self.assertEqual(out["api_url"], "http://localhost:8000")

    def test_push_to_another_branch_does_not_publish(self):
        for branch in ("main", "feature/x", "devel"):
            rc, out, _ = meta("decide", EVENT="push", REF_NAME=branch, SHA=SHA)
            self.assertEqual((rc, out["publish"]), (0, "false"), branch)

    def test_owner_is_lowercased_for_the_registry(self):
        _, out, _ = meta("decide", EVENT="push", REF_NAME="dev", SHA=SHA)
        self.assertEqual(out["registry"], "ghcr.io/acme-org")
        self.assertEqual(out["source"], "https://github.com/Acme-Org/DevSecShield")

    def test_preview_label_added_publishes_the_pr_head(self):
        rc, out, _ = meta("decide", **pr("labeled", ["publish-preview"], "publish-preview"))
        self.assertEqual(rc, 0)
        self.assertEqual((out["publish"], out["prefix"], out["moving"], out["ref"]), ("true", "pr-93", "pr-93", HEAD))

    def test_another_label_added_does_not_publish(self):
        _, out, _ = meta("decide", **pr("labeled", ["publish-preview", "security-config-reviewed"], "security-config-reviewed"))
        self.assertEqual(out["publish"], "false")

    def test_a_push_to_a_labelled_pr_publishes_and_to_an_unlabelled_one_does_not(self):
        for action in ("synchronize", "reopened"):
            self.assertEqual(meta("decide", **pr(action, ["publish-preview"]))[1]["publish"], "true", action)
            self.assertEqual(meta("decide", **pr(action, ["other"]))[1]["publish"], "false", action)

    def test_forks_never_publish(self):
        for event in (pr("labeled", ["publish-preview"], "publish-preview", head_repo="someone/DevSecShield"),
                      pr("synchronize", ["publish-preview"], head_repo="someone/DevSecShield"),
                      pr("synchronize", ["publish-preview"], head_repo="")):
            rc, out, _ = meta("decide", **event)
            self.assertEqual((rc, out["publish"]), (0, "false"))
            self.assertIn("fork", out["reason"])

    def test_other_pr_actions_do_not_publish(self):
        for action in ("opened", "closed", "edited", "unlabeled"):
            self.assertEqual(meta("decide", **pr(action, ["publish-preview"]))[1]["publish"], "false", action)

    def test_dispatch_publishes_a_manual_tag_without_a_moving_tag(self):
        rc, out, _ = meta("decide", EVENT="workflow_dispatch", INPUT_REF="feature/cb-03", INPUT_API_URL="")
        self.assertEqual(rc, 0)
        self.assertEqual((out["publish"], out["prefix"], out["moving"], out["ref"], out["api_url"]),
                         ("true", "manual", "", "feature/cb-03", "http://localhost:8000"))
        rc, out, _ = meta("decide", EVENT="workflow_dispatch", INPUT_REF="dev", INPUT_API_URL="http://192.168.1.20:8000")
        self.assertEqual((rc, out["api_url"]), (0, "http://192.168.1.20:8000"))

    def test_dispatch_inputs_are_validated(self):
        for ref in ("-x", "a..b", "$(id)", "dev\nmoving=dev", "a b", ""):
            rc, _, err = meta("decide", EVENT="workflow_dispatch", INPUT_REF=ref)
            self.assertEqual(rc, 1, ref)
            self.assertIn("::error::", err)
        for url in ("ftp://x", "http://x/path", "http://x\nmoving=dev", "javascript:alert(1)", "http://"):
            rc, _, _ = meta("decide", EVENT="workflow_dispatch", INPUT_REF="dev", INPUT_API_URL=url)
            self.assertEqual(rc, 1, url)

    def test_malformed_event_values_fail(self):
        self.assertEqual(meta("decide", EVENT="push", REF_NAME="dev", SHA="abc")[0], 1)
        self.assertEqual(meta("decide", **(pr("labeled", ["publish-preview"], "publish-preview") | {"PR_HEAD_SHA": "x"}))[0], 1)
        self.assertEqual(meta("decide", **(pr("labeled", ["publish-preview"], "publish-preview") | {"PR_NUMBER": "0"}))[0], 1)
        self.assertEqual(meta("decide", **(pr("synchronize", []) | {"PR_LABELS": "not json"}))[0], 1)
        self.assertEqual(meta("decide", EVENT="push", REF_NAME="dev", SHA=SHA, OWNER="bad owner!")[0], 1)

    def test_other_events_do_not_publish(self):
        for event in ("pull_request_target", "schedule", "merge_group", ""):
            self.assertEqual(meta("decide", EVENT=event)[1]["publish"], "false", event)


class Tags(unittest.TestCase):
    def test_immutable_tag_is_prefix_and_twelve_characters_of_the_commit(self):
        for prefix in ("dev", "staging", "pr-93", "manual"):
            rc, out, _ = meta("tags", PREFIX=prefix, SHA=SHA)
            self.assertEqual((rc, out["tag"], out["sha"]), (0, f"{prefix}-{SHA[:12]}", SHA))

    def test_bad_prefix_or_commit_fails(self):
        for prefix, sha in (("main", SHA), ("pr-0", SHA), ("dev", "HEAD"), ("dev", SHA[:12]), ("", SHA)):
            self.assertEqual(meta("tags", PREFIX=prefix, SHA=sha)[0], 1, (prefix, sha))


class Triggers(unittest.TestCase):
    def test_no_pull_request_target(self):
        self.assertNotIn("pull_request_target", WF)

    def test_triggers(self):
        on = "\n" + WF.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertRegex(on, r"\n  push:\n    branches: \[dev, staging\]\n")
        self.assertRegex(on, r"\n  pull_request:\n    types: \[labeled, synchronize, reopened\]\n")
        self.assertIn("\n  workflow_dispatch:\n", on)

    def test_events_that_do_not_publish_cannot_cancel_a_publish(self):
        group = WF.split("\nconcurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
        self.assertIn("&& 'publish' || github.run_id", group)
        self.assertIn("github.event.label.name == 'publish-preview'", group)
        self.assertIn("cancel-in-progress: true", group)


class Permissions(unittest.TestCase):
    def test_workflow_default_is_no_permission(self):
        self.assertIn("\npermissions: {}\n", WF)

    def test_every_job_declares_its_permissions(self):
        self.assertEqual(sorted(JOBS), sorted(["meta", "contexts", "build", "merge", "promote"]))
        for name, text in JOBS.items():
            self.assertRegex(text, r"\n    permissions:\n", name)

    def test_only_build_merge_and_promote_can_write_packages(self):
        writers = sorted(n for n, t in JOBS.items() if "packages: write" in t)
        self.assertEqual(writers, ["build", "merge", "promote"])
        for name in ("meta", "contexts"):
            perms = JOBS[name].split("\n    permissions:\n", 1)[1].split("\n    ", 1)[0]
            self.assertEqual(perms.strip(), "contents: read", name)

    def test_attestation_permissions_only_where_attesting(self):
        for perm in ("id-token: write", "attestations: write", "artifact-metadata: write"):
            self.assertEqual([n for n, t in JOBS.items() if perm in t], ["merge"], perm)

    def test_every_writing_job_checks_for_forks_itself(self):
        for name in ("build", "merge", "promote"):
            cond = JOBS[name].split("\n    if: >-\n", 1)[1].split("\n    runs-on:", 1)[0]
            self.assertIn("github.event_name != 'pull_request' || " + FORK_GUARD, cond, name)
        self.assertIn(FORK_GUARD, JOBS["meta"].split("\n    runs-on:", 1)[0])

    def test_no_secret_but_the_github_token(self):
        self.assertNotRegex(WF, r"secrets\.")
        self.assertEqual(re.findall(r"password: (.*)", WF), ["${{ github.token }}"] * 3)

    def test_writing_jobs_run_no_repository_script(self):
        for name in ("build", "merge", "promote"):
            for run in re.findall(r"\n        run: \|\n((?:          .*\n|\s*\n)+)", JOBS[name]):
                self.assertNotRegex(run, r"(?m)(scripts/|\.github/|\bpython3?\b|^\s*(bash|sh|source|\.)\s|\s\./)",
                                    f"{name}: {run[:80]}")

    def test_event_data_reaches_scripts_only_through_env(self):
        for run in re.findall(r"\n        run: \|\n((?:          .*\n|\s*\n)+)", WF):
            self.assertNotIn("${{", run)

    def test_checkouts_keep_no_credentials(self):
        n = WF.count("uses: actions/checkout@")
        self.assertEqual(WF.count("persist-credentials: false"), n)


class Actions(unittest.TestCase):
    def test_every_action_is_pinned_by_commit(self):
        uses = re.findall(r"uses: (\S+)(.*)", WF)
        self.assertTrue(uses)
        for ref, comment in uses:
            self.assertRegex(ref, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", ref)
            self.assertRegex(comment, r"^ # v\d+\.\d+\.\d+$", ref)

    def test_provenance_is_attested_on_the_index_and_pushed(self):
        merge = JOBS["merge"]
        self.assertIn("uses: actions/attest-build-provenance@", merge)
        self.assertIn("subject-digest: ${{ steps.index.outputs.digest }}", merge)
        self.assertIn("push-to-registry: true", merge)


class Images(unittest.TestCase):
    def build_matrix_names(self) -> list[str]:
        return re.findall(r"- \{name: ([a-z-]+), context:", JOBS["build"])

    def test_one_list_of_images_everywhere(self):
        self.assertEqual(self.build_matrix_names(), COMPONENTS)
        self.assertIn(f"name: [{', '.join(COMPONENTS)}]", JOBS["merge"])
        self.assertIn(f"COMPONENTS: {' '.join(COMPONENTS)}", JOBS["promote"])

    def test_both_architectures_on_native_runners(self):
        self.assertIn("- {arch: amd64, runner: ubuntu-24.04}", JOBS["build"])
        self.assertIn("- {arch: arm64, runner: ubuntu-24.04-arm}", JOBS["build"])
        self.assertIn("runs-on: ${{ matrix.platform.runner }}", JOBS["build"])
        self.assertNotIn("setup-qemu", WF)
        self.assertIn('[ "$platforms" != "linux/amd64,linux/arm64" ]', JOBS["merge"])

    def test_images_are_pushed_by_digest_with_oci_labels_and_no_buildkit_attestation_manifests(self):
        build = JOBS["build"]
        self.assertIn("push-by-digest=true", build)
        self.assertIn("provenance: false", build)
        self.assertIn("sbom: false", build)
        for label in ("source", "revision", "version", "title"):
            self.assertIn(f'echo "org.opencontainers.image.{label}=', build)
        self.assertNotRegex(build, r"\n          tags:")

    def test_the_contexts_are_checked_before_any_build(self):
        self.assertIn("run: scripts/deploy/check_image_contexts.sh", JOBS["contexts"])
        self.assertIn("needs: [meta, contexts]", JOBS["build"])

    def test_moving_tags_change_only_after_every_image_is_merged(self):
        self.assertIn("needs: [meta, merge]", JOBS["promote"])
        self.assertIn('[ "$got" = "$want" ]', JOBS["promote"])

    def test_frontend_gets_the_api_url_and_the_scan_node_image_of_the_same_build(self):
        self.assertIn('echo "NEXT_PUBLIC_BACKEND_URL=$API_URL"', JOBS["build"])
        self.assertIn('echo "NEXT_PUBLIC_CBOM_NODE_IMAGE=$REGISTRY/devsecshield-scan-node:$TAG"', JOBS["build"])

    def test_minio_copies_nothing_from_its_context(self):
        for line in MINIO.splitlines():
            if re.match(r"\s*(COPY|ADD)\b", line):
                self.assertIn("--from=", line)
        self.assertIn("test \"$(git rev-parse HEAD)\" = \"${MINIO_COMMIT}\"", MINIO)
        self.assertRegex(MINIO, r"\nUSER 10002\n")


class LocalCompose(unittest.TestCase):
    def test_runs_exactly_the_published_images(self):
        used = set(re.findall(r"/devsecshield-([a-z-]+):\$\{DSS_TAG", COMPOSE))
        self.assertEqual(used, set(COMPONENTS) - {"scan-node"})  # the scan node runs on the machines it scans
        self.assertNotIn("build:", COMPOSE)

    def test_ports_listen_on_this_machine_only_by_default(self):
        ports = re.findall(r'- "(\$\{[A-Z_]+:-[0-9.]+\}):(\d+):(\d+)"', COMPOSE)
        self.assertEqual(sorted(p[1] for p in ports), ["3000", "8000", "8025"])
        for bind, _, _ in ports:
            self.assertTrue(bind.endswith(":-127.0.0.1}"), bind)

    def test_frontend_api_port_matches_the_baked_url(self):
        self.assertIn('"${API_BIND:-127.0.0.1}:8000:8080"', COMPOSE)

    def test_env_example_holds_placeholders_only(self):
        for line in ENV_EXAMPLE.splitlines():
            m = re.match(r"([A-Z][A-Z0-9_]*)=(.*)$", line)
            if not m:
                continue
            key, value = m.groups()
            if re.search(r"(PASS|SECRET|KEY|TOKEN|HMAC)", key) and key not in ("AWS_ACCESS_KEY_ID", "CBOM_AWS_ACCESS_KEY_ID"):
                self.assertIn(value, ("", "change-me"), key)
            if key in ("AWS_ACCESS_KEY_ID",):
                self.assertEqual(value, "change-me")
        self.assertNotRegex(ENV_EXAMPLE, r"(?m)^CBOM_MTLS_HEADER_TRUSTED=")
        self.assertNotRegex(ENV_EXAMPLE, r"(?m)^(DSS_DEV_MODE|LOCAL_DEV_VERIFICATION_[A-Z]+)=")


if __name__ == "__main__":
    unittest.main()
