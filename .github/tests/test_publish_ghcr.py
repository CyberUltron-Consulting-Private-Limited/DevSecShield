"""Self-tests for .github/workflows/publish-ghcr.yml, .github/ci/ghcr_meta.py and deploy/local/ (GHCR publishing).

What they pin: forks never publish and every job that can write packages checks that itself; previews need the
publish-preview label; the tag scheme; no secret but GITHUB_TOKEN; the write jobs run no repository script; every
action is pinned by commit; both architectures; the local compose file runs exactly the published images.
Run: python3 -m unittest discover -s .github/tests -v
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
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
FAKES = Path(__file__).resolve().parent / "fakes"
REG = "ghcr.io/acme-org"


def step_script(job: str, name: str) -> str:
    """The `run: |` script of step `name` in `job`."""
    parts = re.split(r"\n      - ", JOBS[job])
    found = [p for p in parts if p.startswith(f"name: {name}\n")]
    assert len(found) == 1, f"{job}: step {name!r}"
    m = re.search(r"\n        run: \|\n((?:(?:\s{10}.*)?\n)+)", found[0] + "\n")
    assert m, name
    return textwrap.dedent(m.group(1))


class Registry:
    """A temporary fake registry + gh for running the workflow's step scripts (fakes/docker, fakes/gh, fakes/sleep)."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "gh").mkdir()
        self.tags: dict[str, str] = {}
        self.out = self.dir / "github_output"
        self.summary = self.dir / "summary"

    def close(self):
        self.tmp.cleanup()

    def put(self, ref: str, payload: dict) -> str:
        data = json.dumps(payload, sort_keys=True).encode()
        hexd = hashlib.sha256(data).hexdigest()
        (self.dir / "blobs").mkdir(exist_ok=True)
        (self.dir / "blobs" / hexd).write_bytes(data)
        if ref:
            self.tags[ref] = hexd
            (self.dir / "tags.json").write_text(json.dumps(self.tags))
        return hexd

    def tag(self, ref: str) -> str | None:
        p = self.dir / "tags.json"
        return json.loads(p.read_text()).get(ref) if p.exists() else None

    def knob(self, name: str, value) -> None:
        (self.dir / name).write_text(json.dumps(value))

    def gh(self, path: str, value) -> None:
        (self.dir / "gh" / path.replace("/", "_")).write_text(json.dumps(value))

    def calls(self) -> list[str]:
        p = self.dir / "calls.log"
        return p.read_text().splitlines() if p.exists() else []

    def outputs(self) -> dict[str, str]:
        if not self.out.exists():
            return {}
        return dict(line.split("=", 1) for line in self.out.read_text().splitlines() if "=" in line)

    def run(self, script: str, **env: str) -> subprocess.CompletedProcess:
        full = {k: v for k, v in os.environ.items() if k in ("HOME", "LANG")} | {
            "PATH": f"{FAKES}:{os.environ['PATH']}", "FAKE_STATE": str(self.dir), "RUNNER_TEMP": str(self.dir),
            "GITHUB_OUTPUT": str(self.out), "GITHUB_STEP_SUMMARY": str(self.summary)} | env
        return subprocess.run(["bash", "-e", "-c", script], env=full, capture_output=True, text=True, timeout=60)


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
        _, out, _ = meta("decide", **pr("labeled", ["publish-preview", "area/ci"], "area/ci"))
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
        rc, out, _ = meta("decide", EVENT="workflow_dispatch", INPUT_REF=SHA)
        self.assertEqual((rc, out["ref"]), (0, SHA))

    def test_an_abbreviated_commit_is_refused_with_the_reason(self):
        rc, _, err = meta("decide", EVENT="workflow_dispatch", INPUT_REF="f4f9b8a")
        self.assertEqual(rc, 1)
        self.assertIn("full 40-character commit", err)

    def test_dispatch_inputs_are_validated(self):
        for ref in ("-x", "a..b", "$(id)", "dev\nmoving=dev", "a b", "", "f4f9b8a", SHA[:12], SHA[:39]):
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

    def test_a_manual_run_for_another_api_url_gets_its_own_tag(self):
        url = "http://192.168.1.20:8000"
        rc, out, _ = meta("tags", PREFIX="manual", SHA=SHA, API_URL=url)
        h = hashlib.sha256(url.encode()).hexdigest()[:8]
        self.assertEqual((rc, out["tag"]), (0, f"manual-{SHA[:12]}-{h}"))
        other = meta("tags", PREFIX="manual", SHA=SHA, API_URL="http://10.0.0.5:8000")[1]["tag"]
        self.assertNotEqual(other, out["tag"])
        self.assertEqual(meta("tags", PREFIX="manual", SHA=SHA, API_URL="http://localhost:8000")[1]["tag"],
                         f"manual-{SHA[:12]}")
        self.assertEqual(meta("tags", PREFIX="dev", SHA=SHA, API_URL=url)[0], 1)
        self.assertEqual(meta("tags", PREFIX="manual", SHA=SHA, API_URL="ftp://x")[0], 1)

    def test_the_workflow_passes_the_api_url_to_tags(self):
        self.assertIn("API_URL: ${{ steps.decide.outputs.api_url }}", JOBS["meta"])

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

    def test_only_pull_request_runs_are_cancelled_dev_and_staging_queue(self):
        # A newer dev push must never kill an older run in the middle of moving the tags (review 5875247534).
        group = WF.split("\nconcurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", group)

    def test_manual_runs_are_grouped_by_their_inputs(self):
        group = WF.split("\nconcurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
        self.assertIn("format('manual-{0}-{1}', inputs.ref, inputs.api_url)", group)


class Permissions(unittest.TestCase):
    def test_workflow_default_is_no_permission(self):
        self.assertIn("\npermissions: {}\n", WF)

    def test_every_job_declares_its_permissions(self):
        self.assertEqual(sorted(JOBS), sorted(["meta", "exists", "contexts", "build", "merge", "promote"]))
        for name, text in JOBS.items():
            self.assertRegex(text, r"\n    permissions:\n", name)

    def test_only_build_merge_and_promote_can_write_packages(self):
        writers = sorted(n for n, t in JOBS.items() if "packages: write" in t)
        self.assertEqual(writers, ["build", "merge", "promote"])
        for name in ("meta", "contexts"):
            perms = JOBS[name].split("\n    permissions:\n", 1)[1].split("\n    ", 1)[0]
            self.assertEqual(perms.strip(), "contents: read", name)

    def test_the_existence_check_only_reads_packages(self):
        perms = JOBS["exists"].split("\n    permissions:\n", 1)[1].split("\n    outputs:", 1)[0]
        self.assertEqual(perms.strip(), "packages: read")

    def test_promote_reads_the_branch_and_pull_request_heads(self):
        perms = JOBS["promote"].split("\n    permissions:\n", 1)[1].split("\n    steps:", 1)[0]
        self.assertEqual(sorted(p.strip() for p in perms.strip().splitlines()),
                         ["contents: read", "packages: write", "pull-requests: read"])

    def test_attestation_permissions_only_where_attesting(self):
        for perm in ("id-token: write", "attestations: write", "artifact-metadata: write"):
            self.assertEqual([n for n, t in JOBS.items() if perm in t], ["merge"], perm)

    def test_every_writing_job_checks_for_forks_itself(self):
        for name in ("exists", "build", "merge", "promote"):
            cond = JOBS[name].split("\n    if: >-\n", 1)[1].split("\n    runs-on:", 1)[0]
            self.assertIn("github.event_name != 'pull_request' || " + FORK_GUARD, cond, name)
        self.assertIn(FORK_GUARD, JOBS["meta"].split("\n    runs-on:", 1)[0])

    def test_no_secret_but_the_github_token(self):
        self.assertNotRegex(WF, r"secrets\.")
        self.assertEqual(re.findall(r"password: (.*)", WF), ["${{ github.token }}"] * 4)

    def test_writing_jobs_run_no_repository_script(self):
        for name in ("exists", "build", "merge", "promote"):
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
        self.assertIn(f"COMPONENTS: {' '.join(COMPONENTS)}", JOBS["exists"])

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
        self.assertIn("needs: [meta, exists, contexts]", JOBS["build"])

    def test_moving_tags_change_only_after_every_image_is_merged(self):
        self.assertIn("needs: [meta, exists, merge]", JOBS["promote"])
        cond = JOBS["promote"].split("\n    if: >-\n", 1)[1].split("\n    runs-on:", 1)[0]
        self.assertIn("needs.merge.result == 'success'", cond)
        self.assertIn("(needs.merge.result == 'skipped' && needs.exists.outputs.missing == '')", cond)
        self.assertIn("needs.exists.result == 'success'", cond)

    def test_promote_only_moves_tags_while_its_commit_is_the_newest(self):
        steps = re.split(r"\n      - ", JOBS["promote"])
        self.assertTrue(steps[1].startswith("name: Is this still the newest commit\n"), steps[1][:60])
        for step in steps[2:]:
            self.assertIn("\n        if: steps.fresh.outputs.fresh == 'true'\n", step, step[:60])

    def test_builds_are_skipped_when_every_tag_exists(self):
        for name in ("contexts", "build"):
            cond = JOBS[name].split("\n    if: >-\n", 1)[1].split("\n    runs-on:", 1)[0]
            self.assertIn("needs.exists.outputs.missing != ''", cond, name)

    def test_frontend_gets_the_api_url_and_the_scan_node_image_of_the_same_build(self):
        self.assertIn('echo "NEXT_PUBLIC_BACKEND_URL=$API_URL"', JOBS["build"])
        self.assertIn('echo "NEXT_PUBLIC_CBOM_NODE_IMAGE=$REGISTRY/devsecshield-scan-node:$TAG"', JOBS["build"])

    def test_minio_copies_nothing_from_its_context(self):
        for line in MINIO.splitlines():
            if re.match(r"\s*(COPY|ADD)\b", line):
                self.assertIn("--from=", line)
        self.assertIn("test \"$(git rev-parse HEAD)\" = \"${MINIO_COMMIT}\"", MINIO)
        self.assertRegex(MINIO, r"\nUSER 10002\n")


def _contexts_from_ci() -> dict[str, tuple]:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    out = {}
    for raw in re.findall(r"add '(\{.*?\})'", text):
        d = json.loads(raw)
        out[d["name"]] = (d["context"], d["dockerfile"], d.get("build-contexts", ""))
    return out


def _contexts_from_build_images() -> dict[str, tuple]:
    text = (ROOT / "scripts" / "deploy" / "build_images.sh").read_text(encoding="utf-8")
    out = {}
    for m in re.finditer(r"\n  build ([a-z-]+) (\S+) (\S+)(.*?)\n(?!    --build-context)", text + "\n", re.S):
        extra = re.findall(r"--build-context (\S+)", m.group(4))
        out[m.group(1)] = (m.group(3), m.group(2), " ".join(extra))
    return out


def _contexts_from_publish() -> dict[str, tuple]:
    out = {}
    for m in re.finditer(r"- \{name: ([a-z-]+), context: ([^,]+), dockerfile: ([^,}]+)(?:, build-contexts: \"([^\"]*)\")?",
                         JOBS["build"]):
        out[m.group(1)] = (m.group(2).strip('"'), m.group(3).strip(), m.group(4) or "")
    return out


def _contexts_from_check_script() -> dict[str, tuple]:
    text = (ROOT / "scripts" / "deploy" / "check_image_contexts.sh").read_text(encoding="utf-8")
    return {n: (c, d) for n, d, c in re.findall(r'^  "([a-z-]+)\|([^|]+)\|([^|]+)\|', text, re.M)}


class OneDefinitionOfEachImage(unittest.TestCase):
    """ci.yml "Decide", scripts/deploy/build_images.sh, check_image_contexts.sh and this workflow's matrix define the
    same images with the same context, Dockerfile and named contexts (review 5875247534, architecture)."""

    def test_the_lists_agree(self):
        ci, script, publish, check = (_contexts_from_ci(), _contexts_from_build_images(), _contexts_from_publish(),
                                      _contexts_from_check_script())
        self.assertEqual(set(publish), set(COMPONENTS))
        self.assertEqual(set(ci), set(COMPONENTS) - {"minio"})
        self.assertEqual(set(script), {"backend", "frontend", "scan-worker", "dast-worker"})
        self.assertTrue(set(COMPONENTS) - {"minio"} <= set(check), set(check))
        for name, want in publish.items():
            if name in ci:
                self.assertEqual(ci[name], want, f"ci.yml vs publish-ghcr.yml: {name}")
            if name in script:
                self.assertEqual(script[name], want, f"build_images.sh vs publish-ghcr.yml: {name}")
            if name in check:
                self.assertEqual(check[name], want[:2], f"check_image_contexts.sh vs publish-ghcr.yml: {name}")


def _index(arch_digests: dict[str, str]) -> dict:
    return {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"digest": f"sha256:{d}", "platform": {"os": "linux", "architecture": a}}
                          for a, d in sorted(arch_digests.items())]}


class ExistsStep(unittest.TestCase):
    def setUp(self):
        self.reg = Registry()
        self.script = step_script("exists", "Which images already exist")

    def tearDown(self):
        self.reg.close()

    def run_it(self):
        return self.reg.run(self.script, REGISTRY=REG, TAG="dev-0123456789ab", COMPONENTS=" ".join(COMPONENTS))

    def test_all_six_exist_so_nothing_is_missing(self):
        for c in COMPONENTS:
            self.reg.put(f"{REG}/devsecshield-{c}:dev-0123456789ab", {"c": c})
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.reg.outputs()["missing"], "")

    def test_a_missing_or_unreadable_tag_is_built(self):
        for c in COMPONENTS[:4]:
            self.reg.put(f"{REG}/devsecshield-{c}:dev-0123456789ab", {"c": c})
        self.reg.knob("inspect-error.json", [f"{REG}/devsecshield-backend:dev-0123456789ab"])
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.reg.outputs()["missing"], "backend scan-node minio")


class MergeStep(unittest.TestCase):
    TAG = "dev-0123456789ab"

    def setUp(self):
        self.reg = Registry()
        self.script = step_script("merge", "Create the multi-architecture index")
        self.img = f"{REG}/devsecshield-backend"
        (self.reg.dir / "digest").mkdir()
        for arch in ("amd64", "arm64"):
            d = self.reg.put("", {"arch": arch})
            (self.reg.dir / "digest" / arch).write_text(f"sha256:{d}\n")

    def tearDown(self):
        self.reg.close()

    def run_it(self):
        return self.reg.run(self.script, IMAGE=self.img, NAME="backend", TAG=self.TAG, SHA=SHA,
                            SOURCE="https://github.com/Acme-Org/DevSecShield")

    def test_creates_the_index_when_the_tag_is_new(self):
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        made = self.reg.tag(f"{self.img}:{self.TAG}")
        self.assertEqual(self.reg.outputs()["digest"], f"sha256:{made}")
        self.assertEqual(sum(" create " in f" {c} " and "--dry-run" not in c for c in self.reg.calls()), 1)

    def test_an_existing_tag_is_reused_never_overwritten(self):
        first = self.reg.put(f"{self.img}:{self.TAG}", _index({"amd64": "a" * 64, "arm64": "b" * 64}))
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.reg.tag(f"{self.img}:{self.TAG}"), first)
        self.assertEqual(self.reg.outputs()["digest"], f"sha256:{first}")
        self.assertFalse([c for c in self.reg.calls() if "imagetools create" in c])
        self.assertIn("::notice::", p.stdout)

    def test_a_registry_error_is_not_taken_for_a_missing_tag(self):
        self.reg.knob("inspect-error.json", [f"{self.img}:{self.TAG}"])
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertIsNone(self.reg.tag(f"{self.img}:{self.TAG}"))

    def test_a_wrong_platform_set_is_refused_before_the_tag_is_written(self):
        d = self.reg.put("", {"arch": "amd64"})
        (self.reg.dir / "digest" / "arm64").write_text(f"sha256:{d}\n")
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertIsNone(self.reg.tag(f"{self.img}:{self.TAG}"))


class FreshStep(unittest.TestCase):
    def setUp(self):
        self.reg = Registry()
        self.script = step_script("promote", "Is this still the newest commit")

    def tearDown(self):
        self.reg.close()

    def run_push(self, head: str):
        self.reg.gh("repos/Acme-Org/DevSecShield/commits/dev", {"sha": head})
        return self.reg.run(self.script, GH_TOKEN="x", REPO=REPO, EVENT="push", BRANCH="dev", PR="", SHA=SHA)

    def test_the_head_itself_is_fresh(self):
        p = self.run_push(SHA)
        self.assertEqual((p.returncode, self.reg.outputs()["fresh"]), (0, "true"), p.stderr)

    def test_a_newer_head_with_only_docs_is_still_fresh(self):
        self.reg.gh(f"repos/Acme-Org/DevSecShield/compare/{SHA}...{HEAD}",
                    {"status": "ahead", "files": [{"filename": "docs/ci/README.md"}, {"filename": "deploy/local/README.md"}]})
        p = self.run_push(HEAD)
        self.assertEqual((p.returncode, self.reg.outputs()["fresh"]), (0, "true"), p.stderr)

    def test_a_newer_head_with_code_skips_with_a_notice(self):
        self.reg.gh(f"repos/Acme-Org/DevSecShield/compare/{SHA}...{HEAD}",
                    {"status": "ahead", "files": [{"filename": "docs/x.md"}, {"filename": "backend/main.py"}]})
        p = self.run_push(HEAD)
        self.assertEqual((p.returncode, self.reg.outputs()["fresh"]), (0, "false"), p.stderr)
        self.assertIn("::notice", p.stdout)

    def test_an_older_or_diverged_head_skips(self):
        for status in ("behind", "diverged"):
            self.reg.gh(f"repos/Acme-Org/DevSecShield/compare/{SHA}...{HEAD}", {"status": status, "files": []})
            p = self.run_push(HEAD)
            self.assertEqual((p.returncode, self.reg.outputs()["fresh"]), (0, "false"), status)
            self.reg.out.unlink()

    def test_a_pull_request_compares_with_its_head(self):
        self.reg.gh("repos/Acme-Org/DevSecShield/pulls/93", {"head": {"sha": HEAD}})
        self.reg.gh(f"repos/Acme-Org/DevSecShield/compare/{SHA}...{HEAD}",
                    {"status": "ahead", "files": [{"filename": "frontend/app/page.tsx"}]})
        p = self.reg.run(self.script, GH_TOKEN="x", REPO=REPO, EVENT="pull_request", BRANCH="", PR="93", SHA=SHA)
        self.assertEqual((p.returncode, self.reg.outputs()["fresh"]), (0, "false"), p.stderr)

    def test_an_unreadable_head_fails(self):
        p = self.reg.run(self.script, GH_TOKEN="x", REPO=REPO, EVENT="push", BRANCH="dev", PR="", SHA=SHA)
        self.assertNotEqual(p.returncode, 0)


class PromoteStep(unittest.TestCase):
    TAG, MOVING = "dev-0123456789ab", "dev"

    def setUp(self):
        self.reg = Registry()
        self.script = step_script("promote", "Point the moving tags at this commit's images")
        self.old, self.new = {}, {}
        for c in COMPONENTS:
            img = f"{REG}/devsecshield-{c}"
            self.old[c] = self.reg.put(f"{img}:{self.MOVING}", _index({"amd64": "1" * 64, "arm64": c.ljust(64, "x")}))
            self.new[c] = self.reg.put(f"{img}:{self.TAG}", _index({"amd64": "2" * 64, "arm64": c.ljust(64, "y")}))

    def tearDown(self):
        self.reg.close()

    def run_it(self):
        return self.reg.run(self.script, REGISTRY=REG, TAG=self.TAG, MOVING=self.MOVING,
                            COMPONENTS=" ".join(COMPONENTS))

    def moving(self, c):
        return self.reg.tag(f"{REG}/devsecshield-{c}:{self.MOVING}")

    def test_every_moving_tag_ends_on_the_new_index(self):
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual({c: self.moving(c) for c in COMPONENTS}, self.new)

    def test_a_transient_failure_is_retried(self):
        self.reg.knob("create-fail.json", {f"{REG}/devsecshield-dast-worker:{self.MOVING}": 2})
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual({c: self.moving(c) for c in COMPONENTS}, self.new)
        self.assertEqual(sum(c.startswith("sleep ") for c in self.reg.calls()), 2)

    def test_a_lasting_failure_rolls_the_moved_tags_back(self):
        self.reg.knob("create-fail.json", {f"{REG}/devsecshield-dast-worker:{self.MOVING}": 99})
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual({c: self.moving(c) for c in COMPONENTS}, self.old, p.stdout + p.stderr)
        tries = [c for c in self.reg.calls() if f"-t {REG}/devsecshield-dast-worker:{self.MOVING}" in c]
        self.assertEqual(len(tries), 3)

    def test_a_moving_tag_that_did_not_exist_is_reported_not_hidden(self):
        tags = json.loads((self.reg.dir / "tags.json").read_text())
        del tags[f"{REG}/devsecshield-backend:{self.MOVING}"]
        (self.reg.dir / "tags.json").write_text(json.dumps(tags))
        self.reg.knob("create-fail.json", {f"{REG}/devsecshield-frontend:{self.MOVING}": 99})
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.moving("backend"), self.new["backend"])
        self.assertIn("did not exist before", p.stdout)
        for c in COMPONENTS[1:]:
            self.assertEqual(self.moving(c), self.old[c], c)

    def test_an_unreadable_new_image_moves_nothing(self):
        self.reg.knob("inspect-error.json", [f"{REG}/devsecshield-minio:{self.TAG}"])
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual({c: self.moving(c) for c in COMPONENTS}, self.old)


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
