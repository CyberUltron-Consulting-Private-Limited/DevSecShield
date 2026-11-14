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


_EXPR_TOKEN = re.compile(r"\s*(?:(?P<op>\|\||&&|==|!=|!|\(|\))|'(?P<str>(?:[^']|'')*)'|(?P<name>[A-Za-z_][\w.*-]*(?:\(\))?))")
STATUS_FUNCTIONS = ("success()", "failure()", "always()", "cancelled()")


def _truthy(value) -> bool:
    return value not in (None, False, "", 0)


def evaluate(expr: str, ctx: dict):
    """Evaluate a GitHub Actions expression: enough of the language for this workflow's `if:` conditions (&&, ||, !,
    ==, !=, parentheses, '...' strings, context paths, status functions). `ctx` maps flat paths such as
    `needs.build.result` or `cancelled()` to values; an unknown path is null, as in GitHub. Strings compare
    case-insensitively and null equals '' (GitHub's loose equality)."""
    tokens, pos, expr = [], 0, expr.strip()
    while pos < len(expr):
        m = _EXPR_TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise ValueError(f"cannot parse {expr[pos:]!r}")
        if m["str"] is not None:
            tokens.append(("str", m["str"].replace("''", "'")))
        else:
            tokens.append(("op", m["op"]) if m["op"] else ("name", m["name"]))
        pos = m.end()
    i = 0

    def peek():
        return tokens[i] if i < len(tokens) else (None, None)

    def take():
        nonlocal i
        i += 1
        return tokens[i - 1]

    def or_():
        v = and_()
        while peek() == ("op", "||"):
            take()
            r = and_()
            v = v if _truthy(v) else r
        return v

    def and_():
        v = cmp()
        while peek() == ("op", "&&"):
            take()
            r = cmp()
            v = r if _truthy(v) else v
        return v

    def cmp():
        v = unary()
        if peek() in (("op", "=="), ("op", "!=")):
            op = take()[1]
            r = unary()
            a, b = ("" if v is None else v), ("" if r is None else r)
            eq = a.casefold() == b.casefold() if isinstance(a, str) and isinstance(b, str) else a == b
            return eq if op == "==" else not eq
        return v

    def unary():
        if peek() == ("op", "!"):
            take()
            return not _truthy(unary())
        kind, val = take()
        if (kind, val) == ("op", "("):
            v = or_()
            if take() != ("op", ")"):
                raise ValueError(f"unbalanced parentheses in {expr!r}")
            return v
        if kind == "str":
            return val
        if kind == "name":
            if val.endswith("()") and val not in STATUS_FUNCTIONS:
                raise ValueError(f"function {val} is not modelled")
            return ctx[val] if val.endswith("()") else ctx.get(val)
        raise ValueError(f"unexpected {val!r} in {expr!r}")

    value = or_()
    if i != len(tokens):
        raise ValueError(f"trailing tokens in {expr!r}")
    return value


def job_runs(job: str, state: dict) -> bool:
    """Whether job `job` runs, by its own `needs:` and `if:`, given the results and outputs of the jobs before it
    (`state`: flat paths, e.g. {"needs.build.result": "skipped"}). Outputs of a job that is not in `needs:` are not
    visible (null), and an `if:` without a status function gets GitHub's implicit `success()` (modelled over the
    direct needs)."""
    text = JOBS[job]
    cond = " ".join(text.split("\n    if: >-\n", 1)[1].split("\n    runs-on:", 1)[0].split())
    needs = [n.strip() for n in re.search(r"\n    needs: \[?([a-z, -]+?)\]?\n", text).group(1).split(",")]
    ctx = {k: v for k, v in state.items() if not k.startswith("needs.") or k.split(".")[1] in needs}
    success = all(state.get(f"needs.{n}.result") == "success" for n in needs)
    ctx = {"success()": success, "always()": True, "cancelled()": False,
           "failure()": any(state.get(f"needs.{n}.result") == "failure" for n in needs)} | ctx
    runs = _truthy(evaluate(cond, ctx))
    return runs and (success or any(f in cond for f in STATUS_FUNCTIONS))


def step_if(job: str, name: str) -> str | None:
    """The `if:` of step `name` in `job` (None when it has none)."""
    parts = [p for p in re.split(r"\n      - ", JOBS[job]) if p.startswith(f"name: {name}\n")]
    assert len(parts) == 1, f"{job}: step {name!r}"
    m = re.search(r"\n        if: (.+)\n", parts[0] + "\n")
    return m.group(1) if m else None


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

    def test_only_a_push_to_staging_is_a_release(self):
        self.assertEqual(meta("decide", EVENT="push", REF_NAME="staging", SHA=SHA)[1]["release"], "true")
        self.assertEqual(meta("decide", EVENT="push", REF_NAME="dev", SHA=SHA)[1]["release"], "false")
        self.assertEqual(meta("decide", EVENT="push", REF_NAME="main", SHA=SHA)[1]["release"], "false")  # not published
        self.assertEqual(meta("decide", **pr("labeled", ["publish-preview"], "publish-preview"))[1]["release"], "false")
        self.assertEqual(meta("decide", EVENT="workflow_dispatch", INPUT_REF="staging")[1]["release"], "false")

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

    def _version_file(self, text: str) -> str:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        path = Path(d) / "__init__.py"
        path.write_text(text)
        return str(path)

    def test_a_release_gets_the_scan_node_version_tags(self):
        f = self._version_file('"""x"""\nimport os\n\nVERSION = "1.0.0"\n')
        rc, out, _ = meta("tags", PREFIX="staging", SHA=SHA, RELEASE="true", NODE_VERSION_FILE=f)
        self.assertEqual((rc, out["node_version"], out["node_release_tags"]), (0, "1.0.0", "1.0.0 1.0 latest"))
        f2 = self._version_file('VERSION = "12.40.3"\n')
        self.assertEqual(meta("tags", PREFIX="staging", SHA=SHA, RELEASE="true", NODE_VERSION_FILE=f2)[1]["node_release_tags"],
                         "12.40.3 12.40 latest")
        # a pre-release names only itself: never latest, never the minor line
        f3 = self._version_file('VERSION = "2.0.0-rc.1"\n')
        self.assertEqual(meta("tags", PREFIX="staging", SHA=SHA, RELEASE="true", NODE_VERSION_FILE=f3)[1]["node_release_tags"],
                         "2.0.0-rc.1")

    def test_the_real_scan_node_version_is_read(self):
        rc, out, _ = meta("tags", PREFIX="staging", SHA=SHA, RELEASE="true",
                          NODE_VERSION_FILE=str(ROOT / "scan_node" / "zs_scan_node" / "__init__.py"))
        self.assertEqual(rc, 0)
        self.assertRegex(out["node_release_tags"], r"^\d+\.\d+\.\d+ \d+\.\d+ latest$")

    def test_no_release_tags_without_a_release(self):
        f = self._version_file('VERSION = "1.0.0"\n')
        for prefix in ("dev", "pr-93", "manual"):
            rc, out, _ = meta("tags", PREFIX=prefix, SHA=SHA, NODE_VERSION_FILE=f)
            self.assertEqual((rc, out["node_version"], out["node_release_tags"]), (0, "1.0.0", ""), prefix)
        self.assertEqual(meta("tags", PREFIX="dev", SHA=SHA, RELEASE="true", NODE_VERSION_FILE=f)[0], 1)
        rc, out, _ = meta("tags", PREFIX="dev", SHA=SHA)  # no file (older checkout): no version, no failure
        self.assertEqual((rc, out["node_version"]), (0, ""))

    def test_a_release_without_a_valid_version_fails(self):
        for text in ("", 'VERSION = "bad version!"\n', 'VERSION = "1.0.0\nlatest"\n'):
            f = self._version_file(text)
            self.assertEqual(meta("tags", PREFIX="staging", SHA=SHA, RELEASE="true", NODE_VERSION_FILE=f)[0], 1, text)
        self.assertEqual(meta("tags", PREFIX="staging", SHA=SHA, RELEASE="true", NODE_VERSION_FILE="/nonexistent")[0], 1)

    def test_the_workflow_reads_the_version_of_the_built_commit(self):
        meta_job = JOBS["meta"]
        self.assertIn("RELEASE: ${{ steps.decide.outputs.release }}", meta_job)
        self.assertIn("NODE_VERSION_FILE: target/scan_node/zs_scan_node/__init__.py", meta_job)
        self.assertIn("            scan_node/zs_scan_node\n", meta_job)
        self.assertIn("node_release_tags: ${{ steps.tags.outputs.node_release_tags }}", meta_job)

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
        self.assertEqual(sorted(JOBS), sorted(["meta", "exists", "contexts", "build", "merge", "promote", "release"]))
        for name, text in JOBS.items():
            self.assertRegex(text, r"\n    permissions:\n", name)

    def test_only_build_merge_promote_and_release_can_write_packages(self):
        writers = sorted(n for n, t in JOBS.items() if "packages: write" in t)
        self.assertEqual(writers, ["build", "merge", "promote", "release"])
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
        for name in ("exists", "build", "merge", "promote", "release"):
            cond = JOBS[name].split("\n    if: >-\n", 1)[1].split("\n    runs-on:", 1)[0]
            self.assertIn("github.event_name != 'pull_request' || " + FORK_GUARD, cond, name)
        self.assertIn(FORK_GUARD, JOBS["meta"].split("\n    runs-on:", 1)[0])

    def test_no_secret_but_the_github_token(self):
        self.assertNotRegex(WF, r"secrets\.")
        self.assertEqual(re.findall(r"password: (.*)", WF), ["${{ github.token }}"] * 5)
        # helm logs in with the same token, on stdin (never on a command line)
        self.assertEqual(re.findall(r"GH_TOKEN: (.*)", JOBS["release"]), ["${{ github.token }}"])
        self.assertIn('printf \'%s\' "$GH_TOKEN" | helm registry login ghcr.io --username "$ACTOR" --password-stdin', JOBS["release"])

    def test_writing_jobs_run_no_repository_script(self):
        for name in ("exists", "build", "merge", "promote", "release"):
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
        # merge runs on every publishing run, also when nothing was built (review 5878241489): promote needs it green.
        self.assertIn("needs: [meta, merge]", JOBS["promote"])
        cond = JOBS["promote"].split("\n    if: >-\n", 1)[1].split("\n    runs-on:", 1)[0]
        self.assertIn("needs.merge.result == 'success'", cond)
        self.assertNotIn("'skipped'", cond)

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


def run_state(**changes: str) -> dict:
    """Job results/outputs of a push to dev, by default the all-six-exist case: nothing missing, contexts and build
    skipped. Keyword names use __ for dots (needs__build__result)."""
    state = {"github.event_name": "push", "github.repository": REPO,
             "needs.meta.result": "success", "needs.meta.outputs.publish": "true", "needs.meta.outputs.moving": "dev",
             "needs.exists.result": "success", "needs.exists.outputs.missing": "",
             "needs.build.result": "skipped", "needs.merge.result": "success"}
    return state | {k.replace("__", "."): v for k, v in changes.items()}


class JobConditions(unittest.TestCase):
    """The job and step `if:`s, evaluated (review 5878241489: when all six tags existed, merge was skipped, so a tag
    whose attestation had failed was promoted without one)."""

    def test_merge_runs_when_every_tag_existed_and_nothing_was_built(self):
        self.assertTrue(job_runs("merge", run_state()))

    def test_merge_runs_after_the_builds(self):
        self.assertTrue(job_runs("merge", run_state(needs__build__result="success",
                                                    needs__exists__outputs__missing="backend minio")))

    def test_merge_does_not_run_when_the_builds_failed_or_never_ran(self):
        for name, state in {
            "build failed": run_state(needs__build__result="failure", needs__exists__outputs__missing="backend"),
            "build cancelled": run_state(needs__build__result="cancelled", needs__exists__outputs__missing="backend"),
            "contexts failed, so build skipped with tags missing":
                run_state(needs__exists__outputs__missing="backend"),
            "exists failed (no output)": run_state(needs__exists__result="failure"),
            "nothing to publish": run_state(needs__meta__outputs__publish="false", needs__exists__result="skipped"),
            "run cancelled": run_state() | {"cancelled()": True},
            "fork pull request": run_state(github__event_name="pull_request") | {
                "github.event.pull_request.head.repo.full_name": "someone/DevSecShield"},
        }.items():
            self.assertFalse(job_runs("merge", state), name)

    def test_the_digests_are_downloaded_only_when_something_was_built(self):
        cond = step_if("merge", "Download the digests")
        self.assertIsNotNone(cond)
        self.assertFalse(_truthy(evaluate(cond, run_state())))
        self.assertTrue(_truthy(evaluate(cond, run_state(needs__exists__outputs__missing="backend"))))

    def test_promote_runs_only_after_merge_succeeded(self):
        self.assertTrue(job_runs("promote", run_state()))
        for name, state in {
            "merge skipped": run_state(needs__merge__result="skipped"),
            "merge failed (an attestation failed)": run_state(needs__merge__result="failure"),
            "merge cancelled": run_state(needs__merge__result="cancelled"),
            "no moving tag (manual run)": run_state(needs__meta__outputs__moving=""),
            "run cancelled": run_state() | {"cancelled()": True},
        }.items():
            self.assertFalse(job_runs("promote", state), name)

    def test_release_runs_only_after_a_fresh_promote_of_a_release(self):
        ok = run_state(needs__meta__outputs__node_release_tags="1.0.0 1.0 latest", needs__promote__result="success",
                       needs__promote__outputs__fresh="true", needs__meta__outputs__moving="staging")
        self.assertTrue(job_runs("release", ok))
        for name, state in {
            "not a release (dev, PR, manual)": ok | {"needs.meta.outputs.node_release_tags": ""},
            "promote failed": ok | {"needs.promote.result": "failure"},
            "promote skipped": ok | {"needs.promote.result": "skipped"},
            "a newer commit moves the tags": ok | {"needs.promote.outputs.fresh": "false"},
            "nothing published": ok | {"needs.meta.outputs.publish": "false"},
            "run cancelled": ok | {"cancelled()": True},
        }.items():
            self.assertFalse(job_runs("release", state), name)

    def test_the_evaluator_follows_github_semantics(self):
        self.assertTrue(evaluate("!cancelled() && a == 'X'", {"cancelled()": False, "a": "x"}))
        self.assertEqual(evaluate("a || 'd'", {}), "d")
        self.assertTrue(evaluate("missing == ''", {}))
        self.assertFalse(_truthy(evaluate("!(a == 'x' || b != '')", {"a": "x"})))
        self.assertRaises(ValueError, evaluate, "contains(a, 'b')", {})
        # build has no status function: GitHub's implicit success() skips it after a failed context check
        self.assertFalse(job_runs("build", run_state(needs__exists__outputs__missing="backend",
                                                     needs__contexts__result="failure")))
        self.assertTrue(job_runs("build", run_state(needs__exists__outputs__missing="backend",
                                                    needs__contexts__result="success")))


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
        # When every tag existed nothing was built and no digest is downloaded: the reuse path needs none.
        for f in (self.reg.dir / "digest").iterdir():
            f.unlink()
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

    def test_an_existing_tag_with_one_platform_is_refused_not_reused(self):
        first = self.reg.put(f"{self.img}:{self.TAG}", _index({"amd64": "a" * 64}))
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("lists [linux/amd64], expected exactly linux/amd64 and linux/arm64", p.stdout)
        self.assertEqual(self.reg.tag(f"{self.img}:{self.TAG}"), first)
        self.assertNotIn("digest", self.reg.outputs())
        self.assertFalse([c for c in self.reg.calls() if "imagetools create" in c])

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

    def test_a_truncated_compare_is_not_trusted(self):
        # The compare API lists at most 300 files: 300 doc files can hide code changes after them.
        self.reg.gh(f"repos/Acme-Org/DevSecShield/compare/{SHA}...{HEAD}",
                    {"status": "ahead", "files": [{"filename": f"docs/page-{i}.md"} for i in range(300)]})
        p = self.run_push(HEAD)
        self.assertEqual((p.returncode, self.reg.outputs()["fresh"]), (0, "false"), p.stderr)

    def test_a_path_that_only_starts_with_docs_is_code(self):
        self.reg.gh(f"repos/Acme-Org/DevSecShield/compare/{SHA}...{HEAD}",
                    {"status": "ahead", "files": [{"filename": "docs/ci/README.md"}, {"filename": "docsite/app.py"}]})
        p = self.run_push(HEAD)
        self.assertEqual((p.returncode, self.reg.outputs()["fresh"]), (0, "false"), p.stderr)

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

    def test_an_unreadable_moving_tag_moves_nothing(self):
        # A registry error is not "the tag does not exist": nothing may move before every current position is known.
        self.reg.knob("inspect-error.json", [f"{REG}/devsecshield-scan-node:{self.MOVING}"])
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(f"devsecshield-scan-node:{self.MOVING} cannot be read; no moving tag was changed", p.stdout)
        self.assertEqual({c: self.moving(c) for c in COMPONENTS}, self.old)
        self.assertFalse([c for c in self.reg.calls() if "imagetools create" in c])

    def test_a_write_that_lands_but_reports_failure_is_put_back_too(self):
        # Review 5878241489: the registry keeps the write but the response is lost (502, client timeout), so the
        # failing tag itself can be on the new commit; it is put back with the others.
        self.reg.knob("create-lands-but-fails.json", {f"{REG}/devsecshield-dast-worker:{self.MOVING}": 99})
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual({c: self.moving(c) for c in COMPONENTS}, self.old, p.stdout + p.stderr)
        self.assertIn(f"devsecshield-dast-worker:{self.MOVING} is back at sha256:{self.old['dast-worker']}", p.stdout)
        self.assertNotRegex(p.stdout, r"::error::.* is at ")

    def test_a_move_that_reads_back_other_bytes_fails_and_rolls_back(self):
        # Only the read-back shows that the registry stored something else than the index that was sent.
        self.reg.knob("create-wrong.json", {f"{REG}/devsecshield-dast-worker:{self.MOVING}": 3})
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual({c: self.moving(c) for c in COMPONENTS}, self.old, p.stdout + p.stderr)

    def test_a_tag_that_cannot_be_put_back_is_named(self):
        self.reg.knob("create-wrong.json", {f"{REG}/devsecshield-dast-worker:{self.MOVING}": 99})
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        now = self.moving("dast-worker")
        self.assertNotIn(now, (self.old["dast-worker"], self.new["dast-worker"]))
        self.assertIn(f"::error::{REG}/devsecshield-dast-worker:{self.MOVING} is at sha256:{now}, "
                      f"not back at sha256:{self.old['dast-worker']}", p.stdout)
        self.assertIn("1 moving tag(s) dev are not where they were before this run", p.stdout)
        for c in COMPONENTS:
            if c != "dast-worker":
                self.assertEqual(self.moving(c), self.old[c], c)


class ReleaseStep(unittest.TestCase):
    """The version tag (1.0.0) is written once (the wizard pins it); 1.0 and latest follow the version, not the branch."""
    TAG = "staging-0123456789ab"
    IMG = f"{REG}/devsecshield-scan-node"

    def setUp(self):
        self.reg = Registry()
        self.script = step_script("release", "Point the scan node release tags at this commit's image")
        self.new = self.reg.put(f"{self.IMG}:{self.TAG}", _index({"amd64": "2" * 64, "arm64": "3" * 64}))

    def tearDown(self):
        self.reg.close()

    def run_it(self, tags="1.0.0 1.0 latest"):
        return self.reg.run(self.script, IMAGE=self.IMG, TAG=self.TAG, RELEASE_TAGS=tags)

    def tags(self):
        return {t: self.reg.tag(f"{self.IMG}:{t}") for t in ("1.0.0", "1.0", "latest")}

    def test_a_new_version_is_released_from_this_commit(self):
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.tags(), {"1.0.0": self.new, "1.0": self.new, "latest": self.new})
        self.assertIn(f"{self.IMG}:1.0.0 = {self.IMG}:{self.TAG}", self.reg.summary.read_text())

    def test_an_existing_version_is_never_overwritten_and_the_others_follow_it(self):
        old = self.reg.put(f"{self.IMG}:1.0.0", _index({"amd64": "1" * 64, "arm64": "0" * 64}))
        self.reg.put(f"{self.IMG}:latest", _index({"amd64": "9" * 64, "arm64": "8" * 64}))  # somewhere else
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.tags(), {"1.0.0": old, "1.0": old, "latest": old})
        self.assertIn("exists already: kept as it is", p.stdout)
        self.assertFalse([c for c in self.reg.calls() if f"-t {self.IMG}:1.0.0 " in c + " "])

    def test_a_transient_failure_is_retried_and_a_lasting_one_fails(self):
        self.reg.knob("create-fail.json", {f"{self.IMG}:1.0": 2})
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.reg.tag(f"{self.IMG}:1.0"), self.new)
        self.reg.knob("create-wrong.json", {f"{self.IMG}:latest": 99})
        tags = json.loads((self.reg.dir / "tags.json").read_text())
        del tags[f"{self.IMG}:latest"]
        (self.reg.dir / "tags.json").write_text(json.dumps(tags))
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn(f"::error::{self.IMG}:latest is not confirmed", p.stdout)

    def test_a_registry_error_on_the_version_tag_changes_nothing(self):
        self.reg.knob("inspect-error.json", [f"{self.IMG}:1.0.0"])
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("cannot tell whether", p.stdout)
        self.assertFalse([c for c in self.reg.calls() if "imagetools create" in c])

    def test_an_unreadable_image_moves_nothing(self):
        self.reg.knob("inspect-error.json", [f"{self.IMG}:{self.TAG}"])
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse([c for c in self.reg.calls() if "imagetools create" in c])

    def test_a_malformed_tag_is_refused_before_anything_is_written(self):
        p = self.run_it("1.0.0 bad;tag")
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse([c for c in self.reg.calls() if "imagetools create" in c])


class ChartStep(unittest.TestCase):
    def setUp(self):
        self.reg = Registry()
        self.script = step_script("release", "Push the Helm chart (OCI)")
        self.work = self.reg.dir / "work"
        chart = self.work / "deploy" / "helm" / "cbom-scan-node"
        chart.mkdir(parents=True)
        src = ROOT / "deploy" / "helm" / "cbom-scan-node"
        for name in ("Chart.yaml", "values.yaml"):
            (chart / name).write_text((src / name).read_text())

    def tearDown(self):
        self.reg.close()

    def run_it(self, version="1.0.0"):
        script = f"cd {self.work}\n" + self.script
        return self.reg.run(script, REGISTRY=REG, NODE_VERSION=version, ACTOR="ci-bot", GH_TOKEN="ghs_TESTONLY")

    def test_the_chart_is_packaged_for_the_ghcr_image_and_pushed_as_oci(self):
        p = self.run_it()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        pushed = (self.reg.dir / "oci" / REG.split("/", 1)[0] / REG.split("/", 1)[1] / "charts" / "cbom-scan-node-1.0.0.tgz")
        text = pushed.read_text()
        self.assertIn("version=1.0.0\nappVersion=1.0.0\n", text)
        self.assertIn(f"\n  repository: {REG}/devsecshield-scan-node\n", text)
        self.assertEqual(text.count("repository: "), (ROOT / "deploy/helm/cbom-scan-node/values.yaml").read_text().count("repository: "))
        calls = self.reg.calls()
        self.assertIn(f"helm push {self.reg.dir}/chart/cbom-scan-node-1.0.0.tgz oci://{REG}/charts", calls)
        self.assertIn("helm registry login ghcr.io --username ci-bot --password-stdin <password on stdin>", calls)
        self.assertFalse([c for c in calls if "ghs_TESTONLY" in c], "the token is never on a command line")
        self.assertIn(f"oci://{REG}/charts/cbom-scan-node --version 1.0.0", self.reg.summary.read_text())

    def test_an_existing_chart_version_is_kept(self):
        self.assertEqual(self.run_it().returncode, 0)
        p = self.run_it()  # the same version again (a later push to staging): not pushed again
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("exists already: kept as it is", p.stdout)
        self.assertEqual(len([c for c in self.reg.calls() if c.startswith("helm push")]), 1)

    def test_a_registry_error_pushes_nothing(self):
        (self.reg.dir / "helm-show-error").write_text("")
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse([c for c in self.reg.calls() if c.startswith("helm push")])

    def test_a_failed_push_fails_the_job(self):
        (self.reg.dir / "helm-push-fail").write_text("")
        p = self.run_it()
        self.assertNotEqual(p.returncode, 0)

    def test_a_bad_version_is_refused_before_anything_is_packaged(self):
        p = self.run_it("1.0.0; rm -rf /")
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse([c for c in self.reg.calls() if c.startswith("helm")])


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
