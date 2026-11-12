"""Pre-flight and bundle helpers that need no stack: SHA matching, migration heads, the G17 seal."""
from __future__ import annotations

import json
import subprocess

import pytest

from fakerun import FakeRun
from harness import bundle, gate, preflight


def test_same_sha_accepts_prefixes_both_ways_and_refuses_short_or_other():
    sha = "83b570b0123456789abcdef0123456789abcdef0"
    assert preflight.same_sha("83b570b", sha) and preflight.same_sha(sha, sha[:12])
    assert not preflight.same_sha("83b5", sha) and not preflight.same_sha("9cb54a0", sha)
    assert not preflight.same_sha(None, sha) and not preflight.same_sha("", sha)


def test_migration_heads_from_git(tmp_path):
    repo = tmp_path / "r"
    versions = repo / preflight.MIGRATIONS
    versions.mkdir(parents=True)
    (versions / "a.py").write_text("revision: str = 'a1'\ndown_revision = None\n")
    (versions / "b.py").write_text("revision: str = 'b2'\ndown_revision: str = 'a1'\n")
    (versions / "c.py").write_text("revision = \"c3\"\ndown_revision = ('a1',)\n")
    git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "m"], check=True)
    sha = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    assert preflight.migration_heads(str(repo), sha) == ["b2", "c3"]


def test_seal_redacts_writes_g17_and_deletes_the_secrets_file(tmp_path):
    fr = FakeRun(tmp_path)
    run = fr.write()
    (run / "steps" / "G1" / "note.txt").write_text("password Pw-very-secret-1 used\n", encoding="utf-8")
    secrets = tmp_path / "s.json"
    secrets.write_text(json.dumps(["Pw-very-secret-1"]), encoding="utf-8")
    bundle.manifest.update(run, sha="abc1234", images={"x": {}}, playwright={"version": "1.62.0"}, started="t",
                           runs=[55], jobs=[{"id": 900}], assets={"1": [101]}, serialNumbers={"1": "urn:uuid:x"},
                           node_image={"ref": "img", "id": "sha256:1"}, lab={"containers": ["cb02-z01"]},
                           harness={"commit": "abc1234", "dirty": False})
    (run / "flow-state.json").write_text(json.dumps({"logged_out": {"A": True, "B": True}}), encoding="utf-8")
    assert bundle.seal(run, secrets, "2026-11-12T09:00:00Z", budget_min=10**6) == 0
    assert not secrets.exists()
    assert "Pw-very-secret-1" not in (run / "steps" / "G1" / "note.txt").read_text()
    g17 = json.loads((run / "steps" / "G17" / "step.json").read_text())
    assert {c["id"]: c["verdict"] for c in g17["checks"]} == {
        "G17/no_residual_secrets": "PASS", "G17/manifest_complete": "PASS", "G17/harness_committed": "PASS",
        "G17/oracle_hash_in_manifest": "PASS", "G17/runtime_le_budget": "PASS", "G17/customers_logged_out": "PASS"}


@pytest.mark.parametrize("harness, ok", [
    ({"commit": "abc1234", "dirty": False, "untracked": []}, True),
    ({"commit": "abc1234", "dirty": True, "untracked": []}, False),               # an edited judge or ledger
    ({"commit": "abc1234", "dirty": False, "untracked": ["e2e/cbom/harness/x.py"]}, False),  # an untracked module
    ({"commit": "abc1234"}, False),                                               # not recorded: not proven clean
])
def test_g17_fails_on_an_uncommitted_judge(tmp_path, harness, ok):
    """Review 5878413538 minor: a gate PASS from an edited or untracked judge/ledger proves nothing."""
    run = FakeRun(tmp_path).write()
    bundle.manifest.update(run, harness=harness)
    bundle.seal(run, None, "2026-11-12T09:00:00Z", budget_min=10**6)
    g17 = {c["id"]: c["verdict"] for c in json.loads((run / "steps" / "G17" / "step.json").read_text())["checks"]}
    assert g17["G17/harness_committed"] == ("PASS" if ok else "FAIL")


def test_harness_state_lists_untracked_files_under_e2e_cbom(tmp_path):
    import subprocess
    repo = tmp_path / "repo"
    (repo / "e2e" / "cbom").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "e2e" / "cbom" / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "t"], check=True)
    assert bundle.harness_state(repo / "e2e" / "cbom")["dirty"] is False
    (repo / "e2e" / "cbom" / "new.py").write_text("y = 2\n")
    state = bundle.harness_state(repo / "e2e" / "cbom")
    assert state["dirty"] is False and state["untracked"] == ["e2e/cbom/new.py"]
    (repo / "e2e" / "cbom" / "a.py").write_text("x = 3\n")
    assert bundle.harness_state(repo / "e2e" / "cbom")["dirty"] is True


def test_report_and_manifest_name_the_ledger_that_judged(tmp_path):
    """Review 5878413538 minor: the bundle proves which ledger judged it (path + sha256)."""
    import hashlib
    import ledgers
    run = FakeRun(tmp_path).write()
    led = ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE)
    _, report = gate.judge(run, led)
    want = hashlib.sha256(led.read_bytes()).hexdigest()
    assert report["ledger_file"]["sha256"] == want and report["ledger_file"]["path"].endswith("l.yaml")
    assert json.loads((run / "MANIFEST.json").read_text())["ledger"]["sha256"] == want


def test_manifest_complete_needs_node_image_id_and_lab_containers(tmp_path):
    run = FakeRun(tmp_path).write()
    bundle.manifest.update(run, sha="abc1234", images={"x": {}}, playwright={"version": "1.62.0"}, started="t",
                           runs=[55], jobs=[{"id": 900}], assets={"1": [101]}, serialNumbers={"1": "urn:uuid:x"},
                           node_image={"ref": None, "id": None}, lab={"containers": []})
    (run / "flow-state.json").write_text(json.dumps({"logged_out": {"A": True}}), encoding="utf-8")
    bundle.seal(run, None, "2026-11-12T09:00:00Z", budget_min=10**6)
    g17 = {c["id"]: c for c in json.loads((run / "steps" / "G17" / "step.json").read_text())["checks"]}
    assert g17["G17/manifest_complete"]["verdict"] == "FAIL"
    assert g17["G17/manifest_complete"]["observed"] == ["harness", "harness.commit", "lab.containers", "node_image.id"]


def test_seal_fails_the_budget_and_a_missing_logout(tmp_path):
    run = FakeRun(tmp_path).write()
    bundle.seal(run, None, "2026-01-01T00:00:00Z", budget_min=45)
    g17 = {c["id"]: c for c in json.loads((run / "steps" / "G17" / "step.json").read_text())["checks"]}
    assert g17["G17/runtime_le_budget"]["verdict"] == "FAIL"
    assert g17["G17/customers_logged_out"]["verdict"] == "FAIL"
    empty = tmp_path / "empty.yaml"
    empty.write_text("[]\n", encoding="utf-8")
    passed, report = gate.judge(run, empty)
    assert not passed and "G17/runtime_le_budget" in {c["id"] for c in report["blocking"]}


def test_image_revision_accepts_a_ci_only_commit(tmp_path):
    """Run 5: dev moved from 3df26fd to b5e6004 with CI/docs changes only, so the stack's images (built at 3df26fd)
    are the build under test; a code change still fails (CB-05's equivalent_build, ported)."""
    import subprocess
    repo = tmp_path / "r"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    git = ["git", "-C", str(repo), "-c", "user.email=e2e@lab", "-c", "user.name=e2e"]

    def commit(msg: str) -> str:
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", msg], check=True)
        return subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()

    (repo / "backend").mkdir()
    (repo / "backend" / "main.py").write_text("a\n")
    one = commit("one")
    (repo / ".github").mkdir()
    (repo / ".github" / "ci.yml").write_text("x\n")
    (repo / "docs").mkdir()
    (repo / "docs" / "ci.md").write_text("x\n")
    two = commit("ci")
    assert preflight.equivalent_build(str(repo), one, two)[0]
    (repo / "backend" / "main.py").write_text("b\n")
    three = commit("code")
    ok, why = preflight.equivalent_build(str(repo), one, three)
    assert not ok and "backend/main.py" in why
    assert not preflight.equivalent_build(str(repo), None, three)[0]
