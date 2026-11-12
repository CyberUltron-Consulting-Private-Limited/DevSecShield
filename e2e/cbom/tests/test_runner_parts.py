"""Pre-flight and bundle helpers that need no stack: SHA matching, migration heads, the G17 seal."""
from __future__ import annotations

import json
import subprocess

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
    bundle.manifest.update(run, sha="abc1234", images={"x": {}}, playwright={"version": "1.62.0"}, started="t")
    (run / "flow-state.json").write_text(json.dumps({"logged_out": {"A": True, "B": True}}), encoding="utf-8")
    assert bundle.seal(run, secrets, "2026-11-12T09:00:00Z", budget_min=10**6) == 0
    assert not secrets.exists()
    assert "Pw-very-secret-1" not in (run / "steps" / "G1" / "note.txt").read_text()
    g17 = json.loads((run / "steps" / "G17" / "step.json").read_text())
    assert {c["id"]: c["verdict"] for c in g17["checks"]} == {
        "G17/no_residual_secrets": "PASS", "G17/manifest_complete": "PASS", "G17/oracle_hash_in_manifest": "PASS",
        "G17/runtime_le_budget": "PASS", "G17/customers_logged_out": "PASS"}


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
