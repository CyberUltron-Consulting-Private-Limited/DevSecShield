"""CB-35: the §4.5 waves, their PR triggers, the nightly's two lock holds, the report and the issue drafts."""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from harness import waves as Wv

REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def config() -> Wv.Config:
    return Wv.load()


# ----------------------------------------------------------------------------- waves.yaml
# DEVILS-ADVOCATE.md §4.5, one changed path per row, as it is named in this repository.
SECTION_4_5 = [
    ("scan_node/zs_scan_node/collectors/network.py", "W-NET"),
    ("scan_node/zs_scan_node/tlsprobe.py", "W-NET"),
    ("scan_node/zs_scan_node/netutil.py", "W-NET"),
    ("scan_node/zs_scan_node/collectors/linux_ssh.py", "W-HOST"),
    ("scan_node/zs_scan_node/collectors/database.py", "W-HOST"),
    ("scan_node/zs_scan_node/collectors/kubernetes.py", "W-HOST"),
    ("scan_node/zs_scan_node/collectors/hsm_pkcs11.py", "W-KEY"),
    ("scan_node/zs_scan_node/collectors/kmip.py", "W-KEY"),
    ("backend/utilities/cbom_sources/jobs.py", "W-STATE"),
    ("backend/utilities/cbom_sources/schedules.py", "W-STATE"),
    ("backend/utilities/cbom_sources/inventory.py", "W-OUT"),
    ("backend/utilities/cbom_sources/classify.py", "W-OUT"),
    ("backend/utilities/cbom_sources/data/crypto_kb.json", "W-OUT"),
    ("backend/utilities/integrations/siem.py", "W-INT"),
    ("aibom/src/aibom/cbom/detect.py", "W-D1"),
    ("RabbitMQ/worker/main.py", "W-D1"),
    ("backend/utilities/cbom_sources/aws_collect.py", "W-CLOUD"),
    ("backend/utilities/cbom_sources/azure_collect.py", "W-CLOUD"),
    ("prod_database_migrations/migrations/versions/x_add_column.py", "W-UPGRADE"),
    ("scan_node/zs_scan_node/agent.py", "W-SKEW"),
    ("scan_node/zs_scan_node/jobctx.py", "W-SKEW"),
]


@pytest.mark.parametrize("path,wave", SECTION_4_5)
def test_each_section_4_5_row_triggers_its_wave(config, path, wave):
    assert wave in Wv.select([path], config)


def test_paths_outside_every_wave_trigger_none(config):
    assert Wv.select(["README.md", "frontend/app/page.tsx", "scan_node/zs_scan_node/netutil_extra.py"], config) == []


def test_every_wave_of_the_plan_is_defined_and_scale_runs_nightly_only(config):
    assert set(config.waves) == {"W-NET", "W-HOST", "W-KEY", "W-STATE", "W-OUT", "W-INT", "W-D1", "W-CLOUD",
                                 "W-UPGRADE", "W-SKEW", "W-SCALE"}
    assert config.waves["W-SCALE"].paths == []


def test_the_nightly_is_two_lock_holds_each_within_its_budget(config):
    order = Wv.plan(config)
    assert list(order["holds"]) == ["A", "B"]
    for hold, steps in order["holds"].items():
        assert steps and all(s.live for s in steps)
        assert sum(s.budget_min for s in steps) <= config.hold_budget_min, hold
    assert all(not s.live for s in order["hermetic"])
    assert sum(len(w.steps) for w in config.waves.values()) == len(order["hermetic"]) + sum(
        len(v) for v in order["holds"].values())


def test_the_w_state_hold_budgets_the_restart_case(config):
    """R3 S11: budget at least 17 min of the hold for the cloud-worker restart case, or use --once with a seeded lease
    (the restart-semantics step does the latter, so it needs no hold time)."""
    step = {s.id: s for s in config.waves["W-STATE"].steps}["restart-semantics"]
    assert "test_cbom_cb35_restart_semantics.py" in step.run and not step.live


def test_every_named_test_file_exists_or_is_guarded_by_a_file_need(config):
    for wave in config.waves.values():
        for step in wave.steps:
            base = "backend" if "{backend_pytest}" in step.run else "scan_node" if "{node_pytest}" in step.run else None
            if base is None:
                continue
            for name in re.findall(r"tests/\S+\.py", step.run):
                rel = f"{base}/{name}"
                assert (REPO / rel).is_file() or f"file:{rel}" in step.needs, f"{step.key}: {rel} does not exist"


def test_every_step_names_only_needs_the_runner_knows(config, tmp_path):
    ctx = Wv.Context(repo=REPO, run_dir=tmp_path, sha="0" * 40)
    for wave in config.waves.values():
        for step in wave.steps:
            for need in step.needs:
                assert "unknown need" not in (Wv._probe(need, ctx) or ""), f"{step.key}: {need}"


@pytest.mark.parametrize("bad,match", [
    ({"A": ["W-X"], "B": ["W-X"]}, "holds A and B"),
    ({"A": ["W-X"]}, "in no hold: W-Y"),
    ({"A": ["W-X", "W-Y", "W-Z"]}, "unknown wave W-Z"),
])
def test_a_plan_that_is_not_runnable_is_refused(tmp_path, bad, match):
    cfg = _config(tmp_path, {"W-X": [{"id": "a", "run": "true"}], "W-Y": [{"id": "b", "run": "true"}]}, holds=bad)
    with pytest.raises(Wv.PlanError, match=match):
        Wv.plan(cfg)


def test_a_hold_over_its_budget_is_refused(tmp_path):
    cfg = _config(tmp_path, {"W-X": [{"id": "a", "run": "true", "live": True, "budget_min": 60}],
                             "W-Y": [{"id": "b", "run": "true", "live": True, "budget_min": 31}]},
                  holds={"A": ["W-X", "W-Y"]})
    with pytest.raises(Wv.PlanError, match="91 min, over the 90-min hold"):
        Wv.plan(cfg)


@pytest.mark.parametrize("pattern,path,hit", [
    ("scan_node/**/{network,netutil}.py", "scan_node/zs_scan_node/collectors/network.py", True),
    ("scan_node/**/{network,netutil}.py", "scan_node/netutil.py", True),
    ("scan_node/**/{network,netutil}.py", "scan_node/zs_scan_node/netutil.pyc", False),
    ("**/collectors/{database*,mssql}.py", "scan_node/zs_scan_node/collectors/database_tls.py", True),
    ("**/collectors/{database*,mssql}.py", "scan_node/zs_scan_node/collectors/sub/mssql.py", False),
    ("backend/utilities/integrations/**", "backend/utilities/integrations/a/b.py", True),
])
def test_glob_rules(pattern, path, hit):
    assert bool(Wv.glob_regex(pattern).match(path)) is hit


# ----------------------------------------------------------------------------- run, holds, report, issues
def _config(tmp_path: Path, steps: dict, holds: dict | None = None, budget: float = 90) -> Wv.Config:
    data = {"version": 1, "hold_budget_min": budget, "holds": holds or {"A": list(steps)},
            "waves": {w: {"title": w, "paths": [], "steps": s} for w, s in steps.items()}}
    path = tmp_path / "waves.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")
    return Wv.load(path)


def _ctx(tmp_path: Path, missing: dict | None = None, **kw) -> Wv.Context:
    run = tmp_path / "run"
    run.mkdir(exist_ok=True)
    return Wv.Context(repo=REPO, run_dir=run, sha="a" * 40,
                      probe=lambda need, _ctx: (missing or {}).get(need), **kw)


def test_verdicts_pass_fail_not_run_and_timeout(tmp_path):
    cfg = _config(tmp_path, {"W-X": [
        {"id": "ok", "run": "echo fine"},
        {"id": "bad", "run": "echo broken; exit 3"},
        {"id": "no-stack", "run": "true", "needs": ["stack"]},
        {"id": "slow", "run": "sleep 30", "budget_min": 0.01},
    ]})
    data = Wv.run(cfg, _ctx(tmp_path, {"stack": "no Tier-L stack here"}))
    got = {r["step"]: (r["verdict"], r["reason"]) for r in data["results"]}
    assert got["ok"] == ("PASS", "")
    assert got["bad"] == ("FAIL", "exit 3")
    assert got["no-stack"] == ("NOT-RUN", "stack: no Tier-L stack here")
    assert got["slow"][0] == "FAIL" and got["slow"][1].startswith("killed after 1 s")
    ok = next(r for r in data["results"] if r["step"] == "ok")
    log = tmp_path / "run" / ok["log"]
    assert log.read_text() == "fine\n" and ok["log_sha256"] == Wv.sha256_file(log)


def test_live_steps_are_not_run_on_a_hermetic_runner_and_never_count_as_passed(tmp_path):
    cfg = _config(tmp_path, {"W-X": [{"id": "live", "run": "true", "live": True}]})
    ctx = _ctx(tmp_path, hermetic=True, lock=tmp_path / "stack.lock")
    Wv.run(cfg, ctx)
    rep = Wv.report(ctx.run_dir)
    assert rep["counts"] == {"PASS": 0, "FAIL": 0, "NOT-RUN": 1}
    assert rep["verdict"] == "INCOMPLETE" and rep["waves"] == {"W-X": "INCOMPLETE"}
    assert rep["holds"] == [{"hold": "A", "steps": ["W-X/live"], "taken": False}]
    assert not (tmp_path / "stack.lock").exists()  # nothing could run: the lock is never taken for nothing


def test_live_steps_run_inside_the_hold_and_the_lock_is_released_between_holds(tmp_path):
    lock = tmp_path / "stack.lock"
    held = f"(flock -n {lock} true && echo free || echo held); echo ${{CBOM_STACK_LOCK_HELD:-unset}}"
    cfg = _config(tmp_path, {"W-X": [{"id": "first", "run": held, "live": True}],
                             "W-Y": [{"id": "second", "run": held, "live": True}],
                             "W-Z": [{"id": "hermetic", "run": held}]},
                  holds={"A": ["W-X", "W-Z"], "B": ["W-Y"]})
    ctx = _ctx(tmp_path, lock=lock)
    data = Wv.run(cfg, ctx)
    out = {r["step"]: (ctx.run_dir / r["log"]).read_text().strip() for r in data["results"]}
    # inside a hold the gate is told the lock is already held (run-gate.sh then takes no lock of its own)
    assert out == {"hermetic": "free\nunset", "first": "held\n1", "second": "held\n1"}
    assert [r["step"] for r in data["results"]] == ["hermetic", "first", "second"]  # hermetic steps before the holds
    assert [(h["hold"], h["taken"]) for h in data["holds"]] == [("A", True), ("B", True)]
    assert subprocess.run(["flock", "-n", str(lock), "true"]).returncode == 0  # released at the end


def test_a_hold_that_cannot_get_the_lock_in_time_is_not_run(tmp_path):
    lock = tmp_path / "stack.lock"
    cfg = _config(tmp_path, {"W-X": [{"id": "live", "run": "true", "live": True}]})
    holder = subprocess.Popen(["flock", str(lock), "sleep", "30"])
    try:
        for _ in range(50):
            if subprocess.run(["flock", "-n", str(lock), "true"]).returncode != 0:
                break
            __import__("time").sleep(0.1)
        data = Wv.run(cfg, _ctx(tmp_path, lock=lock, lock_wait_s=0.5))
    finally:
        holder.kill()
    assert data["results"][0]["verdict"] == "NOT-RUN" and "held for more than" in data["results"][0]["reason"]


def test_the_report_names_new_failures_and_fixes_against_the_previous_nightly(tmp_path):
    root = tmp_path / "nightly"
    first, second = root / "N-1", root / "N-2"
    for run, outcome in ((first, {"a": 1, "b": 0, "c": 1}), (second, {"a": 1, "b": 1, "c": 0})):
        run.mkdir(parents=True)
        cfg = _config(tmp_path, {"W-X": [{"id": k, "run": f"exit {v}"} for k, v in outcome.items()]})
        Wv.run(cfg, Wv.Context(repo=REPO, run_dir=run, sha="b" * 40, probe=lambda *_: None))
    assert Wv.previous_run(root, second) == first
    rep = Wv.report(second, Wv.previous_run(root, second))
    assert rep["new_failures"] == ["W-X/b"]  # a kept failing: not new
    assert rep["fixed"] == ["W-X/c"]
    assert rep["verdict"] == "FAIL" and rep["waves"] == {"W-X": "FAIL"}
    md = (second / "report.md").read_text()
    assert "New failures: W-X/b." in md and "Fixed: W-X/c." in md and "| W-X/b | FAIL |" in md


def test_issue_drafts_carry_the_evidence_set_and_are_filed_only_when_asked(tmp_path):
    cfg = _config(tmp_path, {"W-X": [{"id": "boom", "run": "echo 'Authorization: Bearer abcdefghijklmnopqrstuvwx'; "
                                                         "echo assertion failed; exit 1"}]})
    ctx = _ctx(tmp_path)
    Wv.run(cfg, ctx)
    Wv.report(ctx.run_dir)
    calls: list = []
    drafts = Wv.issues(ctx.run_dir, runner=lambda *a, **k: calls.append(a))
    assert calls == [] and [p.name for p in drafts] == ["W-X--boom.md"]
    body = drafts[0].read_text()
    result = json.loads((ctx.run_dir / "results.json").read_text())["results"][0]
    for needle in ("a" * 40, "W-X/boom", "exit 1", result["log"], result["log_sha256"], "assertion failed"):
        assert needle in body, needle
    assert "abcdefghijklmnopqrstuvwx" not in body and "[REDACTED:bearer:" in body
    Wv.issues(ctx.run_dir, file=True, repo_slug="org/repo", runner=lambda *a, **k: calls.append(a[0]))
    assert calls == [["gh", "issue", "create", "--title", f"CBOM nightly wave W-X/boom fails on {'a' * 12}",
                      "--body-file", str(drafts[0]), "--repo", "org/repo"]]


def test_run_gate_takes_no_lock_inside_a_wave_hold():
    """Without this, a gate step inside a hold would wait for the hold's own stack.lock for ever."""
    gate = (REPO / "e2e" / "cbom" / "run-gate.sh").read_text()
    assert 'if [ "${CBOM_STACK_LOCK_HELD:-}" = 1 ]; then\n  # a CB-35 wave' in gate
    assert gate.count('"${CBOM_STACK_LOCK_HELD:-}"') == 2  # the gate's hold and the restack-to-dev hold


def test_the_cli_plans_and_selects(capsys):
    assert Wv.main(["plan"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("hermetic: ") and "hold A (" in out and "hold B (" in out
    assert Wv.main(["select", "backend/utilities/cbom_sources/jobs.py"]) == 0
    assert capsys.readouterr().out.strip() == "W-STATE"
