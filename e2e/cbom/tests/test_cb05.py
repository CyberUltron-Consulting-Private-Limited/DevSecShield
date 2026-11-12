"""CB-05: same-SHA verdict comparison (exit F), the tightened ledger rows and the deferred-part rows."""
from __future__ import annotations

import json
from pathlib import Path

from harness import compare, gate, ledger
from harness.checks import FAIL, NOT_RUN, Check, Checks


def _run(tmp: Path, name: str, asset_ids: list[int], job_id: int, verdicts: dict[str, str], team: int, run_id: int) -> Path:
    run = tmp / name
    (run / "api").mkdir(parents=True)
    items = [{"id": i, "type": "tls_endpoint", "location": f"10.231.0.{17 + k}:443"} for k, i in enumerate(asset_ids)]
    (run / "api" / "assets-run1.json").write_text(json.dumps({"items": items, "targets": [{"job_id": job_id, "source_name": "S-zoo"}]}))
    (run / "flow-state.json").write_text(json.dumps({"teams": {"A": team}, "runs": [run_id]}))
    checks = [{"id": cid.format(a0=asset_ids[0], a1=asset_ids[1], job=job_id, run=run_id), "verdict": v} for cid, v in verdicts.items()]
    (run / "report.json").write_text(json.dumps({"passed": False, "checks": checks, "ledger": [{"row": "KF-9", "status": "holds"}]}))
    return run


BASE = {"G11/join/run1/asset/{a0}/key_size/export": "KNOWN-FAIL", "G11/join/run1/asset/{a1}/key_size/export": "PASS",
        "G10/job_{job}_ui_eq_db": "PASS", "G11/oracle/run1/z01/extra/{a1}": "FAIL", "G1/credits_ui_eq_db": "PASS"}


def test_same_verdicts_with_different_product_ids_are_identical(tmp_path):
    a = _run(tmp_path, "a", [1, 2], 4, BASE, team=21, run_id=7)
    b = _run(tmp_path, "b", [31, 32], 19, BASE, team=23, run_id=9)
    result = compare.compare(a, b)
    assert result["identical"], result["differences"]
    assert result["checks"]["a"] == result["checks"]["b"] == 5


def test_one_changed_verdict_is_reported(tmp_path):
    a = _run(tmp_path, "a", [1, 2], 4, BASE, team=21, run_id=7)
    b = _run(tmp_path, "b", [31, 32], 19, {**BASE, "G10/job_{job}_ui_eq_db": "FAIL"}, team=23, run_id=9)
    result = compare.compare(a, b)
    assert not result["identical"]
    assert result["differences"] == [{"check": "G10/job:S-zoo_ui_eq_db", "a": ["PASS"], "b": ["FAIL"]}]


def test_compare_cli_exit_codes(tmp_path):
    a = _run(tmp_path, "a", [1, 2], 4, BASE, team=21, run_id=7)
    b = _run(tmp_path, "b", [31, 32], 19, BASE, team=23, run_id=9)
    c = _run(tmp_path, "c", [41, 42], 29, {**BASE, "G1/credits_ui_eq_db": "FAIL"}, team=25, run_id=11)
    assert gate.main(["compare", str(a), str(b)]) == 0
    assert gate.main(["compare", str(a), str(c)]) == 1


def _flow(cid: str, gate_: str, verdict: str, **subject) -> Check:
    return Check(id=cid, gate=gate_, kind="flow", verdict=verdict, subject=subject, reason="", expected=None, observed=None, evidence=[])


def test_tightened_rows_do_not_swallow_other_failures_of_the_same_step():
    """KF-13 covers the Zeek option only: an unrelated G7 failure stays blocking (the old {step: G7} match took all)."""
    rows = ledger.load(gate.DEFAULT_LEDGER)
    checks = Checks()
    checks.add(_flow("G7/zeek_option_absent", "G7", FAIL, check="zeek_option_absent"))
    checks.add(_flow("G7/aws_banner_eq_staging", "G7", FAIL, check="aws_banner_eq_staging"))
    _, blocking = ledger.apply(rows, checks)
    assert [c.id for c in blocking] == ["G7/aws_banner_eq_staging"]


def test_deferred_parts_are_covered_only_as_not_run():
    rows = [dict(r) for r in ledger.load(gate.DEFAULT_LEDGER) if r["row"] == "LAB-deferred"]
    assert len(rows) == 1
    rows[0]["expect_not_run"] = 4
    checks = Checks()
    checks.add(_flow("G7/deferred_idp", "G7", NOT_RUN, check="deferred", part="idp"))
    checks.add(_flow("G4/deferred_ubuntu-tier2", "G4", NOT_RUN, check="deferred", part="ubuntu-tier2", what="sudoers"))
    checks.add(_flow("G15/deferred_ubuntu-tier2", "G15", NOT_RUN, check="deferred", part="ubuntu-tier2", what="forcecommand_allowlist"))
    checks.add(_flow("G13/deferred_receiver", "G13", NOT_RUN, check="deferred", part="receiver"))
    results, blocking = ledger.apply(rows, checks)
    assert blocking == [] and {r.status for r in results} == {"not-run-ok"}
    # a deferred part whose check FAILS is never hidden as not-run: the row's counts move and the gate fails
    checks2 = Checks()
    checks2.add(_flow("G7/deferred_idp", "G7", FAIL, check="deferred", part="idp"))
    results2, _ = ledger.apply(rows, checks2)
    assert {r.row: r.status for r in results2}["LAB-deferred"] not in ("not-run-ok", "holds")
    assert not ledger.verdict(results2, [])


def test_the_cb05_rows_name_checks_not_whole_steps():
    for row in ledger.load(gate.DEFAULT_LEDGER):
        assert "step" not in row["match"], f"{row['row']} matches a whole step"
        assert not str(row.get("not_run_ok", "")).startswith(("CB-05", "G5b runs", "G7 runs", "G8 runs", "G13b runs")), row["row"]


def test_trace_zips_are_redacted(tmp_path):
    """G15 found the typed database password and request bodies inside Playwright traces: the bundle scrubs them."""
    import secrets
    import zipfile
    canary = secrets.token_hex(16)  # generated at run time: no secret-shaped literal in the repo
    run = tmp_path / "run"
    (run / "steps" / "G6").mkdir(parents=True)
    z = run / "steps" / "G6" / "trace.zip"
    with zipfile.ZipFile(z, "w") as out:
        out.writestr("trace.trace", '{"method":"fill","params":{"value":"%s"}}\n' % canary)
        out.writestr("resources/abc.json", '{"secrets":{"password":"%s"}}' % canary)
        out.writestr("resources/shot.jpeg", b"\xff\xd8binary" + canary.encode())
    problems = gate.redact_run(run, [canary])
    with zipfile.ZipFile(z) as zin:
        assert canary not in zin.read("trace.trace").decode() and canary not in zin.read("resources/abc.json").decode()
        assert "[REDACTED:known-0" in zin.read("trace.trace").decode()
        assert zin.read("resources/shot.jpeg").startswith(b"\xff\xd8")
    assert problems == []


def test_a_truncated_trace_does_not_stop_the_seal(tmp_path):
    import secrets
    canary = secrets.token_hex(16)
    run = tmp_path / "run"
    (run / "steps" / "G1").mkdir(parents=True)
    (run / "steps" / "G1" / "trace.zip").write_bytes(b"PK\x03\x04" + canary.encode())
    problems = gate.redact_run(run, [canary])
    assert problems == ["steps/G1/trace.zip: unreadable zip (removed: held a known secret)"]
    assert not (run / "steps" / "G1" / "trace.zip").exists()


def test_preflight_treats_ci_only_commits_as_the_same_build(tmp_path):
    import subprocess
    from harness import preflight
    repo = tmp_path / "r"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    git = ["git", "-C", str(repo), "-c", "user.email=e2e@lab", "-c", "user.name=e2e"]
    (repo / "backend").mkdir()
    (repo / "backend" / "main.py").write_text("a\n")
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "one"], check=True)
    one = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    (repo / ".github").mkdir()
    (repo / ".github" / "ci.yml").write_text("x\n")
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "ci"], check=True)
    two = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert preflight.equivalent_build(str(repo), one, two)[0]
    (repo / "backend" / "main.py").write_text("b\n")
    subprocess.run(git + ["commit", "-q", "-am", "code"], check=True)
    three = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    ok, why = preflight.equivalent_build(str(repo), one, three)
    assert not ok and "backend/main.py" in why


def test_g16_stored_lines_are_keyed_by_source_not_job_id(tmp_path):
    a = _run(tmp_path, "a", [1, 2], 59, {**BASE, "G16/assets-stored/{job}-1-0": "PASS"}, team=21, run_id=7)
    b = _run(tmp_path, "b", [31, 32], 76, {**BASE, "G16/assets-stored/{job}-1-3": "PASS"}, team=23, run_id=9)
    assert compare.compare(a, b)["identical"]


def test_a_run_id_equal_to_a_port_does_not_rewrite_the_port(tmp_path):
    base = {"G11/join/run1/asset/{a0}/key_size/db": "PASS", "G11/join/run1/asset/{a1}/key_size/db": "PASS"}
    a = _run(tmp_path, "a", [1, 2], 4, base, team=21, run_id=7)
    b = _run(tmp_path, "b", [31, 32], 19, base, team=23, run_id=443)   # run 443, assets at ...:443
    assert compare.compare(a, b)["identical"]


def test_run_two_is_timed_by_its_own_step(tmp_path):
    from harness import timing
    run = tmp_path / "run"
    for g, s, e in (("G9", "2026-11-12T16:05:22Z", "2026-11-12T16:05:40Z"), ("G12", "2026-11-12T16:09:00Z", "2026-11-12T16:10:17Z"),
                    ("G13", "2026-11-12T16:10:20Z", "2026-11-12T16:13:00Z")):
        (run / "steps" / g).mkdir(parents=True)
        (run / "steps" / g / "step.json").write_text(json.dumps({"started": s, "ended": e, "checks": []}))
    s1, e1 = timing.window(run, "1")
    s2, e2 = timing.window(run, "2")
    assert (s1.isoformat(), e1.isoformat()) == ("2026-11-12T16:05:22+00:00", "2026-11-12T16:10:17+00:00")
    assert (s2.isoformat(), e2.isoformat()) == ("2026-11-12T16:10:20+00:00", "2026-11-12T16:13:00+00:00")


def test_g16_job_logged_ids_are_keyed_by_source(tmp_path):
    a = _run(tmp_path, "a", [1, 2], 102, {**BASE, "G16/assets-stored/job-{job}-logged": "PASS"}, team=21, run_id=7)
    b = _run(tmp_path, "b", [31, 32], 114, {**BASE, "G16/assets-stored/job-{job}-logged": "PASS"}, team=23, run_id=9)
    assert compare.compare(a, b)["identical"]
