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
    rows = [r for r in ledger.load(gate.DEFAULT_LEDGER) if r["row"] == "LAB-deferred"]
    assert len(rows) == 1
    checks = Checks()
    checks.add(_flow("G7/deferred_idp", "G7", NOT_RUN, check="deferred", part="idp"))
    checks.add(_flow("G4/deferred_ubuntu-tier2", "G4", NOT_RUN, check="deferred", part="ubuntu-tier2", what="sudoers"))
    checks.add(_flow("G15/deferred_ubuntu-tier2", "G15", NOT_RUN, check="deferred", part="ubuntu-tier2", what="forcecommand_allowlist"))
    checks.add(_flow("G13/deferred_receiver", "G13", NOT_RUN, check="deferred", part="receiver"))
    results, blocking = ledger.apply(rows, checks)
    assert blocking == [] and {r.status for r in results} == {"not-run-ok"}
    # a deferred part whose check FAILS is never hidden as not-run: the row then "holds", and the gate still reports it
    checks2 = Checks()
    checks2.add(_flow("G7/deferred_idp", "G7", FAIL, check="deferred", part="idp"))
    results2, _ = ledger.apply(rows, checks2)
    assert {r.row: r.status for r in results2}["LAB-deferred"] == "holds"


def test_the_cb05_rows_name_checks_not_whole_steps():
    for row in ledger.load(gate.DEFAULT_LEDGER):
        assert "step" not in row["match"], f"{row['row']} matches a whole step"
        assert not str(row.get("not_run_ok", "")).startswith(("CB-05", "G5b runs", "G7 runs", "G8 runs", "G13b runs")), row["row"]
