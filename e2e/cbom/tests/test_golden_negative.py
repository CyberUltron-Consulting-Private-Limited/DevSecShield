"""The golden negative-control suite (review 5874859738): a trimmed, sanitised snapshot of a real Tier-L run
(tests/golden/<run>/, made by tools/golden.py) is judged as captured, where it must PASS against its frozen ledger
snapshot (tests/golden/known-fail.yaml), and then once per deliberately wrong CBOM (harness/negative.py: the 47 cases
of reviews 5874859738 and 5878413538), where each must FAIL through the check it is aimed at (``negative.INTENDED``),
never through an incidental one. The fixture carries no lab secret: the canary is generated here, at test time.
"""
from __future__ import annotations

import json
import secrets
import shutil
from pathlib import Path

import pytest

from harness import manifest, negative

GOLDEN = Path(__file__).resolve().parent / "golden"


def _source() -> Path:
    runs = sorted(p for p in GOLDEN.iterdir() if p.is_dir() and p.name.startswith("L-"))
    assert len(runs) == 1, f"tests/golden must hold exactly one run directory, found {runs}"
    return runs[0]


@pytest.fixture(scope="module")
def golden(tmp_path_factory) -> Path:
    src = _source()
    run = tmp_path_factory.mktemp("golden") / src.name
    shutil.copytree(src, run)
    value = secrets.token_urlsafe(18)
    (run / "lab" / "secrets").mkdir(parents=True)
    (run / "lab" / "secrets" / "golden.txt").write_text(value, encoding="utf-8")
    (run / "oracle" / "canaries.json").write_text(json.dumps({"schema": "zs-cbom-canaries/1", "canaries": [
        {"id": "golden-db-password", "kind": "string", "secret_kind": "db_password", "value": value,
         "allowed": ["oracle/canaries.json", "lab/secrets/golden.txt"], "control": "lab/secrets/golden.txt"}]}),
        encoding="utf-8")
    manifest.freeze_oracle(run)  # the trimmed oracle plus the generated canary (O-5 has its own unit tests)
    return run


@pytest.fixture(scope="module")
def table(golden, tmp_path_factory):
    return {r["case"]: r for r in negative.run_cases(golden, GOLDEN / "known-fail.yaml",
                                                     work=tmp_path_factory.mktemp("neg"))}


def test_there_are_47_wrong_cboms_each_with_its_intended_check():
    assert len(negative.WRONG) == 47 and set(negative.INTENDED) == set(negative.WRONG)


def test_the_golden_run_passes_as_captured(table):
    assert table["A_correct"]["gate"] == "PASS", (table["A_correct"]["blocking"], table["A_correct"]["ledger_rows_moved"])


@pytest.mark.parametrize("case", negative.WRONG)
def test_every_wrong_cbom_fails(table, case):
    row = table[case]
    assert row["gate"] == "FAIL", f"{case} ({row['doc']}) passed the gate"
    # review 5878413538: the case must be caught by the check it is aimed at (blocking, or a moved ledger identity)
    assert row["caught_by"], f"{case} failed, but not through {row['intended']}: {row['blocking']} {row['ledger_rows_moved']}"


def test_the_fixture_is_complete():
    """Every log the judge requires (core services, every lab container in lab.json) is in the fixture: e2e/.gitignore
    ignores *.log, which once dropped them from the commit (tests/golden/.gitignore re-includes them)."""
    src = _source()
    lab = json.loads((src / "lab" / "lab.json").read_text(encoding="utf-8"))
    names = [x.get("container") for x in (lab.get("targets") or []) + (lab.get("listeners") or []) if x.get("container")]
    missing = [n for n in ["backend", "cbom-cloud-worker", "nginx", "postgres", *names] if not (src / "logs" / f"{n}.log").is_file()]
    assert missing == []
    assert list((src / "har").glob("*.har")) and (src / "db" / "jobs.csv").is_file()


def test_the_fixture_carries_no_lab_secret_or_token():
    import re
    bad = [re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
           re.compile(r"eyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}"), re.compile(r"zsr_[A-Za-z0-9]{16,}")]
    src = _source()
    hits = [f"{p.relative_to(src)}" for p in src.rglob("*") if p.is_file()
            for rx in bad if rx.search(p.read_text(encoding="utf-8", errors="replace"))]
    assert hits == []
    assert not (src / "oracle" / "canaries.json").exists() and not (src / "lab" / "secrets").exists()
