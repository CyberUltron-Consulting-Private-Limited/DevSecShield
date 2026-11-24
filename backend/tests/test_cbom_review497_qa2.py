"""PR #497 review 6038990137: D12's population (M2, Rule P), the job-history read (M3), the D14 issue rule (m1).

M2: the register's total and Q-grade split counted assets only a deleted source read, while D1 / D14 counted none of
them, so D1's reconciliation said "1 asset occurrence" and "D12 holds 2 distinct assets". Scenario of the review
(``qa/497/scripts/d12_deleted.py``): two sources each read one certificate, then one source is deleted.
"""
from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402
import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, select  # noqa: E402
from test_cbom_cb20_estate import World, _sqlite, cert  # noqa: E402

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource  # noqa: E402
from backend.tests.support.pdf_text import pdf_text  # noqa: E402
from backend.utilities.cbom_sources import collections_view as CV  # noqa: E402
from backend.utilities.cbom_sources import q0register  # noqa: E402,F401  (registers the register hook)
from backend.utilities.cbom_sources import risk_register as RR  # noqa: E402
from backend.utilities.dashboard import cbom_team_rollup as R  # noqa: E402
from backend.utilities.pdf import cbom_board_report_pdf as d14  # noqa: E402
from backend.utilities.pdf import cbom_population as P  # noqa: E402
from backend.utilities.pdf import cbom_risk_register_pdf as d12  # noqa: E402

NOW = dt.datetime(2026, 11, 24, 12, 0)


def _cert(host: str, serial: str, cn: str) -> dict:
    return {**cert(host, f"{host}:443#chain[0]", serial=serial, not_after="2027-01-01T00:00:00Z",
                   subject=f"CN={cn},O=Bank,C=IN", issuer="CN=CA,O=Bank,C=IN"), "qv": True,
            "codes": ["QUANTUM_VULNERABLE"]}


@pytest.fixture
def deleted_world(tmp_path):
    w = World(_sqlite(tmp_path / "e.db"))
    lab, dmz = w.source("network", "lab"), w.source("network", "dmz")
    c1, c2 = _cert("10.0.0.1", "11" * 16, "a.bank.in"), _cert("10.9.0.1", "22" * 16, "b.bank.in")
    w.finalise(w.run({lab: {"rows": [c1]}, dmz: {"rows": [c2]}}))
    with Session(w.engine) as s:  # removal.py: the jobs and rows are detached, the source row goes
        s.execute(sa.update(CbomCollectionJob).where(CbomCollectionJob.source_id == dmz).values(source_id=None))
        s.execute(sa.update(CbomCollectedAsset).where(CbomCollectedAsset.source_id == dmz).values(source_id=None))
        s.execute(sa.delete(CbomCollectionSource).where(CbomCollectionSource.id == dmz))
        s.commit()
    w.finalise(w.run({lab: {"rows": [c1]}}))
    yield w
    w.engine.dispose()


def test_d12_leaves_the_assets_only_a_deleted_source_read_out_of_its_total(deleted_world):
    with Session(deleted_world.engine) as s:
        summary = RR.summary(s, 1, NOW)
        report = RR.report(s, 1, NOW)
    assert summary["total"] == 1 and summary["q_grades"]["Q2"] == 1
    assert summary["removed_from_scope"]["total"] == 1 and summary["removed_from_scope"]["q_grades"]["Q2"] == 1
    removed = report["removed_from_scope"]
    assert len(removed["items"]) == 1 and "10.9.0.1" in str(removed["items"][0]["label"])
    assert report["assets_total"] == 1 and len(report["assets"]) == 1
    assert {i["item_key"] for i in report["assets"]}.isdisjoint({i["item_key"] for i in removed["items"]})


def test_d1_d12_and_d14_print_one_population(deleted_world):
    view = R.load_team_cbom_view(deleted_world.engine, 1, now=NOW.replace(tzinfo=dt.timezone.utc))
    steps = " ".join(P.reconciliation_steps(view))
    assert "Total: 1 asset occurrence" in steps and "holds 1 distinct asset" in steps
    assert "Not counted: 1 asset only deleted sources read" in steps
    d14_text = re.sub(r"\s+", " ", pdf_text(d14.build_pdf(view)))
    assert "Grades from the quantum risk register (D12): 1 distinct assets" in d14_text
    assert "Not counted: 1 asset only deleted sources read" in d14_text
    d12_text = re.sub(r"\s+", " ", pdf_text(d12.build_pdf(view)))
    assert "G. Removed from scope" in d12_text and "none of them is counted in any total" in d12_text


# ----------------------------------------------------------------------------- M3: the history is aggregated in SQL
def test_collection_history_is_three_statements_and_reads_no_params(deleted_world):
    statements: list[str] = []
    engine = deleted_world.engine

    def seen(_conn, _cursor, statement, *_rest) -> None:
        statements.append(statement)

    with Session(engine) as s:
        sources = {x.id: x for x in s.exec(select(CbomCollectionSource)).all()}
        sa.event.listen(engine, "before_cursor_execute", seen)
        try:
            history = CV.collection_history(s, 1, sources)
        finally:
            sa.event.remove(engine, "before_cursor_execute", seen)
    reads = [q for q in statements if q.lstrip().upper().startswith("SELECT")]
    assert len(reads) == 3, reads  # live sources, detached (deleted) sources, the latest job of each
    assert all("GROUP BY" in q.upper() for q in reads[:2])
    assert "params" not in reads[2]  # only the latest job's status, error and outcome
    lab = next(v for k, v in history.items() if not k.startswith("deleted:") and v["scans"] == 2)
    assert lab["last_attempt_status"] == "success" and lab["last_attempt_run_id"] == 2
    gone = [v for v in history.values() if v["scans"] == 1]
    assert len(gone) == 1 and gone[0]["last_attempt_run_id"] == 1  # the deleted source, by its params' uid
