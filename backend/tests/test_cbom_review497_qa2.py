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
def test_collection_history_is_two_aggregate_statements(deleted_world):
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
    assert len(reads) == 2, reads  # per-source totals, then each source's newest job (no params read into Python)
    assert "GROUP BY" in reads[0].upper() and "GROUP BY" not in reads[1].upper()
    lab = next(v for k, v in history.items() if not k.startswith("deleted:") and v["scans"] == 2)
    assert lab["last_attempt_status"] == "success" and lab["last_attempt_run_id"] == 2
    gone = [v for v in history.values() if v["scans"] == 1]
    assert len(gone) == 1 and gone[0]["last_attempt_run_id"] == 1  # the deleted source, by its params' uid


def test_collection_history_reads_the_totals_and_the_newest_jobs_from_the_history_index(deleted_world):
    """Tracker "source history query too slow at scale": the per-source totals come from the history index alone (no
    job row, no params JSON) and each source's newest job is found by (source, created_at) on it. PostgreSQL, 60
    sources x 1000 runs (60k jobs, 88 MB): 70 ms before the index, 39 ms with it (index-only scan, 0 heap fetches)."""
    statements: list[tuple[str, tuple]] = []
    engine = deleted_world.engine

    def seen(_conn, _cursor, statement, parameters, *_rest) -> None:
        statements.append((statement, parameters))

    with Session(engine) as s:
        sources = {x.id: x for x in s.exec(select(CbomCollectionSource)).all()}
        sa.event.listen(engine, "before_cursor_execute", seen)
        try:
            CV.collection_history(s, 1, sources)
        finally:
            sa.event.remove(engine, "before_cursor_execute", seen)
    reads = [(q, p) for q, p in statements if q.lstrip().upper().startswith("SELECT")]
    with engine.connect() as conn:
        plans = [" ".join(str(r[-1]) for r in conn.exec_driver_sql("EXPLAIN QUERY PLAN " + q, p)) for q, p in reads]
    # totals by source on the index (SQLite has no INCLUDE; on PostgreSQL the same plan is an index-only scan)
    assert "USING INDEX ix_cbomcollectionjob_team_source_hist (team_id=? AND source_id>?)" in plans[0], plans[0]
    assert "SCAN cbomcollectionjob" not in plans[1], plans[1]  # newest jobs: a search (by key on PostgreSQL)


# ----------------------------------------------------------------------------- review 6057627810 M3 / m2
def test_every_d12_figure_leaves_out_the_assets_only_a_deleted_source_read(deleted_world):
    """Rule P everywhere in D12: the default-Mosca count, the families, the Q0 reasons and the heat-map agree with the
    total (the deleted source's certificate is in none of them); D14 section 3 / 8 and D2 section 6 print that count."""
    with Session(deleted_world.engine) as s:
        summary = RR.summary(s, 1, NOW)
        heat = RR.heatmap(s, 1)
        live_refs = {r for (r,) in s.execute(sa.select(CbomCollectionSource.source_uid)).all()}
    total = summary["total"]
    assert total == 1 and summary["removed_from_scope"]["total"] == 1
    assert summary["default_assumptions"]["count"] == 1  # was 2: the deleted source's asset was graded on defaults
    assert sum(n for fam in summary["families"].values() for n in fam.values()) == total
    assert sum(summary["q0_reasons"].values()) == summary["q_grades"]["Q0"]
    assert heat["total"] == total and sum(c["total"] for c in heat["cells"]) == total
    assert {c["source_ref"] for c in heat["columns"]} <= live_refs  # no column for the deleted source
    assert all(c["source_name"] for c in heat["columns"])
    view = R.load_team_cbom_view(deleted_world.engine, 1, now=NOW.replace(tzinfo=dt.timezone.utc))
    d14_text = re.sub(r"\s+", " ", pdf_text(d14.build_pdf(view)))
    assert "1 asset graded on defaults" in d14_text and "2 assets graded on defaults" not in d14_text
    from backend.utilities.pdf import cbom_methodology_pdf as d2

    d2_text = re.sub(r"\s+", " ", pdf_text(d2.build_pdf(view)))
    assert "1 asset graded on defaults" in d2_text and "2 assets graded on defaults" not in d2_text


def test_d14_and_d2_define_mosca_and_say_what_the_defaults_imply(deleted_world):
    """m2: X, Y, Z and the X + Y > Z rule (``qgrade.MOSCA_DEFINITION``), the default Z as NIST IR 8547's disallowance
    date and not a quantum-computer estimate, and that on this year's defaults every quantum-vulnerable asset is at
    risk."""
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.pdf import cbom_methodology_pdf as d2

    view = R.load_team_cbom_view(deleted_world.engine, 1, now=NOW.replace(tzinfo=dt.timezone.utc))
    year = view.register["summary"]["default_assumptions"]["horizon"]["year"]
    z = QG.default_z(year)
    assert QG.DEFAULT_X + QG.DEFAULT_Y > z
    for doc in (d14, d2):
        text = re.sub(r"\s+", " ", pdf_text(doc.build_pdf(view)))
        assert QG.MOSCA_DEFINITION in text, doc.__name__
        assert "a regulatory deadline, not an estimate of when a cryptographically relevant quantum computer" in text
        assert (f"On the defaults in {year} (X {QG.DEFAULT_X} + Y {QG.DEFAULT_Y} = {QG.DEFAULT_X + QG.DEFAULT_Y} > "
                f"Z {z}), every quantum-vulnerable asset is at risk") in text
