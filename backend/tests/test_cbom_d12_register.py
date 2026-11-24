"""SOW D12 Quantum Risk Register: the CSV and the PDF (audit A-03, A-15, A-17).

* CSV: UTF-8 with a byte order mark (Excel), RFC 4180 (CRLF, quoting), no formula injection, and per asset the PQC
  class, algorithm, FIPS 203/204/205 / CNSA 2.0 / SP 800-131A verdicts, fix class, NIST PQ target, data lifetime with
  its basis, the Mosca inputs used ("default assumptions" when a default filled one), criticality and owner.
* Rule P: the CSV's detail columns equal ``GET /register?detail=true`` row for row; the PDF prints the API's numbers.
* "Gaps closed by week": each week has openings, closures and the gaps open at its end; the series is a burn-down
  (q0_gaps_open_at_week_end[i] = q0_gaps_open_at_week_end[i-1] + q0_gaps_opened[i] - closed[i]).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_d12_register.py -q
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backend.new_models import CbomQ0Gap
from backend.utilities.cbom_sources import drift as DRIFT
from backend.utilities.cbom_sources import qgrade as QG
from backend.utilities.cbom_sources import risk_register as REG
from backend.utilities.pdf import cbom_risk_register_pdf as PDF
from sqlmodel import Session
from test_cbom_cb23_register import (
    RSA_KEY,
    key_row,
    lab,
    mosca,
)
from test_cbom_sources_api import api
from test_cbom_sources_api import world as api_world
from test_cbom_wp10_outputs import two_runs

world = api_world
_FIXTURES = (api, two_runs, lab)
T0 = dt.datetime.fromisoformat("2030-01-01T12:00:00")
NEEDED = ("pqc_class", "algorithm", "fips_203_204_205", "cnsa_2_0", "sp800_131a", "fix_class", "nist_pq_target",
          "data_lifetime_years", "exposure", "criticality", "owner", "grade_inputs")


def _get(api, path, **params):
    r = api("GET", path, params=params)
    assert r.status_code == 200, r.text
    return r


def test_csv_is_excel_safe_rfc4180_and_carries_the_sow_columns(api, two_runs):
    DRIFT.record_pending_drift(two_runs["engine"], T0)  # the estate store and register follow the recorded runs
    raw = _get(api, "/1/cbom/register.csv").content
    assert raw.startswith(b"\xef\xbb\xbf")  # UTF-8 byte order mark
    text = raw.decode("utf-8-sig")
    assert "\r\n" in text and "\n" not in text.replace("\r\n", "")  # CRLF records only
    table = list(csv.reader(io.StringIO(text, newline="")))
    assert tuple(table[0]) == REG.CSV_COLUMNS
    for col in NEEDED:
        assert col in table[0], col
    summary = _get(api, "/1/cbom/register/summary").json()
    assert len(table) - 1 == summary["total"] and all(len(r) == len(table[0]) for r in table[1:])
    rows = [dict(zip(table[0], r)) for r in table[1:]]
    graded = [r for r in rows if r["algorithm"]]
    assert graded and all(r["pqc_class"] for r in graded)
    for r in rows:  # no cell a spreadsheet would run as a formula
        assert all(not v.startswith(("=", "+", "-", "@")) for v in r.values()), r


def test_csv_detail_columns_equal_the_api_row_for_row(api, two_runs):
    """Rule P: one function (``add_detail``) for the list and the CSV."""
    DRIFT.record_pending_drift(two_runs["engine"], T0)
    items, after = [], None
    while True:
        page = _get(api, "/1/cbom/register", detail="true", limit=3, **({"after": after} if after else {})).json()
        items += page["items"]
        after = page["next_after"]
        if not after:
            break
    text = _get(api, "/1/cbom/register.csv").content.decode("utf-8-sig")
    table = list(csv.reader(io.StringIO(text, newline="")))
    rows = {r[0]: dict(zip(table[0], r)) for r in table[1:]}
    assert set(rows) == {i["item_key"] for i in items}
    for i in items:
        for col in REG.DETAIL_FIELDS:
            want = i[col]
            want = "" if want is None else str(want)
            got = rows[i["item_key"]][col]
            assert got == want or got == "'" + want, (col, got, want)
    plain = _get(api, "/1/cbom/register", limit=3).json()["items"]
    assert "pqc_class" not in plain[0]  # the detail is on request only (the list stays cheap)


def test_csv_quotes_and_neutralises_hostile_cells():
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow([REG._csv_cell(v) for v in ("=cmd|' /C calc'!A0", "-2+3", "@SUM(1)", "a,b", 'say "hi"', "x\ny")])
    line = buf.getvalue()
    back = next(csv.reader(io.StringIO(line, newline="")))
    assert back == ["'=cmd|' /C calc'!A0", "'-2+3", "'@SUM(1)", "a,b", 'say "hi"', "x\ny"]


def test_grades_on_default_assumptions_are_marked_in_the_csv_and_the_summary(lab):
    s1 = lab.source("linux_servers", "linux")
    lab.finalise(lab.run({s1: {"rows": [RSA_KEY, key_row(type="managed_key", location="db#symmetric_key/LabTdes",
                                                          name="LabTdes", algorithm="DES-EDE3", qv=None, facts={})]}}))
    text = b"".join(REG.csv_rows(lab.engine, 1, {}, now=T0)).decode("utf-8-sig")
    rows = list(csv.DictReader(io.StringIO(text, newline="")))
    rsa = next(r for r in rows if r["algorithm"] == "RSA")
    assert rsa["q_grade"] in ("Q1", "Q2") and rsa["grade_inputs"] == "default assumptions: X, Y, Z"
    assert (rsa["data_lifetime_years"], rsa["data_lifetime_basis"], rsa["migration_years"], rsa["crqc_years"]) == (
        "7", "default", "5", str(QG.default_z()))  # Z: the years left until 2035
    assert rsa["pqc_class"] == "quantum-vulnerable" and rsa["owner"].startswith("unassigned")
    assert "ML-" not in rsa["nist_pq_target"] or rsa["nist_pq_reference"]  # a target with its FIPS reference
    tdes = next(r for r in rows if r["algorithm"] == "DES-EDE3")
    assert (tdes["q_grade"], tdes["q_reason"], tdes["pqc_class"]) == ("Q2", "deprecated", "deprecated")
    assert tdes["sp800_131a"] == "disallowed" and tdes["nist_pq_target"].startswith("AES-256")
    with Session(lab.engine) as s:
        summary = REG.summary(s, 1, T0)
    d = summary["default_assumptions"]
    assert d["count"] == 1 and d["inputs"] == {"x": 1, "y": 1, "z": 1} and "Z the years left until 2035" in d["defaults"]
    assert "Default assumptions: 1 quantum-vulnerable grade" in PDF.assumptions_text(summary)
    mosca(lab, {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12})
    with Session(lab.engine) as s:
        assert REG.default_assumptions(s, 1)["count"] == 0  # the team's inputs: nothing assumed


def test_weekly_series_has_openings_closures_and_open_gaps_as_a_burn_down(lab):
    now = dt.datetime.fromisoformat("2026-11-23T12:00:00")
    monday = dt.datetime.fromisoformat("2026-11-16T00:00:00")
    with Session(lab.engine) as s:
        def gap(key, opened, closed=None):
            s.add(CbomQ0Gap(team_id=1, item_kind="asset", item_key=key, reason="unknown_verdict", opened_at=opened,
                            last_seen_at=opened, closed_at=closed, close_cause="observation" if closed else None,
                            detail={}))
        gap("asset:a", monday - dt.timedelta(weeks=20))  # opened long before the window, still open
        gap("asset:b", monday - dt.timedelta(weeks=2), monday - dt.timedelta(weeks=1) + dt.timedelta(days=1))
        gap("asset:c", monday + dt.timedelta(days=1), monday + dt.timedelta(days=2))
        gap("asset:d", monday + dt.timedelta(days=3))
        s.commit()
        weeks = REG.summary(s, 1, now)["closures_by_week"]
    assert len(weeks) == 12 and all({"q0_gaps_opened", "q0_gaps_open_at_week_end", "total"} <= set(w) for w in weeks)
    assert not any("opened" in w or "open_end" in w for w in weeks)  # never drift's weekly_drift() key "opened"
    by = {w["week"]: w for w in weeks}
    assert (by["2026-11-16"]["q0_gaps_opened"], by["2026-11-16"]["total"], by["2026-11-16"]["q0_gaps_open_at_week_end"]) == (2, 1, 2)
    assert (by["2026-11-09"]["q0_gaps_opened"], by["2026-11-09"]["total"], by["2026-11-09"]["q0_gaps_open_at_week_end"]) == (0, 1, 1)
    assert (by["2026-11-02"]["q0_gaps_opened"], by["2026-11-02"]["q0_gaps_open_at_week_end"]) == (1, 2)
    for prev, cur in itertools.pairwise(weeks):
        assert cur["q0_gaps_open_at_week_end"] == prev["q0_gaps_open_at_week_end"] + cur["q0_gaps_opened"] - cur["total"], cur
    shown = PDF.trend_weeks(weeks)
    assert shown[0]["week"] == weeks[0]["week"]  # asset:a was open all along: no week is trimmed
    assert PDF.trend_weeks([{"week": "w1", "total": 0, "q0_gaps_opened": 0, "q0_gaps_open_at_week_end": 0},
                            {"week": "w2", "total": 0, "q0_gaps_opened": 1, "q0_gaps_open_at_week_end": 1}])[0]["week"] == "w2"
