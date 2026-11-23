"""#289 delta review: a clause cited without a recorded algorithm is "needs evidence", end to end; the clause evidence is
classified once and the clause drill-down is decided without a whole-run id list.

N1  posture: a clause whose every asset was cited for review (``evidence: not_recorded``) has verdict
    ``needs_evidence`` (not ``fail``), ``unrecorded`` == ``assets``; a clause with one recorded asset stays ``fail`` and
    keeps its ``unrecorded`` count; a framework with only such clauses is ``needs_evidence``. An asset is unrecorded for
    a clause only when none of its codes cites the clause on a recorded algorithm.
N2  /results keeps ``unrecorded`` and ``verdict`` per clause and per framework (it dropped ``unrecorded`` before).
N3  OSCAL: the clause link text says "not recorded", the finding carries a ``clause-needs-evidence`` prop and remarks.
N4  a code-scan finding without an algorithm (title ``des3_keys.pem``) never has TDEA decided by its file name.
N5  ``clause=NIST:`` / ``clause=NIST: `` (a colon, no clause id) is a 400.
P1  the clause evidence is classified once per asset: the posture classifies each rule-code asset once, the clause
    drill-down that follows classifies none; the drill-down's SQL carries id ranges, not one id per asset.
P2  20,000 synthetic assets: the posture and one clause drill-down finish under a sane bound, the drill-down equals
    the posture's clause count, and no statement carries more than a few hundred parameters.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import event, insert
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cb38_runs_in_results_api as RUNS
from test_cbom_compliance_precise_clauses import (
    CERTIN_8422,
    NIST_TDEA,
    SEBI_H5,
)

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
)
from backend.utilities.cbom_sources import classify as CLASSIFY
from backend.utilities.cbom_sources import clause_evidence as CE
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import run_results as RR
from backend.utilities.cbom_sources.kb_remediation import (
    code_evidence,
    explain,
)

api = RUNS.api
world = RUNS.world
no_mongo = RUNS.no_mongo
seed_run = RUNS.seed_run

TDEA = f"{NIST_TDEA[0]}:{NIST_TDEA[1]}"
SSH_3DES = {"kex": ["curve25519-sha256"], "hostkey_algorithms": ["ssh-ed25519"], "ciphers": ["3des-cbc", "aes128-cbc"]}
SSH_AES = {"kex": ["curve25519-sha256"], "hostkey_algorithms": ["ssh-ed25519"], "ciphers": ["aes128-cbc"]}
TLS_PLAIN = {"protocols": ["TLSv1.2"]}  # today's classifier raises no WEAK_CIPHER here: nothing recorded


@pytest.fixture(autouse=True)
def _fresh_caches():
    RR.clear_cache()
    CE.clear_cache()
    yield
    RR.clear_cache()
    CE.clear_cache()


def _get(api, path, **params):
    r = api("GET", path, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _seed(engine, ids, name, specs):
    """specs: (asset name, asset_type, codes, facts); impact High for every finding row."""
    rows = [("High" if codes else None, False, a_type, codes) for _n, a_type, codes, _f in specs]
    run_id = seed_run(engine, 1, ids["alice"], rows=rows, source_name=name)
    with Session(engine) as s:
        stored = sorted(s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all(),
                        key=lambda r: r.id)
        for row, (asset_name, _t, _c, facts) in zip(stored, specs):
            row.name, row.facts = asset_name, facts
            row.content_digest = None  # a changed stored row: digest unknown (#352)
            s.add(row)
        s.commit()
        return run_id, {r.name: r.id for r in stored}


def _clauses(posture):
    return {(fw["framework"], c["id"]): c for fw in posture["compliance"] for c in fw["clauses"]}


# ------------------------------------------------------------------------------------------ N1 / N2: the verdict
def test_n1_unrecorded_only_clause_needs_evidence_and_framework_too(api, world, no_mongo):
    engine, ids = world
    # a SEBI-regulated team: SEBI CSCRF binds it (PR #485 M4 filters every surface by the team's profile)
    assert api("PATCH", "/1/cbom/sources/settings", json={"sebi_regulated": True}).status_code == 200
    run_id, _ = _seed(engine, ids, "n1a", [("legacy", "tls_endpoint", ["WEAK_CIPHER"], TLS_PLAIN),
                                           ("hk", "ssh_host_key", [], {})])
    posture = _get(api, f"/1/cbom/sources/runs/{run_id}/posture")["posture"]
    clauses = _clauses(posture)
    tdea = clauses[NIST_TDEA]
    assert (tdea["assets"], tdea["unrecorded"], tdea["verdict"]) == (1, 1, "needs_evidence")
    assert crypto_kb.NOT_RECORDED in tdea["note"]
    # the code's own clauses are confirmed (no algorithm needed): fail, nothing unrecorded
    assert clauses[CERTIN_8422]["verdict"] == "fail" and "unrecorded" not in clauses[CERTIN_8422]
    by_fw = {fw["framework"]: fw for fw in posture["compliance"]}
    assert by_fw["NIST"]["verdict"] == "needs_evidence" and by_fw["NIST"]["unrecorded"] == 1
    assert by_fw["CERT-In"]["verdict"] == "fail" and by_fw["CERT-In"]["unrecorded"] == 0
    assert by_fw["SEBI CSCRF"]["verdict"] == "needs_evidence"

    results = _get(api, f"/1/cbom/sources/runs/{run_id}/results")["compliance"]["frameworks"]
    res = {f["framework"]: f for f in results}
    nist = res["NIST"]
    assert (nist["verdict"], nist["unrecorded"], nist["assets"]) == ("needs_evidence", 1, 1)
    clause = next(c for c in nist["clauses"] if c["clause"] == NIST_TDEA[1])
    assert (clause["assets"], clause["unrecorded"], clause["verdict"]) == (1, 1, "needs_evidence")
    certin = next(c for c in res["CERT-In"]["clauses"] if c["clause"] == CERTIN_8422[1])
    assert (certin["unrecorded"], certin["verdict"]) == (0, "fail")
    assert res["RBI"]["verdict"] == "fail"
    assert res["CNSA 2.0"]["verdict"] is None and res["CNSA 2.0"]["clauses"] == []  # nothing touched


def test_n1_one_recorded_asset_keeps_the_clause_failing_with_its_unrecorded_count(api, world, no_mongo):
    engine, ids = world
    run_id, _ = _seed(engine, ids, "n1b", [("legacy", "tls_endpoint", ["WEAK_CIPHER"], TLS_PLAIN),
                                           ("box2", "ssh_endpoint", ["SSH_CBC_CIPHER", "SSH_WEAK_CIPHER"], SSH_3DES)])
    posture = _get(api, f"/1/cbom/sources/runs/{run_id}/posture")["posture"]
    tdea = _clauses(posture)[NIST_TDEA]
    assert (tdea["assets"], tdea["unrecorded"], tdea["verdict"]) == (2, 1, "fail")
    nist = next(fw for fw in posture["compliance"] if fw["framework"] == "NIST")
    assert (nist["verdict"], nist["assets"], nist["unrecorded"]) == ("fail", 2, 1)
    res = next(f for f in _get(api, f"/1/cbom/sources/runs/{run_id}/results")["compliance"]["frameworks"]
               if f["framework"] == "NIST")
    clause = next(c for c in res["clauses"] if c["clause"] == NIST_TDEA[1])
    assert (clause["unrecorded"], clause["verdict"], res["verdict"]) == (1, "fail", "fail")


def test_n1_an_asset_is_unrecorded_only_when_no_code_records_the_clause(api, world, no_mongo):
    """box2 offers 3des-cbc (SSH_CBC_CIPHER records TDEA) and also carries a stored WEAK_CIPHER the SSH rules never
    raise (TDEA not recorded for that code): the asset is behind TDEA on a recorded algorithm."""
    engine, ids = world
    run_id, _ = _seed(engine, ids, "n1c", [("box2", "ssh_endpoint", ["SSH_CBC_CIPHER", "WEAK_CIPHER"], SSH_3DES)])
    tdea = _clauses(_get(api, f"/1/cbom/sources/runs/{run_id}/posture")["posture"])[NIST_TDEA]
    assert (tdea["assets"], tdea.get("unrecorded", 0), tdea["verdict"]) == (1, 0, "fail")


def test_n1_verdict_helpers():
    assert POSTURE.clause_verdict(3, 3) == "needs_evidence"
    assert POSTURE.clause_verdict(3, 2) == "fail"
    assert POSTURE.clause_verdict(0, 0) == "fail"
    assert POSTURE.framework_verdict([{"verdict": "needs_evidence"}, {"verdict": "fail"}]) == "fail"
    assert POSTURE.framework_verdict([{"verdict": "needs_evidence"}]) == "needs_evidence"
    assert POSTURE.framework_verdict([]) is None
    # an older posture without the fields (cached) still gets a verdict in /results
    out = RR._compliance([{"framework": "NIST", "assets": 2, "clauses": [
        {"id": "x", "text": "t", "source": "s", "assets": 2, "codes": ["WEAK_CIPHER"], "unrecorded": 2}]}])
    nist = next(f for f in out["frameworks"] if f["framework"] == "NIST")
    assert nist["clauses"][0]["verdict"] == "needs_evidence" and nist["verdict"] == "needs_evidence"
    assert nist["unrecorded"] == 0  # the framework count is the posture's (absent: 0)


def test_n1_deliverables_count_an_asset_recorded_by_any_code():
    from backend.utilities.pdf.cbom_collected_compliance import collected_clauses

    agg = SimpleNamespace(current=True, source_key="sources:s1", asset_type="protocol", ident="box2", title="box2",
                          finding_codes=("SSH_CBC_CIPHER", "WEAK_CIPHER"), collector_codes=(),
                          clause_evidence={"SSH_CBC_CIPHER": ["3des-cbc"]})
    rows = {(r.framework, r.clause): r for r in collected_clauses(SimpleNamespace(assets=[agg]))}
    assert rows[NIST_TDEA].assets == 1 and rows[NIST_TDEA].unrecorded == 0


# ------------------------------------------------------------------------------------------------------ N3 OSCAL
def test_n3_oscal_marks_clauses_that_need_evidence(api, world, no_mongo):
    from backend.utilities.integrations import oscal

    links = oscal._references("node", "WEAK_CIPHER", [None])
    tdea = next(link for link in links if "(TDEA)" in link["text"])
    assert tdea["text"].endswith(oscal.NOT_RECORDED_ALL)
    certin = next(link for link in links if link["text"].startswith("CERT-In"))
    assert "not recorded" not in certin["text"]
    mixed = oscal._references("node", "SSH_CBC_CIPHER", [None, ["3des-cbc"]])
    assert any("(TDEA) (algorithm not recorded for 1 of 2 assets: verify)" in link["text"] for link in mixed)

    engine, ids = world
    run_id, _ = _seed(engine, ids, "n3", [("legacy", "tls_endpoint", ["WEAK_CIPHER"], TLS_PLAIN)])
    with Session(engine) as session:
        doc = oscal.run_document(session, session.get(CbomCollectionRun, run_id))
    findings = [f for r in doc["assessment-results"]["results"] for f in r.get("findings") or []]
    weak = [f for f in findings if any(p["name"] == "finding-code" and p["value"] == "WEAK_CIPHER" for p in f["props"])]
    assert weak
    for finding in weak:
        marked = {p["value"] for p in finding["props"] if p["name"] == "clause-needs-evidence"}
        assert f"{NIST_TDEA[0]}: {NIST_TDEA[1]}" in marked
        assert f"{CERTIN_8422[0]}: {CERTIN_8422[1]}" not in marked
        assert "not a confirmed violation" in finding["remarks"]
        assert any(link["text"].endswith(oscal.NOT_RECORDED_ALL) for link in finding["links"])


# --------------------------------------------------------------------------------------- N4 / N5: the minors
def test_n4_code_scan_file_name_never_decides_a_clause():
    finding = {"title": "des3_keys.pem", "description": "Certificate signed with SHA256withRSA"}
    assert code_evidence(finding) == []
    for detail in explain({"finding_codes": ["WEAK_ALGORITHM"], **finding}):
        for ref in detail["compliance"]:
            if (ref["framework"], ref["id"]) in (NIST_TDEA, SEBI_H5):
                assert ref.get("evidence") == "not_recorded", ref  # cited for review only, never decided
    # with the scanner's algorithm the rule decides as before
    named = {"title": "des3_keys.pem", "algorithm_name": "DESede", "description": "Weak algorithm DESede"}
    cited = {(r["framework"], r["id"]): r for d in explain({"finding_codes": ["WEAK_ALGORITHM"], **named})
             for r in d["compliance"]}
    assert NIST_TDEA in cited and not cited[NIST_TDEA].get("evidence")
    assert "des3_keys.pem" not in code_evidence(named)


def test_n5_a_colon_without_a_clause_id_is_rejected(api, world, no_mongo):
    engine, ids = world
    run_id, _ = _seed(engine, ids, "n5", [("legacy", "tls_endpoint", ["WEAK_CIPHER"], TLS_PLAIN)])
    path = f"/1/cbom/sources/runs/{run_id}/assets"
    for bad in ("NIST:", "NIST: ", "NIST :  "):
        r = api("GET", path, params={"clause": bad})
        assert r.status_code == 400, (bad, r.text)
    for good in ("NIST", f"NIST:{NIST_TDEA[1]}"):
        assert api("GET", path, params={"clause": good}).status_code == 200, good
    with pytest.raises(ValueError):
        CE.parse_clause("RBI:")


# ------------------------------------------------------------------------------ P1: classified once per asset
class _Counter:
    def __init__(self, monkeypatch):
        self.calls = 0
        real = CLASSIFY.classify

        def counting(*a, **kw):
            self.calls += 1
            return real(*a, **kw)

        monkeypatch.setattr(CLASSIFY, "classify", counting)


class _Statements:
    """Every SQL statement's parameter count while active."""

    def __init__(self, engine):
        self.engine, self.params = engine, []

    def _on(self, conn, cursor, statement, parameters, context, executemany):
        self.params.append(len(parameters) if isinstance(parameters, (tuple, list, dict)) else 0)

    def __enter__(self):
        event.listen(self.engine, "before_cursor_execute", self._on)
        return self

    def __exit__(self, *exc):
        event.remove(self.engine, "before_cursor_execute", self._on)


def test_p1_clause_evidence_is_classified_once_per_asset(api, world, no_mongo, monkeypatch):
    engine, ids = world
    specs = [(f"aes{i}", "ssh_endpoint", ["SSH_CBC_CIPHER"], SSH_AES) for i in range(6)] + \
            [(f"3des{i}", "ssh_endpoint", ["SSH_CBC_CIPHER"], SSH_3DES) for i in range(4)] + \
            [(f"hk{i}", "ssh_host_key", ["QUANTUM_VULNERABLE"], {}) for i in range(3)]
    run_id, by_name = _seed(engine, ids, "p1", specs)
    counter = _Counter(monkeypatch)
    posture = _get(api, f"/1/cbom/sources/runs/{run_id}/posture")["posture"]
    assert counter.calls == 10  # the ten SSH_CBC_CIPHER assets, once each (shown() reads no dates for them)
    assert _clauses(posture)[NIST_TDEA]["assets"] == 4
    counter.calls = 0
    with _Statements(engine) as sql:
        page = _get(api, f"/1/cbom/sources/runs/{run_id}/assets", clause=TDEA, page_size=200)
    assert counter.calls == 0, "the drill-down reuses the posture's evidence"
    assert page["total"] == 4 == len(page["items"])
    assert {i["id"] for i in page["items"]} == {by_name[f"3des{i}"] for i in range(4)}
    assert max(sql.params) < 40, sql.params  # id ranges, never one parameter per candidate asset
    # a second posture: nothing classified again
    RR.clear_cache()
    _get(api, f"/1/cbom/sources/runs/{run_id}/posture")
    assert counter.calls == 0


def test_p1_drill_down_mixes_always_and_rule_codes_in_both_polarities(api, world, no_mongo):
    """Interleaved behind / not-behind assets plus assets whose own clauses always cite: the filter equals
    clause_evidence.matches for every clause of every framework (ranges of either side, never wider)."""
    engine, ids = world
    pattern = [SSH_AES, SSH_3DES, SSH_3DES, SSH_AES, SSH_AES, SSH_AES, SSH_3DES, SSH_AES, SSH_3DES, SSH_3DES]
    specs = []
    for i, facts in enumerate(pattern):
        specs.append((f"s{i}", "ssh_endpoint", ["SSH_CBC_CIPHER"], facts))
        if i % 3 == 0:
            specs.append((f"t{i}", "tls_endpoint", ["WEAK_CIPHER"], TLS_PLAIN))  # rule clauses unrecorded: behind
        if i % 4 == 0:
            specs.append((f"q{i}", "ssh_host_key", ["QUANTUM_VULNERABLE"], {}))
    run_id, _ = _seed(engine, ids, "p1b", specs)
    with Session(engine) as s:
        rows = {r.id: r for r in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all()}
    out = _get(api, f"/1/cbom/sources/runs/{run_id}/results")
    path = f"/1/cbom/sources/runs/{run_id}/assets"
    checked = 0
    for fw in out["compliance"]["frameworks"]:
        for clause in fw["clauses"]:
            page = _get(api, path, clause=f"{fw['framework']}:{clause['clause']}", page_size=200)
            keys = CE.clause_keys(fw["framework"], clause["clause"])
            expected = {aid for aid, row in rows.items() if CE.matches(row, row.finding_codes or [], keys)}
            assert {i["id"] for i in page["items"]} == expected, clause["clause"]
            assert page["total"] == clause["assets"], clause["clause"]
            checked += 1
        if fw["clauses"]:
            assert _get(api, path, clause=fw["framework"], page_size=200)["total"] == fw["assets"], fw["framework"]
    assert checked >= 5


def test_p1_id_ranges_pick_the_smaller_side():
    from sqlalchemy.dialects import sqlite

    from backend.utilities.cbom_sources.run_assets import _id_ranges

    def render(expr):
        return str(expr.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))

    # behind: 1-50 and 60; not behind: 51-59 -> two runs vs one: the exclusion of 51-59 is used
    text = render(_id_ranges(list(range(1, 51)) + [60], list(range(51, 60))))
    assert "NOT" in text and "BETWEEN 51 AND 59" in text
    text = render(_id_ranges([5, 7], list(range(1, 5)) + [6] + list(range(8, 40))))
    assert "NOT" not in text and "IN (5, 7)" in text
    assert render(_id_ranges([1, 2, 3], [])) in ("1", "true")


# ---------------------------------------------------------------------------- P2: 20k assets under a bound
N_ASSETS = 20_000
BOUND_S = 90.0  # the shared 2-CPU box; ~9 s at 50k assets was the extra cost of the second classification alone


def _bulk_run(engine, ids) -> tuple[int, int]:
    """20,000 collected assets in one run: 8,000 SSH servers with CBC ciphers (3des-cbc on every fifth host, in blocks
    as a job writes them), 6,000 TLS endpoints whose stored WEAK_CIPHER has no recorded algorithm, 6,000 SSH host keys.
    Returns (run id, expected TDEA assets)."""
    run_id = seed_run(engine, 1, ids["alice"], rows=[("Low", True, "ssh_host_key", ["QUANTUM_VULNERABLE"])],
                      source_name="p2")
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).first()
        rows, tdea = [], 0
        for n in range(N_ASSETS):
            if n < 8000:
                three = (n // 50) % 5 == 0
                tdea += three
                kw = {"asset_type": "ssh_endpoint", "finding_codes": ["SSH_CBC_CIPHER"], "impact": "Medium",
                      "facts": SSH_3DES if three else SSH_AES, "location": f"10.1.{n // 250}.{n % 250}:22"}
            elif n < 14000:
                tdea += 1
                kw = {"asset_type": "tls_endpoint", "cdx_type": "protocol", "finding_codes": ["WEAK_CIPHER"],
                      "impact": "High", "facts": TLS_PLAIN, "location": f"10.2.{n // 250}.{n % 250}:443"}
            else:
                kw = {"finding_codes": ["QUANTUM_VULNERABLE"], "impact": "Low"}
            obj = RUNS._asset(1, run, job, n + 10, finding="finding", **kw)
            rows.append({c.name: getattr(obj, c.name) for c in CbomCollectedAsset.__table__.columns
                         if c.name != "id" and getattr(obj, c.name, None) is not None})
        for start in range(0, len(rows), 2000):
            s.execute(insert(CbomCollectedAsset.__table__), rows[start:start + 2000])
        s.commit()
    return run_id, tdea


def test_p2_twenty_thousand_assets_posture_and_one_clause_drill(api, world, no_mongo, monkeypatch):
    engine, ids = world
    run_id, tdea = _bulk_run(engine, ids)
    counter = _Counter(monkeypatch)
    started = time.perf_counter()
    posture = _get(api, f"/1/cbom/sources/runs/{run_id}/posture")["posture"]
    posture_s = time.perf_counter() - started
    clause = _clauses(posture)[NIST_TDEA]
    assert clause["assets"] == tdea and clause["unrecorded"] == 6000
    assert counter.calls == 8000 + 6000  # each rule-code asset classified once
    counter.calls = 0
    started = time.perf_counter()
    with _Statements(engine) as sql:
        page = _get(api, f"/1/cbom/sources/runs/{run_id}/assets", clause=TDEA, page_size=50)
    drill_s = time.perf_counter() - started
    assert page["total"] == tdea
    assert counter.calls == 0
    assert max(sql.params) < 500, max(sql.params)
    print(json.dumps({"assets": N_ASSETS, "posture_s": round(posture_s, 2), "drill_s": round(drill_s, 2),
                      "tdea_assets": tdea, "max_sql_params": max(sql.params)}))
    assert posture_s < BOUND_S and drill_s < BOUND_S / 3, (posture_s, drill_s)
