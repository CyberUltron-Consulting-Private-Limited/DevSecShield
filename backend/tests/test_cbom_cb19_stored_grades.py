"""CB-19 PR-3: the quantum risk grade stored on each asset at ingest (PLAN §2.5, §2.6, §2.9, §4 PR-3).

* ingest stores the grade the run's views compute (node batches through ``jobs.store_rows``);
* the run asset list filters and counts on the stored column, equal to the list's own grades and to the posture;
* a run whose grades were not stored (before PR-3, another grade model, a job without its metadata snapshot) hides
  the filter and says why; filtering it is a 409;
* CB-18 EC-3 (a row another job read with a verdict is not an unknown verdict) holds on the stored column although
  the other job stores its rows later;
* the heat-map's grade metric and a cell's drill-down come from one loop;
* the run diff: grades differ in ``changed`` only when the estate does; a new grade model or new inputs go to
  ``rule_changes``; drift events are the same multiset either way (DA-5);
* migration ``cb19grade002`` up / down / up on a populated table (SQLite; PostgreSQL with ``CBOM_TEST_PG_URL``).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb19_stored_grades.py -q
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import itertools
import os
import sys
from collections import Counter
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as _base  # noqa: E402  (shared fixtures: SQLite world + real routers)

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomDriftEvent,
)
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import heatmap as HEAT  # noqa: E402
from backend.utilities.cbom_sources import qgrade as QG  # noqa: E402
from backend.utilities.cbom_sources import qgrade_store as QSTORE  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402

world = _base.world
api = _base.api
NOW = dt.datetime(2026, 11, 15, 9, 0)
ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "prod_database_migrations" / "migrations" / "versions" / "cb19grade002_asset_stored_grade.py"
PG = os.environ.get("CBOM_TEST_PG_URL")
MOSCA = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
_IDS = itertools.count(1)

QV_TLS = {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}
HYBRID_ONLY = {"protocols": ["TLSv1.3"], "pq_hybrid": True, "pq_group": "X25519MLKEM768"}
HYBRID_FALLBACK = {"protocols": ["TLSv1.2", "TLSv1.3"], "pq_hybrid": True, "pq_group": "X25519MLKEM768"}
CA = {"is_ca": True, "key_alg": "RSA", "key_size": 2048, "not_after": "2034-01-01T00:00:00Z", "subject": "CN=Corp CA",
      "issuer": "CN=Corp CA", "sig_alg": "sha256WithRSAEncryption", "self_signed": True, "fingerprint_sha256": "cd" * 32}
UNKNOWN_CERT = {"key_alg": "1.2.3.4.5.6.7", "not_after": "2030-01-01T00:00:00Z", "subject": "CN=x", "issuer": "CN=y"}
XTS128 = {"source": "bitlocker", "status": "FullyEncrypted", "method": "XtsAes128", "protection": "On", "mount": "C:"}


def _a(type_, location, target="10.20.0.1", facts=None, algorithm=None, key_size=None, name=None):
    return {"type": type_, "location": location, "target": target, "facts": facts or {}, "algorithm": algorithm,
            "key_size": key_size, "name": name}


def _cov(target, check, status, detail=""):
    return _a("coverage", f"{target}#{check}", target, {"check": check, "status": status, "detail": detail}, name=check)


# 10 asset shapes (PLAN §4 PR-3) and two coverage rows: every grade, "no grade" and "not an item"
SHAPES = [
    _a("tls_endpoint", "10.20.0.1:443", facts=QV_TLS),  # Q2 qv_exceeds (internal)
    _a("tls_endpoint", "52.95.110.1:443", target="52.95.110.1", facts=QV_TLS),  # Q1 qv_exceeds_internet
    _a("tls_endpoint", "10.20.0.1:8443", facts=HYBRID_ONLY),  # Q4 pq_observed
    _a("tls_endpoint", "10.20.0.1:9443", facts=HYBRID_FALLBACK),  # Q2 qv_fallback_exceeds
    _a("certificate", "/etc/ssl/ca.pem", facts=CA, algorithm="RSA", key_size=2048),  # Q1 qv_exceeds_anchor
    _a("tls_endpoint", "app-01.bank.local:443", target="app-01.bank.local", facts=QV_TLS),  # Q2 exposure unknown
    _a("disk_encryption", "C:", facts=XTS128, algorithm="XtsAes128"),  # Q3 grover_weakened
    _a("database_config", "10.20.0.1:5432", facts={"password_encryption": "scram-sha-256"}),  # no grade
    _a("certificate", "/etc/ssl/odd.pem", facts=UNKNOWN_CERT),  # Q0 unknown_verdict
    _a("ssh_endpoint", "10.20.0.1:22", facts={"kex": ["mlkem768x25519-sha256", "curve25519-sha256"],
                                              "host_key_types": ["ssh-ed25519"]}),  # Q2 qv_fallback_exceeds
    _cov("10.20.0.1", "package list", "denied", "sudo refused"),  # Q0 coverage_gap
    _cov("10.20.0.1", "BitLocker", "not_installed"),  # not an item
]


# ----------------------------------------------------------------------------- the real ingest path (node API)
def _settings(api) -> dict:
    return api("GET", "/1/cbom/sources/settings").json()["settings"]


def _set_mosca(api, **values) -> None:
    r = api("PATCH", "/1/cbom/sources/settings",
            json={"risk_model": values, "expected_version": _settings(api)["row_version"]})
    assert r.status_code == 200, r.text


def _ingest(api, assets, *, mosca=MOSCA, request_id=None) -> tuple[int, int]:
    """Start a run through the API (its grade-input snapshot), claim the job as the node, post one batch. Returns
    (run id, job id)."""
    if mosca:
        _set_mosca(api, **mosca)
    node_id, token, _ = _base.enroll_node(api, name=f"n-{next(_IDS)}")
    src = api("POST", "/1/cbom/sources/items", json=_base.linux_body(
        name=f"linux-{next(_IDS)}", node_id=node_id, targets=["10.20.0.1", "52.95.110.1", "app-01.bank.local"],
        window="any"))
    assert src.status_code == 201, src.text
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True},
                                                    "client_request_id": request_id or f"pr3-run-{next(_IDS):04d}"})
    assert run.status_code == 201, run.text
    hdr = {"X-ZS-Node-Token": token}
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert claim.status_code == 200, claim.text
    job = claim.json()["job"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": assets})
    assert r.status_code == 200 and r.json()["accepted"] == len(assets), r.text
    return run.json()["run"]["id"], job["id"]


def _page(api, run_id, **params) -> dict:
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/assets", params={"page_size": 200, **params})
    assert r.status_code == 200, r.text
    return r.json()


def _stored(engine, run_id) -> dict[int, tuple]:
    with Session(engine) as s:
        return {r.id: (r.q_grade, r.q_reason) for r in s.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.run_id == run_id)).all()}


def test_ingest_stores_the_grade_every_view_computes(api, world):
    engine, _ = world
    run_id, _job = _ingest(api, SHAPES)
    listed = {i["id"]: (i["q_grade"], i["q_reason"]) for i in _page(api, run_id)["items"]}
    stored = _stored(engine, run_id)
    assert len(stored) == len(SHAPES) and stored == listed  # one value per asset, ingest = view
    grades = set(stored.values())
    assert {("Q1", "qv_exceeds_internet"), ("Q1", "qv_exceeds_anchor"), ("Q2", "qv_exceeds"),
            ("Q2", "qv_exceeds_exposure_unknown"), ("Q2", "qv_fallback_exceeds"), ("Q3", "grover_weakened"),
            ("Q4", "pq_observed"), (None, "not_applicable"), ("Q0", "unknown_verdict"), ("Q0", "coverage_gap"),
            (None, "not_an_item")} <= grades
    for aid in stored:  # the asset detail (explain=True path) agrees as well
        d = api("GET", f"/1/cbom/sources/assets/{aid}").json()["asset"]
        assert (d["q_grade"], d["q_reason"]) == stored[aid]


def test_filter_and_facet_equal_the_list_and_the_posture(api, world):
    run_id, _job = _ingest(api, SHAPES)
    page = _page(api, run_id)
    assert page["grade_filter"] == {"available": True, "reason": None}
    facet = page["facets"]["q_grade"]
    counted = Counter(i["q_grade"] or "none" for i in page["items"])
    assert facet == {g: counted.get(g, 0) for g in QSTORE.GRADE_FILTERS}
    for grade in QSTORE.GRADE_FILTERS:
        got = _page(api, run_id, q_grade=grade)
        assert got["total"] == facet[grade] and got["q_grade_filter"] == grade
        assert all((i["q_grade"] or "none") == grade for i in got["items"])
    # the posture counts assets (coverage rows are scope items there): the facet less the coverage rows
    posture = api("GET", f"/1/cbom/sources/runs/{run_id}/posture").json()["posture"]
    coverage = Counter(i["q_grade"] or "none" for i in page["items"] if i["type"] == "coverage")
    assert posture["q_grades"] == {g: facet[g] - coverage.get(g, 0) for g in QSTORE.GRADE_FILTERS}
    # the findings view and the grade filter combine (SQL, server-side)
    findings_q2 = _page(api, run_id, view="findings", q_grade="Q2")
    assert all(i["q_grade"] == "Q2" and i["type"] != "coverage" for i in findings_q2["items"])


def test_an_unknown_grade_filter_value_is_a_400(api, world):
    run_id, _job = _ingest(api, SHAPES[:2])
    assert api("GET", f"/1/cbom/sources/runs/{run_id}/assets", params={"q_grade": "Q9"}).status_code in (400, 422)


# ----------------------------------------------------------------------------- runs whose grades were not stored
def test_a_run_from_before_stored_grades_hides_the_filter(api, world):
    engine, _ = world
    run_id, _job = _ingest(api, SHAPES[:3])
    with Session(engine) as s:  # what a row inserted before cb19grade002 looks like
        for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all():
            row.q_grade = row.q_reason = None
            s.add(row)
        s.commit()
    page = _page(api, run_id)
    assert page["facets"]["q_grade"] is None and page["grade_filter"]["available"] is False
    assert "3 of the run's assets" in page["grade_filter"]["reason"]
    assert all(i["q_grade"] is not None for i in page["items"])  # the list still grades at view
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/assets", params={"q_grade": "Q2"})
    assert r.status_code == 409 and "not available for this run" in r.text


def test_a_run_started_under_another_grade_model_stores_nothing(api, world):
    engine, _ = world
    _set_mosca(api, **MOSCA)
    node_id, token, _ = _base.enroll_node(api, name="n-model")
    api("POST", "/1/cbom/sources/items", json=_base.linux_body(name="linux-model", node_id=node_id,
                                                                targets=["10.20.0.1"], window="any"))
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True},
                                                    "client_request_id": "pr3-model-0001"}).json()["run"]
    with Session(engine) as s:  # a deploy between Start and ingest changed the grade model
        row = s.get(CbomCollectionRun, run["id"])
        row.grade_model_version = "qg-1+000000000000"
        s.add(row)
        s.commit()
    hdr = {"X-ZS-Node-Token": token}
    job = api("POST", "/cbom/node/jobs/claim", None, headers=hdr).json()["job"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": SHAPES[:2]})
    assert r.status_code == 200, r.text
    assert set(_stored(engine, run["id"]).values()) == {(None, None)}
    page = _page(api, run["id"])
    assert page["grade_filter"]["available"] is False and "qg-1+000000000000" in page["grade_filter"]["reason"]


def test_a_job_without_its_metadata_snapshot_stores_nothing(world):
    engine, _ = world
    w = _seed(engine, [SHAPES[0]], job_metadata=False)
    assert set(_stored(engine, w["run"]).values()) == {(None, None)}


def test_a_grade_that_fails_leaves_that_row_unstored_and_keeps_the_batch(world, monkeypatch):
    engine, _ = world
    real = QG.GradeContext.grade_row

    def flaky(self, row, codes, **kw):
        if row.location == "10.20.0.1:443":
            raise RuntimeError("boom")
        return real(self, row, codes, **kw)

    monkeypatch.setattr(QG.GradeContext, "grade_row", flaky)
    w = _seed(engine, SHAPES[:3])
    stored = _stored(engine, w["run"])
    assert len(stored) == 3 and sum(1 for v in stored.values() if v == (None, None)) == 1


# ----------------------------------------------------------------------------- seeding through ingest_grades
def _seed(engine, assets, *, mosca=MOSCA, run_model=None, metadata=None, job_metadata=True, source_id=None,
          extra_jobs=(), at=NOW) -> dict:
    """One finished run with a snapshot, one collect job (plus ``extra_jobs``: lists of assets, one job each, same
    run, new sources), rows graded by ``qgrade_store.ingest_grades`` and inserted as ``store_rows`` inserts them."""
    out: dict = {"jobs": []}
    with Session(engine) as s:
        settings = get_or_create_settings(s, 1)
        settings.risk_model = dict(mosca or {})
        s.add(settings)
        s.commit()
        snap = {"model": "qg-1", "mosca": QG.mosca_of(mosca), "digest": "seed", "captured_at": "x"}
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"pr3-seed-{next(_IDS):04d}",
                                status="done", created_at=at, finished_at=at + dt.timedelta(minutes=5),
                                breakdown={"groups": {}, "skipped": []}, include={},
                                kb_version=_kb(), classifier_version=_classifier(),
                                grade_model_version=run_model or QG.GRADE_MODEL_VERSION, grade_inputs=snap)
        s.add(run)
        s.commit()
        s.refresh(run)
        out["run"] = run.id
        for n, batch in enumerate([assets, *extra_jobs]):
            sid = source_id if (n == 0 and source_id) else None
            if sid is None:
                src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="linux_servers",
                                           name=f"S-{next(_IDS)}", name_lower=f"s-{next(_IDS)}", config={},
                                           created_at=at - dt.timedelta(days=1))
                s.add(src)
                s.commit()
                s.refresh(src)
                sid = src.id
                if n == 0:
                    out["source"] = sid
            src = s.get(CbomCollectionSource, sid)
            meta = {"business_criticality": None, "exposure": None, "data_lifetime_years": None,
                    "node_segment": None, **(metadata or {})}
            params = {"source_name": src.name, "source_uid": src.source_uid}
            if job_metadata:
                params["metadata"] = meta
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=sid, kind="collect", status="success",
                                    outcome="ok", attempts=1, result={}, params=params, finished_at=at)
            s.add(job)
            s.commit()
            s.refresh(job)
            out["jobs"].append(job.id)
            rows = []
            for i, a in enumerate(batch):
                v = classify(a["type"], a["algorithm"], a["key_size"], None, a["facts"], at)
                rows.append({"team_id": 1, "run_id": run.id, "job_id": job.id, "source_id": sid, "attempt": 1,
                             "asset_key": hashlib.sha256(f"{i}|{a['location']}".encode()).hexdigest(),
                             "asset_type": a["type"], "cdx_type": v["cdx_type"], "target": a["target"],
                             "location": a["location"], "name": a["name"], "algorithm": a["algorithm"],
                             "key_size": a["key_size"], "protocol": None,
                             "quantum_vulnerable": v["quantum_vulnerable"], "impact": v["impact"],
                             "finding_codes": v["finding_codes"], "finding": v["finding"], "facts": a["facts"],
                             "created_at": at})
            QSTORE.ingest_grades(s, job, rows)
            for row in rows:
                s.add(CbomCollectedAsset(**row))
            s.commit()
    return out


def _kb() -> str:
    from backend.utilities.cbom_sources import crypto_kb

    return crypto_kb.version()


def _classifier() -> str:
    from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION

    return CLASSIFIER_VERSION


# ----------------------------------------------------------------------------- CB-18 EC-3 on the stored column
def test_read_elsewhere_holds_on_the_stored_column(api, world):
    engine, _ = world
    unknown = _a("certificate", "/etc/ssl/odd.pem", facts=UNKNOWN_CERT)
    judged = _a("certificate", "/etc/ssl/odd.pem", facts={**CA, "is_ca": False}, algorithm="RSA", key_size=2048)
    # job 1 stores its unknown row first; job 2 (another source of the same run) reads the same file later
    w = _seed(engine, [unknown, SHAPES[0]], extra_jobs=[[judged]])
    stored = _stored(engine, w["run"])
    assert ("Q0", "unknown_verdict") in stored.values()  # stored without the rule (job 2 had not landed)
    page = _page(api, w["run"])
    by_loc = {(i["job_id"], i["location"]): i for i in page["items"]}
    assert by_loc[(w["jobs"][0], "/etc/ssl/odd.pem")]["q_grade"] is None  # the list applies EC-3
    facet = page["facets"]["q_grade"]
    assert facet == {g: Counter(i["q_grade"] or "none" for i in page["items"]).get(g, 0)
                     for g in QSTORE.GRADE_FILTERS}
    assert facet["Q0"] == 0
    assert _page(api, w["run"], q_grade="Q0")["total"] == 0
    assert (w["jobs"][0], "/etc/ssl/odd.pem") in {(i["job_id"], i["location"])
                                                  for i in _page(api, w["run"], q_grade="none")["items"]}


# ----------------------------------------------------------------------------- heat-map
def test_heatmap_grade_metric_and_cell_drill_down(api, world):
    run_id, _job = _ingest(api, SHAPES)
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/heatmap", params={"metric": "grade"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["metric"] == "grade"
    page = _page(api, run_id)
    assets = [i for i in page["items"] if i["type"] != "coverage"]
    total = Counter()
    for cell in body["cells"]:
        total.update(cell["by_grade"])
        assert sum(cell["by_grade"].values()) == cell["count"]
        assert cell["worst_grade"] == HEAT.worst_grade(cell["by_grade"])
        cells = api("GET", f"/1/cbom/sources/runs/{run_id}/heatmap/cell",
                    params={"row": cell["row"], "column": cell["column"], "metric": "grade", "page_size": 200}).json()
        assert cells["total"] == cell["count"] == len(cells["items"])
        assert Counter(i["q_grade"] or "none" for i in cells["items"]) == Counter(
            {k: v for k, v in cell["by_grade"].items() if v})
        listed = {i["id"]: i["q_grade"] for i in assets}
        assert all(listed[i["id"]] == i["q_grade"] for i in cells["items"])  # the list's grade, per asset
    assert {g: total.get(g, 0) for g in QSTORE.GRADE_FILTERS} == {
        g: Counter(i["q_grade"] or "none" for i in assets).get(g, 0) for g in QSTORE.GRADE_FILTERS}
    impact = api("GET", f"/1/cbom/sources/runs/{run_id}/heatmap").json()
    assert impact["metric"] == "impact" and all("by_grade" not in c for c in impact["cells"])
    assert api("GET", f"/1/cbom/sources/runs/{run_id}/heatmap", params={"metric": "x"}).status_code in (400, 422)


def test_a_known_grade_is_never_hidden_by_q0():
    assert HEAT.worst_grade({"Q0": 9, "Q3": 1}) == "Q3"
    assert HEAT.worst_grade({"Q0": 2, "none": 1}) == "Q0"
    assert HEAT.worst_grade({"Q4": 1, "Q1": 1}) == "Q1"
    assert HEAT.worst_grade({"none": 3}) is None


def test_the_cell_drill_down_is_paged_worst_first(api, world):
    engine, _ = world
    many = [_a("tls_endpoint", f"10.20.0.{i}:443", target=f"10.20.0.{i}", facts=QV_TLS) for i in range(1, 6)]
    many.append(_a("tls_endpoint", "52.95.110.1:443", target="52.95.110.1", facts=QV_TLS))
    w = _seed(engine, many)
    cell = {"by": "type", "row": "Elliptic curve", "column": "tls_endpoint", "metric": "grade"}  # x25519 endpoints
    with Session(engine) as s:
        full = HEAT.heatmap_cell(s, 1, w["run"], **cell, page_size=200)
        first = HEAT.heatmap_cell(s, 1, w["run"], **cell, page=1, page_size=2)
        second = HEAT.heatmap_cell(s, 1, w["run"], **cell, page=2, page_size=2)
    assert full["total"] == 6 and full["items"][0]["q_grade"] == "Q1"
    assert [i["id"] for i in first["items"] + second["items"]] == [i["id"] for i in full["items"][:4]]


# ----------------------------------------------------------------------------- the run diff (§2.9)
def _two_runs(engine, before_assets, after_assets, *, before_mosca=MOSCA, after_mosca=MOSCA, before_model=None,
              before_metadata=None, after_metadata=None) -> tuple[int, int]:
    first = _seed(engine, before_assets, mosca=before_mosca, run_model=before_model, metadata=before_metadata,
                  at=NOW)
    second = _seed(engine, after_assets, mosca=after_mosca, metadata=after_metadata, source_id=first["source"],
                   at=NOW + dt.timedelta(days=1))
    return first["run"], second["run"]


def _diff(engine, base_id, run_id) -> dict:
    with Session(engine) as s:
        return D.run_diff(s, s.get(CbomCollectionRun, run_id), s.get(CbomCollectionRun, base_id))


def _events(engine, run_id) -> list[tuple]:
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        D.record_run_drift(s, run, NOW + dt.timedelta(days=2))
        s.commit()
        rows = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.run_id == run_id)).all()
        return sorted((e.kind, e.asset_key, e.code, e.severity, str(sorted((e.detail or {}).items())))
                      for e in rows)


def _restore(engine, run_id, *, grade: str, reason: str, model: str) -> None:
    """Make a run look graded by an older model: its rows' stored grades and its model version."""
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, run_id)
        run.grade_model_version = model
        s.add(run)
        for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all():
            if row.q_grade in ("Q1", "Q2"):
                row.q_grade, row.q_reason = grade, reason
                s.add(row)
        s.commit()


ESTATE = [SHAPES[0], SHAPES[4], SHAPES[7]]  # an internal RSA endpoint (Q2), a CA (Q1), a database setting (none)


def test_da5_a_new_grade_model_re_judges_without_estate_drift(world):
    engine, _ = world
    grown = ESTATE + [SHAPES[1]]  # one new internet endpoint on the later side: real events to compare
    same_base, same_run = _two_runs(engine, ESTATE, grown)
    old_base, old_run = _two_runs(engine, ESTATE, grown)
    _restore(engine, old_base, grade="Q3", reason="qv_within", model="qg-0+0123456789ab")
    same, old = _diff(engine, same_base, same_run), _diff(engine, old_base, old_run)
    assert not any("q_grade" in c["changes"] for c in same["changed"] + old["changed"])
    assert not [r for r in same["rule_changes"] if r.get("field") == "q_grade"]
    grade_changes = [r for r in old["rule_changes"] if r.get("field") == "q_grade"]
    assert len(grade_changes) == 2 and {r["label_change"] for r in grade_changes} == {"grade model change"}
    assert {tuple(r["stored"]) for r in grade_changes} == {("Q3", "Q2"), ("Q3", "Q1")}
    assert all(r["current"][0] == r["current"][1] for r in grade_changes)
    assert old["versions"]["grade_model_changed"] is True and same["versions"]["grade_model_changed"] is False
    assert old["versions"]["before"]["grade_model_version"] == "qg-0+0123456789ab"
    # the drift events of the two runs are the same multiset (no event comes from a grade)
    def kinds(events):
        return sorted((k, c, sev) for k, _key, c, sev, _d in events)

    same_events, old_events = kinds(_events(engine, same_run)), kinds(_events(engine, old_run))
    assert same_events and same_events == old_events and "new_asset" in {k for k, *_ in same_events}


def test_inputs_change_between_runs_is_a_rule_change_not_drift(world):
    engine, _ = world
    base, run = _two_runs(engine, ESTATE, ESTATE, after_mosca={**MOSCA, "threat_years": 20})
    diff = _diff(engine, base, run)
    assert not any("q_grade" in c["changes"] for c in diff["changed"])
    grade_changes = [r for r in diff["rule_changes"] if r.get("field") == "q_grade"]
    assert grade_changes and {r["label_change"] for r in grade_changes} == {"grade inputs change"}
    assert ("Q2", "Q3") in {tuple(r["stored"]) for r in grade_changes}  # 10 + 5 > 12, then 10 + 5 <= 20
    assert diff["versions"]["grade_inputs_changed"] is True
    assert diff["versions"]["before"]["grade_inputs_digest"] != diff["versions"]["after"]["grade_inputs_digest"]
    assert _events(engine, run) == []


def test_an_estate_change_moves_the_grade_and_adds_no_event_kind(world):
    engine, _ = world
    internal = _a("tls_endpoint", "10.20.0.1:443", facts={**QV_TLS, "internet_facing": False})
    facing = _a("tls_endpoint", "10.20.0.1:443", facts={**QV_TLS, "internet_facing": True})
    base, run = _two_runs(engine, [internal], [facing])
    diff = _diff(engine, base, run)
    changed = [c for c in diff["changed"] if "q_grade" in c["changes"]]
    assert len(changed) == 1 and changed[0]["changes"]["q_grade"] == ["Q2", "Q1"]
    assert not [r for r in diff["rule_changes"] if r.get("field") == "q_grade"]
    assert {k for k, *_ in _events(engine, run)} <= set(D.EVENT_KINDS)
    assert not [e for e in _events(engine, run) if "q_grade" in e[4]]


def test_a_baseline_without_stored_grades_compares_on_current_grades_only(world):
    engine, _ = world
    base, run = _two_runs(engine, ESTATE, ESTATE)
    with Session(engine) as s:
        for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == base)).all():
            row.q_grade = row.q_reason = None
            s.add(row)
        r = s.get(CbomCollectionRun, base)
        r.grade_model_version = None
        s.add(r)
        s.commit()
    diff = _diff(engine, base, run)
    assert not any("q_grade" in c["changes"] for c in diff["changed"])
    assert not [r for r in diff["rule_changes"] if r.get("field") == "q_grade"]  # no record to compare
    assert diff["versions"]["grade_model_changed"] is True


# ----------------------------------------------------------------------------- migration cb19grade002
def _migration():
    spec = importlib.util.spec_from_file_location("cb19grade002", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_migration_is_the_one_head():
    import re

    mod = _migration()
    versions = MIGRATION.parent
    revisions, parents = set(), set()
    for path in versions.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down_line = re.search(r"^down_revision\b.*", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down_line:
            parents.update(re.findall(r"['\"]([^'\"]+)['\"]", down_line.group(0)))
    assert mod.revision == "cb19grade002" and mod.down_revision in revisions
    assert len(revisions - parents) == 1 and ("cb19grade002" in parents or revisions - parents == {"cb19grade002"})


ROWS = 2_000


def _shape(conn) -> tuple[set[str], set[str], list[tuple]]:
    insp = sa.inspect(conn)
    cols = {c["name"] for c in insp.get_columns("cbomcollectedasset")}
    idx = {i["name"] for i in insp.get_indexes("cbomcollectedasset")}
    rows = [tuple(r) for r in conn.execute(sa.text(
        "SELECT id, run_id, asset_type, impact FROM cbomcollectedasset ORDER BY id"))]
    return cols, idx, rows


def _up_down_up(engine, rows: int = ROWS) -> dict:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    def run(step):  # as prod_database_migrations/migrations/env.py runs a revision (autocommit_block needs it)
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            with ctx.begin_transaction(), Operations.context(ctx):
                getattr(_migration(), step)()
        with engine.begin() as conn:
            return _shape(conn)

    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS cbomcollectedasset"))
        conn.execute(sa.text("CREATE TABLE cbomcollectedasset (id integer PRIMARY KEY, run_id integer, "
                             "asset_type varchar(32) NOT NULL, impact varchar(16), facts text)"))
        conn.execute(sa.text("INSERT INTO cbomcollectedasset (id, run_id, asset_type, impact, facts) "
                             "VALUES (:i, :r, 'tls_endpoint', 'High', '{\"protocols\": [\"TLSv1.2\"]}')"),
                     [{"i": i, "r": i % 50} for i in range(1, rows + 1)])
        before = _shape(conn)[2]
        node = _relfilenode(conn)
    try:
        cols, idx, got = run("upgrade")
        assert {"q_grade", "q_reason"} <= cols and QSTORE_INDEX in idx and got == before
        with engine.begin() as conn:  # old rows read NULL ("graded at view"); nothing was backfilled
            assert conn.execute(sa.text("SELECT count(*) FROM cbomcollectedasset WHERE q_grade IS NULL "
                                        "AND q_reason IS NULL")).scalar() == rows
            after_node = _relfilenode(conn)
        cols, idx, got = run("downgrade")
        assert not ({"q_grade", "q_reason"} & cols) and QSTORE_INDEX not in idx and got == before
        cols, idx, got = run("upgrade")
        assert {"q_grade", "q_reason"} <= cols and QSTORE_INDEX in idx and got == before
        return {"relfilenode_before": node, "relfilenode_after_upgrade": after_node}
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomcollectedasset"))
        engine.dispose()


QSTORE_INDEX = "ix_cbomcollectedasset_run_qgrade"


def _relfilenode(conn) -> int | None:
    if conn.dialect.name != "postgresql":
        return None
    return conn.execute(sa.text("SELECT relfilenode FROM pg_class WHERE relname = 'cbomcollectedasset'")).scalar()


def test_migration_up_down_up_on_sqlite(tmp_path):
    _up_down_up(sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}"))


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
def test_migration_up_down_up_on_postgresql_does_not_rewrite_the_table():
    rows = int(os.environ.get("CBOM_TEST_PG_ROWS", "200000"))
    out = _up_down_up(sa.create_engine(PG), rows=rows)
    assert out["relfilenode_before"] == out["relfilenode_after_upgrade"]  # ADD COLUMN NULL: metadata only
