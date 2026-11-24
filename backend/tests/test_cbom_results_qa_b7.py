"""Staging QA of the ONE results template, lane B7 (SQLite + the real routers, the CB-19 run fixtures).

* Bug 1: a run asset opened from the Certificates table or Top risks (not on the findings page) gets the same row as
  the findings table: ``GET /sources/assets/{id}`` carries every field of the run's ``/assets`` item, equal values.
* Bug 3: a run whose source was deleted names it by the job's snapshot name everywhere (top risks, asset detail), as
  the findings table does; no posture number changes (Rule P).
* Bug 4: "Q0 Unknown: why" counts assets per reason (``q0_reason_assets``, summing to the Q0 bar) and the unread
  scope per reason apart (``q0_scope_reasons``); ``q0_reasons`` keeps counting items (the CB-19 contract).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_results_qa_b7.py -q
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_cb19_run_grades as G  # seed, list, detail and posture helpers

world = G.world
api = G.api

CERT_QV = {"is_ca": False, "key_alg": "RSA", "key_size": 2048, "not_after": "2027-01-01T00:00:00Z",
           "subject": "CN=api.bank.local", "issuer": "CN=Corp CA", "sig_alg": "sha256WithRSAEncryption",
           "self_signed": False, "fingerprint_sha256": "ab" * 32}


def _run(engine, *, mosca=G.MOSCA, idle=()):
    return G.seed(engine, mosca=mosca, idle=idle, sources=[{
        "name": "dmz-web", "metadata": {"business_criticality": "high"},
        "assets": [G._asset("certificate", "/etc/ssl/api.pem", facts=CERT_QV, algorithm="RSA", key_size=2048),
                   G._asset("certificate", "/etc/ssl/ca.pem", facts=G.CA, algorithm="RSA", key_size=2048),
                   G._asset("tls_endpoint", "10.20.0.1:443", facts=G.QV_TLS),
                   G._cov("10.20.0.1", "ssh host keys", "timeout", "no answer")]}])


# ----------------------------------------------------------------------------- bug 1: the dialog's row
def test_asset_detail_carries_the_findings_table_row(api, world):
    w = _run(world[0])
    listed = G.items(api, w["run"])
    assert listed, "the run lists its assets"
    for aid, item in listed.items():
        d = G.detail(api, aid)
        # every field the findings table row has, with the same value: the dialog renders the same grid, location,
        # finding, OWASP / controls / fix and provenance whether it was opened from the table or not
        missing = sorted(k for k in item if k not in d)
        assert not missing, (aid, missing)
        differ = {k: (item[k], d[k]) for k in item if d[k] != item[k]}
        assert not differ, (aid, differ)
        for key in ("type_label", "crypto_strength", "risk_score", "status", "job_id", "bom_ref", "suggested_fix"):
            assert key in d, key
    cert = G.detail(api, w["dmz-web"]["assets"]["/etc/ssl/api.pem"])
    assert cert["type_label"] and cert["job_id"] == w["dmz-web"]["job"] and cert["status"] == "not_started"
    assert isinstance(cert["risk_score"], float)
    assert any(it["risk_score"] > 0 for it in listed.values()), "a scored row was compared"


def test_asset_detail_of_another_team_is_404(api, world):
    w = _run(world[0])
    aid = next(iter(w["dmz-web"]["assets"].values()))
    assert api("GET", f"/2/cbom/sources/assets/{aid}", who="carol").status_code in (403, 404)


# ----------------------------------------------------------------------------- bug 3: a deleted source's name
def test_deleted_source_keeps_its_snapshot_name_on_top_risks_and_detail(api, world):
    w = _run(world[0])
    before = G.posture(api, w["run"])
    assert before["top_risks"] and {r["source_name"] for r in before["top_risks"]} == {"dmz-web"}
    r = api("DELETE", f"/1/cbom/sources/items/{w['dmz-web']['source']}")
    assert r.status_code in (200, 204), r.text
    listed = G.items(api, w["run"])
    assert {it["source_name"] for it in listed.values()} == {"dmz-web"}, "the findings table: job snapshot name"
    after = G.posture(api, w["run"])
    assert [r["source_name"] for r in after["top_risks"]] == [r["source_name"] for r in before["top_risks"]]
    # Rule P: only the name was read differently; every posture number is the same
    for key in ("assets", "pqc_classes", "pqc_class_bases", "pqc_readiness_pct", "hndl_assets", "impacts",
                "exposure", "q_grades", "q0_counts"):
        assert after[key] == before[key], key
    assert [(r["id"], r["score"]) for r in after["top_risks"]] == [(r["id"], r["score"]) for r in before["top_risks"]]
    for aid in listed:
        assert G.detail(api, aid)["source_name"] == "dmz-web", aid


# ----------------------------------------------------------------------------- bug 4: Q0 reasons by asset
def test_q0_reasons_count_affected_assets_and_scope_apart(api, world):
    idle = [{"name": f"unchosen-{i}"} for i in range(5)]
    w = _run(world[0], mosca=None, idle=idle)
    p = G.posture(api, w["run"])
    listed = G.items(api, w["run"])
    q0_assets = Counter(it["q_reason"] for it in listed.values() if it["type"] != "coverage" and it["q_grade"] == "Q0")
    # SOW D12: Mosca unset no longer parks quantum-vulnerable assets at Q0: they are graded on the documented
    # defaults ("default assumptions"), so no asset is Q0 here and there is no "inputs:mosca" item
    assert not q0_assets and "mosca_missing" not in p["q0_reasons"] and p["q0_reasons"]["excluded_by_choice"] == 5
    assert any(it["q_grade"] in ("Q1", "Q2", "Q3") for it in listed.values() if it["type"] != "coverage")
    # assets per reason, summing to the Q0 bar and to q0_counts.assets
    assert p["q0_reason_assets"] == dict(q0_assets) == {}
    assert sum(p["q0_reason_assets"].values()) == p["q_grades"]["Q0"] == p["q0_counts"]["assets"] == 0
    # the unread scope per reason (items), apart from the assets; it sums to q0_counts.scope_items
    assert p["q0_scope_reasons"] == {"coverage_gap": 1, "excluded_by_choice": 5}
    assert sum(p["q0_scope_reasons"].values()) == p["q0_counts"]["scope_items"]
    # every item is a scope item
    assert p["q0_items_total"] == sum(p["q0_scope_reasons"].values())


def test_q0_reason_assets_with_mosca_set_and_nothing_unknown(api, world):
    w = _run(world[0])
    p = G.posture(api, w["run"])
    assert p["q_grades"]["Q0"] == 0 and p["q0_reason_assets"] == {}
    assert p["q0_scope_reasons"] == {"coverage_gap": 1}
