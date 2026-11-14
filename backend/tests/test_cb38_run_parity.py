"""CB-38 W2b: a Sources run feeds every section of the code-scan results page in the code page's payload shapes.

P1  GET /runs/{id}/parity: ``scan_metadata`` carries the code page's keys; ``cbom_compliance`` is the code lane's
    tri-state blob (13 frameworks, FrameworkCoverage / ComplianceRequirement keys parsed from the TypeScript types,
    the verdict vocabulary of ``ComplianceVerdict``), coverage = pass / (pass + fail).
P2  The compliance verdicts agree with the run API (Rule P): NIST SP 1800-38B PQC-1 fails exactly on the run's
    quantum-vulnerable assets (``posture.run_posture`` class), and passes on a run with none.
P3  RBI CSF roll-up and CERT-In posture are the backend's own roll-up functions over that blob.
P4  Crypto dependency graph in ``CbomGraph`` shape: one node per asset (``zs-asset-<id>``), certificate chain
    ``signed_by`` edges, compact <= 40 / expanded <= 120 nodes with source / target folders.
P5  "What this scan covered": ``CbomCoverageReport`` with the run's not-collected targets and coverage rows.
P6  Team-scoped (404), cached like /results (one computation; a new UTC day / run update recomputes), live while active.
P7  /runs/{id}/diff carries ``events`` like /code-scans/{id}/diff; /assets items carry the ``CbomFinding`` keys the code
    page reads (bom_ref, title, owasp_top_10, compliance_controls, suggested_fix).
P8  GET /runs/{id}/assets/{asset_id}/remediation is the code page's RemediationData (KB, no AI); 404 across runs/teams.
P9  Without the engine the compliance keys are null and ``engine.compliance`` says unavailable; the rest still works.
"""
from __future__ import annotations

import datetime as dt
import re
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_run_results as RRT
from test_cbom_run_results import PROBE, _cert, _run_with

api = RRT.api
world = RRT.world

from sqlmodel import Session

from backend.new_models import CbomCollectionRun
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import run_parity as RP
from backend.utilities.cbom_sources import run_results as RR

REPO = Path(__file__).resolve().parents[2]
FRAMEWORKS = {"nist_1800_38b", "nist_800_57", "omb_m_23_02", "eu_cra", "eu_dora", "pci_dss_4", "fips_140_3",
              "bsi_tr_02102", "nist_1800_38c", "cnsa_2_0", "rbi_free_ai_protection", "cert_in_cbom",
              "sebi_cscrf_cbom"}


@pytest.fixture(autouse=True)
def _fresh():
    RP.clear_cache()
    RR.clear_cache()
    yield
    RP.clear_cache()
    RR.clear_cache()


def _required(path: Path, name: str) -> set[str]:
    """Non-optional members of a TypeScript interface (``key:`` not ``key?:``)."""
    text = path.read_text(encoding="utf-8")
    start = re.search(rf"interface\s+{name}\s*\{{", text)
    assert start, name
    i, depth = start.end(), 1
    while depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", text[start.end():i - 1], flags=re.DOTALL)
    return set(re.findall(r"^\s*([A-Za-z_]\w*)\s*:", body, flags=re.MULTILINE))


def _verdicts() -> set[str]:
    text = (REPO / "frontend/components/compliance/types.ts").read_text(encoding="utf-8")
    block = re.search(r"type ComplianceVerdict\s*=([^;]+);", text)
    assert block
    return set(re.findall(r'"([a-z_]+)"', block.group(1)))


CHAIN = [
    {"type": "tls_endpoint", "target": "10.20.0.9", "location": "10.20.0.9:443",
     "facts": {"protocols": ["TLSv1.2"], "group": "x25519"}},
    {"type": "certificate", "target": "10.20.0.9", "location": "10.20.0.9:443#chain[0]",
     "facts": {**_cert("CN=leaf.bank"), "chain_index": 0}},
    {"type": "certificate", "target": "10.20.0.9", "location": "10.20.0.9:443#chain[1]",
     "facts": {**_cert("CN=Bank Issuing CA", issuer="CN=Bank Root"), "chain_index": 1, "is_ca": True}},
]


def _parity(api, run_id, team=1, who="alice"):
    r = api("GET", f"/{team}/cbom/sources/runs/{run_id}/parity", who)
    assert r.status_code == 200, r.text
    return r.json()


def _posture(engine, run_id):
    with Session(engine) as s:
        return POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)


def _vulnerable_ids(engine, run_id) -> set[str]:
    from sqlmodel import select

    from backend.new_models import CbomCollectedAsset
    from backend.utilities.cbom_sources.classify import shown

    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    out = set()
    with Session(engine) as s:
        for row in s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run_id)).all():
            if row.asset_type == "coverage":
                continue
            codes = [c for c in shown(row, now)["finding_codes"] or [] if not c.startswith("COVERAGE_")]
            if POSTURE.classify_pqc(row, codes)[0] == "quantum-vulnerable":
                out.add(f"zs-asset-{row.id}")
    return out


def _again(api, hdr, assets, crid):
    """Another run of the same source on the same node (the node is enrolled once per test)."""
    from test_cbom_run_results import _finish, _post_assets

    created = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": crid})
    assert created.status_code == 201, created.text
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert claim.status_code == 200, claim.text
    _post_assets(api, claim.json(), hdr, assets, batch=crid[-4:])
    _finish(api, claim.json(), hdr)
    return created.json()["run"]


# ----------------------------------------------------------------------------- P1 shapes
def test_p1_compliance_blob_in_the_code_pages_shape(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE + CHAIN)
    out = _parity(api, run["id"])
    meta = out["scan_metadata"]
    for key in ("cbom_compliance", "rbi_csf_rollup", "certin_posture", "cbom_graph", "cbom_graph_compact",
                "cbom_graph_expanded", "cbom_coverage", "cbom_input", "repo_url", "branch"):
        assert key in meta, key
    assert out["engine"] == {"compliance": "available"}
    comp = meta["cbom_compliance"]
    assert FRAMEWORKS <= set(comp), sorted(comp)
    assert isinstance(comp["disclaimer"], str)
    cov_keys = _required(REPO / "frontend/components/compliance/types.ts", "FrameworkCoverage")
    req_keys = _required(REPO / "frontend/components/compliance/types.ts", "ComplianceRequirement")
    assert cov_keys == {"pass", "fail", "na", "coverage"} and req_keys == {"id", "title", "verdict"}
    verdicts = _verdicts()
    ids = {f"zs-asset-{i}" for i in range(1, 10_000)}
    for fw in FRAMEWORKS:
        block = comp[fw]
        assert cov_keys <= set(block), fw
        assert block["requirements"], fw
        for req in block["requirements"]:
            assert req_keys <= set(req) and req["verdict"] in verdicts, (fw, req)
            assert all(r in ids for r in req.get("refs") or []), req  # refs are the run's asset bom_refs
        p, f = block["pass"], block["fail"]
        assert block["coverage"] == (round(p / (p + f), 3) if p + f else None)
        counted = sum(block.get(k, 0) for k in ("pass", "pass_with_evidence", "fail", "out_of_scope",
                                                "not_bom_evidenceable", "na"))
        assert counted == len(block["requirements"]), fw


# ----------------------------------------------------------------------------- P2 agrees with posture
def test_p2_pqc_verdict_matches_the_runs_posture_classes(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE + CHAIN)
    p = _posture(engine, run["id"])
    vulnerable = _vulnerable_ids(engine, run["id"])
    assert p["pqc_classes"]["quantum-vulnerable"] == len(vulnerable) >= 2  # RSA host key, x25519 endpoint, certs
    pqc1 = next(r for r in _parity(api, run["id"])["scan_metadata"]["cbom_compliance"]["nist_1800_38b"]["requirements"]
                if r["id"] == "PQC-1")
    assert pqc1["verdict"] == "fail"
    assert set(pqc1["refs"]) == vulnerable  # exactly the assets /posture calls quantum-vulnerable


def test_p2b_a_run_without_quantum_vulnerable_assets_passes_pqc1(api, world):
    engine, _ = world
    hybrid = [PROBE[1]]  # TLS 1.3 with X25519MLKEM768
    _s, run, _c, _h = _run_with(api, engine, hybrid)
    assert _posture(engine, run["id"])["pqc_classes"]["quantum-vulnerable"] == 0
    reqs = _parity(api, run["id"])["scan_metadata"]["cbom_compliance"]["nist_1800_38b"]["requirements"]
    assert next(r for r in reqs if r["id"] == "PQC-1")["verdict"] == "pass"


# ----------------------------------------------------------------------------- P3 roll-ups
def test_p3_rbi_and_certin_rollups_are_the_backend_functions_over_the_blob(api, world):
    from backend.utilities.dashboard.certin_posture import build_certin_posture
    from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup

    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE + CHAIN)
    meta = _parity(api, run["id"])["scan_metadata"]
    assert meta["rbi_csf_rollup"] == build_rbi_csf_rollup(cbom_compliance=meta["cbom_compliance"])
    assert meta["certin_posture"] == build_certin_posture(cbom_compliance=meta["cbom_compliance"])
    pillars = meta["rbi_csf_rollup"]["rbi_csf_rollup"]
    assert set(pillars) == {"governance", "identification", "protection", "detection", "response"}
    assert pillars["protection"]["pass"] + pillars["protection"]["fail"] > 0  # FREE-AI protection verdicts land
    assert "cbom_crypto_assets" in meta["certin_posture"]["certin_posture"]


# ----------------------------------------------------------------------------- P4 graph
def test_p4_dependency_graph_in_cbomgraph_shape(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE + CHAIN)
    meta = _parity(api, run["id"])["scan_metadata"]
    node_keys = _required(REPO / "frontend/utils/backend_api.ts", "CbomGraphNode")
    edge_keys = _required(REPO / "frontend/utils/backend_api.ts", "CbomGraphEdge")
    assert node_keys == {"id", "label", "kind"} and edge_keys == {"source", "target", "rel"}
    full = meta["cbom_graph"]
    assert len(full["nodes"]) == len(PROBE + CHAIN) - 1  # every asset but the coverage row
    assert all(node_keys <= set(n) for n in full["nodes"])
    assert all(n["id"].startswith("zs-asset-") for n in full["nodes"])
    lib = [n for n in full["nodes"] if n["kind"] == "framework"]
    assert len(lib) == 1 and lib[0]["label"] == "openssl"
    ids = {n["label"]: n["id"] for n in full["nodes"]}
    chain = [e for e in full["edges"] if e["rel"] == "signed_by"]
    assert chain == [{"source": ids["CN=leaf.bank"], "target": ids["CN=Bank Issuing CA"], "rel": "signed_by"}]
    for view, cap in (("cbom_graph_compact", RP.COMPACT_MAX_NODES), ("cbom_graph_expanded", RP.EXPANDED_MAX_NODES)):
        g = meta[view]
        assert g["nodes"] and len(g["nodes"]) <= cap
        assert all(node_keys <= set(n) for n in g["nodes"]) and all(edge_keys <= set(e) for e in g["edges"])
        shown = {n["id"] for n in g["nodes"]}
        assert all(e["source"] in shown and e["target"] in shown for e in g["edges"])
        folders = [n for n in g["nodes"] if n["kind"] == "location"]
        assert folders and all("10.20.0." in n["label"] for n in folders), folders  # source / target layer
        assert any(n["kind"] == "family" for n in g["nodes"])
        assert not any("∕" in n["label"] or "∶" in n["label"] for n in folders)


def test_p4b_large_run_is_folded_within_the_node_budget(api, world):
    engine, _ = world
    many = [{"type": "tls_endpoint", "target": f"10.30.{i // 250}.{i % 250}", "location": f"10.30.{i // 250}.{i % 250}:443",
             "facts": {"protocols": ["TLSv1.2"], "group": "x25519"}} for i in range(300)]
    _s, run, _c, _h = _run_with(api, engine, many)
    meta = _parity(api, run["id"])["scan_metadata"]
    assert len(meta["cbom_graph"]["nodes"]) == 300
    compact = meta["cbom_graph_compact"]
    assert len(compact["nodes"]) <= RP.COMPACT_MAX_NODES
    assert any(n.get("cluster") and n["label"].startswith("+") for n in compact["nodes"])  # "+N more"
    assert compact["meta"]["assets"] == 300 and compact["meta"]["folded_assets"] > 0


# ----------------------------------------------------------------------------- P5 coverage
def test_p5_coverage_report_lists_what_the_run_did_not_collect(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE, partial=True)
    cov = _parity(api, run["id"])["scan_metadata"]["cbom_coverage"]
    assert set(cov) == {"notes", "skipped"}
    assert all(set(n) == {"key", "text", "kind"} and n["kind"] in ("skipped", "info") for n in cov["notes"])
    texts = " | ".join(n["text"] for n in cov["notes"])
    assert "10.20.0.2" in texts and "auth failed" in texts  # the target not reached
    assert "disk encryption state not collected" in texts and "sudo not allowed" in texts  # the coverage row
    assert cov["skipped"] == sum(1 for n in cov["notes"] if n["kind"] == "skipped") >= 2


def test_p5b_a_complete_run_has_no_coverage_banner(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, [PROBE[1]])
    assert _parity(api, run["id"])["scan_metadata"]["cbom_coverage"] is None


# ----------------------------------------------------------------------------- P6 tenancy, cache, live
def test_p6_tenancy_404_and_auth(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    assert api("GET", f"/2/cbom/sources/runs/{run['id']}/parity", "carol").status_code == 404
    assert api("GET", "/1/cbom/sources/runs/999999/parity").status_code == 404
    assert api("GET", f"/2/cbom/sources/runs/{run['id']}/parity", "alice").status_code in (401, 403)
    assert api("GET", f"/1/cbom/sources/runs/{run['id']}/parity", None).status_code in (401, 403)
    assert api("GET", f"/1/cbom/sources/runs/{run['id']}/parity", "bob").status_code == 200  # a member reads


def test_p6b_cached_like_results_and_recomputed_on_change(api, world, monkeypatch):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    rid = run["id"]
    outs: list = []
    threads = [threading.Thread(target=lambda: outs.append(_parity(api, rid))) for _ in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert RP.COMPUTE_COUNT[rid] == 1 and len({o["inputs_digest"] for o in outs}) == 1
    _parity(api, rid)
    assert RP.COMPUTE_COUNT[rid] == 1
    with Session(engine) as s:  # the run changes: recomputed
        r = s.get(CbomCollectionRun, rid)
        r.last_updated = (r.last_updated or dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc).replace(tzinfo=None)) + dt.timedelta(seconds=5)
        s.add(r)
        s.commit()
    _parity(api, rid)
    assert RP.COMPUTE_COUNT[rid] == 2
    real = RP.utcnow
    monkeypatch.setattr("backend.routers.cbom_sources.utcnow", lambda: real() + dt.timedelta(days=1))
    out = _parity(api, rid)
    assert RP.COMPUTE_COUNT[rid] == 3 and out["judged_on"] == (real() + dt.timedelta(days=1)).date().isoformat()


def test_p6c_active_run_is_live(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE, finish=False)
    out = _parity(api, run["id"])
    assert out["state"] == "live" and out["scan_metadata"]["cbom_graph"]["nodes"]


# ----------------------------------------------------------------------------- P7 diff events, finding fields
def test_p7_run_diff_carries_events_and_assets_carry_cbomfinding_keys(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    d = api("GET", f"/1/cbom/sources/runs/{run['id']}/diff", "alice")
    assert d.status_code == 200, d.text  # first run: nothing to compare, the message
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?view=findings&page_size=200", "alice")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    required = _required(REPO / "frontend/utils/backend_api.ts", "CbomFinding")
    assert {"title", "owasp_top_10", "compliance_controls", "description", "impact", "risk_score", "status"} <= required
    weak = next(i for i in items if i["location"] == "10.20.0.1:443")
    assert required <= set(weak), required - set(weak)
    assert weak["bom_ref"] == f"zs-asset-{weak['id']}"
    assert isinstance(weak["owasp_top_10"], dict) and weak["owasp_top_10"]
    assert isinstance(weak["compliance_controls"], dict) and weak["compliance_controls"]
    assert weak["suggested_fix"]
    # the bom_refs join the graph and the compliance refs
    nodes = {n["id"] for n in _parity(api, run["id"])["scan_metadata"]["cbom_graph"]["nodes"]}
    assert {i["bom_ref"] for i in items} <= nodes


def test_p7b_second_run_diff_has_events(api, world):
    engine, _ = world
    _s, _run1, _c, hdr = _run_with(api, engine, [PROBE[1]])
    run2 = _again(api, hdr, [PROBE[1], PROBE[4]], "parity-second-0001")  # a new weak endpoint
    assert api("GET", f"/1/cbom/sources/runs/{run2['id']}/changes", "alice").status_code == 200  # records drift
    d = api("GET", f"/1/cbom/sources/runs/{run2['id']}/diff", "alice").json()
    assert d["against_run_id"] == _run1["id"], d
    assert isinstance(d["events"], list) and d["events"], d
    assert {"id", "kind", "run_id", "asset_label"} <= set(d["events"][0])
    assert all(e["run_id"] == run2["id"] for e in d["events"])
    assert any(e["kind"] in ("new_asset", "opened") for e in d["events"])


# ----------------------------------------------------------------------------- P8 remediation
def test_p8_asset_remediation_is_the_code_pages_remediation_data(api, world):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    items = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?view=findings", "alice").json()["items"]
    weak = next(i for i in items if i["location"] == "10.20.0.1:443")
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets/{weak['id']}/remediation", "alice")
    assert r.status_code == 200, r.text
    rd = r.json()
    assert rd["source"] == "knowledge_base" and rd["status"] == "completed" and rd["kb_version"]
    assert {"description", "original_code", "fixed_code", "language", "confidence", "references"} <= set(rd["fix"])
    assert rd["details"]
    assert api("GET", f"/2/cbom/sources/runs/{run['id']}/assets/{weak['id']}/remediation", "carol").status_code == 404
    other = _again(api, _h, [PROBE[1]], "parity-other-0001")
    assert api("GET", f"/1/cbom/sources/runs/{other['id']}/assets/{weak['id']}/remediation",
               "alice").status_code == 404
    cov = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?type=coverage", "alice").json()["items"]
    if cov:
        assert api("GET", f"/1/cbom/sources/runs/{run['id']}/assets/{cov[0]['id']}/remediation",
                   "alice").status_code == 404


# ----------------------------------------------------------------------------- P9 no engine
def test_p9_without_the_engine_compliance_is_null_and_the_rest_works(api, world, monkeypatch):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    monkeypatch.setattr(RP, "engine", lambda: {"compliance": None, "graph": None, "component": None, "result": None,
                                               "reason": "crypto compliance engine not installed (ImportError)"})
    out = _parity(api, run["id"])
    meta = out["scan_metadata"]
    assert out["engine"]["compliance"] == "unavailable" and "not installed" in out["engine"]["reason"]
    assert meta["cbom_compliance"] is None and meta["rbi_csf_rollup"] is None and meta["certin_posture"] is None
    assert meta["cbom_graph"]["nodes"] and meta["cbom_coverage"]


# ----------------------------------------------------------------------------- follow-ups (review 5905604614)
def test_f1_cache_is_bounded_by_rows_like_results(api, world, monkeypatch):
    """The cache holds at most CACHE_ROWS summed assets (as /results), least recently used out first."""
    engine, _ = world
    _s, run1, _c, hdr = _run_with(api, engine, PROBE)  # 5 non-coverage assets
    run2 = _again(api, hdr, [PROBE[1], PROBE[4]], "parity-cache-0001")
    monkeypatch.setattr(RP, "CACHE_ROWS", 6)
    assert _parity(api, run1["id"])["assets_total"] == 5
    assert _parity(api, run2["id"])["assets_total"] == 2  # 5 + 2 > 6: run 1 leaves
    assert set(RP._CACHE) == {run2["id"]}
    _parity(api, run1["id"])
    assert RP.COMPUTE_COUNT[run1["id"]] == 1  # its counter left with it; recomputed once more
    assert set(RP._CACHE) == {run1["id"]}  # the newest entry always stays


def test_f1b_eviction_never_drops_a_held_lock(api, world, monkeypatch):
    engine, _ = world
    _s, run1, _c, hdr = _run_with(api, engine, PROBE)
    run2 = _again(api, hdr, [PROBE[1]], "parity-lock-00001")
    monkeypatch.setattr(RP, "CACHE_ROWS", 1)
    _parity(api, run1["id"])
    held = RP._lock(run1["id"])
    with held:  # a request is computing run 1 while run 2 evicts it
        _parity(api, run2["id"])
        assert RP._lock(run1["id"]) is held  # the same lock: no second computation of run 1 in parallel



def test_f1c_cache_eviction_is_least_recently_used(api, world, monkeypatch):
    """A cache hit refreshes the run: the run read most recently survives, the one unread longest leaves."""
    engine, _ = world
    _s, run1, _c, hdr = _run_with(api, engine, PROBE)  # 5 assets
    run2 = _again(api, hdr, [PROBE[1], PROBE[4]], "parity-lru-00001")  # 2 assets
    run3 = _again(api, hdr, [PROBE[2]], "parity-lru-00002")  # 1 asset
    monkeypatch.setattr(RP, "CACHE_ROWS", 7)
    _parity(api, run1["id"])
    _parity(api, run2["id"])  # 5 + 2 = 7 fits
    _parity(api, run1["id"])  # hit: run 1 is now the most recently used
    assert RP.COMPUTE_COUNT[run1["id"]] == 1
    _parity(api, run3["id"])  # 8 > 7: run 2 (least recently used) leaves, not run 1
    assert set(RP._CACHE) == {run1["id"], run3["id"]}


def test_f2b_engine_error_result_is_retried_after_the_live_ttl(api, world, monkeypatch):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    real = RP.engine()

    class Boom:
        @staticmethod
        def run_cbom_compliance(_result):
            raise RuntimeError("secret-host.example.com broke")

    monkeypatch.setattr(RP, "engine", lambda: {**real, "compliance": Boom})
    assert _parity(api, run["id"])["engine"]["compliance"] == "unavailable"
    _parity(api, run["id"])
    assert RP.COMPUTE_COUNT[run["id"]] == 1  # within the TTL it is reused
    monkeypatch.setattr(RP, "engine", lambda: real)
    monkeypatch.setattr(RP.RR, "LIVE_TTL_S", -1)
    assert _parity(api, run["id"])["engine"]["compliance"] == "available"  # retried once the TTL passed
    assert RP.COMPUTE_COUNT[run["id"]] == 2
    RP._ERRORS_LOGGED.clear()  # errors are logged once per process; let later tests see their own line

def test_f2_engine_error_at_runtime_degrades_instead_of_500(api, world, monkeypatch, capsys):
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    real = RP.engine()

    class Boom:
        @staticmethod
        def run_cbom_compliance(_result):
            raise RuntimeError("engine bug")

    class BadGraph:
        @staticmethod
        def build_detailed(_g, **_kw):
            raise KeyError("x")

    monkeypatch.setattr(RP, "engine", lambda: {**real, "compliance": Boom, "graph": BadGraph})
    out = _parity(api, run["id"])
    meta = out["scan_metadata"]
    assert out["engine"]["compliance"] == "unavailable" and "RuntimeError" in out["engine"]["reason"]
    assert meta["cbom_compliance"] is None and meta["rbi_csf_rollup"] is None and meta["certin_posture"] is None
    assert meta["cbom_graph"]["nodes"]  # the full graph and the banner still come back
    assert meta["cbom_graph_compact"] is None and meta["cbom_graph_expanded"] is None
    logged = capsys.readouterr().out
    assert "cbom run parity engine error" in logged and "RuntimeError" in logged
    assert "engine bug" not in logged  # exception text (may hold asset names) is not logged


def test_f6_library_weak_flag_follows_its_findings(api, world):
    engine, _ = world
    clean = {"type": "crypto_library", "target": "10.20.0.1", "location": "package:libsodium", "name": "libsodium",
             "facts": {"name": "libsodium", "version": "1.0.20", "source": "package"}}
    _s, run, _c, _h = _run_with(api, engine, [PROBE[3], clean])
    items = {i["name"]: i for i in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets", "alice").json()["items"]}
    nodes = {n["label"]: n for n in _parity(api, run["id"])["scan_metadata"]["cbom_graph"]["nodes"]}
    for name in ("openssl", "libsodium"):
        codes = [c for c in items[name]["finding_codes"] or [] if not c.startswith("COVERAGE_")]
        assert nodes[name]["weak"] is bool(codes), (name, codes)
    assert nodes["libsodium"]["weak"] is False



def test_f7_asset_detail_carries_the_same_dialog_fields_as_the_run_item(api, world):
    """Dialogs opened from top risks / certificates read GET /assets/{id}: same OWASP, controls and fix as /assets."""
    engine, _ = world
    _s, run, _c, _h = _run_with(api, engine, PROBE)
    items = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?page_size=200", "alice").json()["items"]
    for item in items:
        detail = api("GET", f"/1/cbom/sources/assets/{item['id']}", "alice").json()["asset"]
        for key in ("bom_ref", "owasp_top_10", "compliance_controls", "suggested_fix"):
            assert detail[key] == item[key], (item["location"], key)
    weak = next(i for i in items if i["location"] == "10.20.0.1:443")
    assert all(re.match(r"^A\d\d:2021 ", v) for v in weak["owasp_top_10"].values()), weak["owasp_top_10"]
