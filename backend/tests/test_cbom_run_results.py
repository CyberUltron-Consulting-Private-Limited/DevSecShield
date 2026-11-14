"""CB-38 PR-2 / PR-5 / PR-7 data: GET /{team_id}/cbom/sources/runs/{run_id}/results.

B6  every Rule-P figure (readiness, quantum-vulnerable, severity totals, quantum split, PQC counts, top risks,
    compliance clauses) equals ``posture.run_posture`` called directly on the same run, and the readiness is NOT the
    code-lane ``node_row`` -> ``summarize_code_rows`` number (the run holds an XTS-128 volume key, which that path
    calls "broken today").
B8  two concurrent GETs compute once; a ``run.last_updated`` change or a new UTC day recomputes.
B9  ``dashboard`` carries every key of the frontend ``CbomScanDashboardData`` and ``distributions`` every key of
    ``CbomDistributions`` (both parsed from the TypeScript sources).
Plus tenancy (404), empty / coverage-only / active / cancelled / partial runs, orphaned and unmanaged certificates,
the live remediation join, and a 5,000-asset bench (kept under 10 s).

Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as SOURCES_API  # noqa: E402  (shared SQLite + real-router harness)
from test_cbom_sources_api import _collect_job, linux_body  # noqa: E402

api = SOURCES_API.api  # fixtures
world = SOURCES_API.world

from sqlmodel import Session, select  # noqa: E402

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun  # noqa: E402
from backend.utilities.cbom_sources import collections_view as CV  # noqa: E402
from backend.utilities.cbom_sources import posture as POSTURE  # noqa: E402
from backend.utilities.cbom_sources import run_results as RR  # noqa: E402
from backend.utilities.cbom_sources.cbom_metrics import summarize_code_rows  # noqa: E402
from backend.utilities.cbom_sources.classify import shown  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
FUTURE = (dt.datetime.utcnow() + dt.timedelta(days=400)).strftime("%Y-%m-%dT00:00:00Z")
PAST = (dt.datetime.utcnow() - dt.timedelta(days=400)).strftime("%Y-%m-%dT00:00:00Z")


@pytest.fixture(autouse=True)
def _fresh_cache():
    RR.clear_cache()
    yield
    RR.clear_cache()


def _cert(subject: str, *, not_after: str = FUTURE, issuer: str = "CN=Bank Issuing CA", size: int = 2048) -> dict:
    return {"subject": subject, "issuer": issuer, "not_before": "2025-01-01T00:00:00Z", "not_after": not_after,
            "sig_alg": "sha256WithRSAEncryption", "key_alg": "RSA", "key_size": size, "self_signed": False,
            "fingerprint_sha256": (subject.encode().hex() * 8)[:64]}


# the probe run of PLAN 0 / B6: XTS-128 volume key, hybrid TLS 1.3, RSA-2048, an end-of-life library, a coverage row
PROBE = [
    {"type": "disk_encryption", "target": "10.20.0.1", "location": "C:", "name": "C:", "algorithm": "XtsAes128",
     "facts": {"source": "bitlocker", "status": "FullyEncrypted", "method": "XtsAes128", "protection": "On",
               "mount": "C:"}},
    {"type": "tls_endpoint", "target": "10.20.0.2", "location": "10.20.0.2:443",
     "facts": {"protocols": ["TLSv1.3"], "group": "X25519MLKEM768", "pq_hybrid": True}},
    {"type": "ssh_host_key", "target": "10.20.0.1", "location": "/etc/ssh/ssh_host_rsa_key.pub", "algorithm": "RSA",
     "key_size": 2048, "facts": {"key_type": "ssh-rsa", "bits": 2048}},
    {"type": "crypto_library", "target": "10.20.0.1", "location": "package:openssl", "name": "openssl",
     "facts": {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package"}},
    {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
     "facts": {"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519", "weak_ciphers": ["DES-CBC3-SHA"]}},
    {"type": "coverage", "target": "10.20.0.1", "location": "10.20.0.1#sudo",
     "facts": {"reason": "sudo not allowed", "what": "disk encryption state"}},
]


def _post_assets(api, claim, hdr, assets, batch="b1"):
    job = claim["job"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": job["lease_id"], "batch_id": batch, "assets": assets})
    assert r.status_code == 200, r.text


def _finish(api, claim, hdr, *, partial=False):
    job = claim["job"]
    result = {"counts": {"total": 2, "ok": 2, "failed": 0, "skipped": 0}}
    if partial:
        result = {"counts": {"total": 2, "ok": 1, "failed": 1, "skipped": 0},
                  "targets": [{"target": "10.20.0.1", "status": "ok"},
                              {"target": "10.20.0.2", "status": "auth_failed", "error": "denied"}]}
    r = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr,
            json={"lease_id": job["lease_id"], "status": "success", "result": result})
    assert r.status_code == 200, r.text


def _run_with(api, engine, assets, *, finish=True, partial=False):
    src, run, claim, hdr = _collect_job(api, engine)
    if assets:
        _post_assets(api, claim, hdr, assets)
    if finish:
        _finish(api, claim, hdr, partial=partial)
    return src, run, claim, hdr


def _results(api, run_id, team=1, who="alice"):
    r = api("GET", f"/{team}/cbom/sources/runs/{run_id}/results", who)
    assert r.status_code == 200, r.text
    return r.json()


def _posture(engine, run_id):
    with Session(engine) as s:
        return POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)


# ----------------------------------------------------------------------------- B6 Rule P
def test_b6_rule_p_figures_equal_run_posture_and_not_the_code_lane_adapter(api, world):
    engine, _ = world
    _src, run, _claim, _hdr = _run_with(api, engine, PROBE)
    out = _results(api, run["id"])
    p = _posture(engine, run["id"])
    card, dash = out["dashboard"]["card_data"], out["dashboard"]
    classes = p["pqc_classes"]
    assert classes["grover-weakened"] == 1 and classes["hybrid"] == 1 and classes["quantum-vulnerable"] >= 1

    # every Rule-P figure, 1:1
    assert card["quantum_readiness_score"] == p["pqc_readiness_pct"]
    assert card["quantum_readiness_judged"] is True
    assert card["total_quantum_vulnerable"] == classes["quantum-vulnerable"]
    assert card["total_crypto_assets"] == p["assets"]
    assert card["total_crypto_vulnerabilities"] == sum(p["impacts"].values())
    sev = dash["severity_distribution"]
    assert {k: sev[k.lower()] for k in p["impacts"]} == p["impacts"]
    assert sev["informational"] == p["assets"] - sum(p["impacts"].values())
    assert dash["quantum_readiness"] == {
        "quantum_vulnerable": classes["quantum-vulnerable"],
        "quantum_safe": classes["quantum-safe"] + classes["hybrid"] + classes["grover-weakened"],
        "unknown": classes["not-applicable"]}
    pqc = out["distributions"]["pqc"]
    assert pqc["readiness_pct"] == p["pqc_readiness_pct"]
    assert pqc["quantum_vulnerable"] == classes["quantum-vulnerable"] and pqc["hybrid"] == classes["hybrid"]
    assert pqc["migration_total"] == classes["quantum-vulnerable"] == len(pqc["migration"])
    assert out["top_risks"] == json.loads(json.dumps(p["top_risks"]))
    assert [(r["asset_id"], r["risk_score"], r["impact"]) for r in dash["top_risks"]] == \
        [(r["id"], r["score"], r["impact"]) for r in p["top_risks"]]
    flat = {(f["framework"], c["clause"]): (c["assets"], c["codes"])
            for f in out["compliance"]["frameworks"] for c in f["clauses"]}
    want = {(RR._framework(f["framework"]), c["id"]): (c["assets"], c["codes"])
            for f in p["compliance"] for c in f["clauses"]}
    assert flat == want and flat

    # the code-lane adapter on the same rows gives another readiness: the page must not show it
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run["id"])).all()
        coll = CV.Collection(run_id=run["id"], job_id=0, source_ref="x", source_name="x", source_kind="",
                             observed_at=dt.datetime.now(dt.timezone.utc))
        adapter = summarize_code_rows([CV.node_row(r, coll, shown(r)) for r in rows if r.asset_type != "coverage"])
    assert adapter.readiness_pct is not None and adapter.readiness_pct < p["pqc_readiness_pct"]
    assert card["quantum_readiness_score"] != adapter.readiness_pct

    # inventory: the EOL library is a weakness code, the coverage row is not an asset but is in provenance
    assert "LIB_EOL" in out["distributions"]["weakness"]
    assert "DISK_XTS_128" in out["distributions"]["weakness"]
    assert out["distributions"]["protocols"]["TLS 1.3"] == 1 and out["distributions"]["protocols"]["TLS 1.0"] == 1
    assert card["total_crypto_assets"] == len(PROBE) - 1
    prov = out["provenance"]
    assert len(prov) == 1 and prov[0]["assets"] == len(PROBE) - 1 and prov[0]["not_collected"] == 1
    assert prov[0]["endpoints_probed"] == 2 and prov[0]["runner"] == "node" and prov[0]["source"] == "linux-dc"
    assert out["state"] == "ready" and out["stale"] is False and out["run"]["id"] == run["id"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", out["judged_on"]) and len(out["inputs_digest"]) == 16


# ----------------------------------------------------------------------------- B9 contract keys
def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _ts_interface(path: Path, name: str) -> dict[str, dict | None]:
    """Keys of a TypeScript interface: {key: nested keys (object / Array<{...}> members) or None}."""
    text = _strip_comments(path.read_text(encoding="utf-8"))
    start = re.search(rf"interface\s+{name}\s*\{{", text)
    assert start, f"{name} not found in {path}"
    i, depth = start.end(), 1
    body_start = i
    while depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    body = text[body_start:i - 1]
    return _members(body)


def _members(body: str) -> dict[str, dict | None]:
    out: dict[str, dict | None] = {}
    i, n = 0, len(body)
    key_re = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)\??\s*:")
    while i < n:
        m = key_re.match(body, i)
        if not m:
            i += 1
            continue
        key, j = m.group(1), m.end()
        # the member's type runs to the next ";" / newline outside any bracket
        depth, k = 0, j
        while k < n:
            ch = body[k]
            if ch in "{<([":
                depth += 1
            elif ch in "}>)]":
                depth -= 1
            elif depth == 0 and ch in ";\n":
                break
            k += 1
        type_text = body[j:k]
        brace = type_text.find("{")
        out[key] = _members(type_text[brace + 1:type_text.rfind("}")]) if brace >= 0 else None
        i = k + 1
    return out


def _assert_has(shape: dict[str, dict | None], value: object, where: str) -> None:
    assert isinstance(value, dict), f"{where} is not an object"
    for key, nested in shape.items():
        assert key in value, f"{where}.{key} missing"
        if nested is None:
            continue
        inner = value[key]
        if isinstance(inner, list):
            for item in inner[:3]:
                _assert_has(nested, item, f"{where}.{key}[]")
        else:
            _assert_has(nested, inner, f"{where}.{key}")


def test_b9_response_keys_cover_the_frontend_types(api, world):
    engine, _ = world
    _src, run, _c, _h = _run_with(api, engine, PROBE + [
        {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/web.pem", "name": "web",
         "algorithm": "RSA", "key_size": 2048, "facts": _cert("CN=web.bank.local")},
        {"type": "private_key", "target": "10.20.0.1", "location": "/etc/ssl/web.key", "name": "web.key",
         "algorithm": "RSA", "key_size": 2048, "facts": {"format": "PEM"}}])
    out = _results(api, run["id"])
    dash_shape = _ts_interface(REPO / "frontend/utils/backend_api.ts", "CbomScanDashboardData")
    dist_shape = _ts_interface(REPO / "frontend/components/cbom/CbomCryptoCharts.tsx", "CbomDistributions")
    migration_shape = _ts_interface(REPO / "frontend/components/cbom/CbomCryptoCharts.tsx", "PqcMigrationRow")
    # the parser itself (so a TS refactor cannot make this test vacuous)
    assert {"card_data", "remediation_metrics", "remediation_actions_required", "top_risks"} <= set(dash_shape)
    assert "quantum_readiness_score" in (dash_shape["card_data"] or {})
    assert {"algorithms", "weakness", "pqc", "certificates", "protocols", "key_material"} <= set(dist_shape)
    assert "migration_target" in migration_shape and "expired" in (dist_shape["certificates"] or {})
    _assert_has(dash_shape, out["dashboard"], "dashboard")
    _assert_has(dist_shape, out["distributions"], "distributions")
    assert out["distributions"]["pqc"]["migration"] and out["distributions"]["certificates"]
    assert out["distributions"]["key_material"]
    for row in out["distributions"]["pqc"]["migration"]:
        _assert_has(migration_shape, row, "distributions.pqc.migration[]")
    assert out["dashboard"]["top_risks"]
    # the contract's top-level keys (BRIEF C)
    assert {"run", "dashboard", "distributions", "compliance", "certificates_orphaned", "certificates_unmanaged",
            "provenance", "top_risks", "judged_on", "computed_at", "inputs_digest", "state", "stale"} <= set(out)
    assert [f["framework"] for f in out["compliance"]["frameworks"]][:5] == list(RR.FRAMEWORKS)
    for ref in out["certificates_orphaned"] + out["certificates_unmanaged"]:
        assert {"asset_id", "subject", "issuer", "not_after", "location", "source"} <= set(ref)
    for row in out["provenance"]:
        assert {"source_id", "source", "kind", "node", "runner", "outcome", "assets", "endpoints_probed",
                "duration_s", "credits"} <= set(row)


# ----------------------------------------------------------------------------- B8 cache
def test_b8_single_flight_and_recompute_on_last_updated_and_day(api, world, monkeypatch):
    engine, _ = world
    _src, run, _c, _h = _run_with(api, engine, PROBE)
    rid = run["id"]
    real = RR._compute
    gate = threading.Event()

    def slow(*args, **kwargs):
        gate.wait(5)
        return real(*args, **kwargs)

    monkeypatch.setattr(RR, "_compute", slow)
    results: list[dict] = []

    def get():
        results.append(_results(api, rid))

    threads = [threading.Thread(target=get) for _ in range(2)]
    for t in threads:
        t.start()
    time.sleep(0.3)
    gate.set()
    for t in threads:
        t.join(10)
    assert len(results) == 2 and RR.COMPUTE_COUNT[rid] == 1
    assert results[0]["inputs_digest"] == results[1]["inputs_digest"]
    assert results[0]["computed_at"] == results[1]["computed_at"]
    _results(api, rid)
    assert RR.COMPUTE_COUNT[rid] == 1  # cached

    with Session(engine) as s:  # the run changed (a job re-opened and finished again)
        row = s.get(CbomCollectionRun, rid)
        row.last_updated = row.last_updated + dt.timedelta(seconds=5)
        s.add(row)
        s.commit()
    after = _results(api, rid)
    assert RR.COMPUTE_COUNT[rid] == 2 and after["inputs_digest"] != results[0]["inputs_digest"]

    tomorrow = dt.datetime.utcnow() + dt.timedelta(days=1)
    monkeypatch.setattr(RR, "utcnow", lambda: tomorrow)
    from backend.routers import cbom_sources as router

    monkeypatch.setattr(router, "utcnow", lambda: tomorrow)
    nxt = _results(api, rid)
    assert RR.COMPUTE_COUNT[rid] == 3 and nxt["judged_on"] == tomorrow.date().isoformat()


def test_remediation_status_is_live_not_cached(api, world):
    engine, _ = world
    _src, run, _c, _h = _run_with(api, engine, PROBE)
    first = _results(api, run["id"])["dashboard"]
    actions = first["remediation_actions_required"]
    assert actions["total_findings"] == first["card_data"]["total_crypto_vulnerabilities"] > 0
    assert actions["total_not_started"] == actions["total_findings"] and actions["total_fixed"] == 0
    assert first["remediation_metrics"]["metrics_available"] is False
    items = api("GET", f"/1/cbom/sources/runs/{run['id']}/remediation").json()["items"]
    target = next(i for i in items if i["impact"])
    r = api("PUT", "/1/cbom/remediation", json={"run_id": run["id"], "items": [{"asset_key": target["asset_key"],
                                                                                 "status": "done"}]})
    assert r.status_code == 200, r.text
    again = _results(api, run["id"])["dashboard"]["remediation_actions_required"]
    assert RR.COMPUTE_COUNT[run["id"]] == 1  # the summary stayed cached; the status join did not
    assert again["total_fixed"] == 1 and again["total_not_started"] == actions["total_findings"] - 1


# ----------------------------------------------------------------------------- tenancy and run states
def test_tenancy_another_teams_run_is_404(api, world):
    engine, _ = world
    _src, run, _c, _h = _run_with(api, engine, PROBE[:2])
    assert api("GET", f"/2/cbom/sources/runs/{run['id']}/results", "carol").status_code == 404
    assert api("GET", "/1/cbom/sources/runs/999999/results").status_code == 404
    assert api("GET", f"/2/cbom/sources/runs/{run['id']}/results", "alice").status_code in (401, 403)


def test_empty_run_and_coverage_only_run(api, world):
    engine, _ = world
    _src, run, _c, _h = _run_with(api, engine, [PROBE[-1]])
    out = _results(api, run["id"])
    card = out["dashboard"]["card_data"]
    assert card["total_crypto_assets"] == 0 and card["quantum_readiness_score"] == 0
    assert card["quantum_readiness_judged"] is False and out["distributions"]["pqc"]["readiness_pct"] is None
    assert out["dashboard"]["severity_distribution"] == {"critical": 0, "high": 0, "medium": 0, "low": 0,
                                                         "informational": 0}
    assert out["provenance"][0]["not_collected"] == 1 and out["provenance"][0]["assets"] == 0
    assert out["certificates_orphaned"] == [] and out["dashboard"]["remediation_actions_required"]["total_findings"] == 0
    assert all(f["clauses"] == [] for f in out["compliance"]["frameworks"])


def test_active_run_is_live_and_never_cached(api, world):
    engine, _ = world
    _src, run, _c, _h = _run_with(api, engine, PROBE[:3], finish=False)
    one = _results(api, run["id"])
    two = _results(api, run["id"])
    assert one["state"] == two["state"] == "live" and one["run"]["status"] == "running"
    assert RR.COMPUTE_COUNT[run["id"]] == 2
    assert one["dashboard"]["card_data"]["total_crypto_assets"] == 3


def test_partial_and_cancelled_runs(api, world):
    engine, _ = world
    _src, run, _c, _h = _run_with(api, engine, PROBE, partial=True)
    out = _results(api, run["id"])
    assert out["run"]["status"] == "partial" and out["state"] == "ready"
    assert out["provenance"][0]["outcome"] == "partial"
    assert out["dashboard"]["card_data"]["quantum_readiness_score"] == _posture(engine, run["id"])["pqc_readiness_pct"]

    src2 = api("POST", "/1/cbom/sources/items", json=linux_body(name="linux-b", node_id=_src["node_id"],
                                                                targets=["10.20.0.9"], window="any")).json()["source"]
    created = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True},
                                                        "client_request_id": "cancel-me-000001"})
    assert created.status_code == 201, created.text
    rid = created.json()["run"]["id"]
    assert api("POST", f"/1/cbom/sources/runs/{rid}/cancel").json()["run"]["status"] == "cancelled"
    out = _results(api, rid)
    assert out["state"] == "ready" and out["run"]["status"] == "cancelled"
    assert out["dashboard"]["card_data"]["total_crypto_assets"] == 0
    assert {p["status"] for p in out["provenance"]} == {"cancelled"} and src2["id"]


# ----------------------------------------------------------------------------- PR-5 certificates
def test_orphaned_and_unmanaged_certificates_within_the_run(api, world):
    engine, _ = world
    web, old, pay = _cert("CN=web.bank.local"), _cert("CN=old.bank.local", not_after=PAST), _cert("CN=pay.svc")
    assets = [
        # presented by an endpoint (chain) and stored on disk: not orphaned, not managed
        {"type": "certificate", "target": "10.20.0.1", "location": "10.20.0.1:443#chain[0]", "name": "web",
         "algorithm": "RSA", "key_size": 2048, "facts": web},
        {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/web.pem", "name": "web",
         "algorithm": "RSA", "key_size": 2048, "facts": web},
        # stored, presented by nothing in this run: orphaned (and unmanaged)
        {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/old.pem", "name": "old",
         "algorithm": "RSA", "key_size": 2048, "facts": old},
        # a cert-manager Certificate owns the pay/pay-tls secret: managed, but no endpoint presents it (orphaned)
        {"type": "k8s_certificate", "target": "10.20.0.2", "location": "pay/certificate/pay", "name": "pay/pay",
         "algorithm": "RSA", "key_size": 2048,
         "facts": {"namespace": "pay", "name": "pay", "secret": "pay-tls", "dns_names": ["pay.svc"],
                   "not_after": FUTURE}},
        {"type": "k8s_tls_secret", "target": "10.20.0.2", "location": "pay/secret/pay-tls", "name": "pay/pay-tls",
         "algorithm": "RSA", "key_size": 2048, "facts": {**pay, "namespace": "pay", "secret": "pay-tls"}},
    ]
    _src, run, _c, _h = _run_with(api, engine, assets)
    out = _results(api, run["id"])
    with Session(engine) as s:
        ids = {r.location: r.id for r in s.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.run_id == run["id"])).all()}
    orphaned = {r["asset_id"] for r in out["certificates_orphaned"]}
    unmanaged = {r["asset_id"] for r in out["certificates_unmanaged"]}
    assert orphaned == {ids["/etc/ssl/old.pem"], ids["pay/secret/pay-tls"]}
    assert unmanaged == {ids["10.20.0.1:443#chain[0]"], ids["/etc/ssl/web.pem"], ids["/etc/ssl/old.pem"]}
    assert out["certificates_orphaned_total"] == 2 and out["certificates_unmanaged_total"] == 3
    assert out["certificates_scope"] == "run"
    old_ref = next(r for r in out["certificates_orphaned"] if r["asset_id"] == ids["/etc/ssl/old.pem"])
    assert old_ref["subject"] == "CN=old.bank.local" and old_ref["source"] == "linux-dc"
    certs = out["distributions"]["certificates"]
    assert {c["asset_id"] for c in certs if c["expired"]} == {ids["/etc/ssl/old.pem"]}
    buckets = out["distributions"]["certificate_expiry"]
    assert buckets["expired"] == 1 and sum(buckets.values()) == len(certs)


# ----------------------------------------------------------------------------- bench (5,000 assets)
@pytest.mark.skipif(not os.environ.get("CBOM_BENCH"), reason="bench: set CBOM_BENCH=1 (kept out of CI)")
def test_bench_5000_assets_under_budget(api, world, capsys, monkeypatch):
    """5,001 assets (1,000 of them library rows). Most of the cold time is ``crypto_kb.library_status`` (uncached
    today, CB-19 F-1; memoised by CB-38 PR-1): CBOM_BENCH_LIBCACHE=1 memoises it here to measure that case."""
    engine, _ = world
    if os.environ.get("CBOM_BENCH_LIBCACHE"):
        from functools import lru_cache

        from backend.utilities.cbom_sources import crypto_kb

        cached = lru_cache(maxsize=4096)(lambda package, version, today: crypto_kb.__dict__["_bench_real"](
            package, version, today=today))
        monkeypatch.setitem(crypto_kb.__dict__, "_bench_real", crypto_kb.library_status)
        monkeypatch.setattr(crypto_kb, "library_status",
                            lambda package, version, *, today=None: cached(package, version, today))
    _src, run, claim, _hdr = _run_with(api, engine, PROBE[:1])
    rid, job_id = run["id"], claim["job"]["id"]
    kinds = [
        ("tls_endpoint", "protocol", {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}, None, True, "High",
         ["QUANTUM_VULNERABLE", "PROTO_TLS10"]),
        ("certificate", "certificate", _cert("CN=bench"), "RSA", True, None, ["QUANTUM_VULNERABLE"]),
        ("crypto_library", "library", {"name": "openssl", "version": "3.0.2-0ubuntu1.15"}, None, None, "Medium",
         ["LIB_EOL"]),
        ("kms_key", "related-crypto-material", {"key_spec": "SYMMETRIC_DEFAULT"}, "AES", False, None, []),
        ("ssh_host_key", "related-crypto-material", {"bits": 2048}, "RSA", True, None, ["QUANTUM_VULNERABLE"]),
    ]
    with Session(engine) as s:
        team_source = s.get(CbomCollectionJob, job_id).source_id
        for i in range(5_000):
            a_type, cdx, facts, alg, qv, impact, codes = kinds[i % len(kinds)]
            facts = dict(facts)
            if a_type == "certificate":
                facts["subject"] = f"CN=bench-{i}"
            s.add(CbomCollectedAsset(team_id=1, run_id=rid, job_id=job_id, source_id=team_source, attempt=1,
                                     asset_key=f"bench-{i}", asset_type=a_type, cdx_type=cdx, target=f"10.30.{i // 250}.{i % 250}",
                                     location=f"10.30.{i // 250}.{i % 250}:{443 + i % 3}/{i}", name=f"bench-{i}",
                                     algorithm=alg, key_size=2048 if alg == "RSA" else None, quantum_vulnerable=qv,
                                     impact=impact, finding_codes=codes, facts=facts))
        s.commit()
    started = time.perf_counter()
    out = _results(api, rid)
    cold_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    _results(api, rid)
    warm_ms = (time.perf_counter() - started) * 1000
    assert out["dashboard"]["card_data"]["total_crypto_assets"] == 5_001
    assert out["dashboard"]["card_data"]["total_crypto_assets"] == _posture(engine, rid)["assets"]
    assert len(out["distributions"]["certificates"]) == 1_000 and len(out["distributions"]["pqc"]["migration"]) == 2_000
    assert out["distributions"]["pqc"]["migration_truncated"] is True
    with capsys.disabled():
        print(f"\nBENCH run results 5001 assets: cold {cold_ms:.0f} ms, cached {warm_ms:.0f} ms")
    assert cold_ms < 10_000 and warm_ms < cold_ms
