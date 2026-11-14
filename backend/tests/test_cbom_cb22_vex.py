"""CB-22 VEX semantics (KF-11): the analysis state of every CBOM finding follows what it rests on.

* a weakness a collector observed -> ``exploitable``; a quantum-future code -> ``in_triage`` citing the assets'
  Q-grade; a version/date inference or a CVE match -> ``in_triage``; a finding drift resolved -> ``resolved``;
* the Sources run export (``inventory.vulnerabilities``) and the code-scan VEX (``routers/certin.py``) use the one rule
  set (``cbom_sources.vex_semantics``) and validate against the published CycloneDX 1.6.2 schema (CB-06 oracle);
* ``affects`` is complete or says it was cut, with the true count (R2 ``vexcap``);
* the run export is still written one component at a time (#103).

Uses the same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support.cyclonedx_schema import all_bom_refs, all_references, json_errors, xml_errors  # noqa: E402
from test_cbom_posture import ASSETS, _store  # noqa: E402
from test_cbom_sources_api import _collect_job, api, enroll_node, linux_body, world  # noqa: E402,F401  (fixtures)
from test_cbom_wp10_outputs import FIXED_TLS, WEAK_TLS, _claim, _collect, _row, _run  # noqa: E402

from backend.new_models import CbomCollectedAsset, CbomCollectionRun, CbomDriftEvent, Scan  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources import vex_semantics as VEX  # noqa: E402

SCHEMA = json.loads((Path(__file__).resolve().parent / "fixtures/cyclonedx-1.6.2/bom-1.6.schema.json").read_text())
STATES = set(SCHEMA["definitions"]["impactAnalysisState"]["enum"])
RESPONSES = set(SCHEMA["definitions"]["vulnerability"]["properties"]["analysis"]["properties"]["response"]["items"]["enum"])
FUTURE_RISK = {"QUANTUM_VULNERABLE", "NO_PQ_KEX", "SSH_NO_PQ_KEX"}  # OA-10c's three, named by the DA

PQ_ASSETS = [  # a classical-only TLS endpoint (no PQ group) and an SSH server without a PQ key exchange
    {"type": "tls_endpoint", "target": "10.20.0.4", "location": "10.20.0.4:443",
     "facts": {"protocols": ["TLSv1.3"], "group": "x25519", "internet_facing": True}},
    {"type": "ssh_endpoint", "target": "10.20.0.4", "location": "10.20.0.4:22",
     "facts": {"kex": ["curve25519-sha256"], "host_key_algorithms": ["ssh-ed25519"], "ciphers": ["aes256-gcm@openssh.com"],
               "macs": ["hmac-sha2-256-etm@openssh.com"]}},
]


def _vulns(doc):
    return {v["bom-ref"]: v for v in doc["vulnerabilities"]}


def _props(entry):
    return {p["name"]: p["value"] for p in entry.get("properties") or []}


def _code(entry):
    return entry["id"].removeprefix("ZS-CBOM-")


# ----------------------------------------------------------------------------- the rule, per code family
@pytest.mark.parametrize("code,basis,state", [
    ("PROTO_TLS10", "observed", "exploitable"),     # TLS 1.0 accepted (DA example)
    ("CERT_EXPIRED", "observed", "exploitable"),    # expired (DA example)
    ("RSA_LT_2048", "observed", "exploitable"),     # RSA < 2048 (DA example), quantum-broken too but weak today
    ("SECRET_IN_CONFIG", "observed", "exploitable"),
    ("QUANTUM_VULNERABLE", "quantum_only", "in_triage"),
    ("NO_PQ_KEX", "quantum_only", "in_triage"),
    ("SSH_NO_PQ_KEX", "quantum_only", "in_triage"),
    ("IKE_NO_PQ", "quantum_only", "in_triage"),
    ("DISK_XTS_128", "quantum_only", "in_triage"),  # grover-weakened: no classical attack
    ("LIB_EOL", "inferred", "in_triage"),
    ("LIB_KNOWN_CVE", "inferred", "in_triage"),
    ("DB_EOL_VERSION", "inferred", "in_triage"),
])
def test_node_code_families_get_their_state(code, basis, state):
    assert VEX.code_basis(code, "node") == basis
    analysis = VEX.analysis_for(basis, code=code)
    assert analysis["state"] == state and analysis["state"] in STATES and analysis["detail"]


@pytest.mark.parametrize("code,basis", [
    ("WEAK_ALGORITHM", "static"), ("HARDCODED_KEY", "static"), ("QUANTUM_VULNERABLE", "quantum_only"),
    ("VULNERABLE_CRYPTO_LIBRARY", "inferred"), ("EOL_CRYPTO_LIBRARY", "inferred"),
])
def test_code_scan_families_are_in_triage_with_their_reason(code, basis):
    assert VEX.code_basis(code, "code") == basis
    assert VEX.analysis_for(basis, code=code)["state"] == "in_triage"


def test_every_kb_code_has_a_basis_and_no_quantum_only_code_is_exploitable():
    findings = crypto_kb.load()["findings"]
    for namespace in ("node", "code"):
        for code, entry in findings[namespace].items():
            basis = VEX.code_basis(code, namespace)
            state = VEX.analysis_for(basis, code=code)["state"]
            assert state in STATES
            if entry.get("category") == "pqc" or entry.get("pqc") == "grover-weakened":
                assert (basis, state) == ("quantum_only", "in_triage"), (namespace, code)
            if namespace == "code":
                assert state != "exploitable", code  # a code scan does not observe the running system
    assert FUTURE_RISK <= {c for c in findings["node"] if VEX.code_basis(c) == "quantum_only"}


def test_quantum_detail_names_hndl_for_key_exchange_and_the_q_grades():
    kex = VEX.analysis_for("quantum_only", code="NO_PQ_KEX", q_grades={"Q1": 2, "Q3": 1, None: 1})
    assert "harvest now, decrypt later" in kex["detail"]
    assert "Q1 Critical 2" in kex["detail"] and "Q3 Medium 1" in kex["detail"] and "not graded 1" in kex["detail"]
    assert "forge" in VEX.analysis_for("quantum_only", code="DISK_XTS_128")["detail"]


@pytest.mark.parametrize("status,state,response", [
    ("done", "resolved", None), ("accepted_risk", "exploitable", ["will_not_fix"]),
    ("in_progress", "exploitable", ["update"]), (None, "exploitable", None),
])
def test_remediation_status_maps_to_state_and_response(status, state, response):
    analysis = VEX.analysis_for("observed", status=status)
    assert analysis["state"] == state and analysis.get("response") == response
    assert set(analysis.get("response") or []) <= RESPONSES
    quantum = VEX.analysis_for("quantum_only", status=status, code="NO_PQ_KEX")
    assert quantum["state"] == ("resolved" if status == "done" else "in_triage")


def test_affects_cut_says_so_with_the_true_count():
    assert VEX.affects_cut(5000, 5000) == []
    cut = {p["name"]: p["value"] for p in VEX.affects_cut(5000, 5100)}
    assert cut == {"zs:affected_truncated": "true", "zs:affected_total": "5100", "zs:affects_cap": "5000"}


# ----------------------------------------------------------------------------- the Sources run export
@pytest.fixture()
def run_export(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS + PQ_ASSETS)
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom")
    assert r.status_code == 200, r.text
    x = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=xml")
    assert x.status_code == 200, x.text
    items = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?page_size=200").json()["items"]
    return {"doc": r.json(), "xml": x.content, "items": items, "run": run, "engine": engine}


def test_kf11_export_states_follow_the_finding_not_exploitable_everywhere(run_export):
    doc = run_export["doc"]
    states = {}
    for v in doc["vulnerabilities"]:
        p = _props(v)
        basis = p["zs:vex_basis"]
        assert v["analysis"]["state"] == VEX.DEFAULT_STATE[basis], v["id"]
        if v["id"].startswith("ZS-CBOM-"):
            assert basis == VEX.code_basis(_code(v)), v["id"]
            states[_code(v)] = v["analysis"]["state"]
        else:
            assert basis == "cve" and v["analysis"]["state"] == "in_triage"
    assert states["PROTO_TLS10"] == states["WEAK_CIPHER"] == states["SIG_MD5"] == "exploitable"
    assert states["LIB_EOL"] == "in_triage"
    future = {c for c in states if c in FUTURE_RISK}
    assert future == FUTURE_RISK, states  # the run has all three future-risk codes to judge
    assert all(states[c] == "in_triage" for c in future)
    assert set(states.values()) >= {"exploitable", "in_triage"}  # KF-11: not one state for everything
    assert {"name": "zs:vex_rules", "value": VEX.VEX_RULES} in doc["metadata"]["properties"]


def test_no_quantum_future_only_finding_is_exploitable(run_export):
    for v in run_export["doc"]["vulnerabilities"]:
        if v["id"].startswith("ZS-CBOM-") and VEX.code_basis(_code(v)) == "quantum_only":
            assert v["analysis"]["state"] == "in_triage", v["id"]
            assert "Quantum-only exposure" in v["analysis"]["detail"]


def test_quantum_detail_carries_the_q_grades_the_run_api_gives(run_export):
    by_id = {f"zs-asset-{a['id']}": a for a in run_export["items"]}
    checked = 0
    for v in run_export["doc"]["vulnerabilities"]:
        if not v["id"].startswith("ZS-CBOM-") or VEX.code_basis(_code(v)) != "quantum_only":
            continue
        want: dict[str, int] = {}
        for a in v["affects"]:
            grade = by_id[a["ref"]]["q_grade"] or "none"
            want[grade] = want.get(grade, 0) + 1
        p = _props(v)
        assert json.loads(p["zs:q_grades"]) == want, v["id"]
        assert p["zs:grade_model_version"] and p["zs:grade_inputs_digest"]
        for grade, n in want.items():
            assert (f"{grade} " if grade != "none" else "not graded ") in v["analysis"]["detail"]
            assert f" {n}" in v["analysis"]["detail"]
        checked += 1
    assert checked >= 2


def test_export_with_vex_is_valid_json_and_xml_and_every_reference_resolves(run_export):
    doc = run_export["doc"]
    assert json_errors(doc) == []
    assert xml_errors(run_export["xml"]) == []
    refs = all_bom_refs(doc)
    assert len(refs) == len(set(refs))
    assert not [r for _w, r in all_references(doc) if r not in set(refs)]
    from backend.utilities.cbom_sources.cdx_xml import to_xml

    to_xml(doc, strict=True)  # every VEX key has a place in the XML


def test_affects_over_the_cap_is_marked_with_the_true_count(api, world, monkeypatch):
    """R2 vexcap (5,100 assets -> 5,000 in affects, truncated=false) at a cap of 2."""
    from backend.utilities.cbom_sources import inventory

    engine, _ = world
    _src, run = _store(api, engine, [{**PQ_ASSETS[0], "target": f"10.30.0.{i}", "location": f"10.30.0.{i}:443"}
                                     for i in range(1, 6)])
    monkeypatch.setattr(VEX, "AFFECTS_CAP", 2)
    doc = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    for v in doc["vulnerabilities"]:
        assert len(v["affects"]) == 2
        p = _props(v)
        assert p["zs:affected_truncated"] == "true" and p["zs:affects_cap"] == "2"
        assert p["zs:affected_total"] == "5"
    assert json_errors(doc) == [] and inventory.EXPORT_CAP == 50_000


def test_vexcap_at_the_real_size_lists_5000_and_counts_5100():
    from backend.utilities.cbom_sources import inventory
    from backend.utilities.cbom_sources.classify import shown

    now = dt.datetime(2026, 11, 14)
    from backend.utilities.cbom_sources.classify import classify

    facts = {"protocols": ["TLSv1.3"], "group": "x25519"}
    verdict = classify("tls_endpoint", None, None, None, facts, now)
    assert verdict["finding_codes"] == ["NO_PQ_KEX"]
    rows = [CbomCollectedAsset(id=i, team_id=1, run_id=1, job_id=1, asset_type="tls_endpoint", target=f"h{i}",
                               location=f"h{i}:443", asset_key=f"k{i}", created_at=now, facts=facts,
                               finding_codes=verdict["finding_codes"], impact=verdict["impact"],
                               quantum_vulnerable=verdict["quantum_vulnerable"], finding=verdict["finding"])
            for i in range(1, 5101)]
    view = shown(rows[0], now)
    vulns = inventory.vulnerabilities(rows, {r.id: view for r in rows}, grade_of=lambda _r: "Q2")
    entry = next(v for v in vulns if v["id"] == "ZS-CBOM-NO_PQ_KEX")
    p = _props(entry)
    assert len(entry["affects"]) == 5000 and p["zs:affected_total"] == "5100" and p["zs:affected_truncated"] == "true"
    assert json.loads(p["zs:q_grades"]) == {"Q2": 5100}  # graded over every asset, not only the listed ones
    assert entry["analysis"]["state"] == "in_triage" and "Q2 High 5100" in entry["analysis"]["detail"]


@pytest.fixture()
def drift_runs(api, world):
    """Source A complete twice: run 1 has two weak TLS endpoints, run 2 the first one fixed and the second gone.
    Source B complete, then partial (a target unreachable): never compared, so nothing of it is resolved."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    for name, target in (("src-a", "10.20.0.1"), ("src-b", "10.20.0.2")):
        api("POST", "/1/cbom/sources/items", json=linux_body(name, node_id=node_id, targets=[target], window="any"))
    other = {**WEAK_TLS, "location": "10.20.0.1:8443"}
    b_tls = {**WEAK_TLS, "target": "10.20.0.2", "location": "10.20.0.2:443"}
    run1 = _run(api, "cb22-run-0001")
    _collect(api, hdr, _claim(api, hdr), [WEAK_TLS, other])
    _collect(api, hdr, _claim(api, hdr), [b_tls])
    run2 = _run(api, "cb22-run-0002")
    _collect(api, hdr, _claim(api, hdr), [FIXED_TLS])
    _collect(api, hdr, _claim(api, hdr), [], ok=0, failed=1)
    assert api("GET", f"/1/cbom/sources/runs/{run2['id']}/changes").json()["recorded"] is True
    return {"run1": run1, "run2": run2, "engine": engine}


def test_drift_resolved_findings_are_resolved_and_point_at_assets_still_listed(api, drift_runs):
    run1, run2 = drift_runs["run1"], drift_runs["run2"]
    doc = api("GET", f"/1/cbom/sources/runs/{run2['id']}/cbom").json()
    resolved = {_code(v): v for v in doc["vulnerabilities"] if v["analysis"]["state"] == "resolved"}
    assert {"PROTO_TLS10", "WEAK_CIPHER"} <= set(resolved), sorted(resolved)
    comps = {c["bom-ref"]: c for c in doc["components"]}
    tls = resolved["PROTO_TLS10"]
    # the fixed endpoint is still collected: referenced; the :8443 endpoint is gone: counted and named by its stable
    # key, never a reference that would not resolve; source B (partial, not compared) adds nothing
    assert [_props_of(comps[a["ref"]])["zs:location"] for a in tls["affects"]] == ["10.20.0.1:443"]
    p = _props(tls)
    assert p["zs:vex_basis"] == "drift_resolved" and p["zs:baseline_run_id"] == str(run1["id"])
    assert p["zs:resolved_assets_not_listed"] == "1" and len(p["zs:resolved_asset_key"]) == 40
    assert "not read" in tls["analysis"]["detail"]
    with Session(drift_runs["engine"]) as s:
        keys = {e.asset_key for e in s.exec(select(CbomDriftEvent).where(CbomDriftEvent.run_id == run2["id"],
                                                                          CbomDriftEvent.kind == "resolved")).all()}
    assert p["zs:resolved_asset_key"] in keys
    refs = all_bom_refs(doc)
    assert len(refs) == len(set(refs)) and not [r for _w, r in all_references(doc) if r not in set(refs)]
    assert json_errors(doc) == []
    assert xml_errors(api("GET", f"/1/cbom/sources/runs/{run2['id']}/cbom?format=xml").content) == []
    first = api("GET", f"/1/cbom/sources/runs/{run1['id']}/cbom").json()  # the baseline resolved nothing
    assert not [v for v in first["vulnerabilities"] if v["analysis"]["state"] == "resolved"]


def _props_of(component):
    return {p["name"]: p["value"] for p in component.get("properties") or []}


def test_the_export_is_still_written_one_component_at_a_time(api, world, monkeypatch):
    """#103: the VEX inputs (grades, drift) are read only after every component is written, and the output already
    holds the components when they are."""
    from backend.utilities.cbom_sources import inventory

    engine, _ = world
    _src, run = _store(api, engine, ASSETS + PQ_ASSETS)
    seen = []
    real = inventory._vex_inputs

    def spy(*a, **kw):
        seen.append(out.tell())
        return real(*a, **kw)

    monkeypatch.setattr(inventory, "_vex_inputs", spy)
    for fmt in ("json", "xml"):
        out = io.BytesIO()
        with Session(engine) as s:
            inventory.write_cyclonedx(s, s.get(CbomCollectionRun, run["id"]), dt.datetime.utcnow(), fmt, out)
        body = out.getvalue()
        components_end = body.rindex(b'],"vulnerabilities"') if fmt == "json" else body.index(b"</components>")
        assert seen[-1] >= components_end > 0  # vulnerabilities (and their inputs) come after the components
    assert len(seen) == 2


# ----------------------------------------------------------------------------- code scans
@pytest.fixture()
def certin_db(world, monkeypatch):
    from backend.routers import certin

    engine, ids = world
    monkeypatch.setattr(certin, "get_db", lambda: engine)
    certin.read_limiter.requests.clear()
    certin.write_limiter.requests.clear()
    return engine, ids


def test_code_scan_vex_states_drift_resolved_and_schema(api, certin_db):
    engine, ids = certin_db
    meta = {"repo_url": "https://github.com/acme/vex", "branch": "main"}
    des = _row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"], cves=["CVE-2016-2183"])
    md5 = _row("MD5", "hash.py", ["WEAK_ALGORITHM"])
    rsa = _row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low", quantum_safe=False)
    aes = _row("AES-256-GCM", "app.py", [], quantum_safe=True)
    with Session(engine) as s:
        s.add(Scan(id=60, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="vex", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 1), scan_data={"results": [des, md5, rsa]}))
        s.add(Scan(id=61, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="vex", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 2),
                   # 3DES still listed without its finding; MD5 gone; a stale VEX of rules 2 stored
                   scan_data={"results": [{**des, "finding_codes": [], "impact": None, "cves": []}, rsa, aes],
                              "vex_json": {"metadata": {"properties": [{"name": "zs:vex_rules", "value": "2"}]},
                                           "vulnerabilities": []}}))
        s.commit()
        DRIFT.record_code_scan_drift(s, s.get(Scan, 61), dt.datetime(2026, 10, 2, 12))
        s.commit()
        assert {e.code for e in s.exec(select(CbomDriftEvent).where(CbomDriftEvent.scan_id == 61,
                                                                   CbomDriftEvent.kind == "resolved")).all()} == {
            "WEAK_ALGORITHM"}
    from backend.utilities.dashboard.scan_metadata import get_scan_metadata

    def metadata_vex(scan_id):
        with Session(engine) as s:
            return get_scan_metadata("cbom", s.get(Scan, scan_id))["vex_json"]

    assert metadata_vex(61) is None  # the stale VEX is not served from metadata: the page fetches /vex
    r = api("GET", "/1/cbom/scan/61/vex")
    assert r.status_code == 200, r.text
    vex = r.json()
    assert {"name": "zs:vex_rules", "value": VEX.VEX_RULES} in vex["metadata"]["properties"]
    by = {(v["id"], v["analysis"]["state"]): v for v in vex["vulnerabilities"]}
    quantum = by[("ZS-CBOM-QUANTUM_VULNERABLE", "in_triage")]
    assert "Quantum-only exposure" in quantum["analysis"]["detail"] and "Q-grade" in quantum["analysis"]["detail"]
    fixed = by[("ZS-CBOM-WEAK_ALGORITHM", "resolved")]
    assert fixed["affects"] == [{"ref": des["bom_ref"]}]  # still listed, finding gone
    assert _props(fixed)["zs:resolved_assets_not_listed"] == "1" and _props(fixed)["zs:baseline_scan_id"] == "60"
    assert not any(v["analysis"]["state"] == "exploitable" for v in vex["vulnerabilities"])
    assert json_errors(vex) == []
    assert metadata_vex(61) == vex  # rebuilt and stored: served from metadata from now on

    old = api("GET", "/1/cbom/scan/60/vex").json()  # the baseline: weak algorithm in triage, CVE in triage
    states = {(v["id"], v["analysis"]["state"]) for v in old["vulnerabilities"]}
    assert ("ZS-CBOM-WEAK_ALGORITHM", "in_triage") in states and ("CVE-2016-2183", "in_triage") in states
    assert json_errors(old) == []


def test_code_scan_vex_is_one_rule_set_with_the_export():
    findings = [_row("RSA-2048", "k.py", ["QUANTUM_VULNERABLE"]), _row("AES", "a.py", [])]
    vex = VEX.code_scan_vex(findings)
    q = next(v for v in vex["vulnerabilities"] if v["id"] == "ZS-CBOM-QUANTUM_VULNERABLE")
    assert q["analysis"] == VEX.analysis_for("quantum_only", code="QUANTUM_VULNERABLE", grade_text=VEX.CODE_SCAN_GRADE)
    stub = next(v for v in vex["vulnerabilities"] if v["analysis"]["state"] == "not_affected")
    assert stub["affects"] == [{"ref": findings[1]["bom_ref"]}]  # CERT-In F5 "no weakness found" kept
    assert json_errors(vex) == []
