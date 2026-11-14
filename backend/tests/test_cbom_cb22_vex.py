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
ROOT = Path(__file__).resolve().parents[2]
TABLE = json.loads((ROOT / "scripts/crypto_kb/sources/vex_default.json").read_text())


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
    # hygiene / operational codes: no attack on the asset as observed (review of #134, finding 2)
    ("CERT_UNUSED", "posture", "in_triage"), ("CERT_EXPIRES_30D", "posture", "in_triage"),
    ("KMS_PENDING_DELETION", "posture", "in_triage"), ("KEY_NO_ROTATION", "posture", "in_triage"),
    ("CERT_SELF_SHA1", "posture", "in_triage"), ("KMS_NO_ROTATION", "posture", "in_triage"),
    ("SECRET_NO_ROTATION", "posture", "in_triage"), ("KV_SOFT_DELETE_OFF", "posture", "in_triage"),
    ("LIB_STATIC", "posture", "in_triage"), ("KEYSTORE_JKS", "posture", "in_triage"),
    ("SSH_HMAC_SHA1", "posture", "in_triage"),
])
def test_node_code_families_get_their_state(code, basis, state):
    assert VEX.code_basis(code, "node") == basis
    analysis = VEX.analysis_for(basis, code=code)
    assert analysis["state"] == state and analysis["state"] in STATES and analysis["detail"]
    if basis == "posture":
        assert TABLE["node"][code]["reason"] in analysis["detail"]  # the reviewed reason, not a generic claim


@pytest.mark.parametrize("code,basis", [
    ("WEAK_ALGORITHM", "static"), ("HARDCODED_KEY", "static"), ("QUANTUM_VULNERABLE", "quantum_only"),
    ("VULNERABLE_CRYPTO_LIBRARY", "inferred"), ("EOL_CRYPTO_LIBRARY", "inferred"), ("CERT_NEAR_EXPIRY", "posture"),
])
def test_code_scan_families_are_in_triage_with_their_reason(code, basis):
    assert VEX.code_basis(code, "code") == basis
    assert VEX.analysis_for(basis, code=code, namespace="code")["state"] == "in_triage"


def test_every_kb_code_has_a_reviewed_vex_default_and_no_quantum_only_code_is_exploitable():
    """Guard: a new KB code without a reviewed row fails here (and build_kb.py refuses to build it)."""
    findings = crypto_kb.load()["findings"]
    for namespace in ("node", "code"):
        assert set(TABLE[namespace]) == set(findings[namespace]), namespace
        for code, entry in findings[namespace].items():
            row = TABLE[namespace][code]
            assert entry["vex_default"] == {"basis": row["basis"], "reason": row["reason"]}, (namespace, code)
            assert row["reason"].strip() and row["sources"], (namespace, code)
            basis = VEX.code_basis(code, namespace)
            assert basis == row["basis"] and basis in VEX.KB_BASES
            state = VEX.analysis_for(basis, code=code, namespace=namespace)["state"]
            assert state in STATES
            if entry.get("category") == "pqc" or entry.get("pqc") == "grover-weakened":
                assert (basis, state) == ("quantum_only", "in_triage"), (namespace, code)
            if namespace == "code":
                assert state != "exploitable", code  # a code scan does not observe the running system
    assert FUTURE_RISK <= {c for c in findings["node"] if VEX.code_basis(c) == "quantum_only"}


def test_a_code_without_a_reviewed_default_is_never_exploitable(monkeypatch):
    entry = {k: v for k, v in crypto_kb.entry("node", "PROTO_TLS10").items() if k != "vex_default"}
    monkeypatch.setattr(crypto_kb, "entry", lambda ns, code: entry if code == "PROTO_TLS10" else None)
    assert VEX.code_basis("PROTO_TLS10") == "unreviewed"
    assert VEX.analysis_for("unreviewed")["state"] == "in_triage"
    assert VEX.code_basis("NOT_A_CODE") == "unreviewed"


def test_every_cve_a_code_maps_to_has_a_reviewed_inherent_flag():
    kb = crypto_kb.load()
    mapped = {cid for ns in ("node", "code") for e in kb["findings"][ns].values()
              for cid in list(e.get("cves") or []) + [c for r in e.get("cve_rules") or [] for c in r["cves"]]}
    assert set(TABLE["cves"]) == mapped
    for cid in mapped:
        assert kb["cves"][cid]["vex_inherent"] is TABLE["cves"][cid]["inherent"]
    assert VEX.cve_inherent("CVE-2016-2183") and not VEX.cve_inherent("CVE-2013-0169")  # SWEET32 vs Lucky13
    assert VEX.cve_basis("CVE-2016-2183", ["WEAK_CIPHER"]) == ("observed", "WEAK_CIPHER")
    assert VEX.cve_basis("CVE-2013-0169", ["CBC_ONLY"]) == ("cve", None)  # implementation-specific: triage
    assert VEX.cve_basis("CVE-2023-48795", ["SSH_CBC_CIPHER"]) == ("cve", None)  # Terrapin
    assert VEX.cve_basis("CVE-2022-3602", ["LIB_KNOWN_CVE"]) == ("cve", None)  # library range


def test_quantum_detail_names_hndl_for_key_exchange_and_the_q_grades():
    kex = VEX.analysis_for("quantum_only", code="NO_PQ_KEX", q_grades={"Q1": 2, "Q3": 1, None: 1})
    assert "harvest now, decrypt later" in kex["detail"]
    assert "Q1 Critical 2" in kex["detail"] and "Q3 Medium 1" in kex["detail"] and "not graded 1" in kex["detail"]
    assert "forge" in VEX.analysis_for("quantum_only", code="DISK_XTS_128")["detail"]


COLLECTED = dt.datetime(2026, 11, 10, 9, 0)


@pytest.mark.parametrize("status,changed,basis,state,response", [
    ("done", COLLECTED + dt.timedelta(days=1), "observed", "resolved", None),     # fixed after the run collected it
    ("done", COLLECTED - dt.timedelta(days=1), "observed", "exploitable", ["update"]),  # done, but still observed
    ("done", None, "observed", "exploitable", ["update"]),                         # no timing: not confirmed
    ("done", COLLECTED + dt.timedelta(days=1), "quantum_only", "resolved", None),
    ("accepted_risk", None, "observed", "exploitable", ["will_not_fix"]),
    ("accepted_risk", None, "quantum_only", "in_triage", ["will_not_fix"]),  # decided, still no classical attack
    ("in_progress", None, "observed", "exploitable", ["update"]),
    (None, None, "observed", "exploitable", None),
])
def test_remediation_status_maps_to_state_and_response(status, changed, basis, state, response):
    analysis = VEX.analysis_for(basis, status=status, code="NO_PQ_KEX" if basis == "quantum_only" else None,
                                plan_changed_at=changed, collected_at=COLLECTED)
    assert analysis["state"] == state and analysis.get("response") == response
    assert set(analysis.get("response") or []) <= RESPONSES and analysis["state"] in STATES
    if status == "done" and state != "resolved":
        assert "not confirmed" in analysis["detail"]
    # the overlay never re-judges: an export entry's evidence analysis is kept, only the plan is added
    resolved = VEX.analysis_for("drift_resolved")
    assert VEX.apply_plan_status(resolved, status, plan_changed_at=changed, collected_at=COLLECTED) == resolved


def test_affects_cut_says_so_with_the_true_count():
    assert VEX.affects_cut(5000, 5000) == []
    cut = {p["name"]: p["value"] for p in VEX.affects_cut(5000, 5100)}
    assert cut == {"zs:affected_truncated": "true", "zs:affected_total": "5100", "zs:affects_cap": "5000"}


# ----------------------------------------------------------------------------- the Sources run export
@pytest.fixture()
def run_export(api, world):  # noqa: F811
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
            assert basis in ("cve", "observed")
    assert states["PROTO_TLS10"] == states["WEAK_CIPHER"] == states["SIG_MD5"] == "exploitable"
    assert states["LIB_EOL"] == states["CERT_SELF_SIGNED"] == states["KMS_NO_ROTATION"] == "in_triage"
    future = {c for c in states if c in FUTURE_RISK}
    assert future == FUTURE_RISK, states  # the run has all three future-risk codes to judge
    assert all(states[c] == "in_triage" for c in future)
    assert set(states.values()) >= {"exploitable", "in_triage"}  # KF-11: not one state for everything
    assert {"name": "zs:vex_rules", "value": VEX.VEX_RULES} in doc["metadata"]["properties"]


def test_a_cve_from_an_observed_code_is_never_weaker_than_that_code_unless_implementation_specific(run_export):
    """Review of #134, finding 1: SWEET32 / RC4 / MD5 collisions matched from a cipher or signature the collector
    observed are exploitable on that asset; a library-range CVE and an implementation flaw stay in triage."""
    doc = run_export["doc"]
    code_state: dict[tuple[str, str], str] = {}
    for v in doc["vulnerabilities"]:
        if v["id"].startswith("ZS-CBOM-"):
            for a in v["affects"]:
                code_state[(a["ref"], _code(v))] = v["analysis"]["state"]
    by_asset: dict[tuple[str, str], str] = {}
    for v in doc["vulnerabilities"]:
        if v["id"].startswith("CVE-"):
            for a in v["affects"]:
                by_asset[(v["id"], a["ref"])] = v["analysis"]["state"]
    assert by_asset[("CVE-2016-2183", next(r for (r, c) in code_state if c == "WEAK_CIPHER"))] == "exploitable"
    assert {s for (cid, _r), s in by_asset.items() if cid in ("CVE-2013-2566", "CVE-2015-2808", "CVE-2004-2761")} \
        == {"exploitable"}
    assert by_asset[("CVE-2022-3602", next(r for (r, c) in code_state if c == "LIB_KNOWN_CVE"))] == "in_triage"
    for v in doc["vulnerabilities"]:
        if not v["id"].startswith("CVE-"):
            continue
        for a in v["affects"]:
            for (ref, code), state in code_state.items():
                if ref != a["ref"] or state != "exploitable":
                    continue
                matched = {c["id"] for c in crypto_kb.cves_for("node", code, "")} | {
                    c for r in (crypto_kb.entry("node", code) or {}).get("cve_rules") or [] for c in r["cves"]}
                if v["id"] in matched and VEX.cve_inherent(v["id"]) and v["id"] in v["analysis"]["detail"]:
                    assert v["analysis"]["state"] == "exploitable", (v["id"], code)
        if v["analysis"]["state"] == "exploitable":
            assert VEX.cve_inherent(v["id"]) and "is a flaw of that algorithm or protocol" in v["analysis"]["detail"]
    assert json_errors(doc) == []


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


def test_affects_over_the_cap_is_marked_with_the_true_count(api, world, monkeypatch):  # noqa: F811
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
def drift_runs(api, world):  # noqa: F811
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
    return {"run1": run1, "run2": run2, "engine": engine}


def _record_drift(api, run):  # noqa: F811
    assert api("GET", f"/1/cbom/sources/runs/{run['id']}/changes").json()["recorded"] is True


def test_drift_resolved_findings_are_resolved_and_point_at_assets_still_listed(api, drift_runs):  # noqa: F811
    run1, run2 = drift_runs["run1"], drift_runs["run2"]
    before = api("GET", f"/1/cbom/sources/runs/{run2['id']}/cbom").json()
    meta = {p["name"]: p["value"] for p in before["metadata"]["properties"]}
    assert before["version"] == 1 and meta["zs:drift_recorded"] == "false"  # drift not recorded yet
    assert not [v for v in before["vulnerabilities"] if v["analysis"]["state"] == "resolved"]
    _record_drift(api, run1)
    _record_drift(api, run2)
    doc = api("GET", f"/1/cbom/sources/runs/{run2['id']}/cbom").json()
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    # content added after the run finished: same serial (same run, KB, day), next version, and it says when
    assert doc["serialNumber"] == before["serialNumber"] and doc["version"] == 2 and meta["zs:drift_recorded"] != "false"
    resolved = {_code(v): v for v in doc["vulnerabilities"] if v["analysis"]["state"] == "resolved"}
    assert {"PROTO_TLS10", "WEAK_CIPHER"} <= set(resolved), sorted(resolved)
    comps = {c["bom-ref"]: c for c in doc["components"]}
    tls = resolved["PROTO_TLS10"]
    local = [a["ref"] for a in tls["affects"] if not a["ref"].startswith("urn:cdx:")]
    links = [a["ref"] for a in tls["affects"] if a["ref"].startswith("urn:cdx:")]
    # the fixed endpoint is still collected: a local reference; the :8443 endpoint is gone: a BOM-Link to its
    # component in the baseline run's export, plus its stable key; source B (partial, not compared) adds nothing
    assert [_props_of(comps[r])["zs:location"] for r in local] == ["10.20.0.1:443"]
    base = api("GET", f"/1/cbom/sources/runs/{run1['id']}/cbom").json()
    base_comps = {c["bom-ref"]: c for c in base["components"]}
    assert len(links) == 1
    serial, rest = links[0].removeprefix("urn:cdx:").split("/", 1)
    version, ref = rest.split("#", 1)
    assert f"urn:uuid:{serial}" == base["serialNumber"] and int(version) == base["version"]
    assert _props_of(base_comps[ref])["zs:location"] == "10.20.0.1:8443"
    p = _props(tls)
    assert p["zs:vex_basis"] == "drift_resolved" and p["zs:baseline_run_id"] == str(run1["id"])
    assert p["zs:resolved_assets_not_listed"] == "1" and len(p["zs:resolved_asset_key"]) == 40
    assert "not read" in tls["analysis"]["detail"] and "zs:resolved_truncated" not in p
    with Session(drift_runs["engine"]) as s:
        keys = {e.asset_key for e in s.exec(select(CbomDriftEvent).where(CbomDriftEvent.run_id == run2["id"],
                                                                          CbomDriftEvent.kind == "resolved")).all()}
    assert p["zs:resolved_asset_key"] in keys
    refs = all_bom_refs(doc)
    assert len(refs) == len(set(refs))
    assert not [r for _w, r in all_references(doc) if r not in set(refs) and not r.startswith("urn:cdx:")]
    assert json_errors(doc) == []
    assert xml_errors(api("GET", f"/1/cbom/sources/runs/{run2['id']}/cbom?format=xml").content) == []
    assert not [v for v in base["vulnerabilities"] if v["analysis"]["state"] == "resolved"]  # baseline: nothing


def test_resolved_entries_say_when_drift_reached_its_event_cap(api, drift_runs, monkeypatch):  # noqa: F811
    _record_drift(api, drift_runs["run2"])
    monkeypatch.setattr(DRIFT, "EVENT_CAP", 2)  # the run stored more events than this
    doc = api("GET", f"/1/cbom/sources/runs/{drift_runs['run2']['id']}/cbom").json()
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["zs:drift_events_truncated"] == "true"
    resolved = [v for v in doc["vulnerabilities"] if v["analysis"]["state"] == "resolved"]
    assert resolved and all(_props(v)["zs:resolved_truncated"] == "true" and "may be incomplete" in
                            v["analysis"]["detail"] for v in resolved)


def _props_of(component):
    return {p["name"]: p["value"] for p in component.get("properties") or []}


def test_the_export_is_still_written_one_component_at_a_time(api, world, monkeypatch):  # noqa: F811
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
def certin_db(world, monkeypatch):  # noqa: F811
    from backend.routers import certin

    engine, ids = world
    monkeypatch.setattr(certin, "get_db", lambda: engine)
    certin.read_limiter.requests.clear()
    certin.write_limiter.requests.clear()
    return engine, ids


BASE_SERIAL = "urn:uuid:7b2f2a8e-4c1d-4b8e-9f00-2a1c3d4e5f60"


def test_code_scan_vex_states_drift_resolved_and_schema(api, certin_db, monkeypatch):  # noqa: F811
    engine, ids = certin_db
    meta = {"repo_url": "https://github.com/acme/vex", "branch": "main"}
    des = _row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"], cves=["CVE-2016-2183"])
    md5 = _row("MD5", "hash.py", ["WEAK_ALGORITHM"])
    rsa = _row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low", quantum_safe=False)
    aes = _row("AES-256-GCM", "app.py", [], quantum_safe=True)
    lib = _row("openssl 1.0.2", "Dockerfile", ["VULNERABLE_CRYPTO_LIBRARY"], cves=["CVE-2016-0800"],
               asset_type="library")
    with Session(engine) as s:
        s.add(Scan(id=60, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="vex", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 1),
                   scan_data={"results": [des, md5, rsa, lib],
                              "cbom_json": {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                            "serialNumber": BASE_SERIAL,
                                            "components": [{"type": "cryptographic-asset", "name": r["title"],
                                                            "bom-ref": r["bom_ref"]} for r in (des, md5, rsa, lib)]}}))
        s.add(Scan(id=61, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="vex", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 2),
                   # 3DES still listed without its finding; MD5 gone; a stale VEX of rules 2 stored
                   scan_data={"results": [{**des, "finding_codes": [], "impact": None, "cves": []}, rsa, aes, lib],
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
    # 3DES still listed, finding gone: local ref; MD5 gone: a BOM-Link to its component in the baseline scan's CBOM
    assert fixed["affects"] == [{"ref": des["bom_ref"]},
                                {"ref": VEX.bom_link(BASE_SERIAL, 1, md5["bom_ref"])}]
    assert _props(fixed)["zs:resolved_assets_not_listed"] == "1" and _props(fixed)["zs:baseline_scan_id"] == "60"
    assert not any(v["analysis"]["state"] == "exploitable" for v in vex["vulnerabilities"])
    assert by[("CVE-2016-0800", "in_triage")]["analysis"]["detail"] == VEX.CODE_CVE_LIBRARY  # from the advisory
    meta = {p["name"]: p["value"] for p in vex["metadata"]["properties"]}
    assert vex["serialNumber"].startswith("urn:uuid:") and vex["metadata"]["timestamp"].endswith("Z")
    assert meta["zs:supersedes"] == "rules 2" and meta["zs:scan_id"] == "61"
    assert json_errors(vex) == []
    assert metadata_vex(61) == vex  # rebuilt and stored: served from metadata from now on
    from backend.routers import certin

    writes = []
    real_save = certin._save_scan_data
    monkeypatch.setattr(certin, "_save_scan_data", lambda *a, **kw: (writes.append(a), real_save(*a, **kw)))
    assert api("GET", "/1/cbom/scan/61/vex").json() == vex and writes == []  # current: served, not rebuilt

    old = api("GET", "/1/cbom/scan/60/vex").json()  # the baseline: weak algorithm in triage, CVE in triage
    states = {(v["id"], v["analysis"]["state"]) for v in old["vulnerabilities"]}
    assert ("ZS-CBOM-WEAK_ALGORITHM", "in_triage") in states and ("CVE-2016-2183", "in_triage") in states
    sweet32 = next(v for v in old["vulnerabilities"] if v["id"] == "CVE-2016-2183")
    assert sweet32["analysis"]["detail"] == VEX.CODE_CVE_ALGORITHM
    assert json_errors(old) == []


def test_a_cbom_scan_without_result_rows_gets_a_current_vex_once(api, certin_db, monkeypatch):  # noqa: F811
    """Review of #134, finding 4: empty or non-list results no longer fall back to the rules-2 builder."""
    from backend.routers import certin

    engine, ids = certin_db
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "cryptographic-asset", "name": "AES", "bom-ref": "crypto-aes"}]}
    with Session(engine) as s:
        for sid, results in ((70, []), (71, None)):
            s.add(Scan(id=sid, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title=f"e{sid}",
                       scan_status="success", scan_data={"results": results, "cbom_json": bom}))
        s.commit()
    writes = []
    real_save = certin._save_scan_data
    monkeypatch.setattr(certin, "_save_scan_data", lambda *a, **kw: (writes.append(a[0]), real_save(*a, **kw)))
    for sid in (70, 71):
        first = api("GET", f"/1/cbom/scan/{sid}/vex").json()
        assert VEX.is_current("cbom", first) and json_errors(first) == []
        assert [v["affects"] for v in first["vulnerabilities"]] == [[{"ref": "crypto-aes"}]]  # F5 stub per component
        assert api("GET", f"/1/cbom/scan/{sid}/vex").json() == first
    assert len(writes) == 2  # one write per scan: the second call serves the stored document


def test_code_scan_vex_is_one_rule_set_with_the_export():
    findings = [_row("RSA-2048", "k.py", ["QUANTUM_VULNERABLE"]), _row("AES", "a.py", [])]
    vex = VEX.code_scan_vex(findings)
    q = next(v for v in vex["vulnerabilities"] if v["id"] == "ZS-CBOM-QUANTUM_VULNERABLE")
    assert q["analysis"] == VEX.analysis_for("quantum_only", code="QUANTUM_VULNERABLE", grade_text=VEX.CODE_SCAN_GRADE)
    stub = next(v for v in vex["vulnerabilities"] if v["analysis"]["state"] == "not_affected")
    assert stub["affects"] == [{"ref": findings[1]["bom_ref"]}]  # CERT-In F5 "no weakness found" kept
    assert json_errors(vex) == []


# ----------------------------------------------------------------------------- contract with the run VEX deliverable
def _keyed(entries):
    """(finding id, referenced asset) -> (state, [every zs:vex_basis]) of a VEX; BOM-Links compared by their asset."""
    out = {}
    for v in entries:
        for a in v.get("affects") or []:
            out[(v["id"], str(a["ref"]).rsplit("#", 1)[-1])] = (v["analysis"]["state"], VEX.props_of(v).get("zs:vex_basis"))
    return out


def test_the_run_vex_deliverable_agrees_with_the_export_when_it_exists(api, drift_runs):  # noqa: F811
    """Review of #134, finding 3: CB-38's run VEX (``run_deliverables``, PR #124) is built on this export. Without a
    remediation plan it must give every (finding, asset) the export's state and basis, keep drift-resolved entries
    resolved, carry exactly one ``zs:vex_basis`` per entry and keep the quantum entries' ``zs:q_grades``. Skipped
    until that module is on the branch; whichever PR lands second turns this on."""
    RD = pytest.importorskip("backend.utilities.cbom_sources.run_deliverables")
    _record_drift(api, drift_runs["run1"])
    _record_drift(api, drift_runs["run2"])
    with Session(drift_runs["engine"]) as s:
        run = s.get(CbomCollectionRun, drift_runs["run2"]["id"])
        now = dt.datetime.utcnow()
        data = RD.summary(s, run, now)
        run_vex = RD.run_vex(run, data, {}, RD.stamp(s, run, now))
    export = _keyed(data.vulnerabilities)
    assert any(state == "resolved" for state, _b in export.values())
    for v in run_vex["vulnerabilities"]:
        assert len(VEX.props_of(v).get("zs:vex_basis") or []) == 1, v["bom-ref"]
    assert _keyed(run_vex["vulnerabilities"]) == export
    grades = {v["id"]: VEX.props_of(v).get("zs:q_grades") for v in data.vulnerabilities
              if VEX.entry_basis(v) == "quantum_only"}
    assert grades and all(grades.values())
    for v in run_vex["vulnerabilities"]:
        if VEX.entry_basis(v) == "quantum_only":
            assert VEX.props_of(v).get("zs:q_grades") == grades[v["id"]]
