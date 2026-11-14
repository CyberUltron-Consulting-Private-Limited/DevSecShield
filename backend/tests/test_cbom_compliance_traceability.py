"""Compliance mapping proven on a real collection run (Output 06): CERT-In, RBI, SEBI CSCRF and NSA CNSA 2.0.

A run with known findings is seeded through the real node flow (``two_runs`` / ``one_run``: enrolment, claimed jobs,
uploaded assets). Then, against the real routers:

* every clause the run API maps (``/runs/{id}/posture`` and ``/runs/{id}/results``) traces back to findings: its codes
  are on the run's assets, its asset count is the number of assets carrying one of them, and every finding code with
  a compliance area in the knowledge base reaches all of that area's clauses (nothing mapped is dropped, nothing
  unmapped is shown);
* the OSCAL assessment results of the run carry the same codes, each finding linked to its clauses' sources and to the
  observations of the assets that carry the code;
* the team-wide deliverables (``/cbom/deliverables/{slug}``: the board report with its regulatory exposure and the
  PQC migration roadmap with the CNSA 2.0 timeline) carry the run API's counts.
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_deliverable_common import norm, pdf_full_text  # noqa: E402
from test_cbom_sources_api import CERT_FACTS, api, enroll_node, linux_body, world  # noqa: E402,F401
from test_cbom_wp10_outputs import GONE, OLD_CERT, OPENSSL, WEAK_TLS, _claim, _collect, _run, two_runs  # noqa: E402,F401

from backend.utilities.cbom_sources import crypto_kb  # noqa: E402

_FIXTURES = (api, world, two_runs)  # pytest fixtures shared with the CBOM Sources tests (used by name)
FRAMEWORKS = ("CERT-In", "RBI", "SEBI CSCRF", "NSA CNSA 2.0")


@pytest.fixture()
def deliverables(world, monkeypatch):
    from backend.routers import cbom_deliverables

    engine, _ = world
    monkeypatch.setattr(cbom_deliverables, "get_db", lambda: engine)
    cbom_deliverables.limiter.requests.clear() if hasattr(cbom_deliverables.limiter, "requests") else None


@pytest.fixture()
def one_run(api, world):
    """One complete run: a self-signed RSA-1024 / MD5 certificate (expired), a TLS 1.0 endpoint with 3DES, a DSA host
    key and OpenSSL 3.0.2 on one server."""
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any"))
    run = _run(api, "trace-run-0001")
    _collect(api, hdr, _claim(api, hdr), [OLD_CERT, WEAK_TLS, GONE, OPENSSL])
    return run


def _assets(api, run_id) -> list[dict]:
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/assets?page_size=200")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == len(body["items"])
    return body["items"]


def _posture(api, run_id) -> dict:
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/posture")
    assert r.status_code == 200, r.text
    return r.json()["posture"]


def _expected_clauses(assets: list[dict]) -> dict[tuple[str, str], tuple[set[int], set[str]]]:
    """The oracle, from the knowledge base and the run's assets only: clause -> (asset ids, codes)."""
    table = crypto_kb.load()["compliance"]
    out: dict[tuple[str, str], tuple[set[int], set[str]]] = defaultdict(lambda: (set(), set()))
    for asset in assets:
        for code in asset["finding_codes"]:
            if code.startswith("COVERAGE_"):
                continue
            for area in (crypto_kb.entry("node", code) or {}).get("compliance") or []:
                for ref in table.get(area) or []:
                    ids, codes = out[(ref["framework"], ref["id"])]
                    ids.add(asset["id"])
                    codes.add(code)
    return out


def _check_run(api, run_id):
    assets = _assets(api, run_id)
    expected = _expected_clauses(assets)
    posture = _posture(api, run_id)
    shown = {(fw["framework"], c["id"]): c for fw in posture["compliance"] for c in fw["clauses"]}
    # every clause of the four frameworks: shown when (and only when) a finding maps to it, with the right counts
    for framework in FRAMEWORKS:
        want = {k: v for k, v in expected.items() if k[0] == framework}
        got = {k: v for k, v in shown.items() if k[0] == framework}
        assert set(got) == set(want), (framework, sorted(set(got) ^ set(want)))
        for key, (ids, codes) in want.items():
            assert got[key]["assets"] == len(ids), key
            assert set(got[key]["codes"]) == codes, key
            # traceable: each code is on an asset of the run, and every counted asset carries one of the codes
            assert all(any(c in a["finding_codes"] for a in assets) for c in got[key]["codes"])
    # the results page (CB-38) shows the same clauses and counts
    results = api("GET", f"/1/cbom/sources/runs/{run_id}/results").json()["compliance"]["frameworks"]
    alias = {"CNSA 2.0": "NSA CNSA 2.0"}  # the results page labels the KB's "NSA CNSA 2.0" as "CNSA 2.0"
    page = {(alias.get(fw["framework"], fw["framework"]), c["clause"]): (c["assets"], set(c["codes"]))
            for fw in results for c in fw["clauses"]}
    for key, clause in shown.items():
        if key[0] in FRAMEWORKS:
            assert page.get(key) == (clause["assets"], set(clause["codes"])), key
    # OSCAL: each mapped code is a finding linked to its clauses and to the observations of the assets carrying it
    doc = api("GET", f"/1/cbom/sources/runs/{run_id}/oscal").json()["assessment-results"]["results"][0]
    observations = {o["uuid"]: {p["value"] for p in o.get("props", []) if p["name"] == "finding-code"}
                    for o in doc.get("observations", [])}
    findings = defaultdict(list)
    for f in doc.get("findings", []):
        code = next(p["value"] for p in f["props"] if p["name"] == "finding-code")
        findings[code].append(f)
    for (framework, clause_id), (_ids, codes) in expected.items():
        if framework not in FRAMEWORKS:
            continue
        for code in codes:
            assert findings[code], code
            for f in findings[code]:
                assert any(link["text"] == f"{framework}: {clause_id}" for link in f.get("links", [])), (code, clause_id)
                carriers = [o for o in f["related-observations"]]
                assert carriers and all(code in observations[o["observation-uuid"]] for o in carriers)
                assert len(carriers) == sum(1 for a in assets if code in a["finding_codes"]), code
    return assets, posture, expected


def test_every_mapped_clause_traces_to_findings_on_two_real_runs(api, two_runs):
    a1, _p1, e1 = _check_run(api, two_runs["run1"]["id"])
    a2, _p2, e2 = _check_run(api, two_runs["run2"]["id"])
    # the seeded findings reach all four frameworks in run 1
    assert {k[0] for k in e1} >= set(FRAMEWORKS)
    # run 2 fixed the TLS endpoint and renewed the certificate: the RBI clauses (key length, algorithms, protocols)
    # are no longer touched, CNSA 2.0 still is (RSA certificate, no post-quantum key exchange)
    assert not any(k[0] == "RBI" for k in e2) and any(k[0] == "NSA CNSA 2.0" for k in e2)


def test_every_mapped_clause_traces_to_findings_on_one_run(api, one_run):
    _check_run(api, one_run["id"])


# ------------------------------------------------------------------------------------------------- deliverables
def _pdf(api, slug) -> str:
    r = api("GET", f"/1/cbom/deliverables/{slug}")
    assert r.status_code == 200 and r.content[:4] == b"%PDF", r.text[:200]
    return norm(pdf_full_text(r.content))


def _section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


def _count(text: str, label: str) -> int:
    m = re.search(re.escape(label) + r" (\d+)", text)
    assert m, label
    return int(m.group(1))


def _deliverable_checks(api, run_id):
    assets = _assets(api, run_id)
    posture = _posture(api, run_id)
    dashboard = api("GET", f"/1/cbom/sources/runs/{run_id}/results").json()["dashboard"]["card_data"]
    certs = [a for a in assets if a["type"] == "certificate"]
    board = _pdf(api, "board-executive-report")
    # 3. quantum readiness and 4. certificate posture match the run
    quantum = _section(board, "3. Quantum readiness", "4. Certificate")
    assert _count(quantum, "Quantum-vulnerable") == dashboard["total_quantum_vulnerable"]
    certs_text = _section(board, "4. Certificate and key-material posture", "5. Regulatory exposure")
    assert _count(certs_text, "Unique certificates in the estate") == len(certs)
    assert _count(certs_text, "Self-signed leaf certificates") == sum(
        1 for c in certs if "CERT_SELF_SIGNED" in c["finding_codes"])
    weak_codes = {"SIG_MD5", "SIG_SHA1", "RSA_LT_2048", "RSA_LT_1024", "EC_LT_224"}
    assert _count(certs_text, "Weak signature hash or undersized key") == sum(
        1 for c in certs if weak_codes & set(c["finding_codes"]))
    # 5. regulatory exposure: every CERT-In / RBI / SEBI CSCRF / CNSA 2.0 clause the run maps, with its asset count
    exposure = _section(board, "5. Regulatory exposure", "6. Remediation priorities")
    assert "No compliance results are available" not in exposure
    for fw in posture["compliance"]:
        if fw["framework"] not in FRAMEWORKS:
            continue
        for clause in fw["clauses"]:
            hit = re.search(re.escape(norm(f"{fw['framework']} {clause['id']}")) + r" (\d+)", exposure)
            assert hit and int(hit.group(1)) == clause["assets"], (fw["framework"], clause["id"], exposure[:600])
    # 7. post-quantum summary: never "none found" while the run has quantum-vulnerable assets
    pqc = _section(board, "7. Post-quantum roadmap summary", "8. Governance")
    if dashboard["total_quantum_vulnerable"]:
        assert "No quantum-vulnerable public-key algorithms were found" not in pqc, pqc[:300]
        assert str(dashboard["total_quantum_vulnerable"]) in pqc
    # PQC migration roadmap (CNSA 2.0 timeline): the same quantum-vulnerable count, every one listed, never "none"
    roadmap = _pdf(api, "pqc-migration-roadmap")
    assert "CNSA 2.0" in roadmap
    assert _count(_section(roadmap, "1 Summary", "2 Regulatory timeline"), "Quantum-vulnerable") == \
        dashboard["total_quantum_vulnerable"]
    if dashboard["total_quantum_vulnerable"]:
        assert "No quantum-vulnerable public-key algorithms were found" not in roadmap
        collected = _section(roadmap, "Collected infrastructure (scan nodes and cloud)", "Already quantum-safe")
        qv = [a for a in assets if a["quantum_vulnerable"]]
        assert len(qv) == dashboard["total_quantum_vulnerable"]
        for a in qv:
            assert norm(a["location"]) in collected, a["location"]


def test_deliverables_carry_the_run_counts_after_two_runs(api, two_runs, deliverables):
    _deliverable_checks(api, two_runs["run2"]["id"])  # the team's latest collection of every source


def test_deliverables_carry_the_run_counts_after_one_run(api, one_run, deliverables):
    _deliverable_checks(api, one_run["id"])
