"""CB-16 follow-ups (#294): framework verdicts over CBOM Sources rows, and both lanes on one set of predicates.

Before this change (dev):
* a CBOM Sources collection counted in every team view (``collections_view``, M1x) but in no compliance framework:
  the team roll-up's frameworks and requirements pooled code scans only, so a team whose estate was read by Sources
  showed no FIPS 140-3 or CNSA 2.0 verdict for it;
* the code lane's CNSA 2.0 / FIPS 140-3 checks used their own predicates; parity with ``standards.py`` (the module
  the Sources lane grades with) was proven only by a test, not by a shared call.

Now ``cbom_sources.frameworks`` judges each collection with ``standards.framework_checks`` (the predicates the code
lane's checks call too) and ``merge_collections`` pools the verdicts with the code scans'.

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_cb16_frameworks.py
"""
from __future__ import annotations

import ast
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_as_results import _code_scan, no_mongo, sources_run  # noqa: E402,F401  (fixtures)
from test_cbom_sources_api import api, world  # noqa: E402,F401  (fixtures)

from sqlmodel import Session  # noqa: E402

from backend.utilities.cbom_sources import frameworks as FW  # noqa: E402
from backend.utilities.cbom_sources import standards as S  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
CODE_COMPLIANCE = ROOT / "aibom/src/aibom/cbom/compliance.py"


def verdicts(block):
    return {r["id"]: r["verdict"] for r in block["requirements"]}


# ============================================================================ the predicates
@pytest.mark.parametrize("parts,fips,cnsa", [
    ([("cipher", "TLS_AES_256_GCM_SHA384", None)], {"FIPS-1": "pass", "FIPS-2": "pass", "FIPS-3": "pass"},
     {"CNSA-1": "pass", "CNSA-2": "pass"}),
    ([("cipher", "TLS_AES_128_GCM_SHA256", None)], {"FIPS-1": "pass", "FIPS-2": "pass", "FIPS-3": "pass"},
     {"CNSA-1": "fail", "CNSA-2": "pass"}),
    ([("key", "RSA", 1024), ("signature", "sha1WithRSAEncryption", None)],
     {"FIPS-1": "fail", "FIPS-2": "fail", "FIPS-3": "fail"}, {"CNSA-1": "pass", "CNSA-2": "pass"}),
    ([("key", "RSA", 2048), ("signature", "sha256WithRSAEncryption", None)],
     {"FIPS-1": "pass", "FIPS-2": "pass", "FIPS-3": "pass"}, {"CNSA-1": "pass", "CNSA-2": "pass"}),
    ([("key", "ML-KEM-768", None)], {"FIPS-1": "pass", "FIPS-2": "pass", "FIPS-3": "pass"},
     {"CNSA-1": "pass", "CNSA-2": "fail"}),
    ([("key", "ML-KEM-1024", None)], {"FIPS-1": "pass", "FIPS-2": "pass", "FIPS-3": "pass"},
     {"CNSA-1": "pass", "CNSA-2": "pass"}),
    ([("cipher", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", None)], {"FIPS-1": "fail", "FIPS-2": "pass", "FIPS-3": "fail"},
     {"CNSA-1": "fail", "CNSA-2": "pass"}),
    ([("key", "DSA", 2048)], {"FIPS-1": "fail", "FIPS-2": "pass", "FIPS-3": "fail"},
     {"CNSA-1": "pass", "CNSA-2": "pass"}),
])
def test_one_collection_is_judged_by_the_shared_predicates(parts, fips, cnsa):
    out = FW.collection_compliance([parts])
    assert verdicts(out["fips_140_3"]) == fips and verdicts(out["cnsa_2_0"]) == cnsa
    for block in out.values():  # cbom_compliance's shape: counts + requirements
        assert block["pass"] + block["fail"] + block["out_of_scope"] == len(block["requirements"])


def test_a_collection_with_nothing_the_standards_can_judge_is_out_of_scope():
    out = FW.collection_compliance([[], [("key", None, None)]])
    assert {v for block in out.values() for v in verdicts(block).values()} == {"out_of_scope"}


def test_failing_counts_assets_not_parts():
    out = FW.collection_compliance([[("key", "RSA", 1024), ("signature", "sha1WithRSAEncryption", None)],
                                    [("key", "RSA", 1024)], [("key", "RSA", 4096)]])
    failing = {r["id"]: r["failing"] for r in out["fips_140_3"]["requirements"]}
    # FIPS-1 is the function (an RSA key is approved whatever its size; the SHA-1 signature is not), FIPS-2 the size
    assert failing == {"FIPS-1": 1, "FIPS-2": 2, "FIPS-3": 2}


def test_the_requirement_titles_are_the_code_lanes():
    """The Sources requirements are the code lane's (same ids, same titles), so pooled rows read as one requirement."""
    tree = ast.parse(CODE_COMPLIANCE.read_text(encoding="utf-8"))
    titles = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_req" and len(node.args) >= 3:
            rid, _fw, title = node.args[:3]
            if isinstance(rid, ast.Constant) and isinstance(title, (ast.Constant, ast.JoinedStr, ast.BinOp)):
                try:
                    titles[rid.value] = ast.literal_eval(title)
                except ValueError:
                    pass
    for req, (_framework, title) in S.REQUIREMENTS.items():
        assert titles.get(req) == title, req


def test_the_code_lane_checks_call_the_shared_predicates():
    """Parity by a shared call, not only by a test (#294): compliance.py routes CNSA-1, CNSA-2, FIPS-1, FIPS-2 and
    FIPS-3 through ``standards.framework_checks``; the copies stay byte-identical."""
    text = CODE_COMPLIANCE.read_text(encoding="utf-8")
    assert "from aibom.cbom import standards as _std" in text and "_std.framework_checks(" in text
    for req in ("CNSA-1", "CNSA-2", "FIPS-1", "FIPS-2", "FIPS-3"):
        assert f'_std_checks(c)["{req}"]' in text, req
    backend = ROOT / "backend/utilities/cbom_sources/standards.py"
    code = ROOT / "aibom/src/aibom/cbom/standards.py"
    assert hashlib.sha256(backend.read_bytes()).hexdigest() == hashlib.sha256(code.read_bytes()).hexdigest()


# ============================================================================ the team roll-up (plan AC 4)
def test_the_team_rollup_frameworks_include_sources_rows(api, sources_run, no_mongo):  # noqa: F811
    """The X1 collection: a TLS 1.3 endpoint (AES-256/SHA-384, an RSA-1024 leaf), its RSA-1024 / SHA-1 certificate
    and an RSA-3072 host key.  dev: no framework at all for this Sources-only team."""
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view

    view = load_team_cbom_view(sources_run["engine"], 1)
    pools = {p.framework: p for p in view.frameworks}
    assert {"fips_140_3", "cnsa_2_0"} <= set(pools), sorted(pools)
    fips, cnsa = pools["fips_140_3"], pools["cnsa_2_0"]
    assert fips.sources_pooled == 1 and fips.failed == 3 and fips.passed == 0 and fips.coverage == 0.0
    assert cnsa.sources_pooled == 1 and cnsa.passed == 2 and cnsa.failed == 0 and cnsa.coverage == 1.0
    (collection,) = view.collections
    reqs = {(r.framework, r.req_id): r for r in view.requirements}
    for req in ("FIPS-1", "FIPS-2", "FIPS-3"):
        row = reqs[("fips_140_3", req)]
        assert row.verdicts == {collection.key: "fail"} and row.verdict == "fail" and row.title
        assert row.citation == "FIPS 140-3 / SP 800-140C / SP 800-131A"
    assert reqs[("cnsa_2_0", "CNSA-1")].verdict == "pass"


def test_code_scans_and_sources_collections_pool_into_one_framework_row(api, sources_run, no_mongo):  # noqa: F811
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view

    scan = _code_scan(sources_run["finished"])
    scan.scan_data = {**scan.scan_data, "cbom_distributions": {}, "cbom_compliance": {"fips_140_3": {
        "pass": 3, "fail": 0, "out_of_scope": 0, "not_bom_evidenceable": 1, "na": 0, "pass_with_evidence": 0,
        "requirements": [{"id": "FIPS-1", "verdict": "pass", "title": "Only FIPS-approved security functions in use",
                          "source": "FIPS 140-3 / SP 800-140C / SP 800-131A"},
                         {"id": "FIPS-2", "verdict": "pass"}, {"id": "FIPS-3", "verdict": "pass"},
                         {"id": "FIPS-4", "verdict": "not_bom_evidenceable"}]}}}
    with Session(sources_run["engine"]) as s:
        s.add(scan)
        s.commit()
    view = load_team_cbom_view(sources_run["engine"], 1)
    fips = {p.framework: p for p in view.frameworks}["fips_140_3"]
    # the code scan's copy of the shared certificate wins the tie (collections_view), so the collection is judged on
    # its endpoint (RSA-1024 leaf: FIPS-2, FIPS-3 fail; AES-256 suite: FIPS-1 pass) and its RSA-3072 host key
    assert fips.sources_pooled == 2 and fips.passed == 3 + 1 and fips.failed == 2 and fips.not_bom_evidenceable == 1
    assert fips.coverage == round(4 / 6, 3)
    reqs = {(r.framework, r.req_id): r for r in view.requirements}
    row = reqs[("fips_140_3", "FIPS-2")]
    assert sorted(row.verdicts.values()) == ["fail", "pass"] and row.verdict == "fail"  # the roll-up's precedence
    assert reqs[("fips_140_3", "FIPS-4")].verdicts and "fail" not in reqs[("fips_140_3", "FIPS-4")].verdicts.values()


def test_a_team_without_sources_keeps_its_code_frameworks_unchanged(api, world, no_mongo):  # noqa: F811
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view
    import datetime as dt

    engine, _ = world
    scan = _code_scan(dt.datetime.utcnow())
    scan.scan_data = {**scan.scan_data, "cbom_distributions": {}, "cbom_compliance": {"cnsa_2_0": {
        "pass": 1, "fail": 1, "requirements": [{"id": "CNSA-1", "verdict": "fail"}, {"id": "CNSA-2", "verdict": "pass"}]}}}
    with Session(engine) as s:
        s.add(scan)
        s.commit()
    view = load_team_cbom_view(engine, 1)
    (pool,) = view.frameworks
    assert (pool.framework, pool.sources_pooled, pool.passed, pool.failed) == ("cnsa_2_0", 1, 1, 1)
