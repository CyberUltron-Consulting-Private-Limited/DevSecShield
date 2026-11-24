"""PR #485 review 6027921691: D14 Board report, D1 Scope baseline, Document IDs and the team's regulatory profile.

One test (or a few) per finding; each failed on 5694d1ff8 (the reviewed head) merged with origin/dev 26395f79:

* B1  one Document ID format, dev's two-digit ``CBOM-D%02d`` (#481 pins CBOM-D07 / CBOM-D08); D8 keeps its CSV.
* M1  the Document ID moves when the content moves: regulatory profile, source metadata, register grade inputs.
* M2  one clause filter (``crypto_kb.clauses_for(team=...)``): an NBFC team never sees the Commercial Banks
      Directions or the superseded 2023 Master Direction on the run results API, the asset detail, OSCAL or D14.
* M3  D14 section 5 prints the source count its rows use; the RBI note only with an RBI row, worded for the entity.
* M4  only the frameworks that bind the team: an Indian NBFC sees no OMB M-23-02, EU CRA, DORA, BSI or PCI DSS
      (unless it processes card data) and no CERT-In government-entity clauses (unless it is a government entity).
* M5  D14 section 7 groups EVERY current quantum-vulnerable asset by a usage-based target; its total is section 3's.
* M6  D1 reconciles with the run: run assets -> occurrences -> distinct register assets -> Q-grade split.
* M7  Appendix B lists every included result; material risks once per asset; a trend against the previous issue
      ("first issue" when none); board-readable finding names in section 5.
* minors m1-m8 and nits n1-n2 of the review.

The seeded DB is the reviewer's (``qa/485/scripts/test_render_485.py``): one code scan, five Sources sources across
L2-L4, one certificate seen by two sources, Mosca inputs missing. Oracles are literals.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_cbom_sources_api as _base  # noqa: E402
from test_cbom_cb19_run_grades import _asset, seed  # noqa: E402
from test_cbom_fa3_board_scope import board_text, scope_text, staging_like_view  # noqa: E402
from test_cbom_sources_as_results import _code_scan  # noqa: E402

from backend.new_models import CbomCollectionAuditEvent, CbomCollectionRun, CbomCollectionSource  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb, regulated_entity  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    FrameworkPool,
    load_team_cbom_view,
)
from backend.utilities.pdf import cbom_board_report_pdf as board  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_common as common  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf import cbom_population as population  # noqa: E402
from backend.utilities.pdf.cbom_collected_compliance import collected_clauses  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402

world = _base.world
api = _base.api
NOW = dt.datetime(2026, 11, 14, 9, 0)
SETTINGS = "/1/cbom/sources/settings"
D14 = "/1/cbom/deliverables/board-executive-report"
D1 = "/1/cbom/deliverables/scope-baseline-register"
KB = (ROOT / "backend/utilities/cbom_sources/data/crypto_kb.json", ROOT / "aibom/src/aibom/cbom/data/crypto_kb.json")
BANK_CLAUSE = "Commercial Banks Cybersecurity Directions 2026, para 140"
MD_2023 = "Master Direction on IT Governance (2023), para 16"
NBFC_CLAUSE = "NBFC Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026, para 118"

CERT_FACTS = {"subject": "CN=los.chola.test", "issuer": "CN=Chola Issuing CA", "serial": "1a2b",
              "not_before": "2025-11-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z",
              "sig_alg": "sha256WithRSAEncryption", "key_alg": "RSA", "key_size": 2048, "san": ["los.chola.test"],
              "is_ca": False, "self_signed": False, "fingerprint_sha256": "ab" * 32, "chain_index": 0}
META = {"owner": "Payments Ops", "application": "Loan Origination", "data_classification": "confidential",
        "data_lifetime_years": 10, "business_criticality": "high", "exposure": "internet"}


# ---------------------------------------------------------------------------------------------- the seeded team
def _seed(engine):
    with Session(engine) as s:
        s.add(_code_scan(NOW - dt.timedelta(days=2)))
        s.commit()
    w = seed(engine, mosca={}, sources=[
        {"name": "linux-app", "kind": "linux_servers", "metadata": META, "config": META, "assets": [
            _asset("ssh_host_key", "/etc/ssh/ssh_host_rsa_key.pub", algorithm="ssh-rsa", key_size=3072,
                   facts={"type": "ssh-rsa", "bits": 3072}, name="RSA host key"),
            _asset("tls_endpoint", "10.20.0.1:443", facts={"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"},
                   algorithm="TLS_AES_256_GCM_SHA384"),
            _asset("certificate", "10.20.0.1:443#chain[0]", facts=CERT_FACTS, algorithm="RSA", key_size=2048,
                   name="CN=los.chola.test"),
            _asset("process_library", "/usr/lib/libssl.so.1.1", facts={"library": "openssl", "version": "1.1.1k"},
                   name="OpenSSL 1.1.1k"),
        ]},
        {"name": "dc-range", "kind": "network_range", "metadata": {"owner": "Network Ops"},
         "config": {"owner": "Network Ops"}, "assets": [
            _asset("tls_endpoint", "10.30.0.5:443", target="10.30.0.5",
                   facts={"protocols": ["TLSv1.0", "TLSv1.2"], "group": "secp256r1"}, algorithm="ECDHE-RSA-AES128-SHA"),
            _asset("certificate", "10.30.0.5:443#chain[0]", target="10.30.0.5", facts=CERT_FACTS, algorithm="RSA",
                   key_size=2048, name="CN=los.chola.test"),
            _asset("ssh_endpoint", "10.30.0.6:22", target="10.30.0.6",
                   facts={"kex": ["diffie-hellman-group14-sha1"], "macs": ["hmac-sha1"]}),
        ]},
        {"name": "aws-prod", "kind": "aws_account",
         "config": {"role_arn": "arn:aws:iam::111122223333:role/ZeroShieldCbom"}, "assets": [
            _asset("kms_key", "arn:aws:kms:ap-south-1:111122223333:key/1", target="111122223333/ap-south-1",
                   algorithm="RSA", key_size=2048, facts={"key_spec": "RSA_2048", "key_usage": "SIGN_VERIFY"},
                   name="kms signing"),
            _asset("kms_key", "arn:aws:kms:ap-south-1:111122223333:key/2", target="111122223333/ap-south-1",
                   algorithm="AES", key_size=256, facts={"key_spec": "SYMMETRIC_DEFAULT"}, name="kms data"),
        ]},
        {"name": "core-db", "kind": "database", "metadata": {"application": "Core lending"},
         "config": {"application": "Core lending"}, "assets": [
            _asset("database_tls", "core-db:5432", target="core-db", facts={"protocols": ["TLSv1.2"]},
                   algorithm="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
        ]},
        {"name": "vault", "kind": "key_manager", "assets": [
            _asset("kms_key", "vault:transit/keys/app", target="vault", algorithm="RSA", key_size=1024,
                   facts={"key_spec": "RSA_1024"}, name="transit app key"),
        ]},
    ])
    from backend.utilities.cbom_sources import estate, q0register  # noqa: F401  (q0register registers its hook)
    from backend.utilities.cbom_sources import risk_register as REG

    with Session(engine) as s:
        run = s.exec(select(CbomCollectionRun).where(CbomCollectionRun.id == w["run"])).one()
        estate.record_run(s, run, NOW)
        s.commit()
        for _ in range(5):
            out = REG.regrade_team(s, 1, NOW)
            s.commit()
            if not out["graded"]:
                break
    return w


def _patch(monkeypatch, engine):
    from backend.routers import cbom_deliverables, cbom_register, scans, team as team_router
    from backend.utilities.dashboard import scan_list, team

    monkeypatch.setattr(scan_list, "get_findings_for_scan_id", lambda *a, **k: [])
    monkeypatch.setattr(team, "get_findings_for_scan_id", lambda *a, **k: [])
    for module in (scans, team_router, cbom_deliverables, cbom_register):
        if hasattr(module, "get_db"):
            monkeypatch.setattr(module, "get_db", lambda: engine)
    cbom_deliverables.limiter.requests.clear()


def _pdf_text(content: bytes, tmp_path: Path, name: str) -> str:
    path = tmp_path / f"{name}.pdf"
    path.write_bytes(content)
    out = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, check=True).stdout
    return " ".join(out.split())


def _view(engine):
    return load_team_cbom_view(engine, 1, now=NOW.replace(tzinfo=dt.timezone.utc) + dt.timedelta(days=1))


def _regrade(engine):
    from backend.utilities.cbom_sources import risk_register as REG

    with Session(engine) as s:
        for _ in range(5):
            if not REG.regrade_team(s, 1, NOW)["graded"]:
                break
            s.commit()
        s.commit()


@pytest.fixture
def seeded(api, world, monkeypatch):  # noqa: F811
    engine, _ = world
    w = _seed(engine)
    _patch(monkeypatch, engine)
    return engine, w


# ---------------------------------------------------------------------------------------------- B1
def test_b1_document_ids_use_dev_two_digit_format_and_d8_keeps_its_csv():
    view = staging_like_view()
    assert re.fullmatch(r"CBOM-D07-T1-20261123-[0-9a-f]{8}", common.document_id(view, 7))
    assert common.document_id(view, 14).startswith("CBOM-D14-T1-20261123-")
    assert common.document_id(view, 1).startswith("CBOM-D01-T1-")
    assert DELIVERABLES["certificate-estate-register"].formats == ("pdf", "csv")
    assert DELIVERABLES["certificate-estate-register"].number == 8


# ---------------------------------------------------------------------------------------------- M1
def test_m1_document_id_moves_with_profile_metadata_and_grade_inputs_not_only_with_scans():
    base = staging_like_view()
    ids = {common.document_id(base, 14)}
    bank = staging_like_view()
    bank.regulatory_profile = regulated_entity.profile("bank")
    card = staging_like_view()
    card.regulatory_profile = regulated_entity.profile("nbfc", ["processes_card_data"])
    owner = staging_like_view()
    owner.collections = tuple(dataclasses.replace(c, metadata={**c.metadata, "owner": "Someone else"})
                              for c in base.collections)
    graded = staging_like_view()
    graded.grade_inputs = {"digest": "0123456789abcdef", "model_version": "qg-1"}
    q1 = staging_like_view()
    q1.register = {"summary": {**base.register["summary"], "q_grades": {**base.register["summary"]["q_grades"],
                                                                        "Q1": 3}}}
    for view in (bank, card, owner, graded, q1):
        assert view.fingerprint == base.fingerprint  # the same scans and collections
        ids.add(common.document_id(view, 14))
    assert len(ids) == 6, ids
    # the default profile (NBFC, no flags) is the same content as a view that does not say
    same = staging_like_view()
    same.regulatory_profile = dict(regulated_entity.DEFAULT_PROFILE)
    assert common.document_id(same, 14) == common.document_id(base, 14)


def test_m1_settings_change_moves_the_d14_document_id_and_header(api, seeded, tmp_path):  # noqa: F811
    engine, _w = seeded
    before = api("GET", D14)
    assert before.status_code == 200
    r = api("PATCH", SETTINGS, json={"regulated_entity": "bank", "risk_model": {
        "data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}})
    assert r.status_code == 200, r.text
    _regrade(engine)
    after = api("GET", D14)
    ids = [re.search(r"CBOM-D14-T1-\d{8}-[0-9a-f]{8}", _pdf_text(x.content, tmp_path, n)).group(0)
           for n, x in (("before", before), ("after", after))]
    assert ids[0] != ids[1]
    assert before.headers["x-cbom-fingerprint"] != after.headers["x-cbom-fingerprint"]
    assert ids[1].endswith(after.headers["x-cbom-fingerprint"][:8])


# ---------------------------------------------------------------------------------------------- M2
def _clauses_in(obj) -> set[str]:
    """Every clause id cited anywhere in a JSON document."""
    text = json.dumps(obj)
    return {m for m in (BANK_CLAUSE, MD_2023, NBFC_CLAUSE, "para 139", "para 135", "para 25") if m in text}


def test_m2_an_nbfc_team_never_sees_the_bank_directions_or_the_2023_md_on_any_surface(api, seeded, tmp_path):  # noqa
    engine, w = seeded
    run = w["run"]
    results = api("GET", f"/1/cbom/sources/runs/{run}/results").json()
    posture = api("GET", f"/1/cbom/sources/runs/{run}/posture").json()
    vault = w["vault"]["assets"]["vault:transit/keys/app"]
    detail = api("GET", f"/1/cbom/sources/assets/{vault}").json()
    remediation = api("GET", f"/1/cbom/sources/runs/{run}/assets/{vault}/remediation").json()
    from backend.utilities.integrations import oscal

    feed = oscal.document_for(engine, 1, run_id=run)
    d14 = _pdf_text(api("GET", D14).content, tmp_path, "d14")
    for name, surface in (("results", results), ("posture", posture), ("asset detail", detail),
                          ("remediation", remediation), ("oscal", feed), ("d14", d14)):
        found = _clauses_in(surface)
        assert BANK_CLAUSE not in found and MD_2023 not in found, (name, found)
        assert not {"para 139", "para 135", "para 25"} & found, (name, found)  # SFB, PB, AIFI, CIC, UCB
    for name, surface in (("results", results), ("asset detail", detail), ("oscal", feed)):
        assert NBFC_CLAUSE in json.dumps(surface), name
    assert "NBFC Cybersecurity" in d14


def test_m2_a_bank_team_sees_para_140_and_not_the_nbfc_directions_on_every_surface(api, seeded):  # noqa: F811
    engine, w = seeded
    assert api("PATCH", SETTINGS, json={"regulated_entity": "bank"}).status_code == 200
    run = w["run"]
    vault = w["vault"]["assets"]["vault:transit/keys/app"]
    from backend.utilities.integrations import oscal

    for name, surface in (("results", api("GET", f"/1/cbom/sources/runs/{run}/results").json()),
                          ("asset detail", api("GET", f"/1/cbom/sources/assets/{vault}").json()),
                          ("oscal", oscal.document_for(engine, 1, run_id=run))):
        text = json.dumps(surface)
        assert BANK_CLAUSE in text and NBFC_CLAUSE not in text and MD_2023 not in text, name


def test_m2_the_filter_lives_in_clauses_for_and_the_code_engine_keeps_every_clause():
    nbfc, bank = regulated_entity.profile("nbfc"), regulated_entity.profile("bank")
    every = {r["key"] for r in crypto_kb.clauses_for("node", "RSA_LT_2048", ["RSA-1024"])}
    assert {"rbi-nbfc-2026-para-118", "rbi-cb-2026-para-140", "rbi-sfb-2026-para-139"} <= every  # no team: all
    assert "rbi-md-2023-para-16" not in every  # superseded: cited by no finding
    keys = {r["key"] for r in crypto_kb.clauses_for("node", "RSA_LT_2048", ["RSA-1024"], team=nbfc)}
    assert "rbi-nbfc-2026-para-118" in keys and not {k for k in keys if k.startswith("rbi-") and "nbfc" not in k}
    keys = {r["key"] for r in crypto_kb.clauses_for("node", "RSA_LT_2048", ["RSA-1024"], team=bank)}
    assert "rbi-cb-2026-para-140" in keys and "rbi-nbfc-2026-para-118" not in keys
    rendered = crypto_kb.render("node", ["RSA_LT_2048"], team=nbfc)[0]["compliance"]
    assert {r["key"] for r in rendered if r["framework"] == "RBI"} == {"rbi-nbfc-2026-para-118"}
    assert not crypto_kb.applies(crypto_kb.load()["clauses"]["rbi-md-2023-para-16"], regulated_entity.profile("other"))


# ---------------------------------------------------------------------------------------------- M3
def test_m3_section_5_prints_the_source_counts_its_rows_use_and_an_entity_worded_rbi_note():
    view = staging_like_view()  # rows: eu_cra 1 of 5 (not applicable), cnsa_2_0 5 of 5; compliance_sources_pooled 1
    text = board_text(view)
    assert "Rows are based on 5 of 5 sources" in text and "1 of 5 sources pooled" not in text
    assert "RBI FREE-AI" not in text  # no RBI pooled row: no RBI note
    rbi = staging_like_view()
    rbi.frameworks = (FrameworkPool(framework="rbi_free_ai_protection", passed=1, failed=1, sources_pooled=2,
                                    coverage=0.5),
                      FrameworkPool(framework="cnsa_2_0", passed=4, failed=1, sources_pooled=5, coverage=0.8))
    text = board_text(rbi)
    assert "Rows are based on 2 to 5 of 5 sources" in text
    assert "Cyber Security Framework, 2016" not in text  # a circular for banks, never cited to an NBFC
    assert "not an assessment against the RBI NBFC Cybersecurity" in text and "para 118" in text
    rbi.regulatory_profile = regulated_entity.profile("bank")
    assert "not an assessment against the RBI Commercial Banks" in board_text(rbi)


# ---------------------------------------------------------------------------------------------- M4
def test_m4_an_indian_nbfc_sees_only_the_frameworks_that_bind_it():
    pools = tuple(FrameworkPool(framework=k, passed=1, failed=1, sources_pooled=1, coverage=0.5) for k in (
        "nist_800_57", "omb_m_23_02", "eu_cra", "eu_dora", "pci_dss_4", "bsi_tr_02102", "cnsa_2_0",
        "rbi_free_ai_protection", "cert_in_cbom", "sebi_cscrf_cbom"))
    view = staging_like_view()
    view.frameworks = pools
    shown = [row[0] for row in board.exposure_rows(view)]
    assert shown == ["NIST SP 800-57", "CNSA 2.0", "RBI FREE-AI (Protection)", "CERT-In CBOM (Guidelines v2.0)"]
    hidden = board.not_applicable_frameworks(view)
    assert hidden == ["OMB M-23-02", "EU CRA", "EU DORA", "PCI-DSS 4.0", "BSI TR-02102", "SEBI CSCRF (CBOM)"]
    text = board_text(view)
    assert ("Not applicable to this team and not shown (NBFC in India, no payment-card data, not SEBI-regulated, not "
            "a government entity): OMB M-23-02, EU CRA, EU DORA, PCI-DSS 4.0, BSI TR-02102, SEBI CSCRF (CBOM).") in text
    view.regulatory_profile = regulated_entity.profile("nbfc", ["processes_card_data", "sebi_regulated"])
    assert {"PCI-DSS 4.0", "SEBI CSCRF (CBOM)"} <= {row[0] for row in board.exposure_rows(view)}


def test_m4_clause_applicability_government_and_sebi_clauses_need_the_team_flag():
    kb = crypto_kb.load()
    nbfc = regulated_entity.profile("nbfc")
    gov = regulated_entity.profile("nbfc", ["government_entity"])
    for key in ("certin-gov-4.5.7", "certin-gov-6.1.7", "certin-gov-6.2.7", "certin-gov-7.1"):
        assert not crypto_kb.applies(kb["clauses"][key], nbfc) and crypto_kb.applies(kb["clauses"][key], gov), key
    assert not crypto_kb.applies(kb["clauses"]["sebi-annexure-i"], nbfc)
    assert crypto_kb.applies(kb["clauses"]["sebi-annexure-i"], regulated_entity.profile("nbfc", ["sebi_regulated"]))
    assert crypto_kb.applies(kb["clauses"]["certin-bom-8.4.2.2"], nbfc)
    assert crypto_kb.applies(kb["clauses"]["nist-ir-8547"], nbfc)  # a reference standard, cited everywhere
    for key, rule in kb["applicability"]["frameworks"].items():  # every pooled framework has an applicability
        assert rule.get("jurisdiction"), key
    assert all("applicability" in c for c in kb["clauses"].values())


# ---------------------------------------------------------------------------------------------- M5
def test_m5_section_7_groups_every_quantum_vulnerable_asset_and_totals_section_3():
    view = staging_like_view()  # 5 quantum-vulnerable: a host key, a KMIP key, two TLS endpoints, a certificate
    groups = population.pqc_target_groups(view)
    assert sum(g["occurrences"] for g in groups) == view.pqc_vulnerable == 5
    by = {g["target"]: g for g in groups}
    kem, sig = population.pq_target("kem"), population.pq_target("signature")
    assert by[sig]["occurrences"] == 3 and by[kem]["occurrences"] == 2  # keys + certificate; two endpoints
    assert dict(by[sig]["kinds"]) == {"key": 2, "certificate": 1} and dict(by[kem]["kinds"]) == {"protocol": 2}
    assert sum(r.occurrences for r in board.pqc_families(view)) == view.pqc_vulnerable
    text = board_text(view)
    section = text[text.index(board.H_PQC):text.index(board.H_GOVERNANCE)]
    assert "Target not recorded" not in section and "Total 5" in section
    assert population.pq_target("kem", 5) in section and population.pq_target("signature", 5) in section


# ---------------------------------------------------------------------------------------------- M6
def test_m6_d1_reconciles_run_assets_occurrences_and_register(seeded):
    engine, _w = seeded
    view = _view(engine)
    counts = population.reconciliation_counts(view)
    # run #1 lists 11 assets; the certificate both linux-app and dc-range observed is counted once
    assert (counts["collected"], counts["counted_once"], counts["sources_occurrences"]) == (11, 1, 10)
    assert counts["register"]["total"] == 10
    steps = " ".join(population.reconciliation_steps(view))
    assert "list 11 assets" in steps and "Minus 1 observation" in steps and "= 10 occurrences" in steps
    # PR #490 (merged): assets without Mosca inputs are graded on the KB default assumptions, so none is Q0
    assert "holds 10 distinct assets" in steps and "Q1 Critical 3, Q2 High 5" in steps and "Q0 Unknown 0" in steps
    text = scope_text(view)
    assert "is counted twice" not in text and "one per source that observed the asset" not in text
    per_source = sum(len(v) for k, v in population.current_assets_by_source(view).items() if k.startswith("sources:"))
    assert per_source == counts["collected"] - counts["counted_once"]


# ---------------------------------------------------------------------------------------------- M7
def test_m7a_appendix_b_lists_every_included_result():
    view = staging_like_view()
    rows = board.scan_rows(view)
    assert sum(1 for r in rows if r[0].startswith("Run #")) == len(view.collections) == 4


def test_m7b_material_risks_list_an_asset_once_across_sources():
    view = staging_like_view()
    first = next(a for a in view.assets if a.impact == "Critical")
    twin = dataclasses.replace(first, source_key="sources:lin", source_label="Linux web tier")
    first = dataclasses.replace(first, asset_key="node|tls|10.0.0.5:443")
    twin = dataclasses.replace(twin, asset_key="node|tls|10.0.0.5:443")
    view = dataclasses.replace(view, assets=tuple(a for a in view.assets if a.impact != "Critical") + (first, twin))
    keys = [population.asset_identity(a) for a in board.material_risks(view)]
    assert len(keys) == len(set(keys)) and keys.count(("key", "node|tls|10.0.0.5:443")) == 1
    assert "also observed by 1 other source" in board_text(view)


def test_m7c_trend_says_first_issue_then_compares_with_the_previous_issue(api, seeded, tmp_path):  # noqa: F811
    engine, _w = seeded
    first = _pdf_text(api("GET", D14).content, tmp_path, "first")
    assert "First issue: no earlier issue of this report is recorded" in first
    again = api("GET", D14)
    assert "First issue" in _pdf_text(again.content, tmp_path, "again")  # the same issue: never compared with itself
    with Session(engine) as s:
        events = s.exec(select(CbomCollectionAuditEvent).where(
            CbomCollectionAuditEvent.action == "deliverable_issued")).all()
        assert len(events) == 1 and events[0].object_id == 14
        assert all(re.fullmatch(r"[a-z_0-9]+=[A-Za-z0-9.\- ]+", f) for f in events[0].changed_fields)
    assert api("PATCH", SETTINGS, json={"risk_model": {"data_shelf_life_years": 10, "migration_years": 5,
                                                       "threat_years": 12}}).status_code == 200
    _regrade(engine)
    second = _pdf_text(api("GET", D14).content, tmp_path, "second")
    assert "Trend against the previous issue" in second and "Previous issue: CBOM-D14-T1-" in second
    # PR #490 (merged) grades missing Mosca inputs on the KB default assumptions: Q1 3 and Q0 0 before and after
    trend = second[second.index("Trend"):][:900]
    assert "Q1 Critical (register) 3 3 no change" in trend and "Q0 Unknown (register) 0 0 no change" in trend, trend
    # D14 section 8 follows the merged register: no "graded Q0 for missing inputs" action when nothing is Q0
    assert "graded Q0 for missing" not in first and "graded Q0 for missing" not in second


def test_m7d_section_5_names_findings_not_codes():
    text = board_text(staging_like_view())
    section = text[text.index(board.H_EXPOSURE):text.index(board.H_REMEDIATION)]
    assert "PROTO_TLS10" not in section and "STATIC_RSA_KEX" not in section
    assert authored.finding_label("PROTO_TLS10") in section


# ---------------------------------------------------------------------------------------------- minors
def test_m1_minor_d1_has_method_window_and_credential_reference_never_a_secret(seeded):
    engine, _w = seeded
    with Session(engine) as s:
        src = s.exec(select(CbomCollectionSource).where(CbomCollectionSource.name == "vault")).one()
        src.secret_fields = ["token"]
        src.secret_encrypted = "gAAAAA-never-printed-secret"
        s.add(src)
        s.commit()
    text = scope_text(_view(engine))
    assert "Collection method, window and credential" in text
    assert "Agentless: live TLS and SSH handshakes from a scan node" in text and "API: the provider's" in text
    assert "IAM role arn:aws:iam::111122223333:role/ZeroShieldCbom" in text
    assert "stored secrets (names): token" in text and "never-printed-secret" not in text


def test_m2_minor_kb_has_the_seven_2026_rbi_instruments_and_para_118_binds_middle_layer_and_above():
    clauses = crypto_kb.load()["clauses"]
    by_entity = {tuple(c.get("applies_to") or ()): k for k, c in clauses.items() if c["framework"] == "RBI"
                 and not c.get("superseded")}
    assert set(by_entity) >= {("nbfc",), ("bank",), ("sfb",), ("payments_bank",), ("ucb",), ("aifi",),
                              ("credit_info_company",)}
    assert "Middle Layer and above" in clauses["rbi-nbfc-2026-para-118"]["note"]
    assert clauses["rbi-md-2023-para-16"]["superseded"] is True
    assert authored.entity_instrument("other") is None
    assert "para 118, which binds NBFCs of the Middle Layer and above" in board_text(staging_like_view())


def test_m3_m4_minor_occurrence_labels_and_d1_tiles_add_up():
    view = staging_like_view()
    text = board_text(view)
    assert "gradeable algorithm occurrences" not in text and "gradeable asset occurrences" in text
    tiles = {label: int(value) for label, value, *_ in __import__(
        "backend.utilities.pdf.cbom_scope_register_pdf", fromlist=["x"])._population_kpis(view)}
    kinds = ("Certificates", "Keys and secrets", "Protocols and endpoints", "Algorithms", "Libraries",
             "Encryption settings")
    assert sum(tiles[k] for k in kinds) == tiles["Asset occurrences"] == view.asset_occurrences


def test_m5_minor_no_ir8547_draft_url_in_either_kb_copy():
    assert KB[0].read_bytes() == KB[1].read_bytes()
    assert b"8547/ipd" not in KB[0].read_bytes()


def test_m6_minor_limits_name_only_the_kinds_collected():
    view = staging_like_view()  # linux_servers, aws_account, network_range, key_manager: no IdP, no database
    first = authored.method_limits(view)[0]
    assert "servers, cloud accounts, key managers and network endpoints" in first
    assert "identity providers" not in first


def test_m8_minor_sources_are_named_by_source_and_counts_are_singular():
    from backend.utilities.cbom_sources.collections_view import Collection

    found = Collection(run_id=1, job_id=2, source_ref="u", source_name="linux-app", source_kind="linux_servers",
                       observed_at=dt.datetime(2026, 11, 14, tzinfo=dt.timezone.utc))
    assert found.label == "linux-app"
    assert board._count(1, "source") == "1 source"


def test_m8_minor_seeded_d14_and_d1_name_sources_by_source(api, seeded, tmp_path):  # noqa: F811
    for url, name in ((D14, "d14"), (D1, "d1")):
        text = _pdf_text(api("GET", url).content, tmp_path, name)
        assert "Sources run #1 ·" not in text and "linux-app" in text, name


def test_n1_clause_titles_do_not_repeat_the_framework():
    assert board.clause_title("NSA CNSA 2.0", "CNSA 2.0 FAQ (April 2024)") == "NSA CNSA 2.0 FAQ (April 2024)"
    assert board.clause_title("RBI", NBFC_CLAUSE) == f"RBI {NBFC_CLAUSE}"
    assert "CNSA 2.0 CNSA 2.0" not in board_text(staging_like_view())


def test_collected_clauses_follow_the_view_profile():
    view = staging_like_view()
    assert not {r.clause for r in collected_clauses(view) if r.clause.startswith("Guidelines for Government")}
    view.regulatory_profile = regulated_entity.profile("nbfc", ["government_entity"])
    assert {r.clause for r in collected_clauses(view) if r.clause.startswith("Guidelines for Government")}
