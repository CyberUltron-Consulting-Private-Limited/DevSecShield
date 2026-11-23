"""FIX-A3 (SOW audit AUD-A, 23 Nov 2026): D14 Board / IT Strategy Committee Report, D1 Scope Baseline and Asset
Population Register, and the SOW numbering shared by every team deliverable.

Each test pins one audit finding (``/home/claude/cb38/sow/audit-A.md``) with the staging evidence it came from:

* A-05  D14 cited NIST IR 8547 as "final, 2026" in section 5 and as "initial public draft" in section 7 and Appendix C.
        NIST published the final IR 8547 on 27 Oct 2026 (csrc.nist.gov/pubs/ir/8547/final). ONE citation, from the KB.
* A-06  "Limits of the method" said "No live-network discovery" on a page that says 212 endpoints were probed;
        D1 section E listed "Live TLS endpoints" as outside visibility.
* A-07  Readiness printed 12.2 % under the formula safe / (safe + vulnerable) = 102 / 767 = 13.3 %.
* A-11  Compliance % pooled over 1 of 57 sources presented as estate compliance; RBI mapped to the Commercial Banks
        Directions for an NBFC client.
* A-12  Remediation rows printed raw codes ("Proto tls10") with one boilerplate action; no Q-grade summary.
* A-04  PDFs printed D02 / D15 / D16 where the SOW numbers the documents D12 / D13 / D14.
* A-09  2277 occurrences vs 2043 distinct assets vs 2080 BOM components with no reconciliation.
* A-10  D1: no per-layer (L1-L4) population, Sources assets in "Other", owner / application blank although the
        source metadata (C5) holds them.

Oracles are literals (counts typed in the test), never the product's own aggregation.
"""
from __future__ import annotations

import dataclasses
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from reportlab.platypus import KeepTogether, Paragraph, Table

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    ASSET_ALGORITHM,
    ASSET_CERTIFICATE,
    ASSET_MATERIAL,
    ASSET_OTHER,
    ASSET_PROTOCOL,
    SOURCE_REPO,
    SOURCE_SOURCES,
    AssetAgg,
    CollectionAgg,
    FrameworkPool,
    SourceAgg,
    TeamCbomView,
)
from backend.utilities.pdf import cbom_board_report_pdf as board  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_common as common  # noqa: E402
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf import cbom_scope_register_pdf as scope  # noqa: E402
from backend.utilities.pdf.cbom_collected_compliance import collected_clauses  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

NOW = datetime(2026, 11, 23, 14, 42, tzinfo=timezone.utc)
KB_FILES = (_REPO_ROOT / "backend/utilities/cbom_sources/data/crypto_kb.json",
            _REPO_ROOT / "aibom/src/aibom/cbom/data/crypto_kb.json")


# ---------------------------------------------------------------------------------------------- helpers
def _text(item) -> str:
    if isinstance(item, Paragraph):
        return html.unescape(re.sub(r"<[^>]+>", "", re.sub(r"<br\s*/?>", "\n", item.text)))
    if isinstance(item, str):
        return item
    if isinstance(item, Table):
        return "\n".join(t for row in item._cellvalues for t in (_text(c) for c in row) if t)
    if isinstance(item, KeepTogether):
        return "\n".join(t for t in (_text(c) for c in item._content) if t)
    if isinstance(item, (list, tuple)):
        return "\n".join(t for t in (_text(c) for c in item) if t)
    return ""


def _flat(text: str) -> str:
    return " ".join(text.split())


def board_text(view: TeamCbomView) -> str:
    return _flat(_text(board._body(view, common.get_deliverable_styles(), 540.0)))


def scope_text(view: TeamCbomView) -> str:
    return _flat(_text(scope.build_body(view, common.get_deliverable_styles(), 540.0)))


def _source(key: str, label: str, kind: str) -> SourceAgg:
    return SourceAgg(key=key, label=label, kind=kind, repo_url=None, branch=None, scan_ids=(1,), scan_count=1,
                     first_scanned=NOW, last_scanned=NOW, current_scan_id=1, current_tier="A", current_fidelity="full",
                     last_attempt_scan_id=1, last_attempt_status="success", last_attempt_at=NOW)


def _asset(source_key: str, asset_type: str, ident: str, *, impact: str = "Info", codes: tuple = (),
           row_kind: str | None = None, node_type: str | None = None, qv: bool | None = None,
           broken: bool = False) -> AssetAgg:
    return AssetAgg(source_key=source_key, source_label=source_key, asset_type=asset_type, ident=ident, title=ident,
                    location=ident, impact=impact, finding_codes=codes, current=True, first_seen=NOW, last_seen=NOW,
                    quantum_vulnerable=qv, broken_today=broken, row_kind=row_kind, node_type=node_type)


def _collection(key: str, name: str, kind: str, probed: int = 0, **meta) -> CollectionAgg:
    return CollectionAgg(key=key, label=f"Sources run #50 · {name}", source_name=name, source_kind=kind, run_id=50,
                         job_id=abs(hash(key)) % 10_000, observed_at=NOW, endpoints_probed=probed, metadata=meta)


def staging_like_view(**overrides) -> TeamCbomView:
    """One repository (code scan) and four CBOM Sources collections, one per SOW layer L2-L4, with probing."""
    code = "repo:github.com/acme/pay@main"
    lin, aws, net, kmip = "sources:lin", "sources:aws", "sources:net", "sources:kmip"
    sources = (_source(code, "github.com/acme/pay (main)", SOURCE_REPO),
               _source(lin, "Sources run #50 · Linux web tier", SOURCE_SOURCES),
               _source(aws, "Sources run #50 · aws-prod", SOURCE_SOURCES),
               _source(net, "Sources run #50 · Lab network", SOURCE_SOURCES),
               _source(kmip, "Sources run #50 · KMIP key server", SOURCE_SOURCES))
    collections = (
        _collection(lin, "Linux web tier", "linux_servers", owner="Payments platform team", application="Payments",
                    data_classification="confidential", data_lifetime_years=10, business_criticality="high",
                    exposure="internet"),
        _collection(aws, "aws-prod", "aws_account", owner="Cloud CoE"),
        _collection(net, "Lab network", "network_range", probed=3),
        _collection(kmip, "KMIP key server", "key_manager"),
    )
    assets = (
        # L1: the code scan, an algorithm (quantum-safe) and a library row of the engine ("other", kind library)
        _asset(code, ASSET_ALGORITHM, "AES-256-GCM", row_kind="symmetric", qv=False),
        _asset(code, ASSET_OTHER, "pyjwt@2.3.0", impact="High", codes=("VULNERABLE_CRYPTO_LIBRARY",), row_kind="library"),
        # L2: a host key, a crypto library loaded by a process and a disk encryption setting
        _asset(lin, ASSET_MATERIAL, "ssh-rsa host key", row_kind="key", node_type="ssh_host_key", qv=True),
        _asset(lin, ASSET_OTHER, "libssl.so.3", impact="Medium", codes=("LIB_EOL",), row_kind="library",
               node_type="process_library"),
        _asset(lin, ASSET_OTHER, "LUKS /dev/sda2", row_kind="configuration", node_type="disk_encryption"),
        # L3: a KMS key, an S3 bucket setting and an HSM key
        _asset(aws, ASSET_MATERIAL, "alias/payments", impact="High", codes=("KMS_NO_ROTATION",), row_kind="key",
               node_type="kms_key", qv=False),
        _asset(aws, ASSET_OTHER, "s3://logs", impact="High", codes=("STORAGE_UNENCRYPTED",),
               row_kind="configuration", node_type="storage_encryption"),
        _asset(kmip, ASSET_MATERIAL, "kmip-key-7", row_kind="key", node_type="managed_key", qv=True),
        # L4: three probed TLS endpoints, one on TLS 1.0
        _asset(net, ASSET_PROTOCOL, "10.0.0.5:443", impact="Critical", codes=("PROTO_TLS10", "STATIC_RSA_KEX"),
               row_kind="protocol", node_type="tls_endpoint", qv=True),
        _asset(net, ASSET_PROTOCOL, "10.0.0.6:443", row_kind="protocol", node_type="tls_endpoint", qv=True),
        _asset(net, ASSET_CERTIFICATE, "CN=lab", impact="Low", codes=("CERT_SELF_SIGNED",), row_kind="certificate",
               node_type="certificate", qv=True),
        _asset(net, ASSET_ALGORITHM, "MD5", impact="High", codes=("SIG_MD5",), row_kind="hash", qv=False, broken=True),
    )
    view = TeamCbomView(team_id=1, team_name="Staging", generated_at=NOW, as_of=NOW.date())
    view = dataclasses.replace(
        view, scans_total=5, eligible=5, included=5, fidelity_full=5, sources=sources, assets=assets,
        collections=collections, asset_occurrences=len(assets),
        issue_by_impact={"Critical": 1, "High": 4, "Medium": 1, "Low": 1},
        # readiness inputs: 3 safe (AES, KMS key) ... typed as the oracle, not recomputed
        pqc_vulnerable=5, pqc_safe=2, pqc_broken_today=1, readiness_pct=25.0, compliance_sources_pooled=1,
        frameworks=(FrameworkPool(framework="eu_cra", passed=0, failed=2, sources_pooled=1, coverage=0.0),
                    FrameworkPool(framework="cnsa_2_0", passed=4, failed=1, sources_pooled=5, coverage=0.8)),
        **overrides)
    view.register = {"summary": {"total": 10, "q_grades": {"Q0": 4, "Q1": 1, "Q2": 0, "Q3": 2, "Q4": 3, "none": 0},
                                 "q0_reasons": {"mosca_missing": 3, "unknown_verdict": 1}, "q0_gaps_open": {},
                                 "families": {}, "closures_by_week": [], "pending_regrade": 0}}
    return view


# ---------------------------------------------------------------------------------------------- A-05 IR 8547
def test_kb_carries_ir8547_as_final_with_one_citation_and_both_copies_are_identical():
    assert KB_FILES[0].read_bytes() == KB_FILES[1].read_bytes()
    kb = json.loads(KB_FILES[0].read_text(encoding="utf-8"))
    ir = kb["pqc_context"]["nist_ir_8547"]
    assert (ir["status"], ir["published"], ir["deprecated_after"], ir["disallowed_after"]) == (
        "final", "2026-10-27", 2030, 2035)
    assert ir["landing"] == "https://csrc.nist.gov/pubs/ir/8547/final"
    clause = kb["clauses"]["nist-ir-8547"]
    assert f"{clause['framework']} {clause['id']}" == ir["citation"] == "NIST IR 8547 (final, 2026)"
    assert crypto_kb._version_key(kb["kb_version"]) > crypto_kb._version_key("2026.11.15.6")


def test_every_ir8547_mention_in_the_board_report_is_the_kb_citation_and_none_says_draft():
    text = board_text(staging_like_view())
    citation = crypto_kb.load()["pqc_context"]["nist_ir_8547"]["citation"]
    assert "8547" in text
    assert "draft" not in text.lower(), "the final IR 8547 is cited as a draft somewhere"
    for match in re.finditer(r"IR 8547[^.;]{0,20}", text):
        start = max(0, match.start() - 5)
        assert text[start:].startswith("NIST " + citation[5:]) or citation in text[start - 1:match.end() + 20], \
            text[start:match.end()]
    rows = authored.pqc_timeline_rows()
    nist = [r for r in rows if "8547" in r.source]
    assert nist and {r.status for r in nist} == {"Final"} and {r.url for r in nist} == {
        "https://csrc.nist.gov/pubs/ir/8547/final"}
    assert {r.source for r in nist} == {citation}
    assert "Oct 2026" in [r.when for r in nist]


def test_standards_verdict_text_cites_the_final_ir8547():
    from backend.utilities.cbom_sources import standards

    assert "(draft)" not in standards._IR8547_112 and "(draft)" not in standards._IR8547_128
    assert "NIST IR 8547 (final, 2026)" in standards._IR8547_112


# ---------------------------------------------------------------------------------------------- A-06 limits
def test_limits_of_the_method_follow_what_was_collected():
    text = board_text(staging_like_view())
    assert "No live-network discovery" not in text
    assert "Static analysis only" not in text
    assert "3 endpoints were probed with live TLS or SSH handshakes" in text
    code_only = dataclasses.replace(staging_like_view(), collections=())
    assert "No live-network discovery" in board_text(code_only)


def test_d1_outside_visibility_does_not_deny_probing_or_key_custody_reads():
    text = scope_text(staging_like_view())
    assert "Outside static visibility" not in text
    assert "Live TLS endpoints Negotiated versions and cipher suites need network probing" not in text
    assert "Outside collected visibility" in text
    code_only = dataclasses.replace(staging_like_view(), collections=())
    assert "Live TLS endpoints" in scope_text(code_only)


# ---------------------------------------------------------------------------------------------- A-07 readiness
def test_printed_readiness_formula_reproduces_the_printed_figure():
    text = board_text(staging_like_view())
    match = re.search(r"Readiness = quantum-safe / \(quantum-safe \+ quantum-vulnerable \+ broken today\) = "
                      r"(\d+) / \((\d+) \+ (\d+) \+ (\d+)\) = ([\d.]+)%", text)
    assert match, text[:4000]
    safe, safe2, vulnerable, broken, pct = match.groups()
    assert safe == safe2 and (safe, vulnerable, broken) == ("2", "5", "1")
    assert round(100 * int(safe) / (int(safe) + int(vulnerable) + int(broken)), 1) == float(pct) == 25.0
    assert "Readiness = quantum-safe algorithm occurrences / (quantum-safe + quantum-vulnerable occurrences)" \
        not in text


# ---------------------------------------------------------------------------------------------- A-11 coverage + RBI
def test_compliance_rows_state_their_source_basis_and_are_not_estate_compliance():
    text = board_text(staging_like_view())
    assert "EU CRA 0.0% 0 2 0 0 1 of 5 sources" in text
    assert "CNSA 2.0 80.0% 4 1 0 0 5 of 5 sources" in text
    assert "not a measure of estate-wide compliance" in text


def test_rbi_mapping_defaults_to_the_nbfc_directions_and_never_cites_the_commercial_banks_directions():
    view = staging_like_view()
    assert view.regulated_entity == "nbfc"
    rbi = {r.clause for r in collected_clauses(view) if r.framework == "RBI"}
    assert any("NBFC" in c and "para 118" in c for c in rbi), rbi
    assert not any("Commercial Banks" in c for c in rbi), rbi
    assert not any("Master Direction on IT Governance (2023)" in c for c in rbi), rbi
    text = board_text(view)
    assert "Commercial Banks" not in text
    assert "Regulated entity: NBFC" in text


def test_rbi_mapping_for_a_bank_team_cites_the_commercial_banks_directions():
    view = dataclasses.replace(staging_like_view(), regulated_entity="bank")
    rbi = {r.clause for r in collected_clauses(view) if r.framework == "RBI"}
    assert any("Commercial Banks Cybersecurity Directions 2026, para 140" == c for c in rbi), rbi
    assert not any("NBFC" in c for c in rbi), rbi


def test_kb_nbfc_clause_quotes_para_118_and_applies_to_nbfcs_only():
    clause = crypto_kb.load()["clauses"]["rbi-nbfc-2026-para-118"]
    assert clause["applies_to"] == ["nbfc"]
    assert clause["text"].startswith("The key length, algorithms, cipher suites, and applicable protocols")
    assert crypto_kb.load()["clauses"]["rbi-cb-2026-para-140"]["applies_to"] == ["bank"]
    assert "rbi-nbfc-2026-para-118" in crypto_kb.entry("node", "PROTO_TLS10")["clauses"]
    assert "rbi-nbfc-2026-para-118" in crypto_kb.entry("node", "NO_TLS")["clauses"]  # transmission channels
    assert "rbi-nbfc-2026-para-118" not in crypto_kb.entry("node", "STORAGE_UNENCRYPTED")["clauses"]  # at rest


# ---------------------------------------------------------------------------------------------- A-12 remediation
def test_remediation_rows_use_kb_titles_and_specific_actions():
    rows = {r.code: r for r in board.remediation_rows(staging_like_view())}
    tls10 = rows["PROTO_TLS10"]
    assert tls10.label == crypto_kb.entry("node", "PROTO_TLS10")["title"]
    assert tls10.action == crypto_kb.entry("node", "PROTO_TLS10")["remediation"]["summary"]
    for row in rows.values():
        assert row.action != authored.GENERIC_FINDING_ACTION, row.code
        assert row.label != row.code.replace("_", " ").capitalize(), row.label  # staging printed "Proto tls10"


def test_board_report_has_the_quantum_risk_grade_summary_and_a_mosca_action():
    text = board_text(staging_like_view())
    assert "Quantum risk grades (D12)" in text
    assert "Q1 Critical 1" in text and "Q0 Unknown 4" in text
    assert "Mosca inputs missing 3" in text
    assert "Set the data-lifetime and migration inputs (Mosca X, Y, Z)" in text
    assert "Re-scan the 0 sources" not in text


# ---------------------------------------------------------------------------------------------- A-04 SOW IDs
SOW = {"scope-baseline-register": (1, "Scope Baseline and Asset Population Register"),
       "methodology-evidence-plan": (2, "Discovery Methodology and Evidence Plan"),
       "infrastructure-cloud-encryption-posture": (6, "Infrastructure and Cloud Encryption Posture"),
       "network-tls-protocol-assessment": (7, "Network, TLS and Crypto Protocol Assessment"),
       "certificate-estate-register": (8, "Certificate Estate Register"),
       "data-at-rest-encryption-assessment": (9, "Data-at-Rest Encryption Assessment"),
       "third-party-assurance-register": (10, "Third-Party Cryptographic Assurance and Attestation Register"),
       "quantum-risk-register": (12, "Quantum Risk Register"),
       "pqc-migration-roadmap": (13, "PQC Migration Roadmap"),
       "board-executive-report": (14, "Board / IT Strategy Committee Report")}


def test_registry_numbers_and_titles_are_the_sow_table_7_ids():
    assert {slug: (s.number, s.title) for slug, s in DELIVERABLES.items()} == SOW
    assert [s.number for s in DELIVERABLES.values()] == sorted(n for n, _t in SOW.values())


@pytest.mark.parametrize("slug", sorted(SOW))
def test_every_printed_document_id_carries_the_sow_id(slug):
    spec = DELIVERABLES[slug]
    assert common.sow_number(spec.report_key) == SOW[slug][0]
    view = TeamCbomView(team_id=1, team_name="T", generated_at=NOW, as_of=NOW.date(), fingerprint="0ac3f091e6b8")
    assert common.document_id(view, common.sow_number(spec.report_key)) == f"CBOM-D{SOW[slug][0]:02d}-T1-20261123-0ac3f091"
    assert REPORT_META[spec.report_key]["title"] == SOW[slug][1]


def test_authored_text_refers_to_documents_by_sow_id():
    blob = " ".join(authored.disclaimer_paragraphs(None)) + " ".join(authored.METHOD_LIMITS)
    assert "#5" not in blob and "#6" not in blob and "#9" not in blob
    assert "D6, D7 and D9" in blob


# ---------------------------------------------------------------------------------------------- A-09 reconciliation
def test_population_reconciliation_line_in_d1_and_d14():
    view = staging_like_view()
    expected = ("Population reconciliation: 12 asset occurrences (one per source that observed the asset: 2 in code "
                "scans, 10 in CBOM Sources collections); 10 distinct assets in the quantum risk register (D12)")
    assert expected in board_text(view)
    assert expected in scope_text(view)


# ---------------------------------------------------------------------------------------------- A-10 D1 population
def test_d1_counts_assets_per_sow_layer():
    text = scope_text(staging_like_view())
    # layer, sources, assets
    for line in ("L1 Code, pipelines and images 1 2", "L2 Servers, Kubernetes and databases 1 3",
                 "L3 Cloud keys, HSMs, PKI and identity 2 3", "L4 Network, TLS and appliances 1 4"):
        assert line in text, line


def test_d1_never_puts_sources_assets_in_other():
    text = scope_text(staging_like_view())
    assert "Other types" not in text
    # Assets by kind and impact: Critical High Medium Low Info Total
    assert "Libraries 0 1 1 0 0 2" in text  # pyjwt (code scan, High) and libssl (Linux, Medium)
    assert "Encryption settings 0 1 0 0 1 2" in text  # S3 bucket (High) and LUKS volume (Info)


def test_d1_prefills_source_metadata_and_marks_unknowns_to_confirm():
    text = scope_text(staging_like_view())
    assert ("Sources run #50 · Linux web tier L2 Payments platform team Payments confidential 10 years high internet"
            in text), text
    assert "Sources run #50 · aws-prod L3 Cloud CoE to confirm" in text
    assert "github.com/acme/pay (main) L1 to confirm" in text
