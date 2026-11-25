"""The CBOM and SBOM results pages show the compliance frameworks that bind the team (``bom_applicability``), as the
AI BOM page does (#498): a bank SEBI does not regulate no longer gets SEBI CSCRF, PCI DSS or EU DORA, and the page's
India chip is named after the regulators left ("India / CERT-In"). The compliance report itself is unchanged: the API
adds ``scan_metadata.compliance_applicability``.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from backend.utilities.cbom_sources import regulated_entity
from backend.utilities.compliance import bom_applicability as ba

REPORT = {"pass": 1, "fail": 1, "na": 0, "requirements": []}
CBOM = {k: dict(REPORT) for k in (
    "nist_1800_38b", "nist_800_57", "omb_m_23_02", "eu_cra", "eu_dora", "pci_dss_4", "fips_140_3", "bsi_tr_02102",
    "cnsa_2_0", "rbi_free_ai_protection", "cert_in_cbom", "sebi_cscrf_cbom")}
CBOM["disclaimer"] = "Advisory."
SBOM = {k: dict(REPORT) for k in (
    "rbi_free_ai_supply", "ntia_minimum_elements", "nist_ssdf", "cert_in_sbom", "sebi_cscrf_sbom")}
SBOM["disclaimer"] = "Advisory."

BANK = regulated_entity.profile("bank")
BROKER_BANK = regulated_entity.profile("bank", ["sebi_regulated", "processes_card_data"])
OTHER = regulated_entity.profile("other")


def test_a_bank_sebi_does_not_regulate_drops_sebi_and_the_foreign_instruments_on_the_cbom_page():
    view = ba.page_view("cbom", CBOM, BANK)
    assert view["binding"] == ["nist_1800_38b", "nist_800_57", "fips_140_3", "cnsa_2_0", "rbi_free_ai_protection",
                               "cert_in_cbom"]
    assert [d["framework"] for d in view["not_applicable"]] == [
        "omb_m_23_02", "eu_cra", "eu_dora", "pci_dss_4", "bsi_tr_02102", "sebi_cscrf_cbom"]
    assert view["basis"] == "Commercial bank in India, not SEBI-regulated"
    assert "disclaimer" not in view["binding"]


def test_a_sebi_regulated_card_processing_bank_keeps_sebi_and_pci():
    view = ba.page_view("cbom", CBOM, BROKER_BANK)
    assert {"sebi_cscrf_cbom", "pci_dss_4", "cert_in_cbom", "rbi_free_ai_protection"} <= set(view["binding"])
    assert view["basis"] == "Commercial bank in India, SEBI-regulated"


def test_the_sbom_page_follows_the_clause_frameworks():
    assert ba.page_view("sbom_sca", SBOM, BANK)["binding"] == [
        "rbi_free_ai_supply", "ntia_minimum_elements", "nist_ssdf", "cert_in_sbom"]
    # an "other" entity is not RBI-regulated: RBI FREE-AI goes too
    other = ba.page_view("sbom_sca", SBOM, OTHER)
    assert other["binding"] == ["ntia_minimum_elements", "nist_ssdf", "cert_in_sbom"]
    assert other["not_applicable"] == [{"framework": "rbi_free_ai_supply", "label": "RBI FREE-AI (Supply Chain)"},
                                       {"framework": "sebi_cscrf_sbom", "label": "SEBI CSCRF"}]
    # no profile declared: every framework, said so
    none = ba.page_view("sbom_sca", SBOM, None)
    assert none["binding"] == [k for k in SBOM if k != "disclaimer"] and none["basis"] == ba.UNDECLARED


class _Session:
    def __init__(self, risk_model):
        self.row = None if risk_model is None else SimpleNamespace(risk_model=risk_model)

    def exec(self, *_a, **_k):
        return SimpleNamespace(first=lambda: self.row)


@pytest.mark.parametrize("risk_model,scan_type,entity,declared", [
    ({"regulated_entity": "bank"}, "cbom", "bank", True),
    ({"regulated_entity": "bank"}, "sbom_sca", "bank", True),
    (None, "cbom", "nbfc", False),  # the CBOM PDF's and board report's NBFC default
    ({}, "cbom", "nbfc", False),
    (None, "sbom_sca", None, False),  # the SBOM page shows every framework, as the AI BOM page
    ({"aws_external_id": "x"}, "sbom_sca", None, False),
])
def test_which_profile_each_page_filters_by(risk_model, scan_type, entity, declared):
    team, was_declared = ba.team_profile_for(_Session(risk_model), 1, scan_type)
    assert (team["entity"] if team else None, was_declared) == (entity, declared)


def test_an_undeclared_cbom_team_reads_the_default_in_the_basis():
    view = ba.page_view("cbom", CBOM, regulated_entity.DEFAULT_PROFILE, declared=False)
    assert view["basis"] == "NBFC in India, not SEBI-regulated (default: no regulated entity declared)"


def test_the_metadata_gains_the_view_and_keeps_the_report(monkeypatch):
    import sqlmodel

    class _Ctx:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return _Session({"regulated_entity": "bank"})

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr(sqlmodel, "Session", _Ctx)
    meta = {"cbom_compliance": CBOM, "branch": "main"}
    out = ba.with_applicability("cbom", meta, engine=object(), team_id=3)
    assert out["cbom_compliance"] is CBOM and out["branch"] == "main"  # nothing removed
    assert "sebi_cscrf_cbom" not in out[ba.KEY]["binding"]
    sb = ba.with_applicability("sbom_sca", {"sbom_compliance": SBOM}, engine=object(), team_id=3)
    assert sb[ba.KEY]["binding"][-1] == "cert_in_sbom"
    # other products, and a scan without a report, are unchanged
    assert ba.with_applicability("ai_bom", {"ai_bom_compliance": {}}, engine=object(), team_id=3) == {
        "ai_bom_compliance": {}}
    assert ba.KEY not in ba.with_applicability("cbom", {"cbom_compliance": None}, engine=object(), team_id=3)


def test_a_profile_read_failure_keeps_the_page_as_before(monkeypatch):
    import sqlmodel

    def boom(*_a, **_k):
        raise RuntimeError("db down")

    monkeypatch.setattr(sqlmodel, "Session", boom)
    meta = {"sbom_compliance": SBOM}
    assert ba.with_applicability("sbom_sca", meta, engine=object(), team_id=3) == meta


def test_get_scan_adds_the_view():
    """The router passes every CBOM / SBOM scan's metadata through ``with_applicability`` before answering."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "routers" / "scans.py").read_text(encoding="utf-8")
    body = src[src.index("async def get_scan("):src.index("def _payload_section(")]
    assert "scan_metadata = bom_applicability.with_applicability(type, scan_metadata, engine, team_id)" in body
    assert body.index("with_applicability") < body.index('"scan_metadata": scan_metadata')
