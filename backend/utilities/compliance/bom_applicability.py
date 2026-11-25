"""Which CBOM and SBOM compliance frameworks bind a team, for the results pages' compliance matrix.

The engine's compliance report of a CBOM (``cbom_compliance``) or an SBOM (``sbom_compliance``) holds every framework
it knows, so the results page offered SEBI CSCRF, PCI DSS, EU DORA … and an "India / CERT-In / SEBI" chip to a bank
that SEBI does not regulate. The page now shows the frameworks that bind the team, by its regulatory profile
(``regulated_entity``, #485), and names the others as not applicable (never silently dropped), as the AI BOM page does
(PR #498, ``aibom_applicability``):

* a CBOM framework follows the knowledge base's own rule for that key (``crypto_kb`` ``applicability.frameworks``:
  SEBI CSCRF needs a SEBI-regulated team, PCI DSS a team that processes card data, RBI FREE-AI one of the seven RBI
  entity types, EU / US / German instruments their jurisdiction, NIST / CNSA / FIPS everyone);
* an SBOM framework follows the clause framework it belongs to (CERT-In any Indian team, RBI the RBI entity types,
  SEBI CSCRF a SEBI-regulated team, NIST everyone); the NTIA minimum elements are a baseline every SBOM is held to.

Profiles: the CBOM page reads ``regulated_entity.team_profile`` (NBFC when the team declared none), the profile the
CBOM PDF and the board report already filter by, so the page and its PDF list the same frameworks. The SBOM page reads
the declared profile only: a team that never declared a regulated entity sees every framework ("regulated entity not
set"), as on the AI BOM page. The API adds ``scan_metadata.compliance_applicability``; the compliance report itself is
unchanged.
"""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from backend.utilities.cbom_sources import regulated_entity

KEY = "compliance_applicability"
SCAN_TYPES = ("cbom", "sbom_sca")
UNDECLARED = "regulated entity not set"

# SBOM framework key -> the knowledge base's clause framework that states who it binds (None: binds every team)
_SBOM_RULE: dict[str, str | None] = {
    "cert_in_sbom": "CERT-In",
    "rbi_free_ai_supply": "RBI",
    "sebi_cscrf_sbom": "SEBI CSCRF",
    "nist_ssdf": "NIST",
    "ntia_minimum_elements": None,
}
LABELS = {
    "cert_in_cbom": "CERT-In CBOM", "sebi_cscrf_cbom": "SEBI CSCRF", "rbi_free_ai_protection": "RBI FREE-AI (Protection)",
    "pci_dss_4": "PCI-DSS 4.0", "eu_cra": "EU CRA", "eu_dora": "EU DORA", "omb_m_23_02": "OMB M-23-02",
    "bsi_tr_02102": "BSI TR-02102", "nist_1800_38b": "NIST SP 1800-38B", "nist_1800_38c": "NIST SP 1800-38C",
    "nist_800_57": "NIST SP 800-57", "fips_140_3": "FIPS 140-3", "cnsa_2_0": "CNSA 2.0",
    "cert_in_sbom": "CERT-In SBOM", "sebi_cscrf_sbom": "SEBI CSCRF", "rbi_free_ai_supply": "RBI FREE-AI (Supply Chain)",
    "nist_ssdf": "NIST SSDF (SP 800-218)", "ntia_minimum_elements": "NTIA Minimum Elements",
}


def binds(scan_type: str, key: str, team: Mapping[str, Any] | None) -> bool:
    """Whether framework ``key`` of a ``scan_type`` compliance report binds a team with profile ``team`` (None: no
    profile, every framework is shown)."""
    if team is None:
        return True
    if scan_type == "sbom_sca":
        rule = _SBOM_RULE.get(key)
        return True if rule is None else regulated_entity.framework_binds(rule, dict(team))
    return regulated_entity.framework_binds(key, dict(team))


def profile_sentence(team: Mapping[str, Any] | None, *, declared: bool = True) -> str:
    """"Commercial bank in India, not SEBI-regulated"; "regulated entity not set" without a profile."""
    if team is None:
        return UNDECLARED
    entity = regulated_entity.LABELS[regulated_entity.normalise(team.get("entity"))]
    flags = set(team.get("flags") or ())
    text = f"{entity} in India, " + ("SEBI-regulated" if "sebi_regulated" in flags else "not SEBI-regulated")
    return text if declared else f"{text} (default: no regulated entity declared)"


def page_view(scan_type: str, compliance: Any, team: Mapping[str, Any] | None, *,
              declared: bool = True) -> dict[str, Any] | None:
    """``{regulatory_profile, basis, binding: [keys], not_applicable: [{framework, label}]}`` of a compliance report,
    in the report's order; None without a report. Non-framework keys (the disclaimer) are in neither list."""
    if not isinstance(compliance, Mapping):
        return None
    binding: list[str] = []
    dropped: list[str] = []
    for key, report in compliance.items():
        if not isinstance(report, Mapping):
            continue
        (binding if binds(scan_type, str(key), team) else dropped).append(str(key))
    return {
        "regulatory_profile": dict(team) if team is not None else None,
        "basis": profile_sentence(team, declared=declared),
        "binding": binding,
        "not_applicable": [{"framework": key, "label": LABELS.get(key, key)} for key in dropped],
    }


def _settings_risk_model(session: Any, team_id: int) -> Mapping[str, Any] | None:
    from sqlmodel import select

    from backend.new_models import CbomCollectionSettings

    row = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
    model = row.risk_model if row is not None else None
    return model if isinstance(model, Mapping) else None


def team_profile_for(session: Any, team_id: int, scan_type: str) -> tuple[dict[str, Any] | None, bool]:
    """``(profile, declared)``: the profile a ``scan_type`` page filters by (see the module docstring) and whether the
    team declared it. (PR #498's ``regulated_entity.declared_team_profile`` reads the same row the same way.)"""
    return profile_of_risk_model(_settings_risk_model(session, team_id), scan_type)


def profile_of_risk_model(risk_model: Any, scan_type: str) -> tuple[dict[str, Any] | None, bool]:
    """``team_profile_for`` from a settings row's ``risk_model`` already read (the Sources run endpoints hold it)."""
    model = risk_model if isinstance(risk_model, Mapping) else None
    declared = model is not None and bool(str(model.get(regulated_entity.SETTINGS_KEY) or "").strip())
    if declared:
        return regulated_entity.profile_of(model), True
    if scan_type == "cbom":
        return regulated_entity.profile_of(model), False
    return None, False


def with_run_applicability(parity: Any, risk_model: Any) -> Any:
    """A Sources run's ``/parity`` answer (its ``scan_metadata``: the code page's sections) plus
    ``scan_metadata.compliance_applicability`` for its ``cbom_compliance``, by the team's profile, as a CBOM code scan's
    ``get_scan``: the run page shows the same frameworks and chips as the code page and the CBOM PDF. The cached
    parity is not changed (a copy is returned)."""
    meta = parity.get("scan_metadata") if isinstance(parity, Mapping) else None
    if not isinstance(meta, Mapping) or not isinstance(meta.get("cbom_compliance"), Mapping):
        return parity
    team, declared = profile_of_risk_model(risk_model, "cbom")
    view = page_view("cbom", meta["cbom_compliance"], team, declared=declared)
    return {**parity, "scan_metadata": {**meta, KEY: view}}


def with_applicability(scan_type: str, scan_metadata: Any, engine: Any, team_id: int) -> Any:
    """``scan_metadata`` plus ``compliance_applicability`` for a CBOM or SBOM scan with a compliance report; anything
    else unchanged. A failure to read the profile leaves the metadata as it was (the page then shows every
    framework, as before)."""
    if scan_type not in SCAN_TYPES or not isinstance(scan_metadata, Mapping):
        return scan_metadata
    compliance = scan_metadata.get("cbom_compliance" if scan_type == "cbom" else "sbom_compliance")
    if not isinstance(compliance, Mapping):
        return scan_metadata
    from sqlmodel import Session

    try:
        with Session(engine) as session:
            team, declared = team_profile_for(session, team_id, scan_type)
    except Exception:  # the page still renders, with every framework (as before this view)
        logging.getLogger(__name__).warning("compliance applicability: team profile not read", exc_info=True)
        return scan_metadata
    return {**scan_metadata, KEY: page_view(scan_type, compliance, team, declared=declared)}


__all__ = ["KEY", "LABELS", "SCAN_TYPES", "UNDECLARED", "binds", "page_view", "profile_of_risk_model",
           "profile_sentence", "team_profile_for", "with_applicability", "with_run_applicability"]
