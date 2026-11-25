"""Staging QA round 2, lane Q1: D2 (methodology) and D14 (board report) findings.

* Q1-03: D2 section 13 mapped D12 / D13 / D14 to "Team CBOM deliverable #2 / #15 / #16" (hard-coded menu positions);
  now every team deliverable's number and formats come from the deliverables manifest.
* Q1-04: D2 section 11 listed every framework (OMB, EU CRA, DORA, PCI, BSI, SEBI) for an NBFC, and the NBFC and the
  bank D2 were identical; now it shows the frameworks that bind the team's regulatory profile and names the others
  as not applicable, the rule D14 section 5 applies.
* Q1-05: D2's asset-type table (CycloneDX types: "Algorithm 277") disagreed with D1 ("Algorithms 8, Encryption
  settings 270"); now it prints D1's kinds and numbers.
* Q1-06: with the team's Mosca X/Y/Z unset, D14 said "under the team's Mosca inputs" and D2 said mosca_missing 0
  without saying why; the grade applies documented defaults (``qgrade.effective_mosca``'s ``assumed``), so both now
  say "default Mosca assumptions (team inputs not set)" with the number of assets graded on them, and D14 section 8
  asks the board to set the data lifetimes.
* Q1-07: D14 section 1 said "Issue assets 942", section 2 "Top 10 of 812": now one wording,
  "812 distinct issue assets (942 occurrences)", in sections 1 and 2 and Appendix A.
* Q1-16 (D2 / D14 polish): the grade table cut "Disallowe…"; "Proto sslv3"; the 175 vs 212 endpoints unexplained.
"""
from __future__ import annotations

import dataclasses
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_deliverable_methodology as H
from backend.tests.support import sources_every_type as FX
from backend.utilities.cbom_sources import qgrade as QG
from backend.utilities.dashboard import cbom_team_rollup as R
from backend.utilities.pdf import cbom_board_report_pdf as d14
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf import cbom_kb_text as kb_text
from backend.utilities.pdf import cbom_methodology_pdf as d2
from backend.utilities.pdf import cbom_methodology_text as M
from backend.utilities.pdf import cbom_scope_register_pdf as d1
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _profile(view, entity: str):
    view = dataclasses.replace(view)
    view.regulatory_profile = {"jurisdiction": "IN", "entity": entity, "flags": []}
    view.regulated_entity = entity
    return view


def _sources_view() -> R.TeamCbomView:
    rows, collections = FX.build()
    view = R.TeamCbomView(team_id=1, team_name="Team", generated_at=H.fold().generated_at, as_of=H.fold().as_of,
                          fingerprint="f00dfeed")
    return R.merge_collections(view, rows, collections)


# ----------------------------------------------------------------------------- Q1-03
def test_section13_numbers_and_formats_come_from_the_manifest():
    plan = {row[0]: row for row in M.evidence_plan()}
    for spec in DELIVERABLES.values():
        if spec.number == 2:
            continue  # D2 is this document
        produced = plan[f"D{spec.number}"][2]
        assert produced.startswith(f"Team CBOM deliverable #{spec.number} (PDF)"), (spec.slug, produced)
        assert ("CSV" in produced.split(";")[0]) == (spec.build_csv is not None), produced
    assert M.EVIDENCE_PLAN == M.evidence_plan()  # the module name still reads the same rows


def test_d2_prints_d12_d13_d14_with_their_sow_numbers():
    thirteen = H.section(H.body_text(d2.build_pdf(H.fold())), 13)
    for sow in ("D12", "D13", "D14"):
        assert f"Team CBOM deliverable #{sow[1:]} (PDF" in thirteen, sow
    for stale in ("#2 (PDF", "#15 (PDF", "#16 (PDF"):
        assert stale not in thirteen


# ----------------------------------------------------------------------------- Q1-04
def test_section11_shows_the_frameworks_that_bind_the_profile_and_names_the_others():
    view = H.fold()
    for entity in ("nbfc", "bank"):
        seen = _profile(view, entity)
        eleven = H.section(H.body_text(d2.build_pdf(seen)), 11)
        hidden = [authored.framework_label(k) for k in authored.FRAMEWORK_LABELS
                  if not kb_text.framework_binds(k, seen)]
        shown = [authored.framework_label(k) for k in authored.FRAMEWORK_LABELS if kb_text.framework_binds(k, seen)]
        assert d2._framework_keys(seen) == [k for k in d2._all_framework_keys(seen) if kb_text.framework_binds(k, seen)]
        if hidden:
            assert "Not applicable and not shown: " + ", ".join(hidden) in eleven, entity
        assert all(label in eleven for label in shown), entity
        assert d14.profile_text(seen) in eleven


def test_the_nbfc_and_the_bank_d2_differ_where_applicability_differs():
    """D14 section 5 cites RBI paragraphs from the instrument that binds the entity type; D2 section 11 now says the
    same, so the NBFC's and the bank's D2 differ there."""
    view = H.fold()
    nbfc = H.section(H.body_text(d2.build_pdf(_profile(view, "nbfc"))), 11)
    bank = H.section(H.body_text(d2.build_pdf(_profile(view, "bank"))), 11)
    assert nbfc != bank
    for entity, text in (("nbfc", nbfc), ("bank", bank)):
        instrument, paragraph = authored.entity_instrument(entity)
        assert _norm(f"RBI clauses are cited from {instrument}, {paragraph}") in text, entity
        assert _norm(authored.rbi_mapping_note(entity)) in text, entity
    assert authored.entity_instrument("nbfc")[0] not in bank and authored.entity_instrument("bank")[0] not in nbfc


# ----------------------------------------------------------------------------- Q1-05
def test_the_asset_table_prints_d1s_kinds_and_numbers():
    view = _sources_view()
    d1_tiles = {label: value for label, value, _hint in d1._population_kpis(view)}
    rows = dict(d2._asset_kind_rows(view))
    assert rows == {label: int(d1_tiles[label]) for label in rows}
    assert sum(rows.values()) == view.asset_occurrences
    one = H.section(H.body_text(d2.build_pdf(view)), 1)
    assert "Asset kind (as D1) Occurrences" in one
    assert f"Encryption settings {rows['Encryption settings']}" in one


# ----------------------------------------------------------------------------- Q1-06
def _register(count: int, mosca: dict) -> dict:
    return {"summary": {"total": 158, "q_grades": {"Q0": 5, "Q1": 20, "Q2": 50, "Q3": 30, "Q4": 40, "none": 13},
                        "q0_reasons": {"coverage_gap": 5}, "q0_gaps_open": {"coverage_gap": 5, "mosca_missing": 0},
                        "default_assumptions": {"count": count, "inputs": {"x": count} if count else {},
                                                "team_mosca": mosca, "defaults": QG.DEFAULTS_TEXT}}}


UNSET = {"x": None, "y": None, "z": None}


def test_d14_says_the_grades_rest_on_default_mosca_assumptions_and_asks_to_set_them():
    view = _sources_view()
    view.register = _register(37, UNSET)
    text = _norm(H.body_text(d14.build_pdf(view)))
    assert "default Mosca assumptions (team inputs not set): 37 assets graded on defaults" in text
    assert "under the team's Mosca inputs;" not in text
    actions = [row[0] for row in d14.governance_rows(view)]
    assert any("Set the data lifetimes" in a and a.endswith("(team inputs not set): 37.") for a in actions)


def test_d14_names_the_teams_inputs_when_they_are_set_and_no_default_was_used():
    view = _sources_view()
    view.register = _register(0, {"x": 10, "y": 5, "z": 12})
    assert authored.mosca_basis_text(view) == "under the team's Mosca inputs"
    assert not [row for row in d14.governance_rows(view) if "Set the data lifetimes" in row[0]]


def test_d2_section6_explains_mosca_missing_0_by_the_defaults():
    view = H.fold()
    view.register = _register(37, UNSET)
    six = H.section(H.body_text(d2.build_pdf(view)), 6)
    assert "mosca_missing" in six and "0 (defaults used)" in six
    assert "default Mosca assumptions (team inputs not set): 37 assets graded on defaults" in six
    assert "where it is missing the item says so instead of assuming" not in six


# ----------------------------------------------------------------------------- Q1-07
def _with_a_second_observation() -> R.TeamCbomView:
    """One issue asset observed by a second source: 1 more occurrence, the same distinct asset."""
    view = _sources_view()
    issue = next(a for a in view.assets if a.current and a.finding_codes and a.asset_key)
    twin = dataclasses.replace(issue, source_key="sources:second-role")
    assets = (*view.assets, twin)
    out = dataclasses.replace(view, assets=assets, **R._headline([a for a in assets if a.current]))
    out.register = view.register
    return out


def test_d14_prints_distinct_issue_assets_and_occurrences_with_one_wording():
    before = _sources_view()
    view = _with_a_second_observation()
    distinct, occurrences = len(d14.issue_assets(view)), sum(view.issue_by_impact.values())
    assert distinct == len(d14.issue_assets(before)) and occurrences == sum(before.issue_by_impact.values()) + 1
    assert occurrences > distinct
    phrase = f"{distinct} distinct issue assets ({occurrences} occurrences)"
    assert d14.issue_counts_text(view) == phrase
    text = _norm(H.body_text(d14.build_pdf(view)))
    assert f"Findings were raised on {occurrences} of them: {phrase}; occurrences by impact:" in text  # section 1
    assert re.search(rf"Issue assets {distinct} distinct \({occurrences} occurrences\)", text)  # section 1 KPI
    assert (f"Top {d14.TOP_RISKS} of {phrase}" in text) or (f"All {phrase} are listed" in text)  # section 2
    assert "Impact Issue occurrences Weight Points" in text and f"This report holds {phrase}" in text  # Appendix A


# ----------------------------------------------------------------------------- Q1-16
def test_the_grade_table_is_never_cut():
    six = H.section(H.body_text(d2.build_pdf(H.fold())), 6)
    assert "…" not in six.split("Q0 Unknown policy")[0]
    for _grade, meaning in M.Q_GRADE_ROWS:
        assert _norm(meaning) in six


def test_a_legacy_protocol_code_is_named():
    """D14 printed "Proto sslv3"; the knowledge base names PROTO_TLS10 / PROTO_TLS11, the SSL ones read the same way."""
    assert authored.finding_label("PROTO_SSLv3") == "SSL 3.0 accepted"
    assert authored.finding_label("PROTO_SSLv2") == "SSL 2.0 accepted"
    assert authored.finding_action("PROTO_SSLv3") == (
        "Allow TLS 1.2 and 1.3 only: disable SSL 3.0 on the endpoint or appliance.")
    assert authored.finding_label("PROTO_TLS10") == "TLS 1.0 accepted"  # the knowledge base's own title


def test_the_two_endpoint_counts_are_explained():
    note = M.probed_note(175, 212)
    assert note.startswith("Live TLS endpoints are not a manual item in this edition: 175 endpoints were probed")
    assert "the other 37 of the 212 endpoints probed are the service ports" in note
    assert M.probed_note(175, 175).endswith("collections (Appendix A).")
