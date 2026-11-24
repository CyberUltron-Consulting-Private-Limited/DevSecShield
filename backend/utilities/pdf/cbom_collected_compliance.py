"""Regulatory clauses that the collected infrastructure's findings touch, for the team-wide CBOM deliverables.

The code-scan engine pools a verdict per framework requirement (``TeamCbomView.frameworks``); CBOM Sources
collections carry no such verdicts. Their findings map to clauses through the knowledge base instead
(``crypto_kb.json``: finding code -> the CERT-In, RBI, SEBI CSCRF, NIST and CNSA 2.0 clauses it breaks), exactly
as the run API's posture does (``cbom_sources.posture``: ``compliance``). This module applies the same mapping to the
current collected assets of the team view, so a deliverable shows the clauses and asset counts the run API shows for
each source's latest collection. Pure: no database, no clock, no network (the knowledge base is a local file).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView
from backend.utilities.pdf import cbom_kb_text as kb_text

SOURCES_PREFIX = "sources:"  # AssetAgg.source_key of a CBOM Sources collection


@dataclass(frozen=True)
class ClauseRow:
    framework: str
    clause: str
    assets: int  # current collected assets with at least one finding code mapped to the clause
    codes: tuple[str, ...]
    unrecorded: int = 0  # assets cited for review: the algorithm behind the finding was not recorded (#289)


def collected_clauses(view: TeamCbomView, entity: str | None = None) -> list[ClauseRow]:
    """Clauses touched by the current collected assets' codes (findings and the informational codes the collector
    gave, ``AssetAgg.collector_codes``, as the run API counts them): by framework, then most assets first.

    Only the clauses that bind the team are cited (``crypto_kb.clauses_for`` with the view's regulatory profile, the
    filter the run API, the asset detail and OSCAL apply too): an NBFC is mapped to the NBFC Directions 2026, never
    to the Commercial Banks Directions (SOW audit A-11). ``entity`` overrides the profile's entity type."""
    team = kb_text.view_profile(view)
    if entity:
        team = {**team, "entity": entity}
    assets: dict[tuple[str, str], set[str]] = defaultdict(set)
    codes: dict[tuple[str, str], set[str]] = defaultdict(set)
    recorded: dict[tuple[str, str], set[str]] = defaultdict(set)  # cited on a recorded algorithm by any of its codes
    for asset in view.assets:
        if not asset.current or not asset.source_key.startswith(SOURCES_PREFIX):
            continue
        evidence = asset.clause_evidence or {}  # algorithm names only, never the asset's title or sentence (#289)
        for code in dict.fromkeys((*asset.finding_codes, *asset.collector_codes)):
            if code.startswith("COVERAGE_"):  # a check that was not collected is not a finding
                continue
            for ref in crypto_kb.clauses_for("node", code, evidence.get(code), team=team):  # (#269, A-11)
                key = (str(ref["framework"]), str(ref["id"]))
                ident = f"{asset.source_key}|{asset.asset_type}|{asset.ident}"
                assets[key].add(ident)
                codes[key].add(code)
                if ref.get("evidence") != "not_recorded":
                    recorded[key].add(ident)
    rows = [ClauseRow(fw, clause, len(ids), tuple(sorted(codes[(fw, clause)])), len(ids - recorded[(fw, clause)]))
            for (fw, clause), ids in assets.items()]
    rows.sort(key=lambda r: (r.framework.casefold(), -r.assets, r.clause.casefold()))
    return rows
