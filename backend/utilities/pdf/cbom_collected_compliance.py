"""Regulatory clauses that the collected infrastructure's findings touch, for the team-wide CBOM deliverables.

The code-scan engine pools a verdict per framework requirement (``TeamCbomView.frameworks``); CBOM Sources
collections carry no such verdicts. Their findings map to clauses through the knowledge base instead
(``crypto_kb.json``: finding code -> compliance areas -> CERT-In, RBI, SEBI CSCRF, NIST and CNSA 2.0 clauses), exactly
as the run API's posture does (``cbom_sources.posture``: ``compliance``). This module applies the same mapping to the
current collected assets of the team view, so a deliverable shows the clauses and asset counts the run API shows for
each source's latest collection. Pure: no database, no clock, no network (the knowledge base is a local file).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView

SOURCES_PREFIX = "sources:"  # AssetAgg.source_key of a CBOM Sources collection


@dataclass(frozen=True)
class ClauseRow:
    framework: str
    clause: str
    assets: int  # current collected assets with at least one finding code mapped to the clause
    codes: tuple[str, ...]


def collected_clauses(view: TeamCbomView) -> list[ClauseRow]:
    """Clauses touched by the current collected assets' codes (findings and the informational codes the collector
    gave, ``AssetAgg.collector_codes``, as the run API counts them): by framework, then most assets first."""
    table = crypto_kb.load().get("compliance") or {}
    assets: dict[tuple[str, str], set[str]] = defaultdict(set)
    codes: dict[tuple[str, str], set[str]] = defaultdict(set)
    for asset in view.assets:
        if not asset.current or not asset.source_key.startswith(SOURCES_PREFIX):
            continue
        for code in dict.fromkeys((*asset.finding_codes, *asset.collector_codes)):
            if code.startswith("COVERAGE_"):  # a check that was not collected is not a finding
                continue
            for area in (crypto_kb.entry("node", code) or {}).get("compliance") or []:
                for ref in table.get(area) or []:
                    key = (str(ref["framework"]), str(ref["id"]))
                    assets[key].add(f"{asset.source_key}|{asset.asset_type}|{asset.ident}")
                    codes[key].add(code)
    rows = [ClauseRow(fw, clause, len(ids), tuple(sorted(codes[(fw, clause)])))
            for (fw, clause), ids in assets.items()]
    rows.sort(key=lambda r: (r.framework.casefold(), -r.assets, r.clause.casefold()))
    return rows
