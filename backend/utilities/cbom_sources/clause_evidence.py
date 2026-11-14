"""The compliance clauses a collected asset's findings break, decided on algorithm names only (#269, #289).

Every view that cites clauses for a Sources asset goes through ``asset_clauses``: the run posture (the results page's
"Compliance mapping" and its asset counts), the run's assets filter ``clause=`` (the "N assets" drill-down, so the
filtered table holds exactly the assets the count names), the asset detail and the OSCAL export.

A clause that applies to specific algorithms (SP 800-131A TDEA, SHA-1 signatures, 112-bit; SEBI strong encryption)
is decided on the algorithms the classifier flagged for the code (``classify`` verdict ``algorithms``: the offered
ciphers, transforms or hashes that raised it), never on the asset's name, location or finding sentence: a gateway
called ``des3-gw`` that offers only ``aes128-cbc`` is not cited under TDEA. A code the classifier no longer raises for
the asset's facts, or raises without naming an algorithm, has no recorded evidence: ``crypto_kb.clauses_for`` then
cites the algorithm clauses with a "not recorded, verify" note instead of dropping them.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Iterable

from backend.utilities.cbom_sources import crypto_kb

NAMESPACE = "node"
# the results page groups the knowledge base's "NSA CNSA 2.0" clauses as "CNSA 2.0" (run_results.FRAMEWORKS)
FRAMEWORK_ALIAS = {"NSA CNSA 2.0": "CNSA 2.0"}


def framework_name(name: str) -> str:
    return FRAMEWORK_ALIAS.get(name, name)


def flagged_algorithms(row: Any, codes: Iterable[str]) -> dict[str, list[str]]:
    """code -> the algorithms the classifier flagged for it on this asset, judged as of the collection (the codes of
    a date-based rule name no algorithm). Only codes with algorithm-specific clause rules need it, so the classifier
    runs only for those rows; an asset the current rules cannot read records none."""
    if not any(crypto_kb.has_clause_rules(NAMESPACE, c) for c in codes):
        return {}
    from backend.utilities.cbom_sources.classify import classify

    try:
        verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts or {},
                           getattr(row, "created_at", None))
    except Exception:  # noqa: BLE001 - an asset the current rules cannot read keeps no evidence ("not recorded")
        return {}
    return {code: list(names) for code, names in (verdict.get("algorithms") or {}).items()}


def evidence_by_code(row: Any, codes: Iterable[str]) -> dict[str, list[str] | None]:
    """code -> the algorithm names its clause rules read (None: not recorded)."""
    codes = list(codes)
    flagged = flagged_algorithms(row, codes)
    return {code: (flagged.get(code) or None) for code in codes}


def asset_clauses(row: Any, codes: Iterable[str]) -> list[tuple[str, dict[str, Any]]]:
    """(code, clause) for every clause the asset's finding codes break (``crypto_kb.clauses_for``)."""
    evidence = evidence_by_code(row, codes)
    return [(code, ref) for code, names in evidence.items()
            for ref in crypto_kb.clauses_for(NAMESPACE, code, names)]


# ----------------------------------------------------------------------------- the run assets filter (clause=)
MAX_CLAUSE = 300


def parse_clause(value: str | None) -> tuple[str, str | None] | None:
    """``clause=<framework>`` (every clause of it) or ``clause=<framework>:<clause id>`` as the results page names
    them (``CERT-In:BOM Guidelines v2.0, 8.4.2.2``); None when absent. ValueError (the route answers 400 without
    echoing the value) when it names no clause of the knowledge base."""
    if value is None:
        return None
    text = value.strip()
    if not text or len(text) > MAX_CLAUSE or any(ord(ch) < 32 for ch in text):
        raise ValueError("clause: <framework> or <framework>:<clause id> of the knowledge base")
    framework, _, clause_id = text.partition(":")
    framework, clause_id = framework_name(framework.strip()), clause_id.strip() or None
    if not clause_keys(framework, clause_id):
        raise ValueError("clause: <framework> or <framework>:<clause id> of the knowledge base")
    return framework, clause_id


def clause_keys(framework: str, clause_id: str | None) -> set[str]:
    """The knowledge base's clause keys a ``clause=`` value names."""
    catalog = crypto_kb.load().get("clauses") or {}
    return {key for key, ref in catalog.items() if framework_name(str(ref.get("framework") or "")) == framework
            and (clause_id is None or str(ref.get("id") or "") == clause_id)}


def codes_citing(keys: set[str]) -> list[str]:
    """Finding codes whose clauses or clause rules can cite one of ``keys`` (a pre-filter: only their assets are
    judged one by one)."""
    findings = (crypto_kb.load().get("findings") or {}).get(NAMESPACE) or {}
    out = []
    for code, e in findings.items():
        cited = set(e.get("clauses") or []) | {k for r in e.get("clause_rules") or [] for k in r.get("clauses") or []}
        if cited & keys:
            out.append(code)
    return sorted(out)


def matches(row: Any, codes: Iterable[str], keys: set[str]) -> bool:
    """Whether the asset is behind one of the clauses (the posture's rule: its non-coverage codes, judged today)."""
    if row.asset_type == "coverage":
        return False
    codes = [c for c in codes if isinstance(c, str) and not c.startswith("COVERAGE_")]
    return any(ref.get("key") in keys for _code, ref in asset_clauses(row, codes))


def today_codes(row: Any, now: _dt.datetime) -> list[str]:
    from backend.utilities.cbom_sources.classify import shown

    return list(shown(row, now)["finding_codes"] or [])


__all__ = ["FRAMEWORK_ALIAS", "asset_clauses", "clause_keys", "codes_citing", "evidence_by_code", "flagged_algorithms",
           "framework_name", "matches", "parse_clause", "today_codes"]
