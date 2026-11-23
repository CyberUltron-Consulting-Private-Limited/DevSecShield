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
import hashlib
import json
import threading
from collections import OrderedDict
from typing import Any, Iterable, Mapping

from backend.utilities.cbom_sources import crypto_kb

NAMESPACE = "node"
# the results page groups the knowledge base's "NSA CNSA 2.0" clauses as "CNSA 2.0" (run_results.FRAMEWORKS)
FRAMEWORK_ALIAS = {"NSA CNSA 2.0": "CNSA 2.0"}


def framework_name(name: str) -> str:
    return FRAMEWORK_ALIAS.get(name, name)


def flagged_algorithms(row: Any, codes: Iterable[str]) -> dict[str, list[str]]:
    """code -> the algorithms the classifier flagged for it on this asset, judged as of the collection (the codes of
    a date-based rule name no algorithm). Only codes with algorithm-specific clause rules need it, so the classifier
    runs only for those rows; an asset the current rules cannot read records none.

    The verdict depends only on the stored row (its facts and collection date) and the rules, so it is kept per
    process (``_CACHE``): the run posture classifies each such asset once, and the drill-down, the asset detail and the
    OSCAL export that follow reuse it (#289 review: the asset was classified again on every view)."""
    if not any(crypto_kb.has_clause_rules(NAMESPACE, c) for c in codes):
        return {}
    key = _row_key(row)
    found = _CACHE.get(key) if key is not None else None
    if found is not None:
        return {code: list(names) for code, names in found}
    from backend.utilities.cbom_sources.classify import classify

    try:
        verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts or {},
                           getattr(row, "created_at", None))
    except Exception:  # noqa: BLE001 - an asset the current rules cannot read keeps no evidence ("not recorded")
        verdict = {}
    flagged = tuple((code, tuple(names)) for code, names in (verdict.get("algorithms") or {}).items())
    if key is not None:
        _CACHE.put(key, flagged)
    return {code: list(names) for code, names in flagged}


class _Lru:
    """A small thread-safe LRU of row fingerprint -> flagged algorithms (request threads share it)."""

    def __init__(self, size: int) -> None:
        self.size = size
        self._items: OrderedDict[bytes, tuple] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: bytes) -> tuple | None:
        with self._lock:
            value = self._items.get(key)
            if value is not None:
                self._items.move_to_end(key)
            return value

    def put(self, key: bytes, value: tuple) -> None:
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self.size:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


CACHE_SIZE = 100_000  # one 50k-asset run's rule-code assets, twice over; ~150 bytes an entry
_CACHE = _Lru(CACHE_SIZE)


def _row_key(row: Any) -> bytes | None:
    """The fingerprint of everything the classifier reads (and the knowledge base it reads with); None for a row that
    cannot be fingerprinted (it is classified, not cached)."""
    try:
        created = getattr(row, "created_at", None)
        text = json.dumps([getattr(row, "id", None), row.asset_type, row.algorithm, row.key_size, row.protocol,
                           created.isoformat() if created is not None else None, row.facts or {},
                           crypto_kb.version()], sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError, AttributeError):
        return None
    return hashlib.blake2b(text.encode(), digest_size=16).digest()


def clear_cache() -> None:
    _CACHE.clear()


def evidence_by_code(row: Any, codes: Iterable[str]) -> dict[str, list[str] | None]:
    """code -> the algorithm names its clause rules read (None: not recorded)."""
    codes = list(codes)
    flagged = flagged_algorithms(row, codes)
    return {code: (flagged.get(code) or None) for code in codes}


def asset_clauses(row: Any, codes: Iterable[str], team: Mapping[str, Any] | None) -> list[tuple[str, dict[str, Any]]]:
    """(code, clause) for every clause the asset's finding codes break (``crypto_kb.clauses_for``) that binds the
    team (``regulated_entity.profile_of``; SOW audit A-11). ``team`` has no default on purpose: a caller states the
    team it cites for, so the run page, the asset detail, OSCAL and the PDFs cannot disagree (None: every clause,
    used only where a clause is named explicitly)."""
    evidence = evidence_by_code(row, codes)
    found = dict(team) if team is not None else None
    return [(code, ref) for code, names in evidence.items()
            for ref in crypto_kb.clauses_for(NAMESPACE, code, names, team=found)]


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
    framework, colon, clause_id = text.partition(":")
    framework, clause_id = framework_name(framework.strip()), clause_id.strip() or None
    if colon and clause_id is None:  # "NIST:" or "NIST: " names no clause (the framework alone has no colon)
        raise ValueError("clause: <framework> or <framework>:<clause id> of the knowledge base")
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
    always, by_rule = codes_citing_split(keys)
    return sorted(always + by_rule)


def codes_citing_split(keys: set[str]) -> tuple[list[str], list[str]]:
    """(codes that always cite one of ``keys``: their own clauses name it, so every asset with the code is behind it;
    codes that cite one only through a clause rule: whether an asset with the code is behind it depends on the
    algorithms recorded for it). The run assets filter decides the first in SQL and judges only the second's assets."""
    findings = (crypto_kb.load().get("findings") or {}).get(NAMESPACE) or {}
    always, by_rule = [], []
    for code, e in findings.items():
        if set(e.get("clauses") or []) & keys:
            always.append(code)
        elif {k for r in e.get("clause_rules") or [] for k in r.get("clauses") or []} & keys:
            by_rule.append(code)
    return sorted(always), sorted(by_rule)


def matches(row: Any, codes: Iterable[str], keys: set[str]) -> bool:
    """Whether the asset is behind one of the clauses (the posture's rule: its non-coverage codes, judged today)."""
    if row.asset_type == "coverage":
        return False
    codes = [c for c in codes if isinstance(c, str) and not c.startswith("COVERAGE_")]
    # the clause is named by the caller (``clause=``), so no team filter: a clause that binds nobody matches nobody
    return any(ref.get("key") in keys for _code, ref in asset_clauses(row, codes, None))


def today_codes(row: Any, now: _dt.datetime) -> list[str]:
    from backend.utilities.cbom_sources.classify import shown

    return list(shown(row, now)["finding_codes"] or [])


__all__ = ["CACHE_SIZE", "FRAMEWORK_ALIAS", "asset_clauses", "clause_keys", "clear_cache", "codes_citing",
           "codes_citing_split", "evidence_by_code", "flagged_algorithms", "framework_name", "matches", "parse_clause",
           "today_codes"]
