"""The population reconciliation (SOW audit A-09, staging QA round 2 M4): ONE block, built by ONE function, that the
Scope Baseline (D1), the Quantum Risk Register (D12), the PQC Migration Roadmap (D13), the Board Report (D14) and the
CBOM dashboard all print, so a reader can walk from any count to any other.

The chain, each step with its arithmetic and every bucket named:

1. Run assets: what the latest collection of each CBOM Sources source listed (the runs' asset lists).
2. Asset occurrences: minus the observations of a certificate another source also observed (one certificate, counted
   once from its latest observation), plus the code-scan occurrences. D1 and D14 count these.
   The dashboard's Crypto Assets card counts every row of every successful code scan, so it adds the code-scan rows
   the documents count once (a repository scanned again, a row repeated within a scan) and says how many.
3. Distinct register assets: minus the code-scan occurrences (the register holds collected assets only), minus the
   Sources occurrences of an estate asset already counted (one asset read at several places or by several sources),
   plus the register assets no latest collection holds (not read or removed; kept with their last grade). D12.
4. Their SOW classes (``sow_class``): graded Q1 to Q4 = quantum-broken + deprecated + weakened + quantum-safe; then
   Q0 Unknown and no grade.
5. Quantum-vulnerable (when the roadmap's population is loaded): the occurrences with a quantum-vulnerable verdict (the
   dashboard card, the readiness figure) = the public-key assets D13 plans + the symmetric ones + the ones with no
   algorithm recorded + the code-scan non-algorithm rows.

Every number is read from what the surfaces already print (the view's counts, the register summary, the dashboard's
card): nothing is recounted here (Rule P). Pure: no database, no clock.
"""
from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from backend.utilities.cbom_sources import sow_class as SC

TITLE = "Population reconciliation"
_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Population:
    """Every number of the block, each counted from its own source (review 6038529822 B1: no bucket is the difference
    of two others; when the counts do not close, the block prints the difference as unexplained)."""

    collections: int  # current CBOM Sources collections (a deleted source's is removed from scope)
    collected: int  # their run asset lists
    sources_occurrences: int  # current assets of current collections in the view
    code_occurrences: int
    occurrences: int  # the view's current assets (D1 / D14 "asset occurrences")
    same_source_places: int = 0  # a certificate one source read at another place, counted once
    cross_source: int = 0  # a certificate another source also read, counted once
    to_code: int = 0  # a certificate a code scan saw as late or later, counted from the code scan
    estate_repeats: int = 0  # current Sources occurrences of one estate asset beyond the first
    removed_collections: int = 0  # deleted sources' last collections: outside every total
    removed_assets: int = 0
    removed_counted: int = 0  # of those, occurrences the view still counts (0 once the roll-up drops them, #497)
    register: Mapping[str, Any] | None = None  # risk_register.summary
    card_assets: int | None = None  # the dashboard's Crypto Assets card (the dashboard only)
    quantum: Mapping[str, int] | None = field(default=None)  # quantum_counts(): D13's population


def _n(number: int, singular: str, plural: str | None = None) -> str:
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def quantum_counts(view: Any) -> dict[str, int] | None:
    """D13's population from the view (``waves.roadmap_extras``' ``population``, or the dashboard's
    ``waves.population_from_rows``, and the view's own code-scan assets), None when it was not loaded."""
    rem = getattr(view, "remediation", None)
    pop = rem.get("population") if isinstance(rem, Mapping) else None
    if not isinstance(pop, Mapping):
        return None
    code_planned = code_other = 0
    for a in view.assets:
        if a.current and a.quantum_vulnerable is True and not a.source_key.startswith("sources:"):
            if a.asset_type == "algorithm":
                code_planned += 1
            else:
                code_other += 1
    out = {"occurrences": int(view.pqc_vulnerable), "code_planned": code_planned, "code_other": code_other,
           "sources": int(pop.get("sources") or 0), "sources_planned": int(pop.get("sources_planned") or 0),
           "symmetric": int(pop.get("symmetric") or 0), "no_algorithm": int(pop.get("no_algorithm") or 0)}
    out["planned"] = out["code_planned"] + out["sources_planned"]
    return out


def from_view(view: Any) -> Population:
    """The population of a ``TeamCbomView`` (``load_team_cbom_view``, or the dashboard's ``team_view``): current
    collections only (``cbom_team_rollup.current_collections``); a deleted source's collection is removed from scope."""
    from backend.utilities.dashboard.cbom_team_rollup import current_collections, removed_collections

    current, removed = current_collections(view), removed_collections(view)
    current_keys = {c.key for c in current}
    removed_keys = {c.key for c in removed}
    live = [a for a in view.assets if a.current]
    sources = sum(1 for a in live if a.source_key in current_keys)
    removed_counted = sum(1 for a in live if a.source_key in removed_keys)
    code = sum(1 for a in live if not a.source_key.startswith("sources:"))
    cross = getattr(view, "cross_scope", None) or {}
    register = getattr(view, "register", None)
    summary = (register or {}).get("summary") if isinstance(register, Mapping) else None
    return Population(
        collections=len(current), collected=sum(int(getattr(c, "asset_count", 0) or 0) for c in current),
        sources_occurrences=sources, code_occurrences=code, occurrences=len(live),
        same_source_places=int(cross.get("same_source_places", 0) or 0),
        cross_source=int(cross.get("cross_source", 0) or 0), to_code=int(cross.get("to_code", 0) or 0),
        estate_repeats=int(cross.get("estate_repeats", 0) or 0),
        removed_collections=len(removed), removed_assets=sum(int(getattr(c, "asset_count", 0) or 0) for c in removed),
        removed_counted=removed_counted,
        register=summary if isinstance(summary, Mapping) and isinstance(summary.get("total"), int) else None,
        quantum=quantum_counts(view))


def register_numbers(summary: Mapping[str, Any]) -> dict[str, int]:
    grades = summary.get("q_grades") if isinstance(summary.get("q_grades"), Mapping) else {}
    classes = summary.get("sow_classes") if isinstance(summary.get("sow_classes"), Mapping) else {}
    presence = summary.get("presence") if isinstance(summary.get("presence"), Mapping) else {}
    out = {"total": int(summary.get("total") or 0), "present": int(presence.get("present", 0) or 0),
           "not_present": int(presence.get("not_read", 0) or 0) + int(presence.get("removed", 0) or 0),
           "present_removed": int(summary.get("present_removed_sources", 0) or 0),
           "removed_from_scope": int(summary.get("removed_from_scope", 0) or 0),
           # deprecated rows a quantum computer also breaks (a Triple DES key with no verdict is not one, m4)
           "deprecated_broken": int(summary.get("deprecated_quantum_broken", 0) or 0),
           "graded": sum(int(grades.get(g, 0) or 0) for g in ("Q1", "Q2", "Q3", "Q4")),
           "q0": int(grades.get("Q0", 0) or 0), "none": int(grades.get("none", 0) or 0)}
    for c in SC.CLASSES:
        out[c] = int(classes.get(c, 0) or 0)
    return out


def _unexplained(step: str, gap: int) -> str:
    if gap == 0:
        return ""
    _LOG.warning("population reconciliation: %s does not close, unexplained difference %d", step, gap)
    return f" Unexplained difference {gap:+d}: the counts above do not account for it."


def steps(pop: Population) -> list[dict[str, Any]]:
    """The block, one step per line: ``{"key", "value", "text"}``. The dashboard renders the texts as they are."""
    out: list[dict[str, Any]] = []

    def add(key: str, value: int, text: str) -> None:
        out.append({"key": key, "value": int(value), "text": f"{len(out) + 1}. {text}"})

    if pop.collections:
        add("run_assets", pop.collected,
            f"Run assets: the latest collections of the {_n(pop.collections, 'CBOM Sources source')} list "
            f"{_n(pop.collected, 'asset')} (the runs' asset lists).")
    if pop.removed_collections:
        # "outside every total" only when it is: while the roll-up still counts some of their occurrences (until
        # #497), the line says how many and the steps below subtract them (review 6057476173 m4)
        tail = (f". This view still counts {_n(pop.removed_counted, 'occurrence')} of them; the steps below take "
                "them out." if pop.removed_counted else ", outside every total.")
        add("removed", pop.removed_assets,
            f"Removed from scope: {_n(pop.removed_collections, 'collection')} of deleted sources with "
            f"{_n(pop.removed_assets, 'asset')}{tail}")
    parts = []
    if pop.same_source_places:
        parts.append(f"minus {_n(pop.same_source_places, 'observation')} of a certificate the same source read at "
                     "another place (one certificate, counted once)")
    if pop.cross_source:
        parts.append(f"minus {_n(pop.cross_source, 'observation')} of a certificate another source also read "
                     "(counted once, from its latest observation)")
    if pop.to_code:
        parts.append(f"minus {_n(pop.to_code, 'observation')} of a certificate a code scan found as late or later "
                     "(counted from the code scan)")
    if pop.collections:
        gap = pop.sources_occurrences - (pop.collected - pop.same_source_places - pop.cross_source - pop.to_code)
        sources_text = (f"{pop.collected} run assets " + (", ".join(parts) + " " if parts else "")
                        + f"= {_n(pop.sources_occurrences, 'CBOM Sources occurrence')}"
                        + _unexplained("run assets to occurrences", gap) + "; ")
    else:
        sources_text = ""
    removed_text = (f"plus {_n(pop.removed_counted, 'occurrence')} of removed sources still in this view; "
                    if pop.removed_counted else "")
    gap_occ = pop.occurrences - (pop.sources_occurrences + pop.removed_counted + pop.code_occurrences)
    add("occurrences", pop.occurrences,
        f"Asset occurrences: {sources_text}{removed_text}plus {_n(pop.code_occurrences, 'code-scan occurrence')} = "
        f"{_n(pop.occurrences, 'asset occurrence')} (the Scope Baseline D1 and the Board Report D14 count these)."
        + _unexplained("occurrences", gap_occ))
    if pop.card_assets is not None:
        extra = pop.card_assets - pop.occurrences
        card = "the same occurrences." if extra == 0 else (
            f"{pop.occurrences} occurrences{_unexplained('dashboard card', extra)}")
        add("dashboard_card", pop.card_assets, f"The dashboard's Crypto Assets card counts {pop.card_assets}: {card}")
    if pop.register is None:
        add("register", 0, "The quantum risk register (D12) was not loaded.")
    else:
        r = register_numbers(pop.register)
        expected = (pop.occurrences - pop.code_occurrences - pop.removed_counted - pop.estate_repeats
                    + r["not_present"] + r["present_removed"])
        text = (f"Distinct register assets: {pop.occurrences} occurrences minus "
                f"{_n(pop.code_occurrences, 'code-scan occurrence')} (the register holds collected assets only)")
        if pop.removed_counted:
            text += f" minus {_n(pop.removed_counted, 'occurrence')} of removed sources"
        if pop.estate_repeats:
            text += (f" minus {_n(pop.estate_repeats, 'CBOM Sources occurrence')} of an estate asset already counted "
                     "(one asset, such as an endpoint, read by several sources)")
        if r["not_present"]:
            text += (f" plus {_n(r['not_present'], 'register asset')} no latest collection holds (not read or "
                     "removed, kept with their last grade)")
        if r["present_removed"]:
            text += f" plus {_n(r['present_removed'], 'register asset')} last read by a removed source"
        # the register's rows that only a deleted source read are outside its total (the summary leaves them out); a
        # removed source's occurrences still in the view are subtracted above, so the chain needs no other term
        text += f" = {_n(r['total'], 'distinct asset')} in the Quantum Risk Register (D12)."
        if r["removed_from_scope"]:
            text += (f" Removed from scope: {_n(r['removed_from_scope'], 'register asset')} only a deleted source "
                     "read, outside every total.")
        text += _unexplained("register", r["total"] - expected)
        add("register", r["total"], text)
        grades = pop.register.get("q_grades") if isinstance(pop.register.get("q_grades"), Mapping) else {}
        split = ", ".join(f"{label} {int(grades.get(key, 0) or 0)}" for key, label in (
            ("Q1", "Q1 Critical"), ("Q2", "Q2 High"), ("Q3", "Q3 Medium"), ("Q4", "Q4 Low"), ("Q0", "Q0 Unknown"),
            ("none", "no grade")))
        classes = sum(r[c] for c in SC.CLASSES)
        add("classes", r["total"],
            f"Their grades: {split}. Their SOW classes: {r['graded']} graded Q1 to Q4 ({r[SC.BROKEN]} quantum-broken, "
            f"{r[SC.DEPRECATED]} deprecated, {r[SC.WEAKENED]} weakened, {r[SC.SAFE]} quantum-safe), {r['q0']} Q0 "
            "Unknown, {} no grade (no public-key cryptography).".format(r["none"])
            + _unexplained("SOW classes", r["total"] - classes))
    q = pop.quantum
    if q is not None:
        parts_q = [f"{q['code_planned']} code-scan algorithm{'' if q['code_planned'] == 1 else 's'}",
                   f"{q['sources_planned']} collected"]
        rest = [f"{q['symmetric']} symmetric or hash", f"{q['no_algorithm']} with no algorithm recorded"]
        if q["code_other"]:
            rest.append(f"{q['code_other']} code-scan certificate or key row{'' if q['code_other'] == 1 else 's'}")
        # each part counted: the collected rows by their function (waves.plan_exclusion), the code rows by type. The
        # two closures are checked apart, so a surplus in one never hides a shortfall in the other
        gap_split = q["occurrences"] - (q["code_planned"] + q["code_other"] + q["sources"])
        gap_kind = q["sources"] - (q["sources_planned"] + q["symmetric"] + q["no_algorithm"])
        add("quantum", q["occurrences"],
            f"Quantum-vulnerable: {_n(q['occurrences'], 'occurrence')} "
            f"{'carries' if q['occurrences'] == 1 else 'carry'} a quantum-vulnerable verdict (the "
            f"dashboard card and the readiness figure) = {q['planned']} public-key assets the PQC Migration Roadmap "
            f"(D13) plans ({', '.join(parts_q)}) + " + " + ".join(rest) + ", which are not public-key migrations."
            + (f" The register counts each estate asset once: {register_numbers(pop.register)[SC.BROKEN]} "
               f"quantum-broken and {register_numbers(pop.register)['deprecated_broken']} deprecated that a quantum "
               "computer also breaks."
               if pop.register is not None else "")
            + _unexplained("quantum-vulnerable occurrences to code and collected assets", gap_split)
            + _unexplained("collected quantum-vulnerable assets to planned, symmetric and no algorithm", gap_kind))
    return out


def lines(pop: Population) -> list[str]:
    return [s["text"] for s in steps(pop)]


def public(pop: Population) -> dict[str, Any]:
    """The block as the dashboard API serves it."""
    return {"title": TITLE, "steps": steps(pop)}


_VIEWS: OrderedDict[tuple, Any] = OrderedDict()  # the dashboard's views, by what they are folded from
_VIEWS_MAX = 16
_VIEWS_LOCK = threading.Lock()


def team_view(team_id: int, scans: Any, sources: Any, now: Any = None) -> Any:
    """The documents' team roll-up (``load_team_cbom_view``'s fold) from the scans and CBOM Sources collections a
    caller already loaded: ``cbom_team_rollup.fold_scans`` over the team's CBOM scans (latest successful scan per
    repository and branch is current; a superseded scan is history), then ``merge_collections`` (counts only: the
    dashboard reads no posture fact or compliance pool). The dashboard reads its cards and this block from it, so it
    counts what the documents count (staging QA2 Q1-08). The view is kept in a small per-process cache keyed by what
    it is folded from (every scan's id, status and last update; every collection's job and time; the UTC day the
    date-based findings are judged on): a page reload with unchanged data reuses it (review 6038529822 m4)."""
    import datetime as _dt

    from backend.utilities.dashboard.cbom_team_rollup import (
        ScanHead,
        fold_scans,
        merge_collections,
    )

    moment = now or _dt.datetime.now(_dt.timezone.utc)

    def aware(value: Any) -> _dt.datetime:
        if not isinstance(value, _dt.datetime):
            return _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)

    heads, blobs = [], {}
    for scan in scans:  # the heads load_team_cbom_view builds (Postgres returns naive UTC)
        owner, kind = getattr(scan, "team_id", team_id), getattr(scan, "scan_type", "cbom")
        if owner != team_id or kind != "cbom":
            continue
        made = aware(getattr(scan, "created_at", None))
        updated = getattr(scan, "last_updated", None)
        heads.append(ScanHead(id=scan.id, team_id=team_id, scan_type="cbom", title=getattr(scan, "title", "") or "",
                              status=scan.scan_status, created_at=made,
                              last_updated=aware(updated) if updated else made,
                              scan_metadata=getattr(scan, "scan_metadata", None)))
        blobs[scan.id] = scan.scan_data
    key = (team_id, moment.date(),
           tuple(sorted((h.id, str(h.status), h.last_updated.isoformat()) for h in heads)),
           tuple(sorted((c.job_id, c.source_kind, str(c.observed_at), c.asset_count)
                        for c in (sources.collections if sources is not None else ()))))
    with _VIEWS_LOCK:
        cached = _VIEWS.get(key)
        if cached is not None:
            _VIEWS.move_to_end(key)
            return cached
    view = fold_scans(heads, lambda ids: {i: blobs.get(i) for i in ids}, team_id=team_id, team_name="",
                      now=moment)
    if sources is not None:
        view = merge_collections(view, sources.rows, sources.collections, counts_only=True)
    with _VIEWS_LOCK:
        _VIEWS[key] = view
        while len(_VIEWS) > _VIEWS_MAX:
            _VIEWS.popitem(last=False)
    return view


def for_dashboard(view: Any, register_summary: Mapping[str, Any] | None, card_assets: int | None,
                  sources: Any = None) -> dict[str, Any]:
    """The dashboard's block: the documents' population of ``view`` (``team_view``), the register summary the
    Quantum risk tab reads, the dashboard's own Crypto Assets card and, from the Sources rows, D13's population
    (``waves.population_from_rows``: the quantum-vulnerable step, review 6038529822 M2). ``view`` is not changed."""
    import copy

    from backend.utilities.cbom_sources import waves as W

    shown = copy.copy(view)  # a shallow copy: the cached view never carries one request's register summary
    shown.register = {"summary": register_summary} if isinstance(register_summary, Mapping) else None
    if sources is not None:
        shown.remediation = {"population": W.population_from_rows(sources.rows, view)}
    pop = from_view(shown)
    return public(Population(**{**pop.__dict__, "card_assets": card_assets}))


__all__ = [
    "TITLE",
    "Population",
    "for_dashboard",
    "from_view",
    "lines",
    "public",
    "quantum_counts",
    "register_numbers",
    "steps",
    "team_view",
]
