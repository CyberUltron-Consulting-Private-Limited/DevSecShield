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

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from backend.utilities.cbom_sources import sow_class as SC

TITLE = "Population reconciliation"


@dataclass(frozen=True)
class Population:
    collections: int  # CBOM Sources sources with a latest collection
    collected: int  # their run asset lists
    sources_occurrences: int
    code_occurrences: int
    occurrences: int
    register: Mapping[str, Any] | None = None  # risk_register.summary (total, q_grades, sow_classes, presence)
    card_assets: int | None = None  # the dashboard's Crypto Assets card (the dashboard only)
    quantum: Mapping[str, int] | None = field(default=None)  # quantum_counts(): D13's population

    @property
    def counted_once(self) -> int:
        return self.collected - self.sources_occurrences


def _n(number: int, singular: str, plural: str | None = None) -> str:
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def quantum_counts(view: Any) -> dict[str, int] | None:
    """D13's population from the view (``waves.roadmap_extras``' ``population`` and the view's own code-scan assets),
    None when the roadmap plan was not loaded."""
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
    """The population of a document's ``TeamCbomView`` (``load_team_cbom_view``)."""
    live = [a for a in view.assets if a.current]
    sources = sum(1 for a in live if a.source_key.startswith("sources:"))
    collections = tuple(getattr(view, "collections", ()) or ())
    register = getattr(view, "register", None)
    summary = (register or {}).get("summary") if isinstance(register, Mapping) else None
    return Population(
        collections=len(collections), collected=sum(int(getattr(c, "asset_count", 0) or 0) for c in collections),
        sources_occurrences=sources, code_occurrences=len(live) - sources, occurrences=len(live),
        register=summary if isinstance(summary, Mapping) and isinstance(summary.get("total"), int) else None,
        quantum=quantum_counts(view))


def register_numbers(summary: Mapping[str, Any]) -> dict[str, int]:
    grades = summary.get("q_grades") if isinstance(summary.get("q_grades"), Mapping) else {}
    classes = summary.get("sow_classes") if isinstance(summary.get("sow_classes"), Mapping) else {}
    presence = summary.get("presence") if isinstance(summary.get("presence"), Mapping) else {}
    total = int(summary.get("total") or 0)
    present = int(presence.get("present", total) or 0)
    out = {"total": total, "present": present, "not_present": total - present,
           "graded": sum(int(grades.get(g, 0) or 0) for g in ("Q1", "Q2", "Q3", "Q4")),
           "q0": int(grades.get("Q0", 0) or 0), "none": int(grades.get("none", 0) or 0)}
    for c in SC.CLASSES:
        out[c] = int(classes.get(c, 0) or 0)
    return out


def steps(pop: Population) -> list[dict[str, Any]]:
    """The block, one step per line: ``{"key", "value", "text"}``. The dashboard renders the texts as they are."""
    out: list[dict[str, Any]] = []

    def add(key: str, value: int, text: str) -> None:
        out.append({"key": key, "value": int(value), "text": f"{len(out) + 1}. {text}"})

    if pop.collections:
        add("run_assets", pop.collected,
            f"Run assets: the latest collections of the {_n(pop.collections, 'CBOM Sources source')} list "
            f"{_n(pop.collected, 'asset')} (the runs' asset lists).")
    once = pop.counted_once
    once_text = (f"minus {_n(once, 'observation')} of an asset another source also observed (a certificate two "
                 "sources read is one asset, counted once from its latest observation)" if once >= 0 else
                 f"plus {_n(-once, 'observation')} the collections' asset lists leave out")
    sources_text = (f"{pop.collected} run assets {once_text} = {_n(pop.sources_occurrences, 'CBOM Sources occurrence')}; "
                    if pop.collections else "")
    add("occurrences", pop.occurrences,
        f"Asset occurrences: {sources_text}plus {_n(pop.code_occurrences, 'code-scan occurrence')} = "
        f"{_n(pop.occurrences, 'asset occurrence')} (the Scope Baseline D1 and the Board Report D14 count these).")
    if pop.card_assets is not None:
        extra = pop.card_assets - pop.occurrences
        if extra == 0:
            card = "the same occurrences."
        elif extra > 0:
            card = (f"the {pop.occurrences} occurrences plus {_n(extra, 'code-scan row')} it counts once per scan (a "
                    "repository scanned more than once, a row repeated within a scan), which the documents count "
                    "once.")
        else:
            card = (f"the {pop.occurrences} occurrences minus {_n(-extra, 'code-scan occurrence')} the documents "
                    "count and the card does not.")
        add("dashboard_card", pop.card_assets, f"The dashboard's Crypto Assets card counts {pop.card_assets}: {card}")
    if pop.register is None:
        add("register", 0, "The quantum risk register (D12) was not loaded.")
    else:
        r = register_numbers(pop.register)
        repeated = pop.sources_occurrences + r["not_present"] - r["total"]
        add("register", r["total"],
            f"Distinct register assets: {pop.occurrences} occurrences minus {_n(pop.code_occurrences, 'code-scan occurrence')} "
            f"(the register holds collected assets only) "
            + (f"minus {_n(repeated, 'CBOM Sources occurrence')} of an estate asset already counted (one asset read "
               "at several places or by several sources)" if repeated >= 0 else
               f"plus {_n(-repeated, 'estate asset')} counted from a code-scan observation instead")
            + f" plus {_n(r['not_present'], 'register asset')} no latest collection holds (not read or removed, kept "
            f"with their last grade) = {_n(r['total'], 'distinct asset')} in the Quantum Risk Register (D12).")
        grades = pop.register.get("q_grades") if isinstance(pop.register.get("q_grades"), Mapping) else {}
        split = ", ".join(f"{label} {int(grades.get(key, 0) or 0)}" for key, label in (
            ("Q1", "Q1 Critical"), ("Q2", "Q2 High"), ("Q3", "Q3 Medium"), ("Q4", "Q4 Low"), ("Q0", "Q0 Unknown"),
            ("none", "no grade")))
        add("classes", r["total"],
            f"Their grades: {split}. Their SOW classes: {r['graded']} graded Q1 to Q4 ({r[SC.BROKEN]} quantum-broken, {r[SC.DEPRECATED]} "
            f"deprecated, {r[SC.WEAKENED]} weakened, {r[SC.SAFE]} quantum-safe), {r['q0']} Q0 Unknown, {r['none']} "
            "no grade (no public-key cryptography).")
    q = pop.quantum
    if q is not None:
        parts = [f"{q['code_planned']} code-scan algorithm{'' if q['code_planned'] == 1 else 's'}",
                 f"{q['sources_planned']} collected"]
        rest = [f"{q['symmetric']} symmetric or hash", f"{q['no_algorithm']} with no algorithm recorded"]
        if q["code_other"]:
            rest.append(f"{q['code_other']} code-scan certificate or key row{'' if q['code_other'] == 1 else 's'}")
        add("quantum", q["occurrences"],
            f"Quantum-vulnerable: {_n(q['occurrences'], 'occurrence')} carry a quantum-vulnerable verdict (the "
            f"dashboard card and the readiness figure) = {q['planned']} public-key assets the PQC Migration Roadmap "
            f"(D13) plans ({', '.join(parts)}) + " + " + ".join(rest) + ", which are not public-key migrations."
            + (f" The register counts each estate asset once: {register_numbers(pop.register)[SC.BROKEN]} "
               f"quantum-broken and {register_numbers(pop.register)[SC.DEPRECATED]} deprecated."
               if pop.register is not None else ""))
    return out


def lines(pop: Population) -> list[str]:
    return [s["text"] for s in steps(pop)]


def public(pop: Population) -> dict[str, Any]:
    """The block as the dashboard API serves it."""
    return {"title": TITLE, "steps": steps(pop)}


def team_view(team_id: int, scans: Any, sources: Any, now: Any = None) -> Any:
    """The documents' team roll-up (``load_team_cbom_view``'s fold) from the scans and CBOM Sources collections a
    caller already loaded: ``cbom_team_rollup.fold_scans`` over the team's CBOM scans (latest successful scan per
    repository and branch is current; a superseded scan is history), then ``merge_collections``. The dashboard reads
    its cards and this block from it, so it counts what the documents count (staging QA2 Q1-08)."""
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
    view = fold_scans(heads, lambda ids: {i: blobs.get(i) for i in ids}, team_id=team_id, team_name="",
                      now=moment)
    if sources is not None:
        view = merge_collections(view, sources.rows, sources.collections)
    return view


def for_dashboard(view: Any, register_summary: Mapping[str, Any] | None, card_assets: int | None) -> dict[str, Any]:
    """The dashboard's block: the documents' population of ``view`` (``team_view``), the register summary the
    Quantum risk tab reads, and the dashboard's own Crypto Assets card."""
    view.register = {"summary": register_summary} if isinstance(register_summary, Mapping) else None
    pop = from_view(view)
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
