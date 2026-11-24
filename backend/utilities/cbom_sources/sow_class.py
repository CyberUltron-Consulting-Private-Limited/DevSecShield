"""The SOW classification of a register asset (SOW section 3.2 step 4, staging QA round 2 M3).

The SOW grades each item "as quantum-broken, weakened, deprecated or quantum-safe", and "items that cannot be assessed
are graded Q0 Unknown with a reason". This module names that class for every register row, from the grade the
register already holds (``qgrade.grade``: its ``q_grade`` and ``q_reason``) and, for the one case the reason does not
settle, the grade's own SP 800-131A input (``qgrade.disallowed_now``). It grades nothing itself and never re-reads a
row the grade did not read, so the class, the grade and the reason cannot disagree (Rule P).

Classes, first match wins:

1. ``deprecated``: NIST SP 800-131A disallows the asset's algorithm or key today (RSA or DSA below what SP 800-131A
   allows, DES / Triple DES, RC4, MD5, SHA-1 signatures ...). The grade's reason is ``deprecated`` or
   ``deprecated_internet`` (rules 24-25 and the disallowed cap), or the grade is a Q1 trust-anchor reason whose row is
   disallowed (the cap keeps the worse Q1 anchor grade there, so the reason alone does not say it).
2. ``quantum-broken``: a quantum computer breaks it (Shor): any ``qv_*`` reason (the fallback reasons included).
3. ``weakened``: a quantum computer weakens it (Grover): a symmetric key of 128 bits or less, ``grover_weakened``.
4. ``quantum-safe``: post-quantum, hybrid, or a symmetric key of 192 bits or more, a MAC or a hash (the class function
   reads a symmetric key a collector marked quantum-vulnerable as such, review 6038529822 M5): any ``pq_*`` reason.
5. ``unknown``: Q0 Unknown, whatever the reason (the class, the correlation or a Mosca input is unknown).
6. ``not applicable``: no grade: no public-key cryptography to grade (a library, a setting).

A deprecated asset may also be quantum-broken (RSA-1024, an IKE policy with Triple DES and a classical Diffie-Hellman
group): ``also_quantum_broken`` says so, and every surface prints both facts.

Why a grade reason is enough (FORMULA_TEXT, "Disallowed cap"): a disallowed asset graded by rules 7-23 takes the
worse of that grade and rules 24-25, with the ``deprecated`` reason on a tie. Rules 24-25 give Q1 on the internet,
else Q2, so every disallowed rules-7-23 grade ends with a ``deprecated`` reason except a Q1 that is not internet-
facing: the trust-anchor reasons (``ANCHOR_REASONS``). Only those rows are read again, and only for the SP 800-131A
status the grade itself read.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any

BROKEN = "quantum-broken"
WEAKENED = "weakened"
DEPRECATED = "deprecated"
SAFE = "quantum-safe"
UNKNOWN = "unknown"
NOT_APPLICABLE = "not applicable"
CLASSES = (BROKEN, WEAKENED, DEPRECATED, SAFE, UNKNOWN, NOT_APPLICABLE)
GRADED_CLASSES = (BROKEN, DEPRECATED, WEAKENED, SAFE)  # the classes of a Q1-Q4 grade
DEPRECATED_REASONS = frozenset({"deprecated", "deprecated_internet"})
# Q1 reasons the disallowed cap keeps over "deprecated" (a trust anchor that is not internet-facing)
ANCHOR_REASONS = frozenset({"qv_exceeds_anchor", "qv_fallback_exceeds_anchor"})
# Product text: what each class means, printed in the D12 PDF and the register CSV note
MEANING = {
    DEPRECATED: "NIST SP 800-131A disallows the algorithm or key today",
    BROKEN: "a quantum computer breaks it (Shor)",
    WEAKENED: "a quantum computer weakens it (Grover): a symmetric key of 128 bits or less",
    SAFE: "post-quantum, hybrid, or a symmetric key of 192 bits or more, a MAC or a hash",
    UNKNOWN: "Q0 Unknown: it could not be assessed (the reason says why)",
    NOT_APPLICABLE: "no public-key cryptography to grade",
}
ALSO_BROKEN = "also quantum-broken"


def sow_class(q_grade: str | None, q_reason: str | None, disallowed: bool | Callable[[], bool] = False) -> str:
    """The SOW class of a register row from its grade (see the module docstring). ``disallowed``: the grade's SP
    800-131A input for the row (``qgrade.disallowed_now``), or a callable that reads it; it is read only for a
    trust-anchor reason."""
    reason = str(q_reason or "")
    if reason in DEPRECATED_REASONS:
        return DEPRECATED
    if reason in ANCHOR_REASONS and (disallowed() if callable(disallowed) else disallowed):
        return DEPRECATED
    if q_grade == "Q0":
        return UNKNOWN
    if reason.startswith("qv_"):
        return BROKEN
    if reason == "grover_weakened":
        return WEAKENED
    if reason.startswith("pq_"):
        return SAFE
    return NOT_APPLICABLE if q_grade is None else UNKNOWN


def also_quantum_broken(label: str, pqc_class: str | None, q_reason: str | None) -> bool:
    """A deprecated asset that a quantum computer also breaks: the class the grade read is quantum-vulnerable (or a
    hybrid / post-quantum endpoint graded on its classical fallback), or the grade's reason is a ``qv_*`` one."""
    if label != DEPRECATED:
        return False
    return pqc_class == "quantum-vulnerable" or str(q_reason or "").startswith("qv_")


def text(label: str, also_broken: bool = False) -> str:
    """The class as every surface prints it: the label, then the second fact ("deprecated; also quantum-broken")."""
    return f"{label}; {ALSO_BROKEN}" if also_broken else label


def needs_disallowed(q_reason: str | None) -> bool:
    return str(q_reason or "") in ANCHOR_REASONS


def counts(groups: Iterable[tuple[str | None, str, Any, Any, int]],
           anchors_disallowed: int = 0) -> dict[str, int]:
    """Register rows per SOW class from the register's summary groups ``(q_grade, q_reason, family, presence, n)``
    (``estate_summary_ddl.register_groups``). ``anchors_disallowed``: of the trust-anchor rows, how many the grade read
    as disallowed (``anchor_disallowed_count``); they move from quantum-broken to deprecated."""
    out = {c: 0 for c in CLASSES}
    anchors = 0
    for grade, reason, _family, _presence, n in groups:
        out[sow_class(grade, reason)] += int(n)
        anchors += int(n) if str(reason or "") in ANCHOR_REASONS else 0
    moved = max(0, min(int(anchors_disallowed), anchors))
    out[BROKEN] -= moved
    out[DEPRECATED] += moved
    return out


def anchor_disallowed_count(session: Any, team_id: int) -> int:
    """Of the register's trust-anchor rows (``ANCHOR_REASONS``), how many the grade read as SP 800-131A disallowed:
    the stored row the grade came from (the observation of the row's ``source_ref``, as ``risk_register.add_detail``
    picks it), judged by ``qgrade.disallowed_now``. Anchors are few (CA certificates and CAs), so this reads a few
    rows, never the register."""
    import sqlalchemy as sa

    from backend.new_models import CbomCollectedAsset, CbomRiskRegister
    from backend.utilities.cbom_sources import estate as E
    from backend.utilities.cbom_sources import qgrade as QG

    rt = CbomRiskRegister.__table__  # type: ignore[attr-defined]
    rows = session.execute(sa.select(rt.c.item_key, rt.c.source_ref).where(
        rt.c.team_id == team_id, rt.c.q_reason.in_(sorted(ANCHOR_REASONS)))).all()
    if not rows:
        return 0
    latest = E.latest_rows(session, team_id, [r.item_key for r in rows])
    ids = []
    for r in rows:
        entry = latest.get(r.item_key) or {}
        obs = (entry.get("observations") or {}).get(r.source_ref or "") or entry.get("latest") or {}
        if obs.get("asset_id"):
            ids.append(int(obs["asset_id"]))
    found = 0
    for start in range(0, len(ids), 500):
        for row in session.execute(sa.select(CbomCollectedAsset.asset_type, CbomCollectedAsset.algorithm,
                                             CbomCollectedAsset.key_size, CbomCollectedAsset.facts).where(
                CbomCollectedAsset.id.in_(ids[start:start + 500]))).all():  # type: ignore[union-attr]
            found += 1 if QG.disallowed_now(row) else 0
    return found


def summary_counts(session: Any, team_id: int, groups: Iterable[tuple] | None = None) -> dict[str, int]:
    """The register's rows per SOW class (``risk_register.summary``'s ``sow_classes``)."""
    from backend.utilities.cbom_sources import estate_summary_ddl as SUMMARY

    rows = list(groups) if groups is not None else SUMMARY.register_groups(session, team_id)
    return counts(rows, anchor_disallowed_count(session, team_id))


def graded_total(classes: Mapping[str, int]) -> int:
    return sum(int(classes.get(c, 0) or 0) for c in GRADED_CLASSES)


__all__ = ["ALSO_BROKEN", "ANCHOR_REASONS", "BROKEN", "CLASSES", "DEPRECATED", "DEPRECATED_REASONS", "GRADED_CLASSES",
           "MEANING", "NOT_APPLICABLE", "SAFE", "UNKNOWN", "WEAKENED", "also_quantum_broken", "anchor_disallowed_count",
           "counts", "graded_total", "needs_disallowed", "sow_class", "summary_counts", "text"]
