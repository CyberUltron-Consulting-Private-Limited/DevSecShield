"""The run API's per-asset risk fields: the quantum risk grade (CB-19 qg-1, #114) and the crypto-agility fix class
(CB-24, #113), judged on every item of ``api/assets-run<k>.json`` (G11).

Both are views the product computes at read time, so there is no DB or export copy to join yet (the export and UI
parts are CB-19 PR-1e / PR-1u and CB-25). What is judged here needs no oracle and no product code (O-1): the
vocabularies and the rule tables are transcribed from the signed specs, not from ``backend/``:

* Q-grade, CB-19 PLAN §2 (the qg-1 formula text, "Rules, first match wins") and §3 (API contract) and §5 ("graded
  items equal the oracle grade; N/A items ``q_grade: null`` with ``q_reason: not_applicable``; the CB-05 check
  ``q_grade_present`` that wanted Q0-Q4 on every item cannot pass and is replaced"): every item carries ``q_grade``;
  a grade is one of Q0..Q4 with its label (Q0 Unknown, Q1 Critical, Q2 High, Q3 Medium, Q4 Low) and a reason the
  formula gives that grade; no grade (null) carries one of the formula's two no-grade reasons and no label.
* Fix class, CB-24 PLAN §4 (asset rule) and §12 (API contract): every item carries ``fix_class`` in the closed set;
  ``none`` exactly when the item has no finding code; ``fix_class_confidence`` observed|inferred for the four
  classes and null for ``unknown`` / ``none``; a ``fix_class_floor`` only on ``unknown``.

Whether the grade or class is the RIGHT one is the oracle's (``expect.q_grade`` / ``expect.fix_class`` on an oracle
asset, CB-02 INTERFACES v8, judged by oracle.py like every other stated key). Until the lab states them nothing is
claimed about the values beyond the rules above.
"""
from __future__ import annotations

from typing import Any

from .checks import Checks

GATE = "G11"
# CB-19 PLAN §2: grades and labels; reasons by grade (rules 1-23; "qv_" and "qv_fallback_" families of rules 9-18)
Q_LABELS = {"Q0": "Unknown", "Q1": "Critical", "Q2": "High", "Q3": "Medium", "Q4": "Low"}
Q_REASONS = {
    "Q0": {"coverage_gap", "source_not_read", "source_truncated", "excluded_by_choice", "evidence_e0",
           "unknown_verdict", "not_correlated", "mosca_missing"},
    "Q1": {"qv_exceeds_internet", "qv_exceeds_anchor", "qv_fallback_exceeds_internet", "qv_fallback_exceeds_anchor"},
    "Q2": {"qv_exceeds_exposure_unknown", "qv_exceeds", "qv_fallback_exceeds_exposure_unknown", "qv_fallback_exceeds"},
    "Q3": {"qv_within", "qv_fallback_within", "grover_weakened", "pq_attested_e1"},
    "Q4": {"pq_observed", "pq_code", "pq_attested"},
}
NO_GRADE_REASONS = {"not_applicable", "attested_no_class"}  # rules 3 and 5: "no grade" is not a grade
# CB-24 PLAN §2 (the diagram's chip order, easiest to hardest) + §4 (unknown, none)
FIX_CLASSES = ("configurable", "code-fixed", "vendor-fixed", "hardware-fixed")
FIX_ALL = (*FIX_CLASSES, "unknown", "none")
CONFIDENCE = ("observed", "inferred")


def qgrade_problems(item: dict[str, Any]) -> list[str]:
    if "q_grade" not in item:
        return ["absent"]
    grade, reason, label = item.get("q_grade"), item.get("q_reason"), item.get("q_label")
    out = []
    if grade is None:
        if reason not in NO_GRADE_REASONS:
            out.append(f"no grade with reason {reason!r} (not one of {sorted(NO_GRADE_REASONS)})")
        if label is not None:
            out.append(f"no grade with label {label!r}")
        return out
    if grade not in Q_LABELS:
        return [f"grade {grade!r} not one of Q0..Q4"]
    if label != Q_LABELS[grade]:
        out.append(f"label {label!r} for {grade} (want {Q_LABELS[grade]!r})")
    if reason not in Q_REASONS[grade]:
        out.append(f"reason {reason!r} is not one the formula gives {grade}")
    return out


def fixclass_problems(item: dict[str, Any]) -> list[str]:
    if "fix_class" not in item:
        return ["absent"]
    cls, floor, conf = item.get("fix_class"), item.get("fix_class_floor"), item.get("fix_class_confidence")
    if cls not in FIX_ALL:
        return [f"fix_class {cls!r} not one of {list(FIX_ALL)}"]
    out = []
    codes = item.get("finding_codes") or []
    if (cls == "none") != (not codes):
        out.append(f"fix_class {cls!r} with {len(codes)} finding code(s) (none exactly when there is no code)")
    if cls in FIX_CLASSES and conf not in CONFIDENCE:
        out.append(f"confidence {conf!r} on {cls} (want observed|inferred)")
    if cls in ("unknown", "none") and conf is not None:
        out.append(f"confidence {conf!r} on {cls} (want null)")
    if cls != "unknown" and floor is not None:
        out.append(f"floor {floor!r} on {cls} (a floor only on unknown)")
    if cls == "unknown" and floor not in (None, *FIX_CLASSES):
        out.append(f"floor {floor!r} not one of {list(FIX_CLASSES)}")
    return out


def judge(k: str, checks: Checks, api: dict[int, dict[str, Any]] | None) -> dict[str, int]:
    """One check per asset and field: ``G11/qgrade/run<k>/asset/<id>`` and ``G11/fixclass/run<k>/asset/<id>``."""
    if api is None:
        for name in ("qgrade", "fixclass"):
            checks.not_run(f"{GATE}/{name}/run{k}", GATE, "api", f"api/assets-run{k}.json not captured",
                           {"check": name, "run": k})
        return {}
    bad = {"qgrade": 0, "fixclass": 0}
    for aid, item in sorted(api.items()):
        for name, fn, keys in (("qgrade", qgrade_problems, ("q_grade", "q_label", "q_reason")),
                               ("fixclass", fixclass_problems, ("fix_class", "fix_class_floor", "fix_class_confidence"))):
            problems = fn(item)
            bad[name] += bool(problems)
            reason = "" if not problems else f"{name}-absent" if problems == ["absent"] else f"{name}-malformed"
            checks.verdict(f"{GATE}/{name}/run{k}/asset/{aid}", GATE, "api", not problems, reason,
                           {"kind": "api", "check": name, "run": k, "asset_id": aid, "asset_type": item.get("type"),
                            "location": item.get("location"), "field": name},
                           expected="CB-19 qg-1 grade/label/reason" if name == "qgrade" else "CB-24 fix class rules",
                           observed={"values": {key: item.get(key, "<absent>") for key in keys},
                                     **({"problems": problems} if problems else {})})
    return bad
