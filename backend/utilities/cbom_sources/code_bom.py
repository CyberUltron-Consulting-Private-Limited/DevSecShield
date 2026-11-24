"""The CycloneDX CBOM of a code scan as the server serves it (staging QA A-13b, A-13c, A-13d).

The worker stores the engine's CBOM; every route that serves, packs, signs or verifies it builds it through
``certin_attest.bom_dict_from_scan_data``, which calls ``served_code_cbom`` here:

* **Subject (A-13b).** ``metadata.component.name`` is the scanned repository, ``owner/repo`` from the scan's metadata
  (``certin_attest.subject_name_for``), never the worker's clone directory ("src", "repo_31klki5v").
* **Grade, PQC class and fix class (A-13c).** Each component with a result row carries ``zs:pqc_class`` /
  ``zs:pqc_class_basis`` (``posture.graded_class``), ``zs:q_grade`` / ``zs:q_label`` / ``zs:q_reason`` (``qgrade.grade``
  with ``provenance="code"``, rule 22 "pq_code") and ``zs:fix_class`` / ``zs:fix_class_floor`` /
  ``zs:fix_class_confidence`` (``agility.code_row_fields``, what the results table shows): the functions the team
  register and the run export use (Rule P), with algorithm identities from algid only (through those functions).
  The grade reads the team's Mosca inputs when the caller has them, else the model's defaults, which are named in
  ``zs:grade_inputs_assumed``.
* **Vulnerabilities (A-13d).** ``vulnerabilities[]`` lists what the scan's VEX states (one entry per finding code and
  per matched CVE, ``vex_semantics.code_scan_vulnerabilities``) with plain bom-refs; the standalone VEX names the same
  ids and points at this document's components by BOM-Link.
"""
from __future__ import annotations

import copy
from types import SimpleNamespace
from typing import Any, Mapping


def _rows_by_ref(rows: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and row.get("bom_ref"):
            out.setdefault(str(row["bom_ref"]), row)
    return out


def _quantum_verdict(row: Mapping[str, Any]) -> bool | None:
    """The quantum verdict the class reads: a code row's own, except that a classically broken algorithm that no
    quantum computer breaks (MD5, DES) has none (it is not "quantum-safe"; SP 800-131A grades it as deprecated)."""
    if row.get("asset_type") != "algorithm":
        return None
    if row.get("weak") and not row.get("quantum_vulnerable"):
        return None
    qv = row.get("quantum_vulnerable")
    return qv if isinstance(qv, bool) else None


def assessment(row: Mapping[str, Any], mosca: Mapping[str, Any] | None = None) -> list[dict[str, str]]:
    """The grade, PQC class and fix class properties of one code-scan result row."""
    from backend.utilities.cbom_sources import agility as AG
    from backend.utilities.cbom_sources import posture as P
    from backend.utilities.cbom_sources import qgrade as QG

    codes = [c for c in row.get("finding_codes") or [] if isinstance(c, str) and not c.startswith("COVERAGE_")]
    probe = {"asset_type": row.get("asset_type") or row.get("algorithm_type") or "",
             "quantum_vulnerable": _quantum_verdict(row), "facts": {}, "algorithm": row.get("title"),
             "key_size": row.get("key_size")}
    cls, basis = P.graded_class(probe, codes)
    ns = SimpleNamespace(**probe)
    disallowed = cls == "deprecated" or (cls != "unknown" and QG.disallowed_now(ns))
    m = mosca or {}
    x, y, z, _x_basis, assumed = QG.effective_mosca(None, m.get("x"), m.get("y"), m.get("z"))
    grade = QG.grade(QG.GradeInput(cls=QG.graded_pqc_class(cls, ns, disallowed), provenance="code", x=x, y=y, z=z,
                                   disallowed=disallowed))
    fix = AG.code_row_fields(dict(row))
    props = [
        {"name": "zs:pqc_class", "value": cls},
        {"name": "zs:pqc_class_basis", "value": basis},
        {"name": "zs:q_grade", "value": grade.q_grade or "none"},
        {"name": "zs:q_label", "value": grade.q_label or "none"},
        {"name": "zs:q_reason", "value": grade.q_reason},
        {"name": "zs:fix_class", "value": fix["fix_class"]},
        {"name": "zs:fix_class_floor", "value": fix["fix_class_floor"] or "none"},
        {"name": "zs:fix_class_confidence", "value": fix["fix_class_confidence"] or "none"},
    ]
    if assumed and grade.q_reason.startswith("qv_"):
        props.append({"name": "zs:grade_inputs_assumed", "value": ",".join(assumed)})
    return props


_STAMPED = frozenset({"zs:pqc_class", "zs:pqc_class_basis", "zs:q_grade", "zs:q_label", "zs:q_reason", "zs:fix_class",
                      "zs:fix_class_floor", "zs:fix_class_confidence", "zs:grade_inputs_assumed"})


def served_code_cbom(bom: dict[str, Any], rows: Any, *, subject_name: str | None = None,
                     mosca: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """A copy of a code scan's stored CBOM as served (see the module docstring)."""
    from backend.utilities.cbom_sources import vex_semantics as VEX

    out = copy.deepcopy(bom)
    if subject_name:
        meta = out.setdefault("metadata", {})
        component = meta.get("component") if isinstance(meta.get("component"), dict) else {"type": "application"}
        meta["component"] = {**component, "name": subject_name}
    by_ref = _rows_by_ref(rows)
    for comp in out.get("components") or []:
        if not isinstance(comp, dict):
            continue
        row = by_ref.get(str(comp.get("bom-ref") or ""))
        if row is None:
            continue
        kept = [p for p in comp.get("properties") or [] if not (isinstance(p, dict) and p.get("name") in _STAMPED)]
        comp["properties"] = kept + assessment(row, mosca)
    refs = [str(c.get("bom-ref")) for c in out.get("components") or [] if isinstance(c, dict) and c.get("bom-ref")]
    vulns = VEX.code_scan_vulnerabilities(rows if isinstance(rows, list) else [], components=refs)
    if vulns:
        out["vulnerabilities"] = vulns
    else:
        out.pop("vulnerabilities", None)
    return out


__all__ = ["assessment", "served_code_cbom"]
