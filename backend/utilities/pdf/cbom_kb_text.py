"""What the team deliverables print from the offline crypto knowledge base (``crypto_kb.json``).

The knowledge base is the ONE place that records a standard's status and a finding's title and fix; the authored
text (``cbom_deliverable_text``) and the renderers read it through this module, so a PDF cannot cite NIST IR 8547
as final in one section and as a draft in another (SOW audit A-05), or print a raw finding code with a boilerplate
action (A-12). Pure: the knowledge base is a local JSON file; no database, no clock, no network.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import regulated_entity as entity_types

# the ONE NIST IR 8547 citation (pqc_context.nist_ir_8547); the defaults are only for a knowledge base without it
_IR_DEFAULT = {"citation": "NIST IR 8547", "status": "final", "published": "", "landing": "", "source": "",
               "deprecated_after": 2030, "disallowed_after": 2035, "title": ""}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def ir8547() -> dict[str, Any]:
    """IR 8547 as the knowledge base records it: citation, status, publication date, URLs and transition years."""
    found = (crypto_kb.load().get("pqc_context") or {}).get("nist_ir_8547") or {}
    out = {**_IR_DEFAULT, **{k: v for k, v in found.items() if v not in (None, "")}}
    out["url"] = out.get("landing") or out.get("source") or ""
    published = str(out.get("published") or "")
    out["published_month"] = (f"{_MONTHS[int(published[5:7]) - 1]} {published[:4]}"
                              if len(published) >= 7 and published[5:7].isdigit() and 1 <= int(published[5:7]) <= 12
                              else "")
    return out


def finding(code: object) -> dict[str, str] | None:
    """``{"title", "fix"}`` of a finding code: a CBOM Sources code first, then a code-scan code; None when unknown."""
    key = str(code or "").strip().upper()
    if not key:
        return None
    for namespace in ("node", "code"):
        entry = crypto_kb.entry(namespace, key)
        if entry:
            fix = ((entry.get("remediation") or {}).get("summary") or "").strip()
            return {"title": str(entry.get("title") or "").strip(), "fix": fix}
    return None


# regulated-entity types (team setting) and which knowledge-base clauses bind each
ENTITY_TYPES = entity_types.ENTITY_TYPES
DEFAULT_ENTITY = entity_types.DEFAULT_ENTITY
ENTITY_LABELS = entity_types.LABELS


def clause_applies(clause: Mapping[str, Any], entity: object) -> bool:
    return entity_types.applies(clause, str(entity or ""))


def entity_label(entity: object) -> str:
    return ENTITY_LABELS[entity_types.normalise(entity)]


__all__ = ["DEFAULT_ENTITY", "ENTITY_LABELS", "ENTITY_TYPES", "clause_applies", "entity_label", "finding", "ir8547"]
