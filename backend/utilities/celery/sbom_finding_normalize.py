"""Normalize SBOM SCA finding_data before Mongo persist.

Writer contract: every inserted finding_data has a non-empty ``title`` and a
``description`` string key. Legacy sparse rows (demo / compliance fixtures)
get backfilled here so the GET-scan reader never KeyErrors on identity fields.
"""

from __future__ import annotations

__all__ = ["normalize_sbom_finding_data"]


def normalize_sbom_finding_data(row: dict | None) -> dict:
    """Return a copy of ``row`` with title/description guaranteed.

    - title: strip(title) or strip(dependency) or \"Untitled finding\"
    - description: always a str (missing/None → \"\")
    Other fields are passed through unchanged.
    """
    out = dict(row or {})
    dep = str(out.get("dependency") or "").strip()
    title = str(out.get("title") or "").strip() or dep or "Untitled finding"
    out["title"] = title
    out["description"] = str(out.get("description") or "")
    return out
