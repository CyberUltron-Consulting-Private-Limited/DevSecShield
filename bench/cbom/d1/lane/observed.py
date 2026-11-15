"""What the product reported, in the one shape the judge reads.

`from_run_object` converts the CBOM run-object's `results` rows (what the scan-worker stores and the API returns for a
code scan) into observed rows. `run_product.py` uses it on the engine's own output; the Tier-L gate can use it on
the rows it read from the API (W-D1: the hosted path must give the same verdicts).
"""
from __future__ import annotations

import json
from pathlib import Path

from . import SCHEMA_OBSERVED
from .labels import LaneError


def _row(r: dict) -> dict | None:
    codes = sorted({str(c) for c in (r.get("finding_codes") or r.get("codes") or []) if c})
    if not codes:
        return None  # inventory only: nothing was flagged
    line = r.get("line")
    occ = r.get("occurrences") or []
    location = str(r.get("location") or "").replace("\\", "/")
    while location.startswith("./"):
        location = location[2:]
    return {"location": location,
            "line": int(line) if isinstance(line, int) or (isinstance(line, str) and line.isdigit()) else None,
            "occurrences": sorted({int(x) for x in occ if isinstance(x, int) or (isinstance(x, str) and x.isdigit())}),
            "codes": codes,
            "algorithm": str(r.get("algorithm_name") or r.get("algorithm") or r.get("title") or ""),
            "asset_type": r.get("asset_type")}


def from_run_object(results: list[dict]) -> list[dict]:
    rows = [x for x in (_row(r) for r in results) if x]
    return sorted(rows, key=lambda x: (x["location"], x["line"] or 0, x["algorithm"], x["codes"]))


def document(bench: str, rows: list[dict], product: dict) -> dict:
    return {"schema": SCHEMA_OBSERVED, "bench": bench, "product": product, "rows": rows}


def load(path: Path, bench: str) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("schema") != SCHEMA_OBSERVED or doc.get("bench") != bench:
        raise LaneError(f"{path}: not an observed file for {bench} (schema {doc.get('schema')!r}, bench "
                        f"{doc.get('bench')!r})")
    for r in doc["rows"]:
        if not isinstance(r.get("codes"), list) or "location" not in r:
            raise LaneError(f"{path}: malformed row {r!r}")
    return doc
