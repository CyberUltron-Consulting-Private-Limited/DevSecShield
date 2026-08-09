"""Lock: every CERT-In ledger requirement id appears in cert-in-rollup.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml

_AIBOM = Path(__file__).resolve().parents[1]
_LEDGER = _AIBOM / "src" / "aibom" / "compliance" / "cert_in" / "ledger.yaml"
_YAML = _AIBOM / "config" / "cert-in-rollup.yaml"

_EXPECTED_DIMS = (
    "sbom_minimum_elements",
    "sbom_recommendations",
    "cbom_crypto_assets",
    "cbom_recommendations",
    "aibom_ai_assets",
    "aibom_recommendations",
)


def test_rollup_yaml_covers_every_ledger_id_exactly_once() -> None:
    ledger = yaml.safe_load(_LEDGER.read_text(encoding="utf-8"))
    ledger_ids = {str(r["id"]) for r in (ledger.get("requirements") or []) if r.get("id")}
    cfg = yaml.safe_load(_YAML.read_text(encoding="utf-8"))
    dims = cfg.get("dimensions") or {}
    assert set(dims.keys()) == set(_EXPECTED_DIMS)

    seen: dict[str, str] = {}
    for dim, ids in dims.items():
        for rid in ids or []:
            rid = str(rid)
            assert rid not in seen, f"{rid} in both {seen[rid]} and {dim}"
            seen[rid] = dim

    assert set(seen.keys()) == ledger_ids, (
        f"yaml missing {ledger_ids - set(seen)} extra {set(seen) - ledger_ids}"
    )
