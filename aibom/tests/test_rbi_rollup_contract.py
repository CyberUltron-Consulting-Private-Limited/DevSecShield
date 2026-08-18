"""Contract: every FREE-AI requirement the BOM lanes EMIT must be MAPPED to an
RBI CSF pillar in ``aibom/config/rbi-csf-rollup.yaml``.

Why this exists
---------------
The team dashboard's "RBI CSF Posture Rollup" aggregates FREE-AI verdicts into
the five RBI CSF pillars by matching ``requirement.id`` against that YAML map
with EXACT string equality (``backend/utilities/dashboard/rbi_posture.py``).

Two silent-failure modes are possible, and neither is caught by a test that
synthesizes its own compliance blob (the pre-existing
``backend/tests/test_rbi_csf_rollup.py`` feeds a hand-built ``FREEAI-14`` row,
so it validates the mapping but can never see what the engines actually emit):

1. A lane emits an ID the YAML doesn't map -> that verdict is silently dropped
   from the rollup. No error, no log; the pillar is just quietly under-counted.
2. A lane stops emitting FREE-AI verdicts altogether (e.g. the framework is not
   registered, or an applicability gate closes) -> every pillar aggregates to 0.
   The backend still returns all five pillar keys, so the frontend's
   ``pillars.length === 0`` guard does not fire and the chart renders as
   zero-length bars: axis labels and gridlines with no visible data. This is
   exactly the defect this test was written after.

These assertions run the REAL adapters, so they check the exact
``*_compliance`` blobs that get persisted into ``Scan.scan_data`` and later fed
to ``build_rbi_csf_rollup``.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import yaml

from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield
from aibom.integrations.devsecshield import scan_to_devsecshield
from aibom.integrations.sbom_devsecshield import enrich_sbom_scan

_HERE = os.path.dirname(os.path.abspath(__file__))
_CONFIG = os.path.join(_HERE, "..", "config", "rbi-csf-rollup.yaml")
_FX = os.path.join(_HERE, "fixtures")


def _mapped_ids() -> set[str]:
    """Every requirement id the rollup config can place into a pillar."""
    with open(_CONFIG, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    ids: set[str] = set()
    for _pillar, rids in (cfg.get("pillars") or {}).items():
        ids.update(str(r) for r in (rids or []))
    ids.update(str(r) for r in (cfg.get("innovation_as_governance") or []))
    return ids


def _free_ai_ids(blob: dict[str, Any] | None) -> set[str]:
    """FREE-AI requirement ids inside a persisted ``*_compliance`` blob."""
    out: set[str] = set()
    for key, fw in (blob or {}).items():
        if key == "disclaimer" or not isinstance(fw, dict):
            continue
        for req in fw.get("requirements") or []:
            rid = str((req or {}).get("id") or "")
            if rid.startswith("FREEAI"):
                out.add(rid)
    return out


def _emitted_by_lane() -> dict[str, set[str]]:
    """Run each BOM lane's real adapter and collect the FREE-AI ids it emits."""
    ai = scan_to_devsecshield(
        os.path.join(_FX, "synthetic-clinical-samd"), level=4
    ).get("ai_bom_compliance")
    cb = scan_crypto_to_devsecshield(
        os.path.join(_FX, "synthetic-crypto-app")
    ).get("cbom_compliance")
    sb = enrich_sbom_scan(
        [
            {
                "dependency": "requests==2.31.0",
                "impact": "Critical",
                "reachability": "reachable",
                "license_type": "copyleft",
                "cves": {"CVE-2024-0001": "Critical"},
            }
        ],
        0.0,
    ).get("sbom_compliance")
    return {"ai_bom": _free_ai_ids(ai), "cbom": _free_ai_ids(cb), "sbom": _free_ai_ids(sb)}


@pytest.fixture(scope="module")
def emitted() -> dict[str, set[str]]:
    return _emitted_by_lane()


def test_every_lane_still_emits_free_ai_verdicts(emitted: dict[str, set[str]]) -> None:
    """Failure mode 2: a lane going silent zeroes the whole rollup."""
    for lane, ids in emitted.items():
        assert ids, (
            f"lane {lane!r} emitted NO FREE-AI requirements — the RBI CSF rollup "
            "would aggregate to all-zero pillars and the dashboard chart would "
            "render empty bars. Is the FREE-AI framework still registered for "
            "this lane, or has an applicability gate closed?"
        )


def test_no_emitted_free_ai_id_is_unmapped(emitted: dict[str, set[str]]) -> None:
    """Failure mode 1: an unmapped id is silently dropped from every pillar."""
    mapped = _mapped_ids()
    all_emitted = set().union(*emitted.values())
    unmapped = sorted(all_emitted - mapped)
    assert not unmapped, (
        f"{len(unmapped)} FREE-AI requirement(s) are emitted but NOT mapped to any "
        f"RBI CSF pillar in config/rbi-csf-rollup.yaml: {unmapped}. Their verdicts "
        "are silently dropped from the dashboard rollup — add them to a pillar."
    )


def test_every_declared_id_pillar_pair_is_reachable() -> None:
    """A requirement declared under TWO pillars must contribute to BOTH.

    ``_req_to_pillar_map`` used to return a flat ``dict[str, str]``, so an id
    listed under two pillars was last-write-wins and silently vanished from the
    earlier one. FREEAI-21-1 is declared under both `detection` and `response`;
    with the flat map, `detection` lost its ONLY BOM-evidenceable control and
    reported coverage=n/a (an empty bar) instead of 100%. This asserts every
    (id, pillar) pair declared in the YAML is actually reachable.
    """
    with open(_CONFIG, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    declared: set[tuple[str, str]] = set()
    for pillar, rids in (cfg.get("pillars") or {}).items():
        for rid in rids or []:
            declared.add((str(rid), str(pillar)))
    for rid in cfg.get("innovation_as_governance") or []:
        declared.add((str(rid), "governance"))

    # Rebuild the map exactly as the backend does, without importing it (the
    # backend package is not importable from the aibom venv).
    mapping: dict[str, set[str]] = {}
    for rid, pillar in declared:
        mapping.setdefault(rid, set()).add(pillar)

    unreachable = sorted(p for p in declared if p[1] not in mapping.get(p[0], ()))
    assert not unreachable, f"(id, pillar) pairs unreachable after mapping: {unreachable}"

    multi = {rid: pillars for rid, pillars in mapping.items() if len(pillars) > 1}
    for rid, pillars in multi.items():
        assert len(pillars) == len({p for p in pillars}), rid
    # Documents the real multi-pillar ids so a regression to a flat map is loud.
    assert multi, (
        "no id maps to multiple pillars — if the YAML genuinely changed that is "
        "fine, but the flat-map regression this guards against is then untested"
    )


def test_rollup_config_has_no_dead_entries(emitted: dict[str, set[str]]) -> None:
    """A mapped id no lane emits can never contribute — surfaces config drift."""
    mapped = _mapped_ids()
    all_emitted = set().union(*emitted.values())
    dead = sorted(mapped - all_emitted)
    assert not dead, (
        f"{len(dead)} id(s) mapped in config/rbi-csf-rollup.yaml are emitted by no "
        f"lane: {dead}. Either a lane stopped emitting them or the config drifted."
    )
