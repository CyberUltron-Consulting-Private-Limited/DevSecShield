"""Shipped registry rows match the reviewed finding-from-absence list."""

from pathlib import Path

from aibom.cbom.posture.defaults import (
    DATA_FILES,
    load_registry,
    reviewed_problems,
    url_problems,
)

ROOT = Path(__file__).resolve().parents[1]
REVIEWED = ROOT / "tests" / "cbom_posture_reviewed_rows.txt"
ALLOW = ROOT / "tests" / "cbom_posture_url_allowlist.txt"


def _listed() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in REVIEWED.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        row_id, kind, _evidence = line.split("|", 2)
        out[row_id] = kind
    return out


def _prefixes() -> list[str]:
    return [
        line
        for line in ALLOW.read_text(encoding="utf-8").splitlines()
        if line.startswith("https://")
    ]


def test_shipped_registry_loads_and_matches_the_review() -> None:
    registry = load_registry()
    assert {table.name for table in registry.tables} == set(DATA_FILES)
    listed = _listed()
    assert reviewed_problems(registry, listed) == []
    assert url_problems(registry, _prefixes()) == []
    assessable = [row for row in registry.rows if row.assessable_as_unencrypted]
    finding = [row for row in registry.rows if row.finding_default is not None]
    assert len(assessable) == 10
    assert len(finding) == 3
    elasticache = registry.by_id["aws.elasticache.at_rest.redis"]
    assert elasticache.assessable_as_unencrypted is False
    google = registry.by_id["gcp.kms.rotation_period"]
    assert google.finding_default is None
    assert google.effect == "UNKNOWN"
