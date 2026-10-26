"""WP7 wiring: scan_crypto runs the posture lanes."""

from __future__ import annotations

from pathlib import Path

from aibom.cbom.pipeline import scan_crypto

_RDS = """\
resource "aws_db_instance" "db" {
  storage_encrypted = false
}
"""


def _facts(result: object) -> list[object]:
    components = getattr(result, "components", ())
    found = []
    for comp in components:
        props = comp.properties or {}
        if comp.kind == "infra" and "crypto:factId" in props:
            found.append(comp)
    return found


def test_unencrypted_rds_is_a_posture_fact(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(_RDS, encoding="utf-8")
    result = scan_crypto(tmp_path)
    not_encrypted = [
        comp
        for comp in _facts(result)
        if (comp.properties or {}).get("crypto:factVerdict") == "NOT_ENCRYPTED"
    ]
    flags = [flag for flag in result.flags if flag.code == "UNENCRYPTED_AT_REST"]
    assert len(not_encrypted) == 1 or len(flags) == 1


def test_empty_directory_has_no_posture_fact(tmp_path: Path) -> None:
    result = scan_crypto(tmp_path)
    assert _facts(result) == []
