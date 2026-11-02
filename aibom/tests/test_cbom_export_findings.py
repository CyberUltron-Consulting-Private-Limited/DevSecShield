"""The downloaded code-scan CycloneDX carries what the product decided.

* every crypto asset, crypto library and posture fact has one ``zs:finding_code`` property per finding code and
  ``zs:impact`` (``Info`` for clean inventory), mirroring the node-run export;
* crypto libraries and posture facts say where they were found (``evidence.occurrences`` file + line);
* a component synthesized from a certificate is marked derived and carries no finding of its own;
* clean inventory rows (no finding code) have no impact; quantum-vulnerable rows keep Medium.
"""

from __future__ import annotations

import json
from pathlib import Path

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.emit.cyclonedx import emit_cyclonedx
from aibom.emit.validate import validate_cyclonedx

_FX = Path(__file__).resolve().parent / "fixtures"


def _props(comp: dict) -> list[tuple[str, str]]:
    return [(p["name"], p["value"]) for p in comp.get("properties") or []]


def _codes(comp: dict) -> list[str]:
    return [v for n, v in _props(comp) if n == "zs:finding_code"]


def _impact(comp: dict) -> str | None:
    return next((v for n, v in _props(comp) if n == "zs:impact"), None)


def _run(name: str) -> tuple[object, dict]:
    result = scan_crypto(_FX / name)
    return result, normalize_crypto(result, duration_of_scan=0.0)


def test_every_row_carries_its_codes_and_impact() -> None:
    result, run = _run("synthetic-crypto-app")
    bom = run["cbom_json"]
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    rows = {r["bom_ref"]: r for r in run["results"]}
    assert rows
    for ref, row in rows.items():
        comp = by_ref[ref]
        assert _codes(comp) == sorted(row["finding_codes"]), ref
        assert _impact(comp) == (row["impact"] or "Info"), ref
    md5 = next(c for c in bom["components"] if c["name"] == "MD5")
    assert "WEAK_ALGORITHM" in _codes(md5) and _impact(md5) == "High"


def test_clean_inventory_has_no_impact_and_quantum_vulnerable_keeps_medium() -> None:
    _result, run = _run("synthetic-crypto-app")
    clean = [r for r in run["results"] if not r["finding_codes"]]
    assert clean, "fixture has clean inventory rows (AES-GCM, SHA-256 ...)"
    for row in clean:
        assert row["impact"] is None
        assert row["risk_score"] == 0.0
    qv_only = [r for r in run["results"] if r["finding_codes"] == ["QUANTUM_VULNERABLE"]]
    assert qv_only and all(r["impact"] == "Medium" for r in qv_only)


def test_enriched_bom_is_schema_valid_and_deterministic() -> None:
    _r1, run1 = _run("synthetic-crypto-app")
    _r2, run2 = _run("synthetic-crypto-app")
    assert validate_cyclonedx(run1["cbom_json"]) == []
    assert json.dumps(run1["cbom_json"], sort_keys=True) == json.dumps(run2["cbom_json"], sort_keys=True)


def test_libraries_say_where_they_were_declared() -> None:
    result = scan_crypto(_FX / "synthetic-crypto-manifests")
    bom = emit_cyclonedx(result)
    libs = [c for c in bom["components"] if c["type"] == "library"]
    assert libs
    for comp in libs:
        props = dict(_props(comp))
        if not props.get("crypto:line"):
            continue
        occ = comp["evidence"]["occurrences"]
        assert occ[0] == {"location": props["discovery:source"], "line": int(props["crypto:line"])}
    assert any("evidence" in c for c in libs)


def test_posture_facts_say_where_they_were_read() -> None:
    result, run = _run("synthetic-config-aws-tf")
    facts = [c for c in run["cbom_json"]["components"] if c["type"] == "platform"
             and any(n == "crypto:factId" for n, _ in _props(c))]
    assert facts
    for comp in facts:
        props = dict(_props(comp))
        assert comp["evidence"]["occurrences"] == [
            {"location": props["crypto:factPath"], "line": int(props["crypto:factLine"])}
        ]
        assert _impact(comp) is not None
    assert validate_cyclonedx(run["cbom_json"]) == []


def test_fact_line_is_the_deciding_attribute(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "db" {\n'
        '  engine            = "postgres"\n'
        '  instance_class    = "db.t3.medium"\n'
        "  storage_encrypted = false\n"
        "}\n"
    )
    (tmp_path / "stack.yaml").write_text(
        "Resources:\n"
        "  Db:\n"
        "    Type: AWS::RDS::DBInstance\n"
        "    Properties:\n"
        "      Engine: postgres\n"
        "      StorageEncrypted: false\n"
    )
    result = scan_crypto(tmp_path)
    lines = {
        (c.properties or {}).get("crypto:factPath"): (c.properties or {}).get("crypto:factLine")
        for c in result.components if "crypto:factId" in (c.properties or {})
    }
    assert lines == {"rds.tf": "4", "stack.yaml": "6"}


def test_certificate_derived_algorithms_are_marked_and_unscored() -> None:
    _result, run = _run("synthetic-crypto-certs")
    derived = [c for c in run["cbom_json"]["components"]
               if dict(_props(c)).get("crypto:derived") == "true"]
    assert derived, "certificate-only algorithms are synthesized for this fixture"
    refs = {c["bom-ref"] for c in run["cbom_json"]["components"]}
    for comp in derived:
        props = dict(_props(comp))
        assert props["crypto:derivedFrom"] in refs
        assert "evidence" not in comp
        assert not _codes(comp) and _impact(comp) is None
