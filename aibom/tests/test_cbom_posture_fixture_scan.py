"""A committed Terraform tree is scanned by the registered posture lane."""

import json
from pathlib import Path

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

TREE = Path(__file__).resolve().parent / "fixtures" / "synthetic-config-aws-tf"


def test_committed_terraform_tree_matches_the_oracle() -> None:
    expected = json.loads((TREE / "expected_config_aws_tf.json").read_text())
    result = scan_crypto(TREE)
    found = []
    for comp in result.components:
        props = comp.properties or {}
        if comp.kind != "infra" or "crypto:factId" not in props:
            continue
        found.append(
            {
                "native_type": props.get("crypto:factNativeType"),
                "verdict": props.get("crypto:factVerdict"),
            }
        )
    found.sort(key=lambda row: row["native_type"] or "")
    wanted = sorted(expected["facts"], key=lambda row: row["native_type"])
    assert found == wanted
    codes = {flag.code for flag in result.flags}
    assert "UNENCRYPTED_AT_REST" in codes
    run = normalize_crypto(result, duration_of_scan=0.0)
    rows = [
        row
        for row in run["results"]
        if str(row["bom_ref"]).startswith("crypto-cfg_")
    ]
    assert len(rows) == 1
    assert rows[0]["finding_codes"] == ["UNENCRYPTED_AT_REST"]
    locked = json.loads((TREE / "cbom_posture_scan.json").read_text(encoding="utf-8"))
    detailed = []
    for comp in result.components:
        props = comp.properties or {}
        if comp.kind != "infra" or "crypto:factId" not in props:
            continue
        detailed.append(
            {
                "address": props.get("crypto:factAddress"),
                "finding_codes": props.get("crypto:factFindingCodes"),
                "kind": props.get("crypto:factKind"),
                "native_type": props.get("crypto:factNativeType"),
                "verdict": props.get("crypto:factVerdict"),
            }
        )
    detailed.sort(key=lambda row: (str(row["native_type"]), str(row["address"])))
    assert detailed == locked["facts"]
    assert locked["posture_flags"] == ["UNENCRYPTED_AT_REST"]
