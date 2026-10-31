"""A secret attribute value must not reach the run object or diagnostics."""

from __future__ import annotations

import json
from pathlib import Path

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

_SECRET = "CANARY_PASSWORD_VALUE_9f3a"


def test_unused_secret_attribute_stays_out_of_the_run(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        "resource \"aws_db_instance\" \"plain\" {\n"
        "  storage_encrypted = false\n"
        f'  password = "{_SECRET}"\n'
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    run = normalize_crypto(result, duration_of_scan=0.0)
    blob = json.dumps(run, sort_keys=True)
    diagnostics = json.dumps(
        [
            {"code": item.code, "path": item.path, "line": item.line}
            for item in result.posture.diagnostics
        ]
    )
    assert _SECRET not in blob
    assert _SECRET not in diagnostics
    addresses = [
        (comp.properties or {}).get("crypto:factAddress")
        for comp in result.components
    ]
    assert "aws_db_instance.plain" in addresses
