"""Regenerate the committed Terraform posture scan fixture.

Refuses a dirty ``aibom/`` tree unless ``--allow-dirty`` is passed.
Run from ``aibom/`` with the project environment::

    uv run python tests/fixtures/make_cbom_posture_fixture.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TREE = ROOT / "tests" / "fixtures" / "synthetic-config-aws-tf"
OUT = TREE / "cbom_posture_scan.json"


def _dirty() -> bool:
    probe = subprocess.run(
        ["git", "status", "--short", "--", "src", "tests/fixtures/synthetic-config-aws-tf/main.tf"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(probe.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()
    if _dirty() and not args.allow_dirty:
        print("refusing: aibom tree is dirty (pass --allow-dirty)", file=sys.stderr)
        return 2
    from aibom.cbom.pipeline import scan_crypto
    from aibom.cbom.posture.findings import POSTURE_CODES

    result = scan_crypto(TREE)
    facts = []
    for comp in result.components:
        props = comp.properties or {}
        if comp.kind != "infra" or "crypto:factId" not in props:
            continue
        facts.append(
            {
                "address": props.get("crypto:factAddress"),
                "finding_codes": props.get("crypto:factFindingCodes"),
                "kind": props.get("crypto:factKind"),
                "native_type": props.get("crypto:factNativeType"),
                "verdict": props.get("crypto:factVerdict"),
            }
        )
    facts.sort(key=lambda row: (str(row["native_type"]), str(row["address"])))
    flags = sorted(flag.code for flag in result.flags if flag.code in POSTURE_CODES)
    OUT.write_text(
        json.dumps({"facts": facts, "posture_flags": flags}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
