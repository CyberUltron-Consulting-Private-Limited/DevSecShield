"""Property checks the current posture engine can decide."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aibom.cbom.pipeline import scan_crypto  # noqa: E402
from aibom.cbom.posture.context import CbomScanContext  # noqa: E402
from aibom.cbom.posture.extract_terraform import extract_terraform  # noqa: E402
from aibom.cbom.posture.findings import derive_findings  # noqa: E402
from aibom.cbom.posture.hcl import parse_hcl  # noqa: E402
from aibom.cbom.registry import ordered_cbom_scanners  # noqa: E402
from support.generators import mutate_bytes  # noqa: E402

_TREE = Path(__file__).resolve().parent / "fixtures" / "synthetic-config-aws-tf"
_BASE = (_TREE / "main.tf").read_bytes()


def _rows(components: list) -> tuple:
    found = []
    for comp in components:
        props = comp.properties or {}
        if "crypto:factId" not in props:
            continue
        found.append(
            (
                props.get("crypto:factAddress"),
                props.get("crypto:factVerdict"),
                props.get("crypto:factFindingCodes"),
            )
        )
    return tuple(sorted(found))


def _scan(root: Path, order=None) -> tuple:
    ctx = CbomScanContext(root, file_order=order)
    for scanner in ordered_cbom_scanners():
        if scanner.level <= 1 and scanner.matches(root):
            scanner.scan(ctx)
    return _rows(ctx.components)


def test_parsers_do_not_raise_on_mutated_terraform() -> None:
    for seed in range(1, 21):
        for payload in mutate_bytes(seed, count=50, base=_BASE):
            text = payload.decode("utf-8", "replace")
            parse_hcl(text, path="main.tf")
            extract_terraform(text, "main.tf")


def test_scan_is_idempotent() -> None:
    first = scan_crypto(_TREE)
    second = scan_crypto(_TREE)
    assert _rows(first.components) == _rows(second.components)
    assert sorted(flag.code for flag in first.flags) == sorted(
        flag.code for flag in second.flags
    )


def test_file_order_does_not_change_facts(tmp_path: Path) -> None:
    for index in range(4):
        (tmp_path / f"part_{index}.tf").write_text(
            f'resource "aws_db_instance" "db_{index}" {{\n'
            "  storage_encrypted = false\n}\n",
            encoding="utf-8",
        )
    baseline = _scan(tmp_path)
    assert len(baseline) == 4
    for seed in range(1, 21):
        def reorder(items, seed=seed):
            copied = list(items)
            random.Random(seed).shuffle(copied)
            return copied

        assert _scan(tmp_path, reorder) == baseline


def test_unresolved_storage_is_unknown_and_has_no_verdict_finding() -> None:
    holder = type("Fact", (), {"verdict": "UNKNOWN"})()
    assert "UNENCRYPTED_AT_REST" not in derive_findings(holder, {"at_rest": True})
    for index in range(1000):
        text = (
            'resource "aws_db_instance" "db" {\n'
            f"  storage_encrypted = var.v{index}\n"
            "}\n"
        )
        facts = extract_terraform(text, "main.tf")
        assert len(facts) == 1
        assert facts[0].verdict == "UNKNOWN"
