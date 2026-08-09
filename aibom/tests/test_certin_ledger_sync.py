"""CERT-In Phase 0: LEDGER.md ↔ ledger.yaml ID-set lock + PDF inventory floors.

No runner registration is asserted here — that lives in test_certin_common.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
_LEDGER_MD = _REPO / "docs" / "certin" / "LEDGER.md"
_LEDGER_YAML = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "aibom"
    / "compliance"
    / "cert_in"
    / "ledger.yaml"
)

# Table 5 §4.2 items 1–21 (data fields only; automation IDs are separate).
_T5_DATA = frozenset(
    {
        "T5-Component-Name",
        "T5-Component-Version",
        "T5-Component-Description",
        "T5-Component-Supplier",
        "T5-Component-License",
        "T5-Component-Origin",
        "T5-Component-Dependencies",
        "T5-Vulnerabilities",
        "T5-Patch-Status",
        "T5-Release-Date",
        "T5-EOL-Date",
        "T5-Criticality",
        "T5-Usage-Restrictions",
        "T5-Checksums-or-Hashes",
        "T5-Comments-or-Notes",
        "T5-Author-of-SBOM-Data",
        "T5-Timestamp",
        "T5-Executable-Property",
        "T5-Archive-Property",
        "T5-Structured-Property",
        "T5-Unique-Identifier",
    }
)

_T9_PREFIXES = ("T9-Algorithms-", "T9-Keys-", "T9-Protocols-", "T9-Certificates-")
_T10_PREFIX = "T10-"


def _ids_from_md(text: str) -> frozenset[str]:
    # Requirement rows use `| `ID` | ...`; framework keys also use backticks —
    # only keep IDs that look like CERT-In requirement anchors.
    found = set(re.findall(r"`([A-Za-z0-9._-]+)`", text))
    return frozenset(
        i
        for i in found
        if i.startswith(("T5-", "T9-", "T10-", "7.", "8.", "9."))
        or re.fullmatch(r"\d+\.\d+(\.\d+)?", i)
    )


def _ids_from_yaml(doc: dict) -> frozenset[str]:
    return frozenset(r["id"] for r in doc["requirements"])


def test_ledger_files_exist() -> None:
    assert _LEDGER_MD.is_file(), f"missing {_LEDGER_MD}"
    assert _LEDGER_YAML.is_file(), f"missing {_LEDGER_YAML}"


def test_ledger_md_yaml_id_sets_equal() -> None:
    md_ids = _ids_from_md(_LEDGER_MD.read_text(encoding="utf-8"))
    doc = yaml.safe_load(_LEDGER_YAML.read_text(encoding="utf-8"))
    yaml_ids = _ids_from_yaml(doc)
    assert md_ids == yaml_ids, (
        f"LEDGER.md Δyaml: only_md={sorted(md_ids - yaml_ids)} "
        f"only_yaml={sorted(yaml_ids - md_ids)}"
    )


def test_no_qbom_t8_product_ids() -> None:
    doc = yaml.safe_load(_LEDGER_YAML.read_text(encoding="utf-8"))
    bad = [i for i in _ids_from_yaml(doc) if i.startswith("T8-")]
    assert bad == [], f"QBOM Table-8 IDs must not be productized: {bad}"
    md = _LEDGER_MD.read_text(encoding="utf-8")
    assert "`T8-" not in md


def test_frameworks_exactly_three_cert_in_keys() -> None:
    doc = yaml.safe_load(_LEDGER_YAML.read_text(encoding="utf-8"))
    assert set(doc["frameworks"]) == {
        "cert_in_cbom",
        "cert_in_aibom",
        "cert_in_sbom",
    }


def test_minimum_pdf_inventory_present() -> None:
    doc = yaml.safe_load(_LEDGER_YAML.read_text(encoding="utf-8"))
    ids = _ids_from_yaml(doc)

    assert _T5_DATA <= ids
    assert {
        "T5-Automation-SPDX",
        "T5-Automation-CycloneDX",
        "T5-Inventory-Tools",
        "T5-Vuln-Scanner",
        "T5-Multi-Format-Emit",
    } <= ids

    manuals_71 = {f"7.1.{n}" for n in range(1, 16)}
    manuals_841 = {f"8.4.1.{n}" for n in range(1, 14)}
    manuals_941 = {f"9.4.1.{n}" for n in range(1, 14)}
    assert manuals_71 <= ids
    assert manuals_841 <= ids
    assert manuals_941 <= ids
    assert len(manuals_71) == 15
    assert len(manuals_841) == 13
    assert len(manuals_941) == 13

    for prefix in _T9_PREFIXES:
        assert any(i.startswith(prefix) for i in ids), f"missing Table 9 {prefix}*"
    assert any(i.startswith(_T10_PREFIX) for i in ids)


def test_scope_cites_pdf_and_excludes_qbom_hbom() -> None:
    md = _LEDGER_MD.read_text(encoding="utf-8")
    assert "Version 2.0" in md
    assert "09.07.2025" in md or "2025-07-09" in md
    assert "QBOM" in md  # scope exclusion citation only
    assert "Table 8" in md
    assert "Table 11" in md or "HBOM" in md
    assert "not" in md.lower() and "certification" in md.lower()
