"""F8 lock: India chip present; defaultGroup remains all; no product QBOM."""

from __future__ import annotations

import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FE = REPO / "frontend"


def test_default_group_all_never_india() -> None:
    targets = [
        FE / "components/cbom/CbomCryptoCharts.tsx",
        FE / "components/SbomResults.tsx",
        FE / "components/ai-bom/AiBomVisualizations.tsx",
        FE / "components/compliance/ComplianceMatrix.tsx",
    ]
    for path in targets:
        text = path.read_text(encoding="utf-8")
        assert 'defaultGroup="all"' in text or 'defaultGroup = "all"' in text, path
        assert 'defaultGroup="india"' not in text
        assert "defaultGroup={'india'}" not in text
        assert 'defaultGroup={"india"}' not in text


def test_india_chips_defined_for_all_bom_lanes() -> None:
    labels = (FE / "components/compliance/frameworkLabels.ts").read_text(
        encoding="utf-8"
    )
    for name in (
        "FRAMEWORK_GROUPS_CBOM_WITH_INDIA",
        "FRAMEWORK_GROUPS_AIBOM_WITH_INDIA",
        "FRAMEWORK_GROUPS_SBOM_WITH_INDIA",
    ):
        assert name in labels, name
    assert 'id: "india"' in labels
    assert "India / CERT-In" in labels
    assert "cert_in_cbom" in labels
    assert "cert_in_aibom" in labels
    assert "cert_in_sbom" in labels
    # Comments lock the never-auto-India rule
    assert "never auto-select India" in labels or "never auto-India" in labels


def test_product_fe_has_zero_qbom_word() -> None:
    """Product FE must not surface QBOM (docs/PDF citation only)."""
    roots = [FE / "app", FE / "components", FE / "utils"]
    hits: list[str] = []
    pat = re.compile(r"\bQBOM\b")
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.suffix not in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
                continue
            # Skip node_modules / generated
            if "node_modules" in path.parts or ".next" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if pat.search(text):
                hits.append(str(path.relative_to(REPO)))
    assert hits == [], f"QBOM found in product FE: {hits}"


def test_certin_rollup_mentions_hbom_deferred() -> None:
    text = (FE / "components/certin/CertInRollup.tsx").read_text(encoding="utf-8")
    assert "HBOM deferred" in text
    assert "CERT-In Guidelines posture" in text


def test_scan_pages_use_lane_posture_not_cross_bom_rollup() -> None:
    """Per-scan results must not mount the cross-BOM CertInRollup."""
    pages = {
        FE / "components/SbomResults.tsx": 'lane="sbom"',
        FE / "components/CbomResults.tsx": 'lane="cbom"',
        FE / "components/AiBomResults.tsx": 'lane="aibom"',
    }
    for path, lane_attr in pages.items():
        text = path.read_text(encoding="utf-8")
        assert "CertInLanePosture" in text, path
        assert lane_attr in text, path
        assert "from \"@/components/certin/CertInRollup\"" not in text, path
        assert "from '@/components/certin/CertInRollup'" not in text, path

    team = (FE / "app/[team_id]/page.tsx").read_text(encoding="utf-8")
    assert "CertInRollup" in team
    assert "CertInLanePosture" not in team


def test_lane_posture_titles_are_bom_specific() -> None:
    shared = (FE / "components/certin/certinShared.ts").read_text(encoding="utf-8")
    for title in (
        "CERT-In SBOM posture (advisory)",
        "CERT-In CBOM posture (advisory)",
        "CERT-In AIBOM posture (advisory)",
    ):
        assert title in shared, title
    for label in (
        "Software component inventory",
        "SBOM process controls",
        "Cryptographic asset inventory",
        "Crypto process controls",
        "AI model & dataset inventory",
        "AI process controls",
    ):
        assert label in shared, label
    # Product UI must not surface PDF table/section citations as chart labels.
    assert "Table 5" not in shared
    assert "Table 9" not in shared
    assert "Table 10" not in shared
    assert "§7.1" not in shared
    assert "§8.4" not in shared
    assert "§9.4" not in shared
    lane = (FE / "components/certin/CertInLanePosture.tsx").read_text(encoding="utf-8")
    assert "No CERT-In SBOM verdicts in this scan" in shared or "meta.empty" in lane
    assert "run an AI BOM, CBOM, or SBOM scan" not in lane
