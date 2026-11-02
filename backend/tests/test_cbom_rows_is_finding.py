"""``is_finding``: the one read-time rule that separates CBOM findings from clean inventory rows.

Pure function, no database: run with the backend venv from the repo root.
"""
from __future__ import annotations

import pytest

from backend.utilities.cbom_sources.cbom_rows import display_row, is_finding


def test_legacy_row_without_finding_codes_keeps_counting_as_a_finding() -> None:
    legacy = {"title": "AES-GCM", "impact": "Low", "algorithm_type": "block-cipher"}
    assert is_finding(legacy) is True


def test_row_with_a_weakness_code_is_a_finding() -> None:
    assert is_finding({"title": "MD5", "impact": "High", "finding_codes": ["WEAK_ALGORITHM"]}) is True


def test_quantum_vulnerable_row_is_a_finding() -> None:
    row = {"title": "RSA-2048", "impact": "Medium", "finding_codes": ["QUANTUM_VULNERABLE"],
           "quantum_vulnerable": True}
    assert is_finding(row) is True


def test_clean_new_row_is_inventory() -> None:
    clean = {"title": "AES-256-GCM", "impact": None, "finding_codes": [], "weak": False,
             "quantum_vulnerable": False}
    assert is_finding(clean) is False


def test_empty_codes_but_still_marked_weak_or_quantum_vulnerable_is_a_finding() -> None:
    assert is_finding({"finding_codes": [], "weak": True}) is True
    assert is_finding({"finding_codes": [], "quantum_vulnerable": True}) is True


@pytest.mark.parametrize("codes", [None, [None], [""], [3]])
def test_junk_code_lists_are_inventory(codes) -> None:
    assert is_finding({"finding_codes": codes, "weak": False}) is False


def test_non_dict_is_never_a_finding() -> None:
    assert is_finding(None) is False  # type: ignore[arg-type]
    assert is_finding(["WEAK_ALGORITHM"]) is False  # type: ignore[arg-type]


def test_display_row_and_is_finding_agree_on_old_library_rows() -> None:
    old = {"title": "node-forge@0.9.0", "algorithm_type": "other", "crypto_strength": "strong",
           "finding_codes": ["VULNERABLE_CRYPTO_LIBRARY"], "impact": "High"}
    shown = display_row(old)
    assert shown["weak"] is True
    assert is_finding(shown) is True
    assert is_finding(old) is True
