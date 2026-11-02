"""cbom-mapping.yaml and CODEOWNERS reach the crypto asset ROWS (WP10 / C4), not only the encryption facts."""

from __future__ import annotations

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

APP = (
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "key = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
)


def _rows(tmp_path):
    result = scan_crypto(tmp_path)
    return normalize_crypto(result, duration_of_scan=0.0)["results"]


def test_mapping_entries_and_codeowners_are_applied_to_crypto_rows(tmp_path) -> None:
    pay = tmp_path / "payments"
    pay.mkdir()
    (pay / "keys.py").write_text(APP, encoding="utf-8")
    (tmp_path / "other.py").write_text(APP, encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @platform\npayments/ @payments-team\n", encoding="utf-8")
    dot = tmp_path / ".devsecshield"
    dot.mkdir()
    (dot / "cbom-mapping.yaml").write_text(
        "version: 1\ndefaults:\n  owner: platform-owners\n  data_classification: internal\n"
        "entries:\n  - match:\n      path: 'payments/**'\n    system: card-switch\n    owner: pay-owners\n"
        "    data_classification: restricted\n    data_lifetime: 10y\n",
        encoding="utf-8",
    )
    rows = [r for r in _rows(tmp_path) if r["asset_type"] == "algorithm" and str(r["title"]).startswith("RSA")]
    by_file = {r["location"]: r for r in rows}
    pay_row = by_file["payments/keys.py"]
    assert (pay_row["application"], pay_row["owner"], pay_row["data_classification"], pay_row["data_lifetime"]) == (
        "card-switch", "pay-owners", "restricted", "10y")
    assert pay_row["owner_hint"] == "@payments-team"
    other = by_file["other.py"]
    assert (other["owner"], other["data_classification"], other["owner_hint"]) == ("platform-owners", "internal", "@platform")
    assert "application" not in other


def test_rows_are_unchanged_without_a_mapping(tmp_path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    for row in _rows(tmp_path):
        assert not {"owner", "application", "data_classification", "owner_hint"} & set(row)
