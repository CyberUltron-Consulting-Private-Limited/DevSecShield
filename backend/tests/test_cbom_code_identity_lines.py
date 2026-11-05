"""Code-scan identities are line-independent (WP13): moving a line is not a drift change.

Rows measured on the engine's IaC fixtures with every file shifted one line down: Terraform / Kubernetes key-spec
rows name their location ``<file>:<line>`` and misuse refs end in ``-l<line>``; Dockerfile base-image fact ids no
longer hash the line (engine side, aibom/tests/test_cbom_line_independent_ids.py).
"""
from __future__ import annotations

from backend.utilities.cbom_sources import identity as ID


def _row(location: str, bom_ref: str, title: str = "key (google_kms_crypto_key.app)") -> dict:
    return {"asset_type": "related-crypto-material", "title": title, "location": location, "bom_ref": bom_ref,
            "finding_codes": ["KMS_KEY_ROTATION_DISABLED"]}


def test_a_line_number_in_the_location_or_the_ref_does_not_change_the_identity() -> None:
    assert ID.code_identity(_row("main.tf:1", "crypto-material-5ce50575a643beff")) == ID.code_identity(
        _row("main.tf:2", "crypto-material-5ce50575a643beff"))
    misuse = "crypto-material-misuse-static-iv-iv-static-iv-py"
    assert ID.code_identity(_row("static_iv.py", f"{misuse}-l12")) == ID.code_identity(_row("static_iv.py", f"{misuse}-l14"))


def test_different_assets_in_one_file_keep_different_identities() -> None:
    one = ID.code_identity(_row("main.tf:1", "crypto-material-5ce50575a643beff"))
    two = ID.code_identity(_row("main.tf:9", "crypto-material-e15d4a0ed210a32e", "key (google_kms_crypto_key_iam_binding.open)"))
    assert one != two
    # a file name is never shortened: only a trailing ":<digits>" is a line marker
    assert ID.code_identity(_row("deploy/v1:2/main.tf", "r")) != ID.code_identity(_row("deploy/v1/main.tf", "r"))
    assert ID.stable_key("code", "repo:x@main", one) == ID.stable_key("code", "repo:x@main",
                                                                    ID.code_identity(_row("main.tf:3", "crypto-material-5ce50575a643beff")))
