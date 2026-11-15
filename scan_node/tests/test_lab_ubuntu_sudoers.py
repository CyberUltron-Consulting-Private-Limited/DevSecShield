"""The lab Ubuntu host installs the product's Tier-2 sudoers file, byte for byte (issue #93)."""
from pathlib import Path

from zs_scan_node import commands as C


def test_lab_ubuntu_sudoers_is_the_product_file() -> None:
    text = (Path(__file__).resolve().parents[2] / "e2e/cbom/lab/sudoers.zs-cbom").read_text(encoding="utf-8")
    assert text == C.sudoers_file("zs-cbom")
    assert "NOPASSWD: ZS_CBOM_TIER2" in text
    assert "/bin/cat" not in text
