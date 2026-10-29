"""Code and dependency scan: advisories, custom crypto, and the CLI gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from aibom.cbom.advisories import find_vulnerable, parse_specifier
from aibom.cbom.custom_crypto import detect_custom_crypto
from aibom.cbom.gate import CUSTOM_CRYPTO, VULNERABLE_CRYPTO_LIBRARY, failing_flags
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.posture.verification import detect_verification
from aibom.emit.cyclonedx import emit_cyclonedx

_ROOT = Path(__file__).resolve().parents[1]
_VULN = _ROOT / "tests" / "fixtures" / "code-supply" / "vulnerable"
_CLEAN = _ROOT / "tests" / "fixtures" / "code-supply" / "clean"
_PY = Path(sys.executable)


def test_caret_above_the_fix_is_not_vulnerable() -> None:
    exact, low, high = parse_specifier("^9.0.2")
    assert exact is None
    assert low == "9.0.2"
    assert high == "10.0.0"


def test_vulnerable_tree_matches_direct_and_transitive_advisories() -> None:
    hits = find_vulnerable(_VULN)
    by_name = {hit.pin.name: hit for hit in hits}
    assert by_name["pyjwt"].pin.direct is True
    assert by_name["pyjwt"].advisory.id == "CVE-2022-29217"
    forge = by_name["node-forge"]
    assert forge.pin.direct is False
    assert forge.advisory.id == "CVE-2022-24771"
    assert "golang.org/x/crypto" in by_name
    assert by_name["golang.org/x/crypto"].pin.direct is False
    assert "org.bouncycastle:bcprov-jdk15on" in by_name
    assert "ed25519-dalek" in by_name
    assert "bouncycastle.cryptography" in by_name
    assert "express" not in by_name
    assert "serde" not in by_name


def test_clean_tree_matches_no_advisory() -> None:
    assert find_vulnerable(_CLEAN) == ()


def test_custom_constants_are_found_and_comments_are_not() -> None:
    source = (_VULN / "custom_aes.py").read_text(encoding="utf-8")
    assert detect_custom_crypto(source) is not None
    comment = (_CLEAN / "commented.py").read_text(encoding="utf-8")
    assert detect_custom_crypto(comment) is None


def test_added_certificate_validation_patterns_hit() -> None:
    sample = (
        "ssl._create_unverified_context()\n"
        "rejectUnauthorized: false\n"
        "TrustAllCerts()\n"
    )
    facts = detect_verification(sample, "client.py")
    kinds = {fact.native_type for fact in facts}
    assert "py.unverified_context" in kinds
    assert "node.reject_unauthorized_spaced" in kinds
    assert "java.trustall" in kinds


def test_scan_emits_high_library_findings_and_medium_custom_crypto() -> None:
    result = scan_crypto(_VULN, level=4)
    codes = {flag.code for flag in result.flags}
    assert VULNERABLE_CRYPTO_LIBRARY in codes
    assert CUSTOM_CRYPTO in codes
    assert "TLS_VERIFICATION_DISABLED" in codes
    failed = {flag.code for flag in failing_flags(result.flags)}
    assert VULNERABLE_CRYPTO_LIBRARY in failed
    assert CUSTOM_CRYPTO not in failed
    bom = emit_cyclonedx(result)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    infra = [c for c in result.components if c.kind == "infra"]
    assert infra, "infrastructure-as-code in the same scan produced no fact"


def test_clean_scan_has_no_high_findings() -> None:
    result = scan_crypto(_CLEAN, level=4)
    assert failing_flags(result.flags) == []


def _cli(tree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_PY, "-m", "aibom.cli", "cbom", str(tree)],
        cwd=_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_exits_1_on_the_vulnerable_tree_and_prints_cyclonedx() -> None:
    proc = _cli(_VULN)
    assert proc.returncode == 1, proc.stderr
    assert "VULNERABLE_CRYPTO_LIBRARY" in proc.stderr
    document = json.loads(proc.stdout)
    assert document["bomFormat"] == "CycloneDX"


def test_cli_exits_0_on_the_clean_tree() -> None:
    proc = _cli(_CLEAN)
    assert proc.returncode == 0, proc.stderr
    assert "no high findings" in proc.stderr
    document = json.loads(proc.stdout)
    assert document["specVersion"] == "1.6"
