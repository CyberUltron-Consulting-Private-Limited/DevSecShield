"""C11 — crypto-policy config-file scanner + disabled-but-used compliance.

Drives the REAL CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over a
hand-authored ``synthetic-crypto-policy`` fixture (a ``java.security`` denied-
algorithm policy, an ``openssl.cnf`` TLS floor, and application code that uses
two policy-disabled algorithms) and asserts:

* the policy artifacts become ``protocol`` ``crypto_asset`` policy assets;
* an ``openssl.cnf`` MinProtocol below TLS 1.2 is a weak protocol policy;
* the environment's own disabled-algorithm list is cross-referenced against the
  algorithms actually in use (``disabled-but-used`` -> NIST SP 800-57 KM-7 fail).

No mocks — the CBOM lane touches no network/LLM. The frozen ``synthetic-crypto-app``
oracle carries no policy files, so this lane is inert there (regression-safe).
"""

import os

from aibom.cbom.compliance import (
    disabled_but_used,
    policy_disabled_algorithms,
    protocols,
    run_cbom_compliance,
)
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import WEAK_PROTOCOL
from aibom.emit.cyclonedx import emit_and_validate
from aibom.emit.validate import validate_cyclonedx
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-policy")
_APP_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _policy_assets(r: ScanResult) -> dict[str, dict]:
    """Policy protocol assets keyed by their ``crypto:policySource``."""
    out: dict[str, dict] = {}
    for p in protocols(r):
        props = p.properties or {}
        src = props.get("crypto:policySource")
        if src:
            out[src] = props
    return out


# --------------------------------------------------------------------------- #
# Scanner: java.security + openssl.cnf -> protocol/policy crypto-assets.
# --------------------------------------------------------------------------- #


def test_java_security_becomes_a_policy_asset() -> None:
    props = _policy_assets(_scan())["java-security"]
    assert props["crypto:assetType"] == "protocol"
    assert props["crypto:protocolType"] == "tls"
    assert props["crypto:cryptoPolicy"] == "unlimited"
    disabled = props["crypto:disabledAlgorithms"]
    # both the tls and certpath disabled lists are unioned in
    for tok in ("RC4", "DES", "MD5", "SSLv3"):
        assert tok in disabled


def test_openssl_min_protocol_below_tls12_is_weak() -> None:
    props = _policy_assets(_scan())["openssl-config"]
    assert props["crypto:assetType"] == "protocol"
    assert props["crypto:protocolVersion"] == "1.0"  # MinProtocol = TLSv1
    assert props["crypto:strength"] == "weak"
    # cipher policy captured (CipherString + Ciphersuites)
    assert "TLS_AES_256_GCM_SHA384" in props["crypto:cipherSuite"]
    assert props["crypto:maxProtocolVersion"] == "TLSv1.3"


def test_weak_openssl_policy_raises_a_weak_protocol_flag() -> None:
    r = _scan()
    weak_targets = {f.target for f in r.flags if f.code == WEAK_PROTOCOL}
    openssl_ref = next(
        p.bom_ref
        for p in protocols(r)
        if (p.properties or {}).get("crypto:policySource") == "openssl-config"
    )
    assert openssl_ref in weak_targets


# --------------------------------------------------------------------------- #
# Disabled-algorithm parsing: blanket tokens only, conditioned entries skipped.
# --------------------------------------------------------------------------- #


def test_policy_disabled_algorithms_parses_blanket_tokens() -> None:
    disabled = policy_disabled_algorithms(_scan())
    for fam in ("rc4", "des", "md5", "sslv3", "tlsv1"):
        assert fam in disabled
    # a conditioned entry ("RSA keySize < 1024" / "DH keySize < 1024") carries a
    # numeric predicate we do not evaluate -> never a blanket family disable.
    assert "rsa" not in disabled
    assert "dh" not in disabled


def test_des_disable_does_not_match_3des() -> None:
    # "DES" is a blanket-disabled family; "3DES" must NOT be treated as disabled
    # (3des does not start with des), so a DES policy never false-flags 3DES use.
    r = _scan()
    disabled = policy_disabled_algorithms(r)
    assert "des" in disabled
    assert "3desedecbc" in disabled  # separately disabled, distinct family
    used = {c.name for c in disabled_but_used(r)}
    assert used == {"MD5", "RC4"}  # only the two actually-used disabled algos


# --------------------------------------------------------------------------- #
# Compliance cross-reference: disabled-but-used -> NIST SP 800-57 KM-7 fail.
# --------------------------------------------------------------------------- #


def test_km7_fails_on_disabled_but_used() -> None:
    block = _scan().compliance["nist_800_57"]
    km7 = next(r for r in block["requirements"] if r["id"] == "KM-7")
    assert km7["verdict"] == "fail"
    assert len(km7["refs"]) == 2  # MD5 + RC4


def test_km7_passes_when_policy_present_but_not_violated(tmp_path) -> None:
    # A hardening policy that disables RC4/DES, and code that uses only AES-GCM.
    (tmp_path / "java.security").write_text(
        "jdk.tls.disabledAlgorithms=SSLv3, RC4, DES\n"
    )
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
        "cipher = AESGCM(key)\n"
    )
    report = run_cbom_compliance(scan_crypto(tmp_path))
    km7 = next(
        r for r in report["nist_800_57"]["requirements"] if r["id"] == "KM-7"
    )
    assert km7["verdict"] == "pass"


def test_km7_passes_vacuously_without_a_policy_artifact() -> None:
    # The frozen synthetic-crypto-app has no java.security / openssl.cnf -> no
    # disabled policy -> no violation to evaluate -> KM-7 passes, not fails.
    report = run_cbom_compliance(scan_crypto(_APP_FX))
    km7 = next(
        r for r in report["nist_800_57"]["requirements"] if r["id"] == "KM-7"
    )
    assert km7["verdict"] == "pass"


# --------------------------------------------------------------------------- #
# CycloneDX 1.6 stays schema-valid with the new crypto:policy properties.
# --------------------------------------------------------------------------- #


def test_policy_fixture_emits_schema_valid_cyclonedx() -> None:
    bom = emit_and_validate(_scan())  # raises on any schema error
    assert validate_cyclonedx(bom) == []


# --------------------------------------------------------------------------- #
# Regression: the C11 lane is inert on the frozen oracle (no policy files).
# --------------------------------------------------------------------------- #


def test_policy_lane_inert_on_the_frozen_oracle() -> None:
    r = scan_crypto(_APP_FX)
    assert not _policy_assets(r), "no policy asset on the frozen oracle fixture"
