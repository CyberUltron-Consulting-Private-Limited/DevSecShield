"""C13 — cipher-suite / SSH-algo / IKE-transform negotiation weakness catalog.

A clean-room ``WEAK_CIPHER_SUITE`` predicate over the ``crypto:cipherSuite`` bag
the C3/C5 protocol scanner emits, flagging the negotiated *primitives* (not the
version) that modern baselines disallow:

* **TLS** — NULL / anonymous (ADH/AECDH) / EXPORT / RC4 / RC2 / DES / 3DES suites
  (FREAK / Logjam / SWEET32 / RFC 7465);
* **SSH** — weak kex (``diffie-hellman-group1-sha1``), host keys (``ssh-rsa`` SHA-1,
  ``ssh-dss``), ciphers (``arcfour`` / ``3des-cbc`` / ``blowfish-cbc``) and MACs
  (``hmac-md5`` / ``umac-64``);
* **IKE/IPsec** — weak MODP DH groups (``modp768/1024/1536`` = group 1/2/5).

Lane discipline (mirrors ``weak_finding``): the scanner EMITS the tokens, this
pure predicate QUERIES them, the C8 scorer WEIGHTS the resulting High flag. The
version-weakness lane (``WEAK_PROTOCOL``) is orthogonal — a TLS 1.2 asset that
still offers RC4 is flagged for the suite only, never the version.

Runs the REAL pipeline over a dedicated ``synthetic-crypto-suites`` fixture. Two
frozen-fixture regression assertions guard the C5/C6 zero-delta discipline: the
benchmark oracle ``synthetic-crypto-app`` (CBC-SHA1 only) stays UN-flagged
(Lucky13 tier deferred), while the already-non-oracle ``ipsec.conf``
(``3des-md5-modp1024``) correctly gains the flag.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import (
    WEAK_CIPHER_SUITE,
    WEAK_CRYPTO_CODES,
    cipher_suite_findings,
)
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-suites")
_APP_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")
_PROTO_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-protocols")


def _proto_by_source(result: ScanResult, source: str) -> CryptoAssetComponent:
    for c in result.components:
        props = c.properties or {}
        if (
            c.kind == "crypto_asset"
            and props.get("crypto:assetType") == "protocol"
            and props.get("discovery:source") == source
        ):
            return c  # type: ignore[return-value]
    raise AssertionError(f"no protocol asset from source {source!r}")


def _suite_flag_refs(result: ScanResult) -> set[str]:
    return {f.target for f in result.flags if f.code == WEAK_CIPHER_SUITE}


def _proto(ptype: str, suite: str, version: str | None = None) -> CryptoAssetComponent:
    props = {
        "crypto:assetType": "protocol",
        "crypto:protocolType": ptype,
        "crypto:cipherSuite": suite,
    }
    if version is not None:
        props["crypto:protocolVersion"] = version
    return CryptoAssetComponent(
        bom_ref=f"x-{ptype}", name=ptype.upper(), properties=props
    )


# --------------------------------------------------------------------------- #
# Pipeline: the dedicated weak-suite fixture.
# --------------------------------------------------------------------------- #


def test_weak_tls_suites_flagged_but_not_the_version() -> None:
    """weak_tls.py pins TLS 1.2 (strong) but offers RC4/3DES/NULL/EXPORT/anon."""
    result = scan_crypto(_FX)
    tls = _proto_by_source(result, "weak_tls.py")
    # Version is modern -> not a weak protocol; the ONLY code on it is the suite.
    assert tls.properties.get("crypto:strength") == "strong"
    codes = {f.code for f in result.flags if f.target == tls.bom_ref}
    assert WEAK_CIPHER_SUITE in codes
    assert "WEAK_PROTOCOL" not in codes
    msg = next(
        f.message for f in result.flags
        if f.target == tls.bom_ref and f.code == WEAK_CIPHER_SUITE
    )
    for attack in ("RC4", "SWEET32", "EXPORT", "anonymous", "NULL"):
        assert attack in msg, f"rationale missing {attack!r}: {msg}"


def test_weak_ssh_algorithms_flagged() -> None:
    """weak_ssh.py negotiates group1-sha1 / ssh-dss / arcfour / hmac-md5 …"""
    result = scan_crypto(_FX)
    ssh = _proto_by_source(result, "weak_ssh.py")
    bag = ssh.properties.get("crypto:cipherSuite", "")
    # The emission captured the SSH kex/host-key/cipher/MAC tokens.
    for tok in ("diffie-hellman-group1-sha1", "ssh-dss", "arcfour", "hmac-md5"):
        assert tok in bag, f"scanner did not capture {tok!r}: {bag}"
    assert ssh.bom_ref in _suite_flag_refs(result)


def test_strong_suites_are_not_flagged() -> None:
    """strong.py (TLS 1.3 AEAD + curve25519/ed25519/aes-gcm SSH) is clean."""
    result = scan_crypto(_FX)
    for src in ("strong.py",):
        for c in result.components:
            props = c.properties or {}
            if props.get("discovery:source") == src and props.get(
                "crypto:assetType"
            ) == "protocol":
                assert c.bom_ref not in _suite_flag_refs(result), (
                    f"strong asset {c.name} from {src} wrongly flagged"
                )


def test_weak_cipher_suite_flags_are_high_severity_error() -> None:
    result = scan_crypto(_FX)
    suite_flags = [f for f in result.flags if f.code == WEAK_CIPHER_SUITE]
    assert suite_flags, "expected WEAK_CIPHER_SUITE flags on the fixture"
    for f in suite_flags:
        assert f.severity == "error", "WEAK_CIPHER_SUITE is a High (SARIF error) break"
        assert f.message


def test_weak_cipher_suite_is_a_weak_crypto_code() -> None:
    # So it threads through normalize's weakness distribution + the charts.
    assert WEAK_CIPHER_SUITE in WEAK_CRYPTO_CODES


# --------------------------------------------------------------------------- #
# Predicate-level: synthetic components (no fixture I/O).
# --------------------------------------------------------------------------- #


def test_predicate_tls_rc4_flagged() -> None:
    findings = cipher_suite_findings(_proto("tls", "TLS_RSA_WITH_RC4_128_MD5", "1.2"))
    assert len(findings) == 1
    code, sev, msg = findings[0]
    assert code == WEAK_CIPHER_SUITE and sev == "error"
    assert "RC4" in msg


def test_predicate_ike_weak_modp_flagged() -> None:
    findings = cipher_suite_findings(_proto("ipsec", "3des-md5-modp1024"))
    assert len(findings) == 1
    msg = findings[0][2]
    assert "SWEET32" in msg  # 3DES
    assert "MODP" in msg or "Logjam" in msg  # modp1024


def test_predicate_ssh_hostkey_flagged() -> None:
    findings = cipher_suite_findings(_proto("ssh", "ssh-dss, ssh-ed25519"))
    assert len(findings) == 1
    assert "ssh-dss" in findings[0][2]


def test_predicate_strong_aead_suite_not_flagged() -> None:
    assert cipher_suite_findings(_proto("tls", "TLS_AES_256_GCM_SHA384", "1.3")) == []
    assert cipher_suite_findings(
        _proto("ssh", "curve25519-sha256, aes256-gcm@openssh.com, hmac-sha2-256")
    ) == []


def test_predicate_ignores_non_protocol_and_empty_bag() -> None:
    algo = CryptoAssetComponent(
        bom_ref="a", name="AES", properties={"crypto:assetType": "algorithm"}
    )
    assert cipher_suite_findings(algo) == []
    empty = _proto("tls", "")
    assert cipher_suite_findings(empty) == []


# --------------------------------------------------------------------------- #
# Frozen-fixture regression (the C5/C6 zero-delta discipline).
# --------------------------------------------------------------------------- #


def test_benchmark_oracle_fixture_stays_unflagged() -> None:
    """synthetic-crypto-app's only suite is ECDHE-RSA-AES128-SHA (CBC-SHA1).

    The plain-CBC-SHA1 (Lucky13) tier is deferred, so the benchmark oracle gains
    NO WEAK_CIPHER_SUITE flag — zero delta, exactly as C6 deferred WEAK_PADDING.
    """
    result = scan_crypto(_APP_FX)
    assert not [f for f in result.flags if f.code == WEAK_CIPHER_SUITE]


def test_ipsec_conf_transforms_are_flagged() -> None:
    """synthetic-crypto-protocols/ipsec.conf (3des-md5-modp1024) is a true positive."""
    result = scan_crypto(_PROTO_FX)
    ipsec = _proto_by_source(result, "ipsec.conf")
    assert ipsec.bom_ref in _suite_flag_refs(result)
    # swanctl.conf (aes256-sha256-modp3072) is strong -> not flagged.
    swanctl = _proto_by_source(result, "swanctl.conf")
    assert swanctl.bom_ref not in _suite_flag_refs(result)
