"""C5 — CBOM protocol scanner IPsec/IKE + SSH-version-weakness extension.

C5 broadens the C3 protocol lane (TLS/SSH) with the third protocol family the
story promises — **IPsec / IKE** — and completes the version-weakness signal for
the non-TLS families:

* strongSwan / libreswan config (``ipsec.conf`` / ``swanctl.conf``) is inventoried
  as an ``ipsec`` crypto-asset carrying the negotiated IKE version and the
  transform/proposal tokens (``3des-md5-modp1024`` / ``aes256-sha256-modp3072``);
* **IKEv1** is a weak protocol version (deprecated, RFC 9395) → ``crypto:strength``
  ``weak`` → a ``WEAK_PROTOCOL`` flag; **IKEv2** is strong;
* **SSH protocol 1.x** (``SSH-1.5``) is a weak protocol version (CVE-2001-0361) →
  ``weak`` → flagged; SSH-2.0 is strong.

Lane discipline: C5 EMITS protocol assets + sets ``crypto:strength`` on the
*version* (so the pure ``weak_finding`` predicate raises ``WEAK_PROTOCOL``). The
cipher-suite / kex / transform *weakness catalog* (RC4/DES/modp1024 = SWEET32 /
weak-DH) is a separate predicate story (C13); C5 only carries the tokens for it.
Drives the REAL pipeline over a dedicated fixture; the frozen
``synthetic-crypto-app`` oracle is untouched.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.weakness import WEAK_PROTOCOL, weak_finding
from aibom.model.component import CryptoAssetComponent
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-protocols")


def _protocols(result: ScanResult, ptype: str) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "protocol"
        and (c.properties or {}).get("crypto:protocolType") == ptype
    ]


def _by_source(comps: list, source: str):
    for c in comps:
        if (c.properties or {}).get("discovery:source") == source:
            return c
    raise AssertionError(f"no protocol asset from source {source!r}")


def _weak_protocol_refs(result: ScanResult) -> set[str]:
    return {f.target for f in result.flags if f.code == WEAK_PROTOCOL}


# --- IPsec / IKE inventory -------------------------------------------------- #


def test_ipsec_legacy_conf_is_inventoried_ikev1_weak() -> None:
    result = scan_crypto(_FX)
    ipsec = _by_source(_protocols(result, "ipsec"), "ipsec.conf")
    props = ipsec.properties or {}
    assert props.get("crypto:protocolVersion") == "IKEv1"
    assert props.get("crypto:strength") == "weak"
    # transform tokens carried for C9 / C13 (order-independent).
    suite = props.get("crypto:cipherSuite", "")
    assert "3des-md5-modp1024" in suite
    assert "3des-md5" in suite


def test_ipsec_swanctl_is_inventoried_ikev2_strong() -> None:
    result = scan_crypto(_FX)
    ipsec = _by_source(_protocols(result, "ipsec"), "swanctl.conf")
    props = ipsec.properties or {}
    assert props.get("crypto:protocolVersion") == "IKEv2"
    assert props.get("crypto:strength") == "strong"
    suite = props.get("crypto:cipherSuite", "")
    assert "aes256-sha256-modp3072" in suite
    assert "aes256gcm16-sha256" in suite


def test_ipsec_ikev1_gets_weak_protocol_flag() -> None:
    result = scan_crypto(_FX)
    ipsec = _by_source(_protocols(result, "ipsec"), "ipsec.conf")
    assert ipsec.bom_ref in _weak_protocol_refs(result)


def test_ipsec_ikev2_is_not_weak_flagged() -> None:
    result = scan_crypto(_FX)
    ipsec = _by_source(_protocols(result, "ipsec"), "swanctl.conf")
    assert ipsec.bom_ref not in _weak_protocol_refs(result)


def test_ipsec_protocol_type_is_valid_cyclonedx_enum() -> None:
    result = scan_crypto(_FX)
    valid = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}
    for c in _protocols(result, "ipsec"):
        assert (c.properties or {}).get("crypto:protocolType") in valid


# --- SSH version weakness (SSH-1.x) ----------------------------------------- #


def test_ssh_protocol_1x_is_weak() -> None:
    result = scan_crypto(_FX)
    ssh = _by_source(_protocols(result, "ssh"), "ssh_legacy.py")
    props = ssh.properties or {}
    assert props.get("crypto:protocolVersion") == "1.5"
    assert props.get("crypto:strength") == "weak"
    assert ssh.bom_ref in _weak_protocol_refs(result)


def test_ssh_2_0_is_strong(tmp_path) -> None:
    (tmp_path / "modern_ssh.py").write_text(
        'import paramiko\nBANNER = "SSH-2.0-OpenSSH_9.6"\n'
        "c = paramiko.SSHClient()\n"
    )
    result = scan_crypto(tmp_path)
    ssh = _protocols(result, "ssh")
    assert len(ssh) == 1
    props = ssh[0].properties or {}
    assert props.get("crypto:protocolVersion") == "2.0"
    assert props.get("crypto:strength") == "strong"
    assert ssh[0].bom_ref not in _weak_protocol_refs(result)


def test_ssh_without_pinned_version_has_no_strength(tmp_path) -> None:
    (tmp_path / "deploy.py").write_text(
        "import paramiko\nclient = paramiko.SSHClient()\n"
    )
    result = scan_crypto(tmp_path)
    ssh = _protocols(result, "ssh")
    assert len(ssh) == 1
    props = ssh[0].properties or {}
    assert "crypto:protocolVersion" not in props
    assert "crypto:strength" not in props
    assert ssh[0].bom_ref not in _weak_protocol_refs(result)


# --- predicate-level: protocol-type-aware weakness message ------------------ #


def _proto(ptype: str, version: str, strength: str) -> CryptoAssetComponent:
    return CryptoAssetComponent(
        bom_ref=f"x-{ptype}-{version}",
        name=f"{ptype.upper()} {version}",
        properties={
            "crypto:assetType": "protocol",
            "crypto:protocolType": ptype,
            "crypto:protocolVersion": version,
            "crypto:strength": strength,
        },
    )


def test_weak_ipsec_message_names_ike() -> None:
    finding = weak_finding(_proto("ipsec", "IKEv1", "weak"))
    assert finding is not None
    code, sev, msg = finding
    assert code == WEAK_PROTOCOL and sev == "error"
    assert "IKEv2" in msg  # names the migration target, not a TLS rationale


def test_weak_ssh_message_names_ssh_2() -> None:
    finding = weak_finding(_proto("ssh", "1.5", "weak"))
    assert finding is not None
    _, _, msg = finding
    assert "SSH-2" in msg or "SSH 2" in msg


def test_strong_ipsec_ikev2_predicate_is_not_weak() -> None:
    assert weak_finding(_proto("ipsec", "IKEv2", "strong")) is None


# --- lane isolation --------------------------------------------------------- #


def test_ipsec_config_not_scanned_by_aibom_registry() -> None:
    from aibom.scan.registry import SCANNERS

    assert not any(s.name == "crypto_protocol" for s in SCANNERS)
