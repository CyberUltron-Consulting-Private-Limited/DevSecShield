"""C3 — CBOM protocol (TLS / SSH) scanner.

Drives the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-app`` fixture and asserts the protocol lane
matches the oracle (``expected_crypto.json``):

* the deliberately weak ``tls_config.py`` is inventoried as ONE TLS protocol
  asset at version 1.0, carrying its cipher suite, and surfaced ``weak``;
* prose ("below the TLS 1.2 floor") never inventories a phantom TLS 1.2 asset;
* the strong (TLS 1.3) and SSH cases are covered with synthetic targets.

C3 inventories only — the weak-protocol FLAG is C5/C8 and the CycloneDX
crypto-asset serialization is C4.
"""

from __future__ import annotations

import json
import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _manifest() -> dict:
    with open(os.path.join(_FX, "expected_crypto.json")) as fh:
        return json.load(fh)


def _protocols(result: ScanResult) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "protocol"
    ]


# --- the fixture's weak TLS 1.0 config -------------------------------------- #


def test_protocol_is_detected_exactly_once() -> None:
    protos = _protocols(scan_crypto(_FX))
    assert len(protos) == _manifest()["counts"]["protocols"] == 1
    proto = protos[0]
    props = proto.properties or {}
    assert props.get("crypto:protocolType") == "tls"
    assert props.get("discovery:source") == "tls_config.py"


def test_protocol_version_and_weakness() -> None:
    """The story's core requirement: version captured + the TLS 1.0 floor weak."""
    expected = _manifest()["protocols"][0]
    proto = _protocols(scan_crypto(_FX))[0]
    props = proto.properties or {}
    assert props.get("crypto:protocolVersion") == expected["version"] == "1.0"
    assert props.get("crypto:strength") == "weak"
    assert proto.name == "TLS 1.0"


def test_protocol_cipher_suite_captured() -> None:
    expected = _manifest()["protocols"][0]
    proto = _protocols(scan_crypto(_FX))[0]
    props = proto.properties or {}
    assert expected["cipher"] == "ECDHE-RSA-AES128-SHA"
    assert props.get("crypto:cipherSuite") == expected["cipher"]


def test_prose_does_not_inventory_phantom_version() -> None:
    """`# below the TLS 1.2 floor` in a comment must not create a 1.2 protocol."""
    versions = {
        (c.properties or {}).get("crypto:protocolVersion")
        for c in _protocols(scan_crypto(_FX))
    }
    assert versions == {"1.0"}, f"phantom protocol versions: {versions}"


# --- synthetic strong / SSH targets ----------------------------------------- #


def test_strong_tls_not_marked_weak(tmp_path) -> None:
    (tmp_path / "server.py").write_text(
        "import ssl\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
        "ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n"
    )
    proto = _protocols(scan_crypto(tmp_path))[0]
    props = proto.properties or {}
    assert props.get("crypto:protocolVersion") == "1.3"
    assert props.get("crypto:strength") == "strong"


def test_ssh_protocol_detected(tmp_path) -> None:
    (tmp_path / "deploy.py").write_text(
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
    )
    protos = _protocols(scan_crypto(tmp_path))
    ssh = [
        p
        for p in protos
        if (p.properties or {}).get("crypto:protocolType") == "ssh"
    ]
    assert len(ssh) == 1


def test_generic_tls_without_version_still_inventoried(tmp_path) -> None:
    (tmp_path / "client.py").write_text(
        "import ssl\n"
        "ctx = ssl.create_default_context()\n"
    )
    protos = _protocols(scan_crypto(tmp_path))
    assert len(protos) == 1
    props = protos[0].properties or {}
    # version unknown -> no version/strength keys, but the asset is still listed.
    assert "crypto:protocolVersion" not in props
    assert props.get("crypto:protocolType") == "tls"


def test_protocol_types_are_valid_cyclonedx_enum() -> None:
    valid = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}
    for c in _protocols(scan_crypto(_FX)):
        ptype = (c.properties or {}).get("crypto:protocolType")
        assert ptype in valid, f"invalid protocolType {ptype!r}"


# --- lane isolation --------------------------------------------------------- #


def test_cbom_protocol_scanner_not_in_aibom_registry() -> None:
    from aibom.scan.registry import SCANNERS

    assert not any(s.name == "crypto_protocol" for s in SCANNERS)
