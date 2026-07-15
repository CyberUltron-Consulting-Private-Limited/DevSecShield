"""C1 — CBOM crypto algorithm + library scanner.

Drives the real CBOM pipeline (:func:`aibom.cbom.pipeline.scan_crypto`) over the
hand-labeled ``synthetic-crypto-app`` fixture and asserts every algorithm the
oracle (``expected_crypto.json``) enumerates is detected — with the
parametrization (key size / cipher mode) needed to tell RSA-2048 from RSA-1024
and AES-GCM from AES-ECB apart — plus that the crypto libraries are inventoried.

This is the recall gate. Weak-flagging (C5), PQC grading (C6) and the CycloneDX
crypto-asset emitter (C4) are separate stories; C1 only inventories.
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


def _scan() -> ScanResult:
    return scan_crypto(_FX)


# --- signature helpers: map a manifest/detected algorithm to a tolerant key --- #


def _family(name: str) -> str:
    """Collapse an algorithm display name to its detection family."""
    n = name.upper()
    if n.startswith("RSA"):
        return "RSA"
    if n.startswith("AES"):
        return "AES"
    if "MD5" in n:
        return "MD5"
    if n.startswith("SHA-256") or n == "SHA256":
        return "SHA-256"
    if "RC4" in n:
        return "RC4"
    # the fixture represents DES via cryptography's TripleDES primitive; both are
    # the same weak DES-family block cipher for inventory purposes.
    if "DES" in n:
        return "DES"
    return n


def _manifest_sig(algo: dict) -> tuple:
    fam = _family(algo["name"])
    if fam == "RSA":
        return (fam, algo["key_size"])      # RSA-2048 vs RSA-1024
    if fam == "AES":
        return (fam, algo["mode"])          # AES-GCM vs AES-ECB
    return (fam, None)


def _detected_algorithms(result: ScanResult) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
    ]


def _detected_sig(comp) -> tuple:
    fam = _family(comp.name)
    props = comp.properties or {}
    if fam == "RSA":
        ks = props.get("crypto:keySize")
        return (fam, int(ks) if ks else None)
    if fam == "AES":
        return (fam, props.get("crypto:mode"))
    return (fam, None)


# --------------------------------------------------------------------------- #


def test_all_manifest_algorithms_detected() -> None:
    result = _scan()
    detected = {_detected_sig(c) for c in _detected_algorithms(result)}
    missing = [
        algo["name"]
        for algo in _manifest()["algorithms"]
        if _manifest_sig(algo) not in detected
    ]
    assert not missing, (
        f"C1 missed manifest algorithms: {missing} (detected={detected})"
    )


def test_rsa_variants_are_distinguished_by_key_size() -> None:
    """The added parametrization: RSA-2048 and RSA-1024 are separate assets."""
    result = _scan()
    rsa_sizes = {
        (c.properties or {}).get("crypto:keySize")
        for c in _detected_algorithms(result)
        if _family(c.name) == "RSA"
    }
    assert {"2048", "1024"} <= rsa_sizes, f"RSA key sizes detected: {rsa_sizes}"


def test_aes_variants_are_distinguished_by_mode() -> None:
    """AES-GCM (strong) and AES-ECB (weak) are separate assets via mode."""
    result = _scan()
    aes_modes = {
        (c.properties or {}).get("crypto:mode")
        for c in _detected_algorithms(result)
        if _family(c.name) == "AES"
    }
    assert {"GCM", "ECB"} <= aes_modes, f"AES modes detected: {aes_modes}"


def test_each_algorithm_carries_a_cyclonedx_primitive() -> None:
    result = _scan()
    valid = {
        "block-cipher", "stream-cipher", "hash", "pke", "signature", "mac",
        "kdf", "drbg", "key-agree", "kem", "ae", "xof", "combiner", "other",
        "unknown",
    }
    for c in _detected_algorithms(result):
        prim = (c.properties or {}).get("crypto:primitive")
        assert prim in valid, f"{c.name} has invalid primitive {prim!r}"
        assert prim != "unknown", f"{c.name} primitive should be concrete"


def test_crypto_libraries_detected() -> None:
    result = _scan()
    libs = {
        c.name
        for c in result.components
        if c.kind == "framework"
        and (c.properties or {}).get("crypto:role") == "library"
    }
    # cryptography + pyOpenSSL from requirements.txt; hashlib imported in source.
    assert "pyca/cryptography" in libs
    assert "pyOpenSSL" in libs
    assert any("hashlib" in lib for lib in libs), f"libs={libs}"


def test_crypto_assets_do_not_leak_into_the_aibom_pipeline() -> None:
    """CBOM scanners must not register into the AIBOM scan registry."""
    from aibom.scan.registry import SCANNERS

    assert not any(s.name == "crypto_algorithm" for s in SCANNERS)
