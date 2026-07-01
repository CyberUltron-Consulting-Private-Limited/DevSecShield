"""C2 — extend the clean-room crypto-API detection to Java + Go.

Two Java surfaces (JCA/JCE ``getInstance("...")`` strings + Bouncy Castle
low-level engine/digest/signer CLASSES) and two Go surfaces (``crypto/*`` stdlib
+ ``golang.org/x/crypto``) are proven against a REAL multi-file fixture. The
value over the flat token corpus: constructor/method binding the corpus could not
see (``aes.NewCipher`` / ``new AESEngine()``), same-line parameter resolution
(``rsa.GenerateKey(_, 2048)`` -> RSA-2048; ``ecdsa.GenerateKey(P256)`` -> curve),
and per-API **library attribution** (JCA/JCE vs Bouncy Castle vs Go stdlib vs
x/crypto).

The frozen ``synthetic-crypto-app`` oracle + its benchmark gate stay byte-identical
(they are Python-only; the Java/Go rule tables + the Java-scoped literal lane never
fire on Python) — this fixture isolates the NEW multi-language coverage.
"""

from __future__ import annotations

import os

from aibom.cbom.detect import detect_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-jvm-go")
_JAVA = os.path.join(_FX, "Crypto.java")
_GO = os.path.join(_FX, "crypto.go")


def _detect(path: str, lang: str) -> dict[str, object]:
    """Aggregate detections per algorithm key -> resolved params + libraries."""
    agg: dict[str, dict] = {}
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for d in detect_crypto(text, lang):
        e = agg.setdefault(
            d.key, {"size": None, "mode": None, "curve": None, "libs": set()}
        )
        e["size"] = e["size"] or d.key_size
        e["mode"] = e["mode"] or d.mode
        e["curve"] = e["curve"] or d.curve
        if d.library:
            e["libs"].add(d.library)
    return agg


# --------------------------------------------------------------------------- #
# Java — JCA/JCE strings + Bouncy Castle classes.
# --------------------------------------------------------------------------- #


def test_java_jca_getinstance_strings_detected() -> None:
    j = _detect(_JAVA, "java")
    # algorithm embedded in the getInstance("...") / "<digest>with<pke>" string.
    assert j["aes"]["mode"] == "GCM"           # "AES/GCM/NoPadding"
    assert j["3des"]["mode"] == "CBC"          # "DESede/CBC/..."
    assert j["des"]["mode"] == "CBC"           # "DES/CBC/..." (not DESede)
    assert "rsa" in j                          # getInstance("RSA") + "SHA256withRSA"
    assert "ecdsa" in j                        # "SHA256withECDSA"
    assert "sha256" in j and "md5" in j        # MessageDigest.getInstance(...)
    assert "hmac" in j                         # "HmacSHA256"


def test_java_bouncycastle_classes_detected_with_library() -> None:
    j = _detect(_JAVA, "java")
    # low-level BC classes the flat token corpus never bound (no "AES(" token).
    assert "Bouncy Castle" in j["ed25519"]["libs"]
    assert "Bouncy Castle" in j["sha256"]["libs"]
    assert "Bouncy Castle" in j["aes"]["libs"]
    # PQC engine spelling (FIPS 203 ML-KEM) via BC.
    assert "kyber" in j and "Bouncy Castle" in j["kyber"]["libs"]


def test_java_desede_does_not_leak_a_bare_des() -> None:
    """``getInstance("DESede/...")`` is 3DES, and must NOT also mint a weak DES on
    that line (the DES literal is gated to ``DES/`` or ``DES"``, not ``DESede``)."""
    des_only = detect_crypto('Cipher c = Cipher.getInstance("DESede/CBC/x");', "java")
    keys = {d.key for d in des_only}
    assert "3des" in keys and "des" not in keys


# --------------------------------------------------------------------------- #
# Go — crypto/* stdlib + golang.org/x/crypto.
# --------------------------------------------------------------------------- #


def test_go_stdlib_constructors_and_params() -> None:
    g = _detect(_GO, "go")
    assert "Go crypto (stdlib)" in g["aes"]["libs"]   # aes.NewCipher (corpus miss)
    assert "Go crypto (stdlib)" in g["des"]["libs"]   # des.NewCipher
    assert "rc4" in g                                 # rc4.NewCipher
    # same-line positional parameter resolution.
    assert g["rsa"]["size"] == 2048                   # rsa.GenerateKey(_, 2048)
    assert g["ecdsa"]["curve"] == "P256"              # ecdsa.GenerateKey(P256())


def test_go_xcrypto_kdfs_and_aead() -> None:
    g = _detect(_GO, "go")
    assert "golang.org/x/crypto" in g["bcrypt"]["libs"]
    assert "golang.org/x/crypto" in g["argon2"]["libs"]
    # chacha20poly1305.New — the corpus \bChaCha20\b misses the fused token.
    assert "chacha20-poly1305" in g
    assert "golang.org/x/crypto" in g["chacha20-poly1305"]["libs"]
    # the memory-cost arg must NOT be mistaken for a KDF key size.
    assert g["argon2"]["size"] is None


def test_go_grouped_import_paths_do_not_shadow_call_sites() -> None:
    """A grouped-import entry (``"crypto/ecdsa"``) must not mint an info-less
    detection that precedes and shadows the real ``ecdsa.GenerateKey(P256())``."""
    g = _detect(_GO, "go")
    assert g["ecdsa"]["curve"] == "P256"


# --------------------------------------------------------------------------- #
# Integration — the real pipeline over the multi-language fixture.
# --------------------------------------------------------------------------- #


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _algorithms(result: ScanResult) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "algorithm"
    ]


def test_pipeline_inventories_java_and_go_assets() -> None:
    names = {c.name for c in _algorithms(_scan())}
    # Java (JCA + BC) and Go (stdlib + x/crypto) assets in one inventory.
    for expected in ("AES-GCM", "3DES-CBC", "RSA", "Ed25519", "CRYSTALS-Kyber",
                     "RSA-2048", "ECDSA", "ChaCha20-Poly1305", "bcrypt", "RC4"):
        assert expected in names, f"missing {expected} in {sorted(names)}"


def test_pipeline_every_asset_has_concrete_primitive() -> None:
    for c in _algorithms(_scan()):
        prim = (c.properties or {}).get("crypto:primitive")
        assert prim and prim != "unknown", f"{c.name} primitive={prim!r}"


def test_pipeline_inventories_java_crypto_libraries() -> None:
    libs = {
        c.name
        for c in _scan().components
        if c.kind == "framework"
        and (c.properties or {}).get("crypto:role") == "library"
    }
    assert "Bouncy Castle" in libs
    assert any("JCA/JCE" in lib for lib in libs), f"libs={libs}"
    # the greedy Python "crypto" root must NOT mislabel javax.crypto.
    assert "PyCryptodome" not in libs
