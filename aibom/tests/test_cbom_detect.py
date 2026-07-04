"""C1 — clean-room crypto-API detection-rule model + data-flow-lite symbol table.

Two levels of coverage:

* **Unit** — the :mod:`aibom.cbom.detect` primitives (call-split, symbol table,
  argument-role resolution, receiver binding) against small real snippets, proving
  the capabilities the previous flat per-line regex corpus lacked: cross-line key
  size, byte-length-inferred AES key size, and padding capture.
* **Integration** — the real CBOM pipeline over the ``synthetic-crypto-dataflow``
  fixture, asserting those capabilities survive end-to-end as inventoried assets.

The frozen ``synthetic-crypto-app`` oracle + its benchmark gate stay untouched;
this fixture isolates the NEW resolution so a regression here is unambiguous.
"""

from __future__ import annotations

import os

from aibom.cbom.detect import (
    ROLE_KEY_SIZE,
    ROLE_PADDING,
    CryptoRule,
    build_symbols,
    detect_crypto,
    split_calls,
)
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.rules import extract_key_size
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-dataflow")


# --------------------------------------------------------------------------- #
# Unit — the rule-model primitives.
# --------------------------------------------------------------------------- #


def test_split_calls_captures_receiver_and_balanced_args() -> None:
    calls = split_calls("Cipher(algorithms.AES(aes_key), modes.CBC(iv))")
    chains = {c for c, _ in calls}
    assert "algorithms.AES" in chains
    assert "modes.CBC" in chains
    # the outer Cipher(...) captures its full balanced argument span
    cipher_args = next(a for c, a in calls if c == "Cipher")
    assert "algorithms.AES(aes_key)" in cipher_args and "modes.CBC(iv)" in cipher_args


def test_symbol_table_binds_int_and_byte_length() -> None:
    lines = [
        "RSA_BITS = 2048",
        "aes_key = os.urandom(32)",
        "iv = os.urandom(16)",
        "not_crypto = compute_widget_total()",
    ]
    symbols = build_symbols(lines)
    assert symbols["RSA_BITS"].key_size == 2048
    assert symbols["aes_key"].key_size == 256  # 32 bytes -> 256-bit key
    assert "not_crypto" not in symbols  # only crypto-relevant names are bound


def test_cross_line_key_size_resolves_rsa_variant() -> None:
    """The keystone win: a key size assigned one line up resolves the usage —
    which the same-line ``extract_key_size`` cannot see."""
    src = (
        "RSA_BITS = 2048\n"
        "priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)\n"
    )
    # the previous same-line extractor is blind to the variable reference ...
    assert extract_key_size("rsa.generate_private_key(key_size=RSA_BITS)") is None
    # ... but the rule engine resolves it through the symbol table.
    dets = detect_crypto(src, "python")
    rsa = [d for d in dets if d.key == "rsa"]
    assert rsa and rsa[0].key_size == 2048


def test_literal_key_byte_length_infers_aes_size_and_mode() -> None:
    src = (
        "aes_key = os.urandom(32)\n"
        "cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))\n"
    )
    dets = detect_crypto(src, "python")
    aes = [d for d in dets if d.key == "aes"]
    assert aes, "AES not detected"
    assert aes[0].key_size == 256
    assert aes[0].mode == "CBC"


def test_padding_arg_role_captures_oaep_and_pkcs1v15() -> None:
    oaep = detect_crypto("ct = pub.encrypt(m, padding.OAEP(algorithm=h))", "python")
    assert any(d.key == "rsa" and d.padding == "oaep" for d in oaep)
    pkcs = detect_crypto("sig = priv.sign(m, padding.PKCS1v15(), h)", "python")
    assert any(d.key == "rsa" and d.padding == "pkcs1v15" for d in pkcs)


def test_receiver_binding_ignores_bare_method_without_receiver() -> None:
    """A receiver+method rule needs its receiver token present: a bare
    ``generate_private_key(...)`` with no ``rsa`` receiver must not mint RSA."""
    rule = CryptoRule("python", "pyca/cryptography", "rsa",
                      "generate_private_key", "rsa", (ROLE_KEY_SIZE,))
    assert rule.receiver_re is not None
    assert rule.receiver_re.search("rsa.generate_private_key(key_size=2048)")
    assert not rule.receiver_re.search("dsa.generate_private_key(key_size=2048)")


def test_padding_role_constant_is_wired() -> None:
    assert ROLE_PADDING == "PADDING"


# --------------------------------------------------------------------------- #
# Integration — the real pipeline over the fixture.
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


def test_dataflow_rsa_variants_resolved_cross_line() -> None:
    sizes = {
        (c.properties or {}).get("crypto:keySize")
        for c in _algorithms(_scan())
        if c.name.upper().startswith("RSA-")
    }
    assert {"2048", "1024"} <= sizes, f"RSA sizes resolved: {sizes}"


def test_dataflow_aes_size_and_mode_resolved() -> None:
    aes = [c for c in _algorithms(_scan()) if c.name.upper().startswith("AES")]
    props = [(c.properties or {}) for c in aes]
    assert any(
        p.get("crypto:keySize") == "256" and p.get("crypto:mode") == "CBC"
        for p in props
    ), f"AES assets: {[c.name for c in aes]}"


def test_dataflow_padding_emitted_on_rsa_asset() -> None:
    paddings = {
        (c.properties or {}).get("crypto:padding")
        for c in _algorithms(_scan())
        if (c.properties or {}).get("crypto:padding")
    }
    assert "oaep" in paddings or "pkcs1v15" in paddings, f"paddings: {paddings}"


def test_dataflow_every_algorithm_has_concrete_primitive() -> None:
    for c in _algorithms(_scan()):
        prim = (c.properties or {}).get("crypto:primitive")
        assert prim and prim != "unknown", f"{c.name} primitive={prim!r}"
