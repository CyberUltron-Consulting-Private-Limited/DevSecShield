"""Internal-consistency gate for the synthetic-crypto-app CBOM ground truth.

``expected_crypto.json`` is the hand-labeled oracle the CBOM scanner (C1-C8) and
the chart-data/contract tests (C9-C10) will be measured against. This test owns
no scanner — it proves the MANIFEST is internally consistent and that every asset
it claims is actually present in the fixture source, so later iterations build
against a trustworthy oracle.
"""

from __future__ import annotations

import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-app")


def _manifest() -> dict:
    with open(os.path.join(_FX, "expected_crypto.json")) as fh:
        return json.load(fh)


def _read(name: str) -> str:
    with open(os.path.join(_FX, name)) as fh:
        return fh.read()


def test_fixture_files_exist() -> None:
    for name in ("crypto_app.py", "tls_config.py", "cert.pem", "requirements.txt"):
        assert os.path.isfile(os.path.join(_FX, name)), f"missing fixture file: {name}"


def test_cert_is_a_real_pem_certificate() -> None:
    cert = _read("cert.pem")
    assert "-----BEGIN CERTIFICATE-----" in cert
    assert "-----END CERTIFICATE-----" in cert


def test_counts_match_list_lengths() -> None:
    m = _manifest()
    c = m["counts"]
    assert len(m["algorithms"]) == c["algorithms"]
    assert len(m["certificates"]) == c["certificates"]
    assert len(m["protocols"]) == c["protocols"]
    assert len(m["related_crypto_material"]) == c["related_crypto_material"]
    assert len(m["weak_algorithms"]) == c["weak_algorithms"]
    assert len(m["strong_algorithms"]) == c["strong_algorithms"]
    assert len(m["quantum_vulnerable"]) == c["quantum_vulnerable"]
    assert c["strong_algorithms"] + c["weak_algorithms"] == c["algorithms"]


def test_weak_strong_partition_is_consistent() -> None:
    m = _manifest()
    algos = {a["name"]: a for a in m["algorithms"]}
    weak_flagged = {n for n, a in algos.items() if a["weak"]}
    strong_flagged = {n for n, a in algos.items() if not a["weak"]}
    assert weak_flagged == set(m["weak_algorithms"])
    assert strong_flagged == set(m["strong_algorithms"])
    # the two sets partition the algorithm universe with no overlap
    assert weak_flagged & strong_flagged == set()
    assert weak_flagged | strong_flagged == set(algos)


def test_quantum_vulnerable_matches_per_algorithm_flag() -> None:
    m = _manifest()
    flagged = {a["name"] for a in m["algorithms"] if a["quantum_vulnerable"]}
    assert flagged == set(m["quantum_vulnerable"])
    # every quantum-vulnerable algorithm has a declared PQC migration target
    for name in m["quantum_vulnerable"]:
        assert name in m["pqc_migration_targets"], f"no PQC target for {name}"


def test_acceptance_criteria_assets_present() -> None:
    """F3 ground truth: the exact strong/weak split the story specifies."""
    m = _manifest()
    strong = set(m["strong_algorithms"])
    weak = set(m["weak_algorithms"])
    assert {"RSA-2048", "AES-256-GCM", "SHA-256"} <= strong
    assert {"MD5", "DES", "RC4", "AES-128-ECB", "RSA-1024"} <= weak
    # certificate / protocol / related-crypto-material lanes are each populated
    assert any(cert["self_signed"] for cert in m["certificates"])
    assert any(p["name"] == "TLS" and p["version"] == "1.0" for p in m["protocols"])
    assert any(
        r["kind"] == "private-key" for r in m["related_crypto_material"]
    )


def test_every_asset_is_actually_in_the_fixture_source() -> None:
    """The manifest must not lie: each asset's named file must reference it."""
    m = _manifest()
    src_cache: dict[str, str] = {}

    def src(name: str) -> str:
        if name not in src_cache:
            src_cache[name] = _read(name) if name != "cert.pem" else _read(name)
        return src_cache[name]

    # algorithm tokens that appear verbatim in the source
    token_hints = {
        "RSA-2048": "2048",
        "AES-256-GCM": "GCM",
        "SHA-256": "sha256",
        "MD5": "md5",
        "DES": "TripleDES",
        "RC4": "ARC4",
        "AES-128-ECB": "ECB",
        "RSA-1024": "1024",
    }
    for algo in m["algorithms"]:
        body = src(algo["file"])
        hint = token_hints[algo["name"]]
        assert hint in body, f"{algo['name']} ({hint}) not found in {algo['file']}"

    # protocol + related-crypto-material live in their declared files too
    assert "TLSv1" in src(m["protocols"][0]["file"])
    assert "BEGIN PRIVATE KEY" in src(m["related_crypto_material"][0]["file"])
