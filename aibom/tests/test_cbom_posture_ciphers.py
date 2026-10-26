"""Cipher-string evaluator against an independent reference."""

from __future__ import annotations

import json
import random
import time
from pathlib import Path

from aibom.cbom.posture.ciphers import (
    CipherEvaluator,
    CipherResult,
    GroupResult,
    cap_suites,
    evaluate_cipher_list,
    evaluator_for,
)
from aibom.cbom.posture.context import CbomScanContext, posture_sink
from aibom.cbom.posture.defaults import load_registry, read_data_bytes
from aibom.cbom.weakness import cipher_suite_findings
from aibom.model.component import CryptoAssetComponent
from support.naive_ciphers import (
    classify_groups as naive_groups,
)
from support.naive_ciphers import (
    evaluate_cipher_list as naive_cipher_list,
)
from support.naive_ciphers import (
    evaluate_tls13_suites as naive_tls13,
)

_ECDHE_GCM = (
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
)
_POOL = (
    "ALL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "RC4",
    "AES128",
    "AES256",
    "ECDHE",
    "aNULL",
    "eNULL",
    "3DES",
    "MD5",
    "SHA",
    "kRSA",
    "aRSA",
    "TLSv1.2",
    "!RC4",
    "-RC4",
    "+RC4",
    "!ADH",
    "ECDHE+AESGCM",
    "ECDHE+CHACHA20",
    "@SECLEVEL=0",
    "@SECLEVEL=2",
    "@SECLEVEL=3",
    "@STRENGTH",
    "DEFAULT",
    "AES128-SHA",
    "RC4-MD5",
    "GARBAGE",
    "$ssl_ciphers",
    "rc4",
)
_EXAMPLES = (
    "ALL:!ADH:@STRENGTH",
    "ALL:!aNULL:!eNULL",
    "ALL:+RC4:@STRENGTH",
    "HIGH:!aNULL:!MD5",
    "TLSv1.2:!aNULL",
    "ECDHE+AESGCM:ECDHE+CHACHA20",
    "DEFAULT:!3DES",
    "aRSA+kRSA+SHA",
    "ALL:@SECLEVEL=2",
    "RC4:!RC4:RC4",
    "RC4:-RC4:RC4",
    "@SECLEVEL=2:RC4",
)


def _document() -> dict:
    return json.loads(read_data_bytes("cipher_suites.json"))


def _groups() -> dict:
    return json.loads(read_data_bytes("named_groups.json"))


def _evaluator() -> CipherEvaluator:
    return CipherEvaluator(load_registry())


def _agree(spec: str, evaluator: CipherEvaluator, document: dict) -> CipherResult:
    got = evaluator.cipher_list(spec)
    ref = naive_cipher_list(spec, document)
    assert got.truncated is False
    assert list(got.suites) == ref["suites"]
    assert list(got.explicit) == ref["explicit"]
    assert list(got.unresolved) == ref["unresolved"]
    assert got.complete is ref["complete"]
    assert got.seclevel == ref["seclevel"]
    return got


def test_shipped_tables_load() -> None:
    registry = load_registry()
    names = {table.name for table in registry.tables}
    assert "cipher_suites.json" in names
    assert "named_groups.json" in names
    assert "tls_policies.json" in names


def test_bang_is_permanent_and_dash_is_not() -> None:
    evaluator = _evaluator()
    document = _document()
    banned = _agree("RC4:!RC4:RC4", evaluator, document)
    restored = _agree("RC4:-RC4:RC4", evaluator, document)
    plain = _agree("RC4", evaluator, document)
    assert banned.suites == ()
    assert banned.complete is True
    assert restored.suites == plain.suites
    assert "TLS_RSA_WITH_RC4_128_SHA" in restored.suites
    assert restored.suites != banned.suites


def test_security_level_filters_after_the_list() -> None:
    evaluator = _evaluator()
    document = _document()
    level2 = _agree("ALL:@SECLEVEL=2", evaluator, document)
    level0 = _agree("ALL:@SECLEVEL=0", evaluator, document)
    level3 = _agree("ALL:@SECLEVEL=3", evaluator, document)
    assert level2.seclevel == 2
    assert "TLS_RSA_WITH_RC4_128_SHA" not in level2.suites
    assert "TLS_RSA_WITH_NULL_SHA" not in level2.suites
    assert "TLS_RSA_WITH_DES_CBC_SHA" not in level2.suites
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in level2.suites
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in level2.suites
    assert "TLS_DH_anon_WITH_AES_128_CBC_SHA" in level2.suites
    assert "TLS_RSA_WITH_RC4_128_SHA" in level0.suites
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" not in level3.suites
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" not in level3.suites
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in level3.suites
    broken = _agree("@SECLEVEL=9:HIGH", evaluator, document)
    assert broken.complete is False
    assert broken.seclevel is None
    assert broken.unresolved == ("@SECLEVEL=9",)


def test_documented_openssl_examples_match_the_reference() -> None:
    evaluator = _evaluator()
    document = _document()
    for spec in _EXAMPLES:
        _agree(spec, evaluator, document)
    moved = _agree("ALL:+RC4:@STRENGTH", evaluator, document)
    plain = _agree("ALL", evaluator, document)
    assert moved.suites == plain.suites
    without_adh = _agree("ALL:!ADH", evaluator, document)
    with_strength = _agree("ALL:!ADH:@STRENGTH", evaluator, document)
    assert with_strength.suites == without_adh.suites
    assert "TLS_DH_anon_WITH_AES_128_CBC_SHA" not in without_adh.suites
    assert "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" in without_adh.suites
    gcm = _agree("ECDHE+AESGCM", evaluator, document)
    assert gcm.suites == _ECDHE_GCM
    rsa_sha = _agree("aRSA+kRSA+SHA", evaluator, document)
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in rsa_sha.suites
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in rsa_sha.suites
    assert "TLS_RSA_WITH_RC4_128_SHA" in rsa_sha.suites
    assert "TLS_RSA_WITH_AES_128_GCM_SHA256" not in rsa_sha.suites
    assert "TLS_RSA_WITH_AES_128_CBC_SHA256" not in rsa_sha.suites
    assert "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" not in rsa_sha.suites
    default = _agree("DEFAULT:!3DES", evaluator, document)
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" not in default.suites
    assert "TLS_RSA_WITH_RC4_128_SHA" not in default.suites
    assert "TLS_RSA_WITH_NULL_SHA" not in default.suites
    assert "TLS_DH_anon_WITH_AES_128_CBC_SHA" not in default.suites
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in default.suites
    assert "TLS_RSA_WITH_DES_CBC_SHA" in default.suites
    high = _agree("HIGH:!aNULL:!MD5", evaluator, document)
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in high.suites
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" in high.suites
    assert "TLS_DH_anon_WITH_AES_128_CBC_SHA" not in high.suites
    assert "TLS_RSA_WITH_RC4_128_MD5" not in high.suites
    modern = _agree("TLSv1.2:!aNULL", evaluator, document)
    assert "TLS_RSA_WITH_AES_128_GCM_SHA256" in modern.suites
    assert "TLS_RSA_WITH_AES_128_CBC_SHA" not in modern.suites
    named = _agree("ECDHE-RSA-AES128-GCM-SHA256:NO_SUCH", evaluator, document)
    assert named.complete is False
    assert named.explicit == ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",)
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in named.suites


def test_reference_agrees_on_a_generated_corpus() -> None:
    evaluator = _evaluator()
    document = _document()
    for seed in range(1, 21):
        rng = random.Random(seed)
        for _ in range(50):
            width = rng.randint(1, 6)
            spec = ":".join(rng.choice(_POOL) for _ in range(width))
            _agree(spec, evaluator, document)


def test_tls13_names_and_groups() -> None:
    evaluator = _evaluator()
    listed = evaluator.tls13_suites(
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:NOT_A_SUITE"
    )
    ref = naive_tls13(
        "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:NOT_A_SUITE",
        _document(),
    )
    assert list(listed.suites) == ref["suites"]
    assert listed.suites == (
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
    )
    assert listed.unresolved == ("NOT_A_SUITE",)
    assert listed.complete is False
    ignored = evaluator.cipher_list("TLS_AES_128_GCM_SHA256")
    assert ignored.suites == ()
    assert ignored.complete is True
    groups = evaluator.groups("P-256:x25519:secp192r1:auto:nope")
    ref_groups = naive_groups("P-256:x25519:secp192r1:auto:nope", _groups())
    assert isinstance(groups, GroupResult)
    assert groups.groups == tuple(ref_groups["groups"])
    assert groups.groups == ("secp192r1", "secp256r1", "x25519")
    assert [(item.name, item.bits) for item in groups.weak] == [("secp192r1", 192)]
    assert groups.unresolved == ("nope",)
    assert groups.complete is False
    assert evaluator.groups("auto").groups == ()
    assert evaluator.groups("").complete is True
    assert evaluator.groups("p-256").groups == ("secp256r1",)


def test_cap_keeps_weak_suites_then_fills_to_256() -> None:
    weak = ["RC4-AAAA", "NULL-AAAA"]
    strong = [f"AES-{index:04d}" for index in range(300)]
    kept, truncated = cap_suites([*strong, *weak])
    assert truncated is True
    assert len(kept) == 256
    assert "RC4-AAAA" in kept
    assert "NULL-AAAA" in kept
    assert "AES-0000" in kept
    assert "AES-0299" not in kept
    overflow = [f"RC4-{index:04d}" for index in range(300)]
    kept_weak, truncated_weak = cap_suites([*overflow, "AES-0000"])
    assert truncated_weak is True
    assert len(kept_weak) == 300
    assert "AES-0000" not in kept_weak
    assert "RC4-0299" in kept_weak


def test_registry_agrees_with_predicate() -> None:
    for raw in _document()["rows"]:
        if raw.get("kind") == "suite_set":
            continue
        name = raw["iana"]
        component = CryptoAssetComponent(
            bom_ref="suite",
            name="tls",
            properties={
                "crypto:assetType": "protocol",
                "crypto:protocolType": "tls",
                "crypto:cipherSuite": name,
            },
        )
        flagged = bool(cipher_suite_findings(component))
        justified = (
            raw.get("enc") in {"NULL", "RC4", "RC2", "DES", "3DES"}
            or raw.get("au") == "None"
            or raw.get("export") is True
            or raw.get("mac") == "MD5"
        )
        assert flagged is justified, name


def test_evaluator_is_per_scan_and_memoized_by_string(tmp_path: Path) -> None:
    sink = posture_sink(CbomScanContext(tmp_path))
    first = evaluator_for(sink)
    assert evaluator_for(sink) is first
    assert sink.ciphers is first
    cached = first.cipher_list("HIGH")
    assert first.cipher_list("HIGH") is cached
    other = posture_sink(CbomScanContext(tmp_path))
    second = evaluator_for(other)
    assert second is not first
    assert second.cipher_list("HIGH") == cached
    assert second.cipher_list("HIGH") is not cached


def test_evaluators_do_not_share_an_id_cache() -> None:
    source = Path(evaluate_cipher_list.__code__.co_filename).read_text(encoding="utf-8")
    assert "id(" not in source
    reg = load_registry()
    rc4 = _one_suite("TLS_RSA_WITH_RC4_128_SHA", 5, "RC4", "RC4")
    aes = _one_suite("TLS_RSA_WITH_AES_128_CBC_SHA", 47, "AES", "AES")
    left = CipherEvaluator(reg, cipher_document=rc4, group_document={"rows": []})
    right = CipherEvaluator(reg, cipher_document=aes, group_document={"rows": []})
    assert left.cipher_list("RC4").suites == ("TLS_RSA_WITH_RC4_128_SHA",)
    assert right.cipher_list("RC4").suites == ()
    assert right.cipher_list("AES").suites == ("TLS_RSA_WITH_AES_128_CBC_SHA",)


def test_hostile_strings_stay_total() -> None:
    reg = load_registry()
    hostile = (
        "",
        ":::,,,   ",
        "!" * (1 << 20),
        ":" * 100_000,
        "@SECLEVEL=" + ("9" * 10_000),
        "@SECLEVEL=-4",
        "\ufffd\ufffd",
        ":".join(["NOPE"] * 600),
    )
    for spec in hostile:
        started = time.perf_counter()
        result = evaluate_cipher_list(spec, reg)
        assert time.perf_counter() - started < 1
        assert isinstance(result, CipherResult)


def _one_suite(iana: str, code: int, enc: str, keyword: str) -> dict:
    return {
        "keywords": {keyword: {"enc": [enc]}, "RC4": {"enc": ["RC4"]}},
        "seclevels": {"0": {"deny": [], "min_bits": 0}},
        "rows": [
            {
                "au": "RSA",
                "bits": 128,
                "classes": ["ALL", enc],
                "code": code,
                "enc": enc,
                "enc_bits": 128,
                "enc_mode": "CBC",
                "export": False,
                "fs": False,
                "iana": iana,
                "id": iana,
                "kx": "RSA",
                "mac": "SHA1",
                "min": "1.0",
                "openssl": [iana],
                "tls13": False,
            }
        ],
    }
