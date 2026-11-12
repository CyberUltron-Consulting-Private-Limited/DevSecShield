"""Uploaded CycloneDX CBOM files are judged by the deterministic engine (no model, no network)."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import textwrap
import types
from collections import Counter
from pathlib import Path

import pytest

from aibom.cbom.ingest import MAX_COMPONENTS, components_from_cyclonedx, resolve_algorithm
from aibom.integrations.cbom_devsecshield import (
    CbomFileError,
    analyze_cbom_file_to_devsecshield,
    scan_crypto_to_devsecshield,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _asset(ref, name, asset_type, **props):
    key = {"algorithm": "algorithmProperties", "certificate": "certificateProperties",
           "protocol": "protocolProperties", "related-crypto-material": "relatedCryptoMaterialProperties"}[asset_type]
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": name,
            "cryptoProperties": {"assetType": asset_type, key: props}}


SAMPLE = {
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "metadata": {"component": {"name": "payments-api", "type": "application"}},
    "components": [
        {**_asset("a-md5", "MD5", "algorithm", primitive="hash"),
         "evidence": {"occurrences": [{"location": "src/hash.py:12"}]}},
        _asset("a-rsa", "RSA", "algorithm", primitive="pke", parameterSetIdentifier="1024"),
        _asset("a-aes", "AES-128-ECB", "algorithm", primitive="block-cipher", mode="ecb"),
        _asset("a-3des", "DESede", "algorithm", primitive="block-cipher"),
        _asset("a-sha1", "SHA-1", "algorithm", primitive="hash"),
        _asset("a-mlkem", "ML-KEM-768", "algorithm", primitive="kem", parameterSetIdentifier="768"),
        _asset("a-foo", "FooCipher", "algorithm", primitive="block-cipher"),
        _asset("c-1", "legacy.example.com", "certificate", subjectName="CN=legacy.example.com", issuerName="CN=Old CA",
               notValidBefore="2015-01-01T00:00:00Z", notValidAfter="2020-01-01T00:00:00Z",
               signatureAlgorithmRef="a-sha1", subjectPublicKeyRef="a-rsa"),
        _asset("p-1", "TLS", "protocol", type="tls", version="1.0",
               cipherSuites=[{"name": "TLS_RSA_WITH_RC4_128_SHA"}, {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}]),
        {"type": "library", "name": "openssl", "version": "1.0.2k",
         "components": [_asset("n-1", "SHA-256", "algorithm", primitive="hash")]},
    ],
}


def _write(tmp_path, doc, name="cbom.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc, encoding="utf-8")
    return path


def _by_title(run):
    return {r["title"]: r for r in run["results"]}


def test_sample_findings_mappings_and_fixes(tmp_path):
    run = analyze_cbom_file_to_devsecshield(_write(tmp_path, SAMPLE))
    rows = _by_title(run)
    assert run["cbom_input"]["imported"] == 10 and run["cbom_input"]["skipped_not_crypto"] == 1
    assert run["kb_version"]
    assert rows["MD5"]["finding_codes"] == ["WEAK_ALGORITHM"] and rows["MD5"]["cves"] == ["CVE-2004-2761"]
    assert rows["MD5"]["location"] == "src/hash.py:12"
    assert rows["MD5"]["owasp_top_10"] == {"CRYPTOGRAPHIC_FAILURES": "A02:2021 - Cryptographic Failures"}
    assert "SHA-256" in rows["MD5"]["suggested_fix"]
    assert set(rows["RSA-1024"]["finding_codes"]) == {"WEAK_ALGORITHM", "QUANTUM_VULNERABLE"}
    assert "RSA-3072" in rows["RSA-1024"]["suggested_fix"]
    assert rows["AES-128-ECB"]["finding_codes"] == ["WEAK_CIPHER_MODE"]
    assert rows["3DES"]["cves"] == ["CVE-2016-2183"]
    cert = rows["legacy.example.com"]
    assert set(cert["finding_codes"]) == {"EXPIRED_CERTIFICATE", "WEAK_CERTIFICATE_KEY", "WEAK_CERTIFICATE_SIGNATURE"}
    tls = rows["TLS"]
    assert set(tls["finding_codes"]) == {"WEAK_PROTOCOL", "WEAK_CIPHER_SUITE"}
    assert {"CVE-2013-2566", "CVE-2016-2183", "CVE-2011-3389"} <= set(tls["cves"])
    assert rows["ML-KEM-768"]["finding_codes"] == [] and rows["ML-KEM-768"]["quantum_safe"] is True
    assert rows["FooCipher"]["crypto_strength"] == "unknown" and "does not recognise" in rows["FooCipher"]["suggested_fix"]
    assert "SHA-256" in rows  # nested component is read
    assert {c["name"] for c in run["cbom_json"]["components"] if c["type"] == "cryptographic-asset"} >= {"MD5", "TLS"}


def test_file_claims_about_its_own_risk_are_ignored(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {**_asset("x", "MD5", "algorithm", primitive="hash"),
         "properties": [{"name": "crypto:strength", "value": "strong"},
                        {"name": "crypto:quantumVulnerable", "value": "false"},
                        {"name": "crypto:nistQuantumSecurityLevel", "value": "5"}]}]}
    rows = _by_title(analyze_cbom_file_to_devsecshield(_write(tmp_path, doc)))
    assert rows["MD5"]["finding_codes"] == ["WEAK_ALGORITHM"] and rows["MD5"]["crypto_strength"] == "weak"


@pytest.mark.parametrize("doc,note", [
    ({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": None}, "no cryptographic-asset"),
    ({"bomFormat": "CycloneDX", "specVersion": "1.6"}, "no cryptographic-asset"),
    ({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [{"type": "library", "name": "x"}]}, "1.5"),
    ({"bomFormat": "SPDX", "components": []}, "not CycloneDX"),
])
def test_files_without_crypto_assets_say_why(tmp_path, doc, note):
    run = analyze_cbom_file_to_devsecshield(_write(tmp_path, doc))
    assert run["results"] == []
    assert any(note in n for n in run["cbom_input"]["notes"])


@pytest.mark.parametrize("content,message", [
    ("{not json", "not valid JSON"),
    ("[1, 2]", "JSON object"),
    (b"\xff\xfe\x00junk", "not valid JSON"),
])
def test_bad_files_raise_a_readable_error(tmp_path, content, message):
    path = tmp_path / "bad.json"
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)
    with pytest.raises(CbomFileError, match=message):
        analyze_cbom_file_to_devsecshield(path)


def test_oversized_file_is_refused_before_parsing(tmp_path, monkeypatch):
    import aibom.integrations.cbom_devsecshield as adapter
    monkeypatch.setattr(adapter, "MAX_CBOM_BYTES", 100)
    with pytest.raises(CbomFileError, match="larger than"):
        analyze_cbom_file_to_devsecshield(_write(tmp_path, SAMPLE))


def test_malformed_entries_are_counted_not_fatal_and_duplicates_kept_apart():
    doc = {"components": [
        {"type": "cryptographic-asset", "name": "", "cryptoProperties": {"assetType": "algorithm"}},
        {"type": "cryptographic-asset", "name": "X", "cryptoProperties": {"assetType": "nonsense"}},
        {"type": "cryptographic-asset", "name": "X", "cryptoProperties": None},
        _asset("same", "AES-256-GCM", "algorithm"), _asset("same", "AES-256-GCM", "algorithm"),
        "not-a-dict", 7,
    ]}
    comps, stats = components_from_cyclonedx(doc)
    assert stats.skipped_invalid == 3 and stats.imported == 2 and stats.duplicates == 1
    assert len({c.bom_ref for c in comps}) == 2


def test_component_cap_and_deep_nesting(monkeypatch):
    import aibom.cbom.ingest as ingest
    monkeypatch.setattr(ingest, "MAX_COMPONENTS", 5)
    comps, stats = ingest.components_from_cyclonedx(
        {"components": [_asset(f"a{i}", "SHA-256", "algorithm") for i in range(9)]})
    assert len(comps) == 5 and stats.truncated and any("first 5" in n for n in stats.notes)
    deep: dict = {"type": "library", "name": "d0"}
    node = deep
    for i in range(30):  # deeper than MAX_DEPTH: no recursion error, deep levels ignored
        child = {"type": "library", "name": f"d{i + 1}"}
        node["components"] = [child]
        node = child
    node["components"] = [_asset("deep", "MD5", "algorithm")]
    comps, _ = ingest.components_from_cyclonedx({"components": [deep]})
    assert comps == []
    assert MAX_COMPONENTS == 20_000


@pytest.mark.parametrize("name,size,expected", [
    ("AES-256-GCM", None, ("aes-256", 256, "GCM", None)),
    ("RSA", 2048, ("rsa-2048", 2048, None, None)),
    ("sha1WithRSAEncryption", None, ("sha1", None, None, None)),
    ("ML-KEM-1024", None, ("kyber", None, None, "1024")),
    ("ML-DSA-65", None, ("dilithium", None, None, "65")),
    ("DESede", None, ("3des", None, None, None)),
    ("ChaCha20-Poly1305", None, ("chacha20-poly1305", None, None, None)),
    ("Totally-Unknown", None, (None, None, None, None)),
    # names real CBOM tools emit
    ("RSA-OAEP-256", None, ("rsa", None, None, None)),             # 256 is the digest, not the modulus
    ("FN-DSA-512", None, ("falcon", None, None, "512")),            # FIPS 206 name of Falcon, not DSA-512
    ("X25519MLKEM768", None, ("hybrid", None, None, "768")),
    ("x25519_mlkem768", None, ("hybrid", None, None, "768")),
    ("SecP256r1MLKEM768", None, ("hybrid", None, None, "768")),
    ("sha256WithRSAEncryption", None, ("rsa", None, None, None)),   # sound digest: the RSA key decides
    ("ecdsa-with-SHA1", None, ("sha1", None, None, None)),          # broken digest decides
    ("ecdsa-with-SHA256", None, ("ecdsa", None, None, None)),
    ("DES-EDE3-CBC", None, ("3des", None, "CBC", None)),
    ("rsaEncryption", None, ("rsa", None, None, None)),
    ("secp256r1", None, ("ecdsa", None, None, None)),             # a curve: crypto:curve, not a key size
    ("P-384", None, ("ecdsa", None, None, None)),
    ("DH-1024", None, ("dh", 1024, None, None)),
    ("ffdhe2048", None, ("dh", 2048, None, None)),
    ("ML-KEM", 768, ("kyber", None, None, "768")),                   # parameterSetIdentifier carries the set
    ("Dilithium3", None, ("dilithium", None, None, "65")),
    ("SLH-DSA-SHA2-128s", None, ("sphincs+", None, None, "128")),
])
def test_algorithm_name_resolution(name, size, expected):
    assert resolve_algorithm(name, size) == expected


def test_real_world_names_are_judged_correctly(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        _asset("o", "RSA-OAEP-256", "algorithm", primitive="pke"),
        _asset("f", "FN-DSA-512", "algorithm", primitive="signature"),
        _asset("h", "X25519MLKEM768", "algorithm", primitive="key-agree"),
        _asset("s", "sha256WithRSAEncryption", "algorithm", primitive="signature"),
        _asset("e", "ecdsa-with-SHA1", "algorithm", primitive="signature"),
        _asset("d", "DH-1024", "algorithm", primitive="key-agree"),
        _asset("c", "P-256", "algorithm", primitive="signature"),
    ]}
    rows = {r["bom_ref"].split("-")[-1]: r for r in analyze_cbom_file_to_devsecshield(_write(tmp_path, doc))["results"]}
    assert "WEAK_KEY_SIZE" not in rows["o"]["finding_codes"]                      # no false 256-bit RSA
    assert rows["f"]["finding_codes"] == [] and rows["f"]["quantum_safe"] is True  # not DSA-512
    assert rows["h"]["finding_codes"] == [] and rows["h"]["quantum_safe"] is True  # hybrid PQC key exchange
    assert "QUANTUM_VULNERABLE" in rows["s"]["finding_codes"]                     # RSA signature
    assert "WEAK_ALGORITHM" in rows["e"]["finding_codes"]                         # SHA-1 signature
    assert {"QUANTUM_VULNERABLE", "WEAK_KEY_SIZE"} <= set(rows["d"]["finding_codes"])        # DH-1024 is too small
    assert rows["c"]["finding_codes"] == ["QUANTUM_VULNERABLE"]                    # P-256: sound today, not quantum-safe


def test_analysis_is_deterministic(tmp_path):
    path = _write(tmp_path, SAMPLE)
    a = analyze_cbom_file_to_devsecshield(path)
    b = analyze_cbom_file_to_devsecshield(path)
    for run in (a, b):
        run.pop("duration_of_scan", None)
    assert json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)


@pytest.mark.parametrize("fixture", ["synthetic-crypto-app", "synthetic-crypto-misuse", "synthetic-crypto-pqc",
                                     "synthetic-crypto-protocols", "synthetic-crypto-suites"])
def test_reuploading_a_scan_cbom_keeps_every_crypto_finding(tmp_path, fixture):
    """Scan a repository, upload the CBOM it produced: every crypto-asset finding comes back."""
    run = scan_crypto_to_devsecshield(FIXTURES / fixture, level=4)
    up = analyze_cbom_file_to_devsecshield(_write(tmp_path, run["cbom_json"]))
    # crypto-asset findings only: a vulnerable library row is a dependency, not a cryptographic-asset component
    scanned = Counter(c for r in run["results"] if r.get("algorithm_type") != "library" for c in r["finding_codes"])
    uploaded = Counter(c for r in up["results"] for c in r["finding_codes"])
    assert not scanned - uploaded


# ------------------------------------------------------------------------------------------------ no model, no net
_FORBIDDEN = ("boto3", "botocore", "openai", "anthropic", "langchain", "langchain_core", "langchain_aws",
              "langsmith", "requests", "httpx", "urllib3", "aiohttp")


class _Tripwire(types.ModuleType):
    def __getattr__(self, name):
        raise AssertionError(f"forbidden module {self.__name__!r} used ({name})")


def _refuse(*_a, **_k):
    raise AssertionError("network/process access attempted")


def test_both_cbom_paths_run_with_network_and_model_sdks_blocked(tmp_path, monkeypatch):
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, _refuse)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)
    for name in _FORBIDDEN:
        monkeypatch.setitem(sys.modules, name, _Tripwire(name))
    run = scan_crypto_to_devsecshield(FIXTURES / "synthetic-crypto-app", level=4)
    assert run["results"] and all(r["suggested_fix"] for r in run["results"])
    up = analyze_cbom_file_to_devsecshield(_write(tmp_path, SAMPLE))
    assert any(r["cves"] for r in up["results"])


def test_import_closure_of_the_cbom_paths_is_clean():
    script = textwrap.dedent(f"""
        import json, sys
        import aibom.integrations.cbom_devsecshield, aibom.cbom.ingest, aibom.cbom.crypto_kb
        roots = {{m.split('.')[0] for m in sys.modules}}
        print('PROBE:' + json.dumps(sorted(r for r in roots if r in {list(_FORBIDDEN)!r})))
    """)
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120, check=True)
    line = next(x for x in done.stdout.splitlines() if x.startswith("PROBE:"))
    assert json.loads(line[6:]) == []


@pytest.mark.parametrize("bad", [
    {"type": "cryptographic-asset", "name": "x", "cryptoProperties": {"assetType": ["algorithm"]}},
    {"type": "cryptographic-asset", "name": "x", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": "rsa"}},
    {"type": "cryptographic-asset", "name": "x", "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"cipherSuites": 5}}},
    {"type": "cryptographic-asset", "name": "x", "cryptoProperties": {"assetType": "certificate", "certificateProperties": "c"}},
    {"type": "cryptographic-asset", "name": "x", "cryptoProperties": {"assetType": "related-crypto-material",
                                                                       "relatedCryptoMaterialProperties": 7}},
    {"type": "cryptographic-asset", "name": "x", "properties": 5, "evidence": "e",
     "cryptoProperties": {"assetType": "algorithm"}},
    {"type": "cryptographic-asset", "name": "x", "evidence": {"occurrences": 3}, "cryptoProperties": {"assetType": "algorithm"}},
])
def test_malformed_fields_never_abort_the_import(bad):
    comps, stats = components_from_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [bad]})
    assert stats.crypto_assets == 1 and len(comps) + stats.skipped_invalid == 1


def test_string_metadata_and_unreadable_json_are_handled(tmp_path):
    from aibom.cbom.pipeline import analyze_cbom_document
    analyze_cbom_document({"bomFormat": "CycloneDX", "metadata": "x", "components": []})
    with pytest.raises(CbomFileError):
        analyze_cbom_file_to_devsecshield(_write(tmp_path, '{"a": ' + "9" * 5000 + "}"))
    with pytest.raises(CbomFileError):
        analyze_cbom_file_to_devsecshield(_write(tmp_path, "[" * 100000 + "]" * 100000, "deep.json"))


def test_repeated_bom_refs_stay_linear_and_distinct():
    import time
    comps = [_asset("same", "AES-256-GCM", "algorithm", primitive="ae") for _ in range(20000)]
    t0 = time.monotonic()
    out, stats = components_from_cyclonedx({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps})
    assert time.monotonic() - t0 < 10 and len({c.bom_ref for c in out}) == 20000 and stats.duplicates == 19999


def test_hybrid_claim_in_the_file_is_not_trusted():
    doc = {"components": [{**_asset("r", "RSA-2048", "algorithm", primitive="pke"),
                           "properties": [{"name": "crypto:hybrid", "value": "true"}]}]}
    comps, _ = components_from_cyclonedx(doc)
    assert "crypto:hybrid" not in comps[0].properties



def _part(comp):
    return {**comp, "properties": [{"name": "zs:part_of", "value": "certificate"}]}


def _cbom(*components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": list(components)}


def test_certificate_parts_of_a_run_export_are_read_into_their_certificates():
    """A ZeroShield run export (CB-06 v2) lists each certificate's signature algorithm,
    public key and key algorithm once, as top-level components marked ``zs:part_of`` and
    referenced by bom-ref from every certificate that has them. Re-importing it counts
    the certificates, not the parts; the certificates keep size, curve and
    algorithms."""
    sig = _part(_asset("zs-signature-algorithm-a", "ecdsa-with-SHA384", "algorithm",
                       primitive="signature"))
    key_alg = _part(_asset("zs-public-key-algorithm-b", "EC", "algorithm",
                           primitive="signature", curve="secp384r1"))
    key = _part(_asset("zs-public-key-c", "EC-secp384r1", "related-crypto-material",
                       type="public-key", size=384,
                       algorithmRef="zs-public-key-algorithm-b"))
    certs = [
        _asset(f"zs-asset-{i}", f"CN=h{i}", "certificate",
               signatureAlgorithmRef="zs-signature-algorithm-a",
               subjectPublicKeyRef="zs-public-key-c",
               subjectName=f"CN=h{i}", issuerName="CN=CA")
        for i in (1, 2)
    ]
    comps, stats = components_from_cyclonedx(_cbom(*certs, sig, key_alg, key))
    assert (stats.crypto_assets, stats.imported, stats.certificate_parts) == (2, 2, 3)
    assert any("parts of certificates" in note for note in stats.notes)
    for comp in comps:
        props = comp.properties
        assert props["crypto:assetType"] == "certificate"
        assert props["crypto:keySize"] == "384"
        assert props["crypto:curve"] == "secp384r1"
        assert props["crypto:signatureAlgorithm"] == "ecdsa-with-SHA384"
        # the rule base's name for an EC key (read from its curve)
        assert props["crypto:publicKeyAlgorithm"] == "ECDSA"


def test_a_referenced_algorithm_without_the_part_marker_is_still_an_asset():
    """Other tools' CBOMs: a referenced algorithm with no ``zs:part_of`` stays an
    asset."""
    sig = _asset("alg-sha1rsa", "sha1WithRSAEncryption", "algorithm",
                 primitive="signature")
    cert = _asset("cert-1", "CN=a", "certificate", signatureAlgorithmRef="alg-sha1rsa")
    _comps, stats = components_from_cyclonedx(_cbom(cert, sig))
    assert (stats.crypto_assets, stats.imported, stats.certificate_parts) == (2, 2, 0)
