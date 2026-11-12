"""algid, the one algorithm-identity module (CB-04 PR-1).

The expected values come from the captured registries themselves, parsed here with test-local code that imports
nothing from scripts/algid (so a generator bug cannot hide behind the same parser), and from a FIPS transcription
(fixtures/algid_fips_categories.json). No network; DER inputs are built at test time from random bytes.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_algid.py -q
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import random
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from backend.utilities.cbom_sources import algid as A  # noqa: E402

SRC = REPO / "scripts/algid/sources"
COPIES = (REPO / "backend/utilities/cbom_sources/algid.py", REPO / "scan_node/zs_scan_node/algid.py",
          REPO / "aibom/src/aibom/cbom/algid.py")


def _rows(name: str) -> list[dict[str, str]]:
    return list(csv.DictReader((SRC / name).read_text(encoding="utf-8").splitlines()))


# ----------------------------------------------------------------------------- T-B1 / T-B1b
def test_three_copies_are_identical():
    first = COPIES[0].read_bytes()
    assert all(p.read_bytes() == first for p in COPIES[1:])


def test_generated_region_reproducible_from_sources():
    manifest = json.loads((SRC / "SOURCES.json").read_text())
    listed = {e["file"] for e in manifest["files"]}
    assert listed == {p.name for p in SRC.iterdir() if p.name != "SOURCES.json"}
    for entry in manifest["files"]:
        assert hashlib.sha256((SRC / entry["file"]).read_bytes()).hexdigest() == entry["sha256"], entry["file"]
        for key in ("url", "retrieved_utc", "tool", "licence"):
            assert entry[key], (entry["file"], key)
    done = subprocess.run([sys.executable, str(REPO / "scripts/algid/build_algid.py"), "--check"],
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert A.SOURCES_SHA256 == hashlib.sha256((SRC / "SOURCES.json").read_bytes()).hexdigest()


# ----------------------------------------------------------------------------- T-B2 registries, every row
# PQ rows: construction, parameter set and status as the registry rows and their references describe them.
TLS_PQ = {
    0x0200: ("pure", "ML-KEM-512", "standard"), 0x0201: ("pure", "ML-KEM-768", "standard"),
    0x0202: ("pure", "ML-KEM-1024", "standard"), 0x11E9: ("hybrid", "ML-KEM-512", "draft"),
    0x11EA: ("hybrid", "ML-KEM-512", "draft"), 0x11EB: ("hybrid", "ML-KEM-768", "standard"),
    0x11EC: ("hybrid", "ML-KEM-768", "standard"), 0x11ED: ("hybrid", "ML-KEM-1024", "standard"),
    0x11EE: ("hybrid", "ML-KEM-768", "draft"), 0x11EF: ("hybrid", "ML-KEM-1024", "draft"),
    0x6399: ("hybrid", "ML-KEM-768", "obsolete"), 0x639A: ("hybrid", "ML-KEM-768", "obsolete"),
}


def test_iana_tls_groups_exact():
    seen = 0
    for row in _rows("iana-tls-groups.csv"):
        value, desc, ref = row["Value"], row["Description"], row["Reference"]
        if not value.isdigit():
            continue
        cp = int(value)
        found = A.tls_group(cp)
        if desc == "Reserved" and "RFC 8701" in ref:
            assert found is A.GREASE, cp
            continue
        if desc.startswith(("Reserved", "Unassigned")):
            assert found is None, cp
            continue
        seen += 1
        assert found is not None and found.name == desc.replace(" (OBSOLETE)", ""), (cp, desc, found)
        assert found.matched_by == "codepoint"
        if cp in TLS_PQ:
            assert (found.construction, found.parameter_set, found.status) == TLS_PQ[cp], (cp, found)
            assert found.family_label == "PQ" and A.quantum_vulnerable(desc.split(" ")[0]) is False
        else:
            assert found.quantum == "vulnerable" and found.construction == "classical", (cp, found)
    assert seen >= 60
    assert set(TLS_PQ) <= {cp for cp in range(0x10000) if (A.tls_group(cp) or A.GREASE).family_label == "PQ"}


def test_iana_sigschemes_exact():
    for row in _rows("iana-tls-sigschemes.csv"):
        value, desc, ref = row["Value"], row["Description"], row["Reference"]
        if "-" in value:
            continue
        found = A.tls_sigscheme(int(value, 16))
        if desc.startswith(("Reserved", "Unassigned")):
            assert found is None, value
            continue
        assert found is not None and found.name == desc, (value, desc)
        m = re.fullmatch(r"(mldsa|slhdsa_)(.+)", desc)
        if m and m.group(1) == "mldsa":
            assert (found.parameter_set, found.construction, found.status) == (
                f"ML-DSA-{m.group(2)}", "pure", "standard")
        elif m:
            hashfn, size = m.group(2).split("_")
            assert found.parameter_set == f"SLH-DSA-{hashfn.upper()}-{size}"
            assert found.status == ("draft" if "draft-" in ref else "standard")
        else:
            assert found.quantum == "vulnerable", desc


SSH_PQ = {
    "mlkem768x25519-sha256": ("hybrid", "ML-KEM-768"), "mlkem768nistp256-sha256": ("hybrid", "ML-KEM-768"),
    "mlkem1024nistp384-sha384": ("hybrid", "ML-KEM-1024"), "sntrup761x25519-sha512": ("hybrid", "sntrup761"),
    "mlkem512-sha256": ("pure", "ML-KEM-512"), "mlkem768-sha256": ("pure", "ML-KEM-768"),
    "mlkem1024-sha384": ("pure", "ML-KEM-1024"),
}


def test_iana_ssh_kex_exact():
    for row in _rows("iana-ssh-kex.csv"):
        name = row["Method Name"]
        if name in ("ext-info-s", "ext-info-c", "gss-"):
            assert A.ssh_kex(name) is None
            continue
        found = A.ssh_kex(name)
        assert found is not None, name
        if name in SSH_PQ:
            assert (found.construction, found.parameter_set) == SSH_PQ[name], (name, found)
            assert found.quantum in ("safe", "hybrid")
        else:
            assert found.quantum == "vulnerable", (name, found)
    for line in (SRC / "openssh-kex-aliases.txt").read_text().splitlines()[1:]:
        found = A.ssh_kex(line.strip())
        assert found is not None and found.name == line.split("@")[0], line
    assert A.ssh_kex("ecdh-sha2-1.3.132.0.10").family_label == "ECDH"  # the registry's wildcard row
    assert A.ssh_kex("gss-nistp256-sha256-toWM5Slw5Ew8Mqkay+al2g==").family_label == "ECDH"


def test_iana_ikev2_t4_exact():
    names = {}
    for row in _rows("iana-ikev2-t4.csv"):
        num, desc = row["Number"], row["Name"]
        if not num.isdigit() or desc in ("NONE",):
            continue
        found = A.ike_ke(int(num))
        assert found is not None, (num, desc)
        names[int(num)] = found.name
        m = re.fullmatch(r"ml-kem-(\d+)", desc)
        if m:
            assert (found.name, found.parameter_set, found.quantum) == (
                f"ML-KEM-{m.group(1)}", f"ML-KEM-{m.group(1)}", "safe")
        else:
            assert found.quantum == "vulnerable", desc
    # the product's existing spellings (ikeprobe.GROUPS, classify_ext/node_net WEAK_GROUPS) are unchanged
    assert (names[1], names[14], names[19], names[22], names[31], names[36]) == (
        "MODP-768", "MODP-2048", "ECP-256", "MODP-1024-S160", "CURVE25519", "ML-KEM-768")
    assert names[27] == "BRAINPOOL-P224R1" and A.ike_ke(38) is None


def _csor_oids() -> dict[str, str]:
    text = re.sub(r"<[^>]+>", " ", html.unescape((SRC / "nist-csor.html").read_text(encoding="utf-8")))
    arcs = {"nistAlgorithms": "2.16.840.1.101.3.4"}
    out = {}
    for ident, parent, num in re.findall(r"([\w-]+)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{\s*(\w+)\s+(\d+)\s*\}", text):
        if parent in arcs:
            arcs[ident] = f"{arcs[parent]}.{num}"
            out[ident] = arcs[ident]
    return out


def test_pkix_and_csor_oids_exact():
    csor = _csor_oids()
    pq = {k: v for k, v in csor.items() if re.match(r"id-(alg-ml-kem|ml-dsa|slh-dsa|hash-)", k)}
    assert len(pq) == 33
    for ident, oid in pq.items():
        found = A.resolve(oid)
        assert found is not None and found.matched_by == "oid" and found.oid == oid, ident
        m = re.fullmatch(r"id-(?:alg-)?(ml-dsa|ml-kem)-(\d+)", ident)
        if m:
            assert found.name == f"{m.group(1).upper()}-{m.group(2)}" == found.parameter_set
        m = re.fullmatch(r"id-slh-dsa-(sha2|shake)-(\d+[sf])", ident)
        if m:
            assert found.name == f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}" == found.parameter_set
        m = re.fullmatch(r"id-hash-ml-dsa-(\d+)-with-sha512", ident)
        if m:
            assert found.name == f"HashML-DSA-{m.group(1)}-with-SHA512"
            assert found.parameter_set == f"ML-DSA-{m.group(1)}"
        assert (found.construction, found.quantum, found.status) == ("pure", "safe", "standard"), ident
    for row in _rows("iana-pkix-alg.csv"):
        dec, desc, ref = row["Decimal"], row["Description"], row["Reference"]
        if not dec.isdigit():
            continue
        oid = f"1.3.6.1.5.5.7.6.{dec}"
        found = A.resolve(oid)
        assert found is not None, (oid, desc)
        if re.match(r"id-ML(DSA|KEM)\d+-", desc):
            assert found.construction == "composite" and found.quantum == "hybrid", desc
            assert found.status == ("standard" if "RFC 10073" in ref else "draft"), desc
            assert found.standard == ("RFC 10073" if "RFC 10073" in ref else None), desc
            assert found.parameter_set == re.sub(r"id-ML(DSA|KEM)(\d+)-.*", r"ML-\1-\2", desc)
    assert A.resolve("1.3.6.1.5.5.7.6.34").name == "XMSS" and A.resolve("1.3.6.1.5.5.7.6.35").name == "XMSS^MT"
    assert A.resolve("1.3.6.1.5.5.7.6.34").stateful and A.resolve("1.3.6.1.5.5.7.6.34").quantum == "safe"
    assert A.resolve("1.2.840.113549.1.9.16.3.17").name == "HSS"


def test_categories_match_fips_transcription():
    fixture = json.loads((REPO / "backend/tests/fixtures/algid_fips_categories.json").read_text())
    for name, category in fixture["categories"].items():
        found = A.resolve(name)
        assert found is not None and found.nist_category == category, (name, found)
    # every OID-registered FIPS algorithm carries the transcribed category of its parameter set
    for oid in [f"2.16.840.1.101.3.4.3.{n}" for n in range(17, 47)] + [f"2.16.840.1.101.3.4.4.{n}" for n in (1, 2, 3)]:
        found = A.resolve(oid)
        assert found.nist_category == fixture["categories"][found.parameter_set], oid
    assert A.resolve("X25519MLKEM768").nist_category == 3 and A.resolve("SecP384r1MLKEM1024").nist_category == 5
    assert A.resolve("LMS").nist_category is None  # SP 800-208 defines none
    for no_credit in ("Kyber768", "Dilithium3", "X25519Kyber768Draft00"):
        assert A.resolve(no_credit).nist_category is None, no_credit


def test_aws_spellings_and_enums():
    enums = json.loads((SRC / "botocore-enums.json").read_text())["enums"]
    for key, values in enums.items():
        service, field = key.split(".")
        if field == "SecurityPolicy":
            continue
        for value in values:
            assert A.aws(service, field, value) is not None, key + " " + value
    pca = A.aws("acm-pca", "KeyAlgorithm", "ML_DSA_65")
    assert (pca.name, pca.quantum, pca.key_size, pca.matched_by) == ("ML-DSA-65", "safe", None, "enum")
    assert A.aws("acm-pca", "KeyAlgorithm", "SM2").name == "SM2"
    assert A.aws("kms", "KeySpec", "RSA-2048") == A.aws("kms", "KeySpec", "RSA_2048")
    assert A.aws("kms", "KeySpec", "rsa_2048").key_size == 2048
    assert A.aws("kms", "KeySpec", "ECC_NIST_EDWARDS25519").key_size == 256  # not 25519
    assert A.aws("kms", "KeySpec", "TOTALLY_BOGUS") is None and A.aws("nope", "KeySpec", "RSA_2048") is None
    elb = A._AWS_TLS_POLICY["elbv2"]
    assert len(elb) == 13 and all("-PQ-" in n for n in elb)
    assert set(A.aws_tls_policy("elbv2", "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09")) == {
        "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519MLKEM768"}
    assert A.aws_tls_policy("elbv2", "ELBSecurityPolicy-TLS13-1-2-2021-06") is None
    api = A._AWS_TLS_POLICY["apigateway"]
    # the SDK enum and the documentation spell one FIPS policy differently; both are kept
    assert {"SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09"} <= set(api)
    assert all(A.aws_tls_policy("apigateway", n) == () for n in api)
    assert A.aws_tls_policy("apigateway", "TLS_1_2") is None


# ----------------------------------------------------------------------------- T-B2d DER readers
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def _oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(enc))
    return _tlv(0x06, body)


def _spki(alg: str, params: bytes = b"", key_len: int = 1952) -> bytes:
    return _tlv(0x30, _tlv(0x30, _oid(alg) + params) + _tlv(0x03, b"\x00" + os.urandom(key_len)))


def test_der_readers():
    mldsa65 = _spki("2.16.840.1.101.3.4.3.18")
    assert A.spki_alg(mldsa65) == ("2.16.840.1.101.3.4.3.18", None)
    assert A.spki_alg(_spki("2.16.840.1.101.3.4.4.2", key_len=1184)) == ("2.16.840.1.101.3.4.4.2", None)
    assert A.spki_alg(_spki("2.16.840.1.101.3.4.3.20", key_len=32))[0] == "2.16.840.1.101.3.4.3.20"
    sm2 = _spki("1.2.840.10045.2.1", _oid("1.2.156.10197.1.301"), 65)
    assert A.spki_alg(sm2) == ("1.2.840.10045.2.1", "1.2.156.10197.1.301")
    explicit = _spki("1.2.840.10045.2.1", _tlv(0x30, _tlv(0x02, b"\x01") + os.urandom(8)), 65)
    assert A.spki_alg(explicit) == ("1.2.840.10045.2.1", "explicit")
    for broken in (mldsa65[:40], b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", os.urandom(64)):
        assert A.spki_alg(broken) is None or isinstance(A.spki_alg(broken), tuple)
    assert A.spki_alg(mldsa65[:40]) is None and A.spki_alg(b"") is None
    pkcs8 = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x30, _oid("2.16.840.1.101.3.4.3.18"))
                 + _tlv(0x04, os.urandom(32)))
    assert A.pkcs8_alg(pkcs8) == "2.16.840.1.101.3.4.3.18"
    assert A.pkcs8_alg(pkcs8[:20]) is None and A.pkcs8_alg(mldsa65) is None
    name = _tlv(0x30, _tlv(0x31, _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, b"lab"))))
    validity = _tlv(0x30, _tlv(0x17, b"260101000000Z") * 2)
    tbs = _tlv(0x30, _tlv(0xA0, _tlv(0x02, b"\x02")) + _tlv(0x02, b"\x01") + _tlv(0x30, _oid("2.16.840.1.101.3.4.3.18"))
               + name + validity + name + mldsa65)
    assert A.tbs_spki_alg(tbs) == ("2.16.840.1.101.3.4.3.18", None)
    assert A.tbs_spki_alg(tbs[:60]) is None


# ----------------------------------------------------------------------------- T-B2e resolution order
def test_resolution_order():
    by_oid = A.resolve("2.16.840.1.101.3.4.3.18")
    assert by_oid.matched_by == "oid" and by_oid.name == "ML-DSA-65"
    for text in ("ML DSA 65", "ml_dsa_65", "FN-DSA-512", "FNDSA1024", "rsa3072_dilithium2", "HashML-DSA-44-with-SHA512",
                 "SLH-DSA-SHAKE-256f", "mldsa87"):
        found = A.resolve(text)
        assert found is not None and found.family_label == "PQ", text
        assert A.quantum_vulnerable(text) is False, text
    assert A.resolve("rsa3072_dilithium2").construction == "composite"
    assert A.resolve("rsa3072_dilithium2").status == "pre-standard"
    for sentinel in ("<NULL>", "(NONE)", "NONE", "", "unknown", "Unknown OID", None):
        assert A.resolve(sentinel) is None, sentinel
    assert A.resolve("Kyber768").status == "pre-standard"
    assert A.resolve("X25519Kyber768Draft00").status == "obsolete"
    assert A.resolve("X25519Kyber768Draft00").quantum == "hybrid"  # today's credit kept (OA-CB04-2)
    # today's classical answers are kept by the fallback (cipher-suite names included)
    assert A.family_label("ECDHE-RSA-AES128-GCM-SHA256") == "ECDH"
    assert A.family_label("TLS_AES_256_GCM_SHA384") is None
    assert A.family_label("ECC_NIST_P256") == "EC" and A.family_label("dsaEncryption") == "DSA"
    # strict namespaces never fall back: OpenSSL text is exact, an oqs-provider name stays unknown
    assert A.openssl_text("ML-DSA-65").name == "ML-DSA-65" and A.openssl_text("mldsa65") is None
    assert A.openssl_text("GOST R 34.10-2012 with 256 bit modulus").name == "GOST R 34.10-2012-256"
    assert A.resolve("x25519", "tls_group").name == "x25519" and A.resolve("nope", "tls_group") is None
    with pytest.raises(ValueError):
        A.resolve("x", "no-such-namespace")
    assert A.resolve("1.2.3.4.5") is None and A.hint("1.3.9999.6.4.13") == "oqs-arc"
    prototype = A.resolve("2.16.840.1.114027.80.8.1.4")
    assert prototype.construction == "composite" and prototype.status == "pre-standard" and prototype.name is None
    assert A.compare_key("2.16.840.1.101.3.4.3.18") == "ML-DSA-65" == A.compare_key("ML_DSA_65")
    assert A.compare_key("RSA") == "RSA" and A.compare_key("ECDSA") == "ECDSA" and A.compare_key(None) is None
    assert A.code_lane_x509_name("1.2.840.10045.2.1") == "ecPublicKey"
    assert A.code_lane_x509_name("2.16.840.1.101.3.4.3.18") == "ML-DSA-65"
    assert A.openssl_major_minor("OpenSSL 3.5.7 9 Jun 2026") == (3, 5)
    assert A.openssl_major_minor("OpenSSL 3.0.13 30 Jan 2024") == (3, 0)
    assert A.openssl_major_minor("LibreSSL 3.8.2") is None and A.openssl_major_minor("") is None


def test_openssl_text_30_and_35_agree():
    by_cert = {}
    for name in ("openssl-3.0-text.json", "openssl-3.5-text.json"):
        for row in json.loads((SRC / name).read_text())["rows"]:
            pub = A.resolve(row["public_key_text"], "openssl_text")
            by_cert.setdefault(row["cert"], set()).add(pub.name if pub else None)
    # OpenSSL 3.0 prints the dotted OID where 3.5 prints a name: both resolve to one identity
    for cert, names in by_cert.items():
        assert len(names) == 1 and None not in names, (cert, names)


# ----------------------------------------------------------------------------- T-B2f / T-B2g
def test_tables_immutable_no_memo():
    for table in (A._ALGS, A._OIDS, A._TLS_GROUPS, A._ALIASES, A._AWS, A._AWS_TLS_POLICY["elbv2"]):
        with pytest.raises(TypeError):
            table["x"] = "y"  # type: ignore[index]
    before = {k: id(v) for k, v in vars(A).items()}
    sizes = {k: len(v) for k, v in vars(A).items()
             if isinstance(v, (tuple, frozenset, type(A._ALGS))) and not isinstance(v, type)}
    rng = random.Random(4)
    words = list(A._ALGS) + list(A._OIDS) + ["bogus", "1.2.3", "<NULL>"]
    for _ in range(10_000):
        A.resolve(rng.choice(words))
        A.tls_group(rng.randrange(0x10000))
    assert {k: id(v) for k, v in vars(A).items()} == before
    assert {k: len(v) for k, v in vars(A).items() if k in sizes} == sizes
    assert not any(hasattr(f, "cache_info") for f in vars(A).values())


def test_prober_lists_pinned():
    classical = [29, 23, 24, 25, 30, 256, 257]
    pq = [0x11EC, 0x11EB, 0x11ED, 0x6399, 0x0201, 0x0202, 0x0200, 0x11E9, 0x11EA, 0x11EE, 0x11EF]
    assert list(A.PQ_PROBE_GROUPS) == pq and 0x639A not in A.PQ_PROBE_GROUPS
    assert list(A.TLS13_OFFER_GROUPS) == classical + [258, 259, 260, 31, 32, 33] + list(range(34, 43)) + pq
    sigalgs = [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806, 0x0809, 0x080A, 0x080B,
               0x0401, 0x0501, 0x0601, 0x0203, 0x0201, 0x0402, 0x0202]  # scan_node tlsprobe.SIGALGS today
    assert list(A.TLS13_SIGSCHEMES) == sigalgs + [0x081A, 0x081B, 0x081C, 0x0708] + list(range(0x0709, 0x0710)) + [
        0x0904, 0x0905, 0x0906] + list(range(0x0911, 0x091D))
    assert A.S_CLIENT_GROUPS_35 == (
        "?*X25519MLKEM768/?*X25519:?secp256r1/?X448:?secp384r1:?secp521r1/?ffdhe2048:?ffdhe3072/"
        "?SecP256r1MLKEM768:?SecP384r1MLKEM1024:?MLKEM512:?MLKEM768:?MLKEM1024:?SecP256r1MLKEM512:"
        "?MLKEM512X25519:?curveSM2MLKEM768:?MLKEM1024X448:?brainpoolP256r1tls13:?brainpoolP384r1tls13:"
        "?brainpoolP512r1tls13:?ffdhe4096:?ffdhe6144:?ffdhe8192:?curveSM2")
    for group in A.TLS13_OFFER_GROUPS:
        assert A.tls_group(group) is not None, hex(group)
    for scheme in A.TLS13_SIGSCHEMES:
        assert A.tls_sigscheme(scheme) is not None or scheme in (0x0402, 0x0202), hex(scheme)
    for name in A.TLS_CLASSICAL_SIGSCHEME_NAMES:
        assert A.resolve(name, "tls_sigscheme").quantum == "vulnerable", name
