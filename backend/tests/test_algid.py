"""algid, the one algorithm-identity module (CB-04 PR-1).

The expected values come from the captured registries themselves, parsed here with test-local code that imports
nothing from scripts/algid (so a generator bug cannot hide behind the same parser): names, family, key size and status
are derived from each row's own Description and Reference text. FIPS categories come from a transcription
(fixtures/algid_fips_categories.json). No network; DER inputs are built at test time from random bytes.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_algid.py -q
"""
from __future__ import annotations

import csv
import hashlib
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
FOLDERS = (REPO / "backend/utilities/cbom_sources", REPO / "scan_node/zs_scan_node", REPO / "aibom/src/aibom/cbom")
COPIES = tuple(folder / name for name in ("algid.py", "algid_tables.py") for folder in FOLDERS)
SYMMETRIC = ("mac", "ae", "block-cipher", "stream-cipher", "hash", "other")


def _rows(name: str) -> list[dict[str, str]]:
    return list(csv.DictReader((SRC / name).read_text(encoding="utf-8").splitlines()))


def _status(reference: str, description: str = "") -> str:
    """The documented status rule (curated.json "status_rule"), written here from its text: obsolete, then a published
    RFC (standard), then an RFC-to-be or an Internet-Draft (draft), else standard."""
    if "obsolete" in reference.lower() or "obsolete" in description.lower():
        return "obsolete"
    if re.search(r"\[RFC \d+\]", reference):
        return "standard"
    if "RFC-ietf-" in reference or "draft-" in reference:
        return "draft"
    return "standard"


def _bits(text: str) -> int | None:
    m = re.search(r"(\d{3,4})", text)
    return int(m.group(1)) if m else None


def _same(a: A.Identity | None, b: A.Identity | None) -> bool:
    """Equal identities, ignoring how they were matched (name vs alias)."""
    return (a is None and b is None) or (a is not None and b is not None and a[:-1] == b[:-1])


# ----------------------------------------------------------------------------- T-B1 / T-B1b
def test_three_copies_are_identical():
    for name in ("algid.py", "algid_tables.py"):
        first = (FOLDERS[0] / name).read_bytes()
        assert all((folder / name).read_bytes() == first for folder in FOLDERS[1:]), name
    # exactly these copies: no fourth algid anywhere in the product trees
    found = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", "backend",
                            "scan_node", "aibom/src", "RabbitMQ"], cwd=REPO, capture_output=True, text=True).stdout.split()
    stray = [p for p in found if Path(p).name in ("algid.py", "algid_tables.py")]
    if found:
        assert sorted(stray) == sorted(str(p.relative_to(REPO)) for p in COPIES), stray


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
# PQ TLS groups: construction and parameter set; status is derived from the Reference column. The obsolete Kyber
# draft groups claim no FIPS parameter set (FIPS 203 App. C: round-3 Kyber is not ML-KEM).
TLS_PQ = {
    0x0200: ("pure", "ML-KEM-512"), 0x0201: ("pure", "ML-KEM-768"), 0x0202: ("pure", "ML-KEM-1024"),
    0x11E9: ("hybrid", "ML-KEM-512"), 0x11EA: ("hybrid", "ML-KEM-512"), 0x11EB: ("hybrid", "ML-KEM-768"),
    0x11EC: ("hybrid", "ML-KEM-768"), 0x11ED: ("hybrid", "ML-KEM-1024"), 0x11EE: ("hybrid", "ML-KEM-768"),
    0x11EF: ("hybrid", "ML-KEM-1024"), 0x6399: ("hybrid", None), 0x639A: ("hybrid", None),
}


def _group_expect(desc: str) -> tuple[str, int | None]:
    """(family, key size) of a classical TLS group from its registry name."""
    low = desc.lower()
    if low in ("x25519", "x448"):
        return desc.upper(), 256 if low == "x25519" else 448
    if low.startswith("ffdhe"):
        return "DH", int(low[5:])
    if low == "curvesm2":
        return "SM2", 256
    if low.startswith("arbitrary_explicit"):
        return "EC", None
    m = re.match(r"(?:sect|secp|brainpoolp|gc|bign-curve)(\d{3})", low)
    assert m, desc
    return "EC", int(m.group(1))


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
        name = desc.replace(" (OBSOLETE)", "")
        assert found is not None and found.matched_by == "codepoint", (cp, desc, found)
        assert found.status == _status(ref, desc), (cp, desc, found.status)
        if cp in TLS_PQ:
            assert found.name == name
            assert (found.construction, found.parameter_set) == TLS_PQ[cp], (cp, found)
            assert found.family_label == "PQ" and found.quantum == ("hybrid" if TLS_PQ[cp][0] == "hybrid" else "safe")
            assert all(c in A._ALGS for c in found.components), found
        else:
            family, bits = _group_expect(name)
            assert (found.family_label, found.key_size, found.quantum, found.construction) == (
                family, bits, "vulnerable", "classical"), (cp, desc, found)
    assert seen >= 60
    assert set(TLS_PQ) <= {cp for cp in range(0x10000) if (A.tls_group(cp) or A.GREASE).family_label == "PQ"}
    # draft and RFC-to-be groups keep their ML-KEM category; obsolete ones claim none (OA-CB04-2)
    assert A.tls_group(0x0201).status == "draft" and A.tls_group(0x0201).nist_category == 3
    assert A.tls_group(0x11E9).nist_category == 1 and A.tls_group(0x6399).nist_category is None
    assert A.tls_group(0x6399).standard is None and A.tls_group(0x11EC).status == "standard"


def _sigscheme_family(desc: str) -> str:
    low = desc.lower()
    for prefix, family in (("rsa_", "RSA"), ("ecdsa_", "ECDSA"), ("ed25519", "ED25519"), ("ed448", "ED448"),
                           ("sm2", "SM2"), ("gostr", "EC"), ("eccsi", "EC"), ("iso_", "EC"), ("bign-", "EC"),
                           ("mldsa", "PQ"), ("slhdsa", "PQ")):
        if low.startswith(prefix):
            return family
    raise AssertionError(desc)


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
        assert found.status == _status(ref, desc), (desc, found.status)
        assert found.family_label == _sigscheme_family(desc), (desc, found)
        m = re.fullmatch(r"(mldsa|slhdsa_)(.+)", desc)
        if m and m.group(1) == "mldsa":
            assert (found.parameter_set, found.construction, found.quantum) == (f"ML-DSA-{m.group(2)}", "pure", "safe")
        elif m:
            hashfn, size = m.group(2).split("_")
            assert (found.parameter_set, found.quantum) == (f"SLH-DSA-{hashfn.upper()}-{size}", "safe")
        else:
            assert (found.quantum, found.construction) == ("vulnerable", "classical"), desc
    assert A.tls_sigscheme(0x0905).status == "draft"  # RFC-ietf-tls-mldsa: RFC-to-be is draft


SSH_PQ = {
    "mlkem768x25519-sha256": ("hybrid", "ML-KEM-768", ("ML-KEM-768", "X25519")),
    "mlkem768nistp256-sha256": ("hybrid", "ML-KEM-768", ("ML-KEM-768", "P-256")),
    "mlkem1024nistp384-sha384": ("hybrid", "ML-KEM-1024", ("ML-KEM-1024", "P-384")),
    "sntrup761x25519-sha512": ("hybrid", "sntrup761", ("sntrup761", "X25519")),
    "mlkem512-sha256": ("pure", "ML-KEM-512", ()), "mlkem768-sha256": ("pure", "ML-KEM-768", ()),
    "mlkem1024-sha384": ("pure", "ML-KEM-1024", ()),
}
# RFC 4253 s8.1-8.2 (group1 = Oakley group 2: 1024 bit; group14: 2048), RFC 8268 s3 / RFC 3526 (group15-18)
SSH_DH_BITS = {"group1": 1024, "group14": 2048, "group15": 3072, "group16": 4096, "group17": 6144, "group18": 8192}


def _ssh_expect(name: str) -> tuple[str, int | None]:
    m = re.search(r"(group\d+)", name)
    if name.startswith(("diffie-hellman-", "gss-group", "gss-gex")):
        return "DH", SSH_DH_BITS[m.group(1)] if m else None
    if name.startswith("rsa"):
        return "RSA", _bits(name)
    if name.startswith(("ecdh-sha2-nistp", "gss-nistp")):
        return "ECDH", int(re.search(r"nistp(\d{3})", name).group(1))
    if name.startswith("ecdh-sha2-"):
        return "ECDH", None
    if name.startswith("ecmqv"):
        return "EC", None
    if "curve25519" in name:
        return "X25519", 256
    if "curve448" in name:
        return "X448", 448
    raise AssertionError(name)


def test_iana_ssh_kex_exact():
    for row in _rows("iana-ssh-kex.csv"):
        name = row["Method Name"]
        if name in ("ext-info-s", "ext-info-c", "gss-"):
            assert A.ssh_kex(name) is None
            continue
        found = A.ssh_kex(name)
        assert found is not None, name
        assert found.status == _status(row["Reference"]), (name, found.status)
        if name in SSH_PQ:
            assert (found.construction, found.parameter_set, found.components) == SSH_PQ[name], (name, found)
            assert found.quantum == ("hybrid" if SSH_PQ[name][0] == "hybrid" else "safe")
            assert found.standard == ("FIPS 203" if SSH_PQ[name][1].startswith("ML-KEM") else None), name
        else:
            assert (found.family_label, found.key_size) == _ssh_expect(name), (name, found)
            assert found.quantum == "vulnerable", (name, found)
    for line in (SRC / "openssh-kex-aliases.txt").read_text().splitlines()[1:]:
        found = A.ssh_kex(line.strip())
        assert found is not None and found.name == line.split("@")[0], line
    assert A.ssh_kex("ecdh-sha2-1.3.132.0.10").family_label == "ECDH"  # the registry's wildcard row
    assert A.ssh_kex("gss-nistp256-sha256-mechanism").family_label == "ECDH"  # RFC 8732 suffix
    assert A.ssh_kex("diffie-hellman-group14-sha256").key_size == 2048


def _ike_expect(desc: str) -> tuple[str, int | None]:
    low = desc.lower()
    if "modp" in low:
        return "DH", _bits(desc)
    if "ecp" in low or low.startswith("brainpool"):
        return "EC", _bits(desc)
    if low.startswith("gost3410_2012_"):
        return "EC", int(low.rsplit("_", 1)[1])
    if low in ("curve25519", "curve448"):
        return ("X25519", 256) if low == "curve25519" else ("X448", 448)
    raise AssertionError(desc)


def test_iana_ikev2_t4_exact():
    names = {}
    for row in _rows("iana-ikev2-t4.csv"):
        num, desc = row["Number"], row["Name"]
        if not num.isdigit() or desc in ("NONE",):
            continue
        found = A.ike_ke(int(num))
        assert found is not None, (num, desc)
        assert found.status == _status(row["Reference"], desc), (desc, found.status)
        names[int(num)] = found.name
        m = re.fullmatch(r"ml-kem-(\d+)", desc)
        if m:
            # the binding row keeps the registry spelling (an RFC-to-be: draft); the product spelling ML-KEM-NNN is
            # the FIPS 203 algorithm row (standard) and is what ike_name() returns
            assert (found.name, found.parameter_set, found.quantum, found.status) == (
                desc, f"ML-KEM-{m.group(1)}", "safe", "draft")
            assert A.resolve(f"ML-KEM-{m.group(1)}").status == "standard"
            assert A.ike_name(int(num)) == f"ML-KEM-{m.group(1)}"
            assert A.resolve(f"ML-KEM-{m.group(1)}", "ike_ke") == found._replace(matched_by="name")
        else:
            assert (found.family_label, found.key_size, found.quantum) == (*_ike_expect(desc), "vulnerable"), desc
            assert A.ike_name(int(num)) == found.name
    assert names[27] == "BRAINPOOL-P224R1" and names[36] == "ml-kem-768" and A.ike_ke(38) is None
    assert A.ike_name(38) is None and A.ike_name("36") is None and A.ike_name(True) is None


def test_ike_names_are_what_the_product_emits():
    """ike_name() returns exactly the spellings the scan node emits today: ikeprobe.GROUPS (stored as
    ikev2.pq.method, e.g. "ML-KEM-768") and appliance_parsers.GROUP_NAMES. No stored fact changes."""
    for rel, start, end in (("scan_node/zs_scan_node/ikeprobe.py", "GROUPS = {", "}"),
                            ("scan_node/zs_scan_node/appliance_parsers.py", "GROUP_NAMES = {", "}")):
        text = (REPO / rel).read_text()
        block = text[text.index(start):]
        block = block[:block.index(end) + 1]
        table = {int(k): v for k, v in re.findall(r'(\d+): "([^"]+)"', block)}
        assert table, rel
        assert {k: A.ike_name(k) for k in table} == table, rel


def _csor_oids() -> dict[str, str]:
    """{identifier: dotted OID} from the CSOR extract's ASN.1 definitions, resolved here independently."""
    defs = json.loads((SRC / "nist-csor-oids.json").read_text())["object_identifier_definitions"]
    arcs = {"nistAlgorithms": "2.16.840.1.101.3.4"}
    out = {}
    for ident, body in defs:
        m = re.fullmatch(r"(\w+) (\d+)", body)
        if m and m.group(1) in arcs:
            arcs[ident] = out[ident] = f"{arcs[m.group(1)]}.{m.group(2)}"
    return out


def _csor_param(ident: str) -> str | None:
    """The FIPS parameter set a CSOR identifier names (id-hash-slh-dsa-sha2-128s-with-sha256 -> SLH-DSA-SHA2-128s)."""
    m = re.fullmatch(r"id-(?:alg-|hash-)?(ml-dsa|ml-kem)-(\d+)(?:-with-\w+)?", ident)
    if m:
        return f"{m.group(1).upper()}-{m.group(2)}"
    m = re.fullmatch(r"id-(?:hash-)?slh-dsa-(sha2|shake)-(\d{3}[sf])(?:-with-\w+)?", ident)
    return f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}" if m else None


@pytest.mark.skipif(not os.environ.get("ALGID_RAW_DIR"), reason="raw HTML captures are not committed; set "
                    "ALGID_RAW_DIR to the folder that holds them (CB-04 evidence) to check the extracts")
def test_extracts_match_raw_captures():
    import importlib.util

    raw_dir = Path(os.environ["ALGID_RAW_DIR"])
    spec = importlib.util.spec_from_file_location("extract_html", REPO / "scripts/algid/extract_html.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    for name, doc in module.extracts(raw_dir).items():
        assert (SRC / name).read_text(encoding="utf-8") == module.render(doc), name
        for prov in doc["provenance"]:
            assert hashlib.sha256((raw_dir / prov["raw_file"]).read_bytes()).hexdigest() == prov["raw_sha256"]


# the classical part of a composite, from its registry name (the hash and padding stay in the composite's name)
def _composite_component(suffix: str) -> str:
    m = re.match(r"RSA(\d{4})-", suffix)
    if m:
        return f"RSA-{m.group(1)}"
    m = re.match(r"(?:ECDSA|ECDH)-P(\d{3})-", suffix)
    if m:
        return f"P-{m.group(1)}"
    m = re.match(r"(?:ECDSA|ECDH)-(brainpoolP\d{3}r1)-|(Ed25519|Ed448|X25519|X448)-", suffix)
    assert m, suffix
    return m.group(1) or m.group(2)


def _pkix_family(name: str) -> tuple[str | None, str | None]:
    """(family, quantum) of a non-composite PKIX row from its name."""
    for prefix, family in (("dhPop", "DH"), ("dh-sig", "DH"), ("ecdhPop", "ECDH"), ("eccsi", "EC"),
                           ("RSASSA-PSS", "RSA"), ("ecdsa-with", "ECDSA")):
        if name.startswith(prefix):
            return family, "vulnerable"
    return None, None


def test_pkix_and_csor_oids_exact():
    csor = _csor_oids()
    pq = {k: v for k, v in csor.items() if re.match(r"id-(alg-ml-kem|ml-dsa|slh-dsa|hash-)", k)}
    assert len(pq) == 33
    for ident, oid in pq.items():
        found = A.resolve(oid)
        assert found is not None and found.matched_by == "oid" and found.oid == oid, ident
        assert found.parameter_set == _csor_param(ident), (ident, found.parameter_set)
        m = re.fullmatch(r"id-(?:alg-)?(ml-dsa|ml-kem)-(\d+)", ident)
        if m:
            assert found.name == f"{m.group(1).upper()}-{m.group(2)}"
        m = re.fullmatch(r"id-slh-dsa-(sha2|shake)-(\d+[sf])", ident)
        if m:
            assert found.name == f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}"
        m = re.fullmatch(r"id-hash-ml-dsa-(\d+)-with-sha512", ident)
        if m:
            assert found.name == f"HashML-DSA-{m.group(1)}-with-SHA512"
        assert (found.construction, found.quantum, found.status) == ("pure", "safe", "standard"), ident
    for ident, oid in csor.items():  # the classical CSOR signature OIDs: family from the identifier
        m = re.fullmatch(r"id-(dsa|ecdsa)-with-sha[\d-]+|id-rsassa-pkcs1-v1-5-with-sha3-\d+", ident)
        if m:
            family = {"dsa": "DSA", "ecdsa": "ECDSA"}.get(m.group(1) or "", "RSA")
            assert (A.resolve(oid).family_label, A.resolve(oid).quantum) == (family, "vulnerable"), ident
    for row in _rows("iana-pkix-alg.csv"):
        dec, desc, ref = row["Decimal"], row["Description"], row["Reference"]
        if not dec.isdigit():
            continue
        oid = f"1.3.6.1.5.5.7.6.{dec}"
        found = A.resolve(oid)
        assert found is not None, (oid, desc)
        assert found.status == _status(ref, desc), (desc, found.status)
        name = re.sub(r"^id-(alg-)?", "", desc)
        m = re.fullmatch(r"ML(DSA|KEM)(\d+)-(.+)", name)
        if m:
            param = f"ML-{m.group(1)}-{m.group(2)}"
            assert found.construction == "composite" and found.quantum == "hybrid", desc
            assert found.parameter_set == param and found.components == (param, _composite_component(m.group(3)))
            rfc = re.search(r"\[(RFC \d+)\]", ref)
            assert found.standard == (rfc.group(1) if rfc else None), desc
        elif name in ("xmss-hashsig", "xmssmt-hashsig"):
            assert found.quantum == "safe" and found.stateful
        else:
            assert (found.family_label, found.quantum) == _pkix_family(name), desc
    assert A.resolve("1.3.6.1.5.5.7.6.34").name == "XMSS" and A.resolve("1.3.6.1.5.5.7.6.35").name == "XMSS^MT"
    assert A.resolve("1.2.840.113549.1.9.16.3.17").name == "HSS"
    assert A.resolve("1.3.6.1.5.5.7.6.1").status == "obsolete"  # des40: [Reserved and Obsolete]


def test_categories_match_fips_transcription():
    fixture = json.loads((REPO / "backend/tests/fixtures/algid_fips_categories.json").read_text())
    for name, category in fixture["categories"].items():
        found = A.resolve(name)
        assert found is not None and found.nist_category == category, (name, found)
    # every CSOR FIPS OID carries the transcribed category of the parameter set its IDENTIFIER names
    for ident, oid in _csor_oids().items():
        param = _csor_param(ident)
        if param:
            assert A.resolve(oid).nist_category == fixture["categories"][param], ident
    assert A.resolve("X25519MLKEM768").nist_category == 3 and A.resolve("SecP384r1MLKEM1024").nist_category == 5
    x_wing = A.resolve("X-Wing")  # draft-connolly-cfrg-xwing-kem: ML-KEM-768 inside, category 3
    assert (x_wing.nist_category, x_wing.construction, x_wing.components) == (3, "hybrid", ("ML-KEM-768", "X25519"))
    assert A.resolve("LMS").nist_category is None  # SP 800-208 defines none
    fn = A.resolve("FN-DSA-512")  # FIPS 206 is not published: no standard is claimed
    assert (fn.standard, fn.status, fn.nist_category) == (None, "draft", 1)
    for no_credit in ("Kyber768", "Dilithium3", "Falcon-1024", "X25519Kyber768Draft00", "SecP256r1Kyber768Draft00"):
        found = A.resolve(no_credit)
        assert (found.nist_category, found.parameter_set, found.standard) == (None, None, None), no_credit


def test_symmetric_and_identifier_rows_have_no_quantum_verdict():
    """A MAC, AEAD, block cipher, hash or bare identifier is never quantum-vulnerable (KMS SYMMETRIC_DEFAULT, HMAC
    keys, des40, noSignature), and every public-key row is either vulnerable or post-quantum."""
    for name, attrs in A._ALGS.items():
        found = A._identity(name, "name")
        if found.primitive in SYMMETRIC:
            assert (found.family_label, found.quantum) == (None, None), name
        elif found.family_label == "PQ":
            assert found.quantum in ("safe", "hybrid"), name
        else:
            assert found.family_label is not None and found.quantum == "vulnerable", name
        assert all(c in A._ALGS for c in found.components), name
    for spec in ("SYMMETRIC_DEFAULT", "HMAC_256"):
        assert A.aws("kms", "KeySpec", spec).quantum is None and A.quantum_vulnerable(A.compare_key(spec)) is None


def test_kmip_gost_names():
    """The GOST names the scan node's KMIP reader emits (kmip_ttlv.ALGORITHM 46-49) and PKCS#11 key types."""
    expect = {
        "GOST R 34.10-2012": ("EC", "signature", "vulnerable"),  # RFC 7091
        "GOSTR3410": ("EC", "signature", "vulnerable"), "GOSTR3410-2012": ("EC", "signature", "vulnerable"),
        "GOST R 34.11-2012": (None, "hash", None),  # RFC 6986 (Streebog)
        "GOST R 34.13-2015": (None, "block-cipher", None),
        "GOST 28147-89": (None, "block-cipher", None), "GOST28147": (None, "block-cipher", None),  # RFC 5830
        "Magma": (None, "block-cipher", None), "Kuznyechik": (None, "block-cipher", None),  # RFC 8891, RFC 7801
    }
    for text, (family, primitive, quantum) in expect.items():
        found = A.resolve(text)
        assert found is not None and (found.family_label, found.primitive, found.quantum) == (
            family, primitive, quantum), text
    kmip = (REPO / "scan_node/zs_scan_node/kmip_ttlv.py").read_text()
    for emitted in re.findall(r'\d+: "(GOST[^"]+)"', kmip):
        assert A.resolve(emitted) is not None, emitted
    # A spelling without a year names no version (PKCS#11 CKK_GOSTR3410 holds 2001 and 2012-256 keys alike): the
    # version-neutral rows. A spelling with a year keeps its version.
    names = {"GOST R 34.10": "GOST R 34.10", "GOSTR3410": "GOST R 34.10", "GOST3410": "GOST R 34.10",
             "GOST R 34.11": "GOST R 34.11", "GOSTR3411": "GOST R 34.11", "GOSTR3410-2012": "GOST R 34.10-2012",
             "GOST R 34.10-2012": "GOST R 34.10-2012", "GOST R 34.11-2012": "GOST R 34.11-2012",
             "Streebog": "GOST R 34.11-2012", "GOST3410-2012-256": "GOST R 34.10-2012-256"}
    for text, name in names.items():
        assert A.resolve(text).name == name, text


def test_aws_spellings_and_enums():
    enums = json.loads((SRC / "botocore-enums.json").read_text())["enums"]
    for key, values in enums.items():
        service, field = key.split(".")
        if field == "SecurityPolicy":
            continue
        names = [A.aws(service, field, value) for value in values]
        assert all(names), key
        # one row per value: two enum values of one field never compare equal (compare_key, drift S-2)
        assert len({n.name for n in names}) == len(values), key
    pca = A.aws("acm-pca", "KeyAlgorithm", "ML_DSA_65")
    assert (pca.name, pca.quantum, pca.key_size, pca.matched_by) == ("ML-DSA-65", "safe", None, "enum")
    assert A.aws("acm-pca", "KeyAlgorithm", "SM2").name == "SM2"
    assert A.aws("kms", "KeySpec", "RSA-2048") == A.aws("kms", "KeySpec", "RSA_2048")
    assert A.aws("kms", "KeySpec", "rsa_2048").key_size == 2048
    assert A.aws("kms", "KeySpec", "ECC_NIST_EDWARDS25519").key_size == 256  # not 25519
    assert A.aws("kms", "KeySpec", "TOTALLY_BOGUS") is None and A.aws("nope", "KeySpec", "RSA_2048") is None
    assert A.compare_key("RSASSA_PSS_SHA_256") == "RSASSA-PSS-SHA256" != A.compare_key("RSASSA_PSS_SHA_512")
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


def _base128(value: int) -> bytes:
    enc = [value & 0x7F]
    value >>= 7
    while value:
        enc.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(enc))


def _oid(dotted: str) -> bytes:
    """X.690 8.19: the first two arcs form one base-128 subidentifier (2.999 -> 1079 -> 0x88 0x37)."""
    parts = [int(x) for x in dotted.split(".")]
    body = _base128(40 * parts[0] + parts[1]) + b"".join(_base128(p) for p in parts[2:])
    return _tlv(0x06, body)


def _spki(alg: str, params: bytes = b"", key_len: int = 1952) -> bytes:
    return _tlv(0x30, _tlv(0x30, _oid(alg) + params) + _tlv(0x03, b"\x00" + os.urandom(key_len)))


def test_der_readers():
    mldsa65 = _spki("2.16.840.1.101.3.4.3.18")
    assert A.spki_alg(mldsa65) == ("2.16.840.1.101.3.4.3.18", None)
    assert A.spki_alg(bytearray(mldsa65)) == ("2.16.840.1.101.3.4.3.18", None)
    assert A.spki_alg(_spki("2.16.840.1.101.3.4.4.2", key_len=1184)) == ("2.16.840.1.101.3.4.4.2", None)
    assert A.spki_alg(_spki("2.16.840.1.101.3.4.3.20", key_len=32))[0] == "2.16.840.1.101.3.4.3.20"
    sm2 = _spki("1.2.840.10045.2.1", _oid("1.2.156.10197.1.301"), 65)
    assert A.spki_alg(sm2) == ("1.2.840.10045.2.1", "1.2.156.10197.1.301")
    explicit = _spki("1.2.840.10045.2.1", _tlv(0x30, _tlv(0x02, b"\x01") + os.urandom(8)), 65)
    assert A.spki_alg(explicit) == ("1.2.840.10045.2.1", "explicit")
    # a first subidentifier of two bytes (arc 2, second arc >= 48), and a non-minimal subidentifier
    assert A.spki_alg(_spki("2.999.1", key_len=8)) == ("2.999.1", None)
    padded = _tlv(0x30, _tlv(0x30, _tlv(0x06, bytes([0x2A, 0x80, 0x86, 0x48]))) + _tlv(0x03, b"\x00\x01"))
    assert A.spki_alg(padded) is None
    # structure checks: the key must be a BIT STRING, a long-form length at most 4 octets
    octet_key = _tlv(0x30, _tlv(0x30, _oid("2.16.840.1.101.3.4.3.18")) + _tlv(0x04, os.urandom(16)))
    assert A.spki_alg(octet_key) is None
    body = mldsa65[2 + (mldsa65[1] & 0x7F if mldsa65[1] & 0x80 else 0) :]
    assert _tlv(0x30, body) == mldsa65
    five_octet_length = b"\x30\x85" + len(body).to_bytes(5, "big") + body  # valid DER except a 5-octet length
    assert A.spki_alg(five_octet_length) is None
    for broken in (mldsa65[:40], b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", os.urandom(64)):
        assert A.spki_alg(broken) is None or isinstance(A.spki_alg(broken), tuple)
    assert A.spki_alg(mldsa65[:40]) is None and A.spki_alg(b"") is None
    pkcs8 = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x30, _oid("2.16.840.1.101.3.4.3.18"))
                 + _tlv(0x04, os.urandom(32)))
    assert A.pkcs8_alg(pkcs8) == "2.16.840.1.101.3.4.3.18"
    assert A.pkcs8_alg(pkcs8[:20]) is None and A.pkcs8_alg(mldsa65) is None
    bit_string_key = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x30, _oid("2.16.840.1.101.3.4.3.18"))
                          + _tlv(0x03, os.urandom(32)))
    assert A.pkcs8_alg(bit_string_key) is None  # the private key must be an OCTET STRING
    two_children = _tlv(0x30, _tlv(0x02, b"\x00") + _tlv(0x30, _oid("2.16.840.1.101.3.4.3.18")))
    assert A.pkcs8_alg(two_children) is None  # no privateKey at all
    name = _tlv(0x30, _tlv(0x31, _tlv(0x30, _oid("2.5.4.3") + _tlv(0x0C, b"lab"))))
    validity = _tlv(0x30, _tlv(0x17, b"260101000000Z") * 2)
    tbs = _tlv(0x30, _tlv(0xA0, _tlv(0x02, b"\x02")) + _tlv(0x02, b"\x01") + _tlv(0x30, _oid("2.16.840.1.101.3.4.3.18"))
               + name + validity + name + mldsa65)
    assert A.tbs_spki_alg(tbs) == ("2.16.840.1.101.3.4.3.18", None)
    assert A.tbs_spki_alg(tbs[:60]) is None
    for not_bytes in ("30 03", None, 5, [0x30], memoryview(mldsa65)):
        assert A.spki_alg(not_bytes) is None and A.pkcs8_alg(not_bytes) is None
        assert A.tbs_spki_alg(not_bytes) is None


# ----------------------------------------------------------------------------- T-B2e resolution order
UNICODE_SEPARATED = (
    "ML‑DSA‑65", "ML‐DSA‐65", "ML–DSA–65", "ML−DSA−65",
    "ML DSA 65", "ML DSA 65", "ML​DSA​65", "FN–DSA–512",
    "SLH‐DSA‐SHA2‐128s", "ML‐KEM‐768", "ＭＬ-DSA-65",  # fullwidth "ML"
)


def test_resolution_order():
    by_oid = A.resolve("2.16.840.1.101.3.4.3.18")
    assert by_oid.matched_by == "oid" and by_oid.name == "ML-DSA-65"
    for text in ("ML DSA 65", "ml_dsa_65", "FN-DSA-512", "FNDSA1024", "rsa3072_dilithium2", "HashML-DSA-44-with-SHA512",
                 "SLH-DSA-SHAKE-256f", "mldsa87") + UNICODE_SEPARATED:
        found = A.resolve(text)
        assert found is not None and found.family_label == "PQ", text
        assert A.quantum_vulnerable(text) is False, text
    assert A.resolve("ML‑DSA‑65").name == "ML-DSA-65" and A.resolve("ML‐KEM‐768").name == "ML-KEM-768"
    # the fallback's DSA guard is token-bounded on its own (DA s3.5), whatever separates the letters
    for text in ("FN-DSA-512", "ML DSA 65", "HASHML_DSA", "SLH–DSA", "EC-DSA-P256", "ED_DSA"):
        assert A._fallback(text) is None or A._fallback(text).family_label != "DSA", text
    assert A._fallback("DSA-2048").family_label == "DSA" and A._fallback("SM2-KEY-BLOB").family_label == "SM2"
    assert A.resolve("rsa3072_dilithium2").construction == "composite"
    assert A.resolve("rsa3072_dilithium2").status == "pre-standard"
    marker = A.resolve("p256_mlkem768")  # an oqs-provider style hybrid: the marker scan, quantum "hybrid"
    assert (marker.matched_by, marker.construction, marker.quantum) == ("marker", "hybrid", "hybrid")
    assert A.resolve("frodokem976aes").quantum == "safe"
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
    # unknown and OQS arcs give None (with a hint); a vendor composite prototype arc is a composite
    assert A.resolve("1.2.3.4.5") is None and A.hint("1.3.9999.6.4.13") == "oqs-arc"
    for oqs in ("1.3.9999.6.4.13", "1.3.6.1.4.1.2.267.12.6.5", "1.3.6.1.4.1.22554.5.6.1"):
        assert A.resolve(oqs) is None and A.hint(oqs) == "oqs-arc", oqs
    assert A.hint("2.16.840.1.101.3.4.3.18") is None and A.hint("RSA") is None  # known OIDs need no hint
    prototype = A.resolve("2.16.840.1.114027.80.8.1.4")
    assert prototype.construction == "composite" and prototype.status == "pre-standard" and prototype.name is None
    assert A.compare_key("2.16.840.1.101.3.4.3.18") == "ML-DSA-65" == A.compare_key("ML_DSA_65")
    assert A.compare_key("RSA") == "RSA" and A.compare_key("ECDSA") == "ECDSA" and A.compare_key(None) is None
    assert A.code_lane_x509_name("1.2.840.10045.2.1") == "ecPublicKey"
    assert A.code_lane_x509_name("2.16.840.1.101.3.4.3.18") == "ML-DSA-65"
    assert A.openssl_major_minor("OpenSSL 3.5.7 9 Jun 2026") == (3, 5)
    assert A.openssl_major_minor("OpenSSL 3.0.13 30 Jan 2024") == (3, 0)
    assert A.openssl_major_minor("LibreSSL 3.8.2") is None and A.openssl_major_minor("") is None


def test_classical_family_labels_kept():
    """The family labels classify.family gave these names before algid: the CBOM rules key on them (_key_rules)."""
    expect = {"ECDSA": "ECDSA", "ecdsa": "ECDSA", "EC": "EC", "ECC": "EC", "id-ecPublicKey": "EC", "ECDH": "ECDH",
              "EdDSA": "EDDSA", "DSA": "DSA", "RSA": "RSA", "DH": "DH", "SM2": "SM2", "Ed25519": "ED25519",
              "X25519": "X25519", "ecdsa-with-SHA256": "ECDSA", "ecdhPop-static-sha256-hmac-sha256": "ECDH",
              "1.2.840.10045.2.1": "EC", "ssh-rsa": "RSA", "ecdsa-sha2-nistp256": "ECDSA"}
    for text, family in expect.items():
        assert A.family_label(text) == family, text


def test_namespaces_are_validated_and_codepoints_agree():
    """resolve(value, namespace) is the namespace function for every codepoint, and a namespace that does not exist
    is an error whatever the value (it used to return None, an OID's row or raise, depending on the value)."""
    for namespace, function in (("tls_group", A.tls_group), ("tls_sigscheme", A.tls_sigscheme),
                                ("ike_ke", A.ike_ke)):
        for codepoint in range(0x10000):
            assert A.resolve(codepoint, namespace) == function(codepoint), (namespace, codepoint)
    for bad in ("tls_groups", "bogus", ""):
        for value in (36, "1.2.840.113549.1.1.1", "<NULL>", "RSA", None):
            with pytest.raises(ValueError):
                A.resolve(value, bad)
    assert A.resolve("mldsa65x", "name") is None  # strict: no marker fallback
    assert A.resolve("ML-DSA-65").matched_by == "name" and A.resolve("mldsa65").matched_by == "alias"
    assert A.aws("kms", "KeySpec", " RSA_2048 ").name == "RSA-2048"
    assert A.compare_key(" RSASSA_PSS_SHA_256 ") == "RSASSA-PSS-SHA256"
    assert A.resolve("xwing768").quantum == "hybrid" and A.resolve("xwing768").matched_by == "marker"
    assert A.resolve("HSS-SHA256-N32").stateful and A.resolve("HSS-SHA256-N32").matched_by == "marker"


def test_short_markers_are_tokens():
    """LMS, HSS, HQC and BIKE count only where they start a token and nothing but digits or a NIST level (L1, as in
    oqs-provider's bikel1) follows them in it: classical text and English words never read as PQ. XMSS, like the
    longer markers, counts anywhere once separators are removed ("SHA256withXMSS")."""
    for text in ("SHA1 with SSH", "HELMS", "realms", "WITHSSH", "x25519 WITH HMAC", "bikes", "Bikeshed", "LMSYS",
                 "HSSI", "hqcfoo", "bikes2", "HSSB1"):
        found = A.resolve(text)
        assert found is None or found.family_label != "PQ", text
    for text in ("LMS_SHA256_M32_H10", "HSS/LMS", "hqc-128", "HQC128", "BIKE-L1", "bikel1", "p256_bikel1", "XMSS^MT",
                 "xmssmt_sha2_20/2_256", "ＬＭＳ_SHA256"):  # the last is fullwidth LMS (NFKC first)
        found = A.resolve(text)
        assert found is not None and found.family_label == "PQ", text
    for text in ("SHA256withXMSS", "SHA512WITHXMSSMT", "SHAKE128withXMSS", "LMS_SHA256_M32_H10", "HSS/LMS"):
        found = A.resolve(text)
        assert found is not None and found.family_label == "PQ" and found.stateful, text
    assert not A.resolve("hqc-128").stateful and not A.resolve("bikel1").stateful


def test_names_do_not_depend_on_case():
    """resolve() reads names case-folded with separators removed: one identity per algorithm, whatever the spelling.
    A registry spelling of a curated row ("secp256r1", "x25519") is that row, with its OID."""
    curated = json.loads((SRC / "curated.json").read_text())
    spellings = {s for target, ss in curated["aliases"].items() if not target.startswith("_") for s in ss}
    texts = spellings | set(A._ALGS) | set(A._ALIASES) | set(A._SSH_KEX) | set(A._OPENSSL_TEXT)
    for text in sorted(texts):
        base = A.resolve(text)
        assert base is not None, text
        assert _same(base, A.resolve(text.upper())) and _same(base, A.resolve(text.lower())), text
    for text, (name, oid) in {"secp256r1": ("P-256", "1.2.840.10045.3.1.7"), "SECP256R1": ("P-256", "1.2.840.10045.3.1.7"),
                              "nistp256": ("P-256", "1.2.840.10045.3.1.7"), "x25519": ("X25519", "1.3.101.110"),
                              "mlkem768": ("ML-KEM-768", "2.16.840.1.101.3.4.4.2"),
                              "gost3410-2012-256": ("GOST R 34.10-2012-256", "1.2.643.7.1.1.1.1")}.items():
        found = A.resolve(text)
        assert (found.name, found.oid) == (name, oid), text
    # every alias key is in normal form, and every curated spelling reaches its target
    assert all(A._norm(key) == key for key in A._ALIASES)
    for target, ss in curated["aliases"].items():
        if not target.startswith("_"):
            assert all(A.resolve(s).name == target for s in ss), target


@pytest.mark.parametrize("call", [
    lambda: A.resolve(b"ML-DSA-65"), lambda: A.resolve(bytearray(b"1.2.840.113549.1.1.1")),
    lambda: A.resolve(["RSA"]), lambda: A.resolve(4588), lambda: A.resolve(True), lambda: A.resolve(3.5),
    lambda: A.resolve(4588, "ssh_kex"), lambda: A.resolve(None, "ssh_kex"), lambda: A.ssh_kex(None),
    lambda: A.ssh_kex(5), lambda: A.ssh_kex(b"curve25519-sha256"), lambda: A.openssl_major_minor(b"OpenSSL 3.5.7"),
    lambda: A.openssl_major_minor(None), lambda: A.tls_sigscheme([1]), lambda: A.tls_group("23"),
    lambda: A.tls_group(True), lambda: A.ike_ke(None), lambda: A.aws("kms", "KeySpec", 2048),
    lambda: A.aws("kms", "KeySpec", b"RSA_2048"), lambda: A.hint(5), lambda: A.hint(b"1.3.9999.1"),
    lambda: A.family_label(object()), lambda: A.quantum_vulnerable(b"RSA"), lambda: A.openssl_text(b"RSA"),
    lambda: A.aws_tls_policy("elbv2", None),
])
def test_non_str_input_gives_none(call):
    assert call() is None


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
    from backend.utilities.cbom_sources import algid_tables as T

    for table in (A._ALGS, A._OIDS, A._TLS_GROUPS, A._ALIASES, A._AWS, A._AWS_TLS_POLICY["elbv2"], A._AWS["kms.KeySpec"],
                  A._REVERSE_OID, T.ALGS, T.OIDS):
        with pytest.raises(TypeError):
            table["x"] = "y"  # type: ignore[index]
    for module in (A, T):
        mutable = [k for k, v in vars(module).items() if isinstance(v, (dict, list, set)) and not k.startswith("__")]
        assert not mutable, (module.__name__, mutable)
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
    # DA s5's list governs over s0's wording: the offer stops at 42 (no bign 43/44)
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


def test_generator_refuses_hand_edits_and_wraps_safely(tmp_path):
    """build_algid.py writes only from the master copy, and its string wrapper never loops."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_algid", REPO / "scripts/algid/build_algid.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)  # type: ignore[union-attr]
    root = tmp_path / "repo"
    for rel in ["scripts/algid"] + [str(f.relative_to(REPO)) for f in FOLDERS]:
        (root / rel).mkdir(parents=True, exist_ok=True)
    for f in COPIES:
        (root / f.relative_to(REPO)).write_bytes(f.read_bytes())
    gen.ROOT, gen.SRC = root, SRC
    gen.COPIES = tuple(root / c.relative_to(REPO) for c in COPIES[:3])
    gen.MASTER, gen.TABLES = gen.COPIES[0], tuple(p.with_name("algid_tables.py") for p in gen.COPIES)
    assert gen.main(["--check"]) == 0
    edited = gen.COPIES[1]
    edited.write_text(edited.read_text().replace("NAMESPACES = (", "NAMESPACES = (  # edited\n", 1))
    assert gen.main([]) == 1 and "# edited" in edited.read_text()  # refused: the edit is kept, nothing written
    assert gen.main(["--check"]) == 1
    assert gen.main(["--sync"]) == 0 and edited.read_text() == gen.MASTER.read_text()
    long_tuple = "/".join(["?*X25519MLKEM768"] * 9) + ":?x"  # no ':' within the first 72 characters
    curated = json.loads((SRC / "curated.json").read_text())
    curated["prober"]["S_CLIENT_GROUPS_35"] = long_tuple
    data, digest = gen.load_sources()
    tables = gen.build(data)
    tables.curated = curated
    text = gen.emit(tables, digest)
    assert all(len(line) <= 88 for line in text.splitlines())
    namespace: dict = {}
    exec(compile(text, "algid_tables", "exec"), namespace)  # noqa: S102  (the generated module, from our sources)
    assert namespace["S_CLIENT_GROUPS_35"] == long_tuple


# ----------------------------------------------------------------------------- PR-1b: gcp, kmip, pkcs11, jose
def _extract(name: str) -> dict:
    return json.loads((SRC / name).read_text())


def _pq_name(text: str) -> str | None:
    """The canonical PQ name a vendor spelling names, parsed here: ML_KEM_768 / ML-KEM-768 -> ML-KEM-768,
    ML_DSA_65 -> ML-DSA-65, SLH_DSA_SHA2_128S -> SLH-DSA-SHA2-128s, HASH(-)SLH... -> HashSLH-DSA-...-with-SHA256."""
    up = text.upper().replace("_", "-")
    m = re.search(r"HASH-?(SLH-DSA-(SHA2|SHAKE)-(\d{3})([SF]))-(?:WITH-)?(SHA\d+|SHAKE\d+)", up)
    if m:
        return f"HashSLH-DSA-{m.group(2)}-{m.group(3)}{m.group(4).lower()}-with-{m.group(5)}"
    m = re.search(r"HASH-?ML-DSA-(\d+)-(?:WITH-)?(SHA\d+)", up)
    if m:
        return f"HashML-DSA-{m.group(1)}-with-{m.group(2)}"
    m = re.search(r"SLH-DSA-(SHA2|SHAKE)-(\d{3})([SF])", up)
    if m:
        return f"SLH-DSA-{m.group(1)}-{m.group(2)}{m.group(3).lower()}"
    m = re.search(r"ML-(KEM|DSA)-(\d+)", up)
    return f"ML-{m.group(1)}-{m.group(2)}" if m else None


def _gcp_expected(value: str) -> str | None:
    """The row a Cloud KMS value names, read from its spelling (each description says the same)."""
    if value in ("CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED", "EXTERNAL_SYMMETRIC_ENCRYPTION"):
        return None  # a placeholder; an external key manager's choice
    if value == "GOOGLE_SYMMETRIC_ENCRYPTION":
        return "AES-256-GCM"  # Cloud KMS docs, key purposes and algorithms
    if value == "KEM_XWING":
        return "X-Wing"
    for pattern, row in ((r"AES_(\d+)_(GCM|CBC|CTR|KWP)", "AES-{0}-{1}"), (r"HMAC_SHA(\d+)", "HMAC-SHA{0}"),
                         (r"RSA_(?:SIGN_PSS|SIGN_PKCS1|SIGN_RAW_PKCS1|DECRYPT_OAEP)_(\d+)(?:_SHA\d+)?", "RSA-{0}"),
                         (r"KEM_ECDH_P(256|384)", "secp{0}r1")):  # ECDH keys: the key-agree rows
        m = re.fullmatch(pattern, value)
        if m:
            return row.format(*m.groups())
    m = re.fullmatch(r"EC_SIGN_(P256|P384|SECP256K1|ED25519)(?:_SHA\d+)?", value)
    if m:
        return {"P256": "P-256", "P384": "P-384", "SECP256K1": "secp256k1", "ED25519": "Ed25519"}[m.group(1)]
    name = _pq_name(value)  # ML_KEM_*, PQ_SIGN_* (an external mu signs with the same parameter set)
    assert name, f"no expectation for the Cloud KMS value {value}: add one"
    return name


def test_gcp_algorithms():
    """Every Cloud KMS CryptoKeyVersionAlgorithm value names exactly the row its spelling names."""
    algorithms = _extract("gcp-kms-algorithms.json")["algorithms"]
    assert len(algorithms) >= 50
    for value, _desc in algorithms:
        found = A.gcp(value)
        assert (found.name if found else None) == _gcp_expected(value), (value, found)
        assert _same(found, A.gcp(value.lower())) and _same(found, A.gcp(f" {value}\n")), value
        if found is None:
            continue
        assert found.matched_by == "enum", value
        if value.startswith(("PQ_SIGN_", "ML_KEM_")):
            assert found.quantum == "safe", value
        elif value.startswith("RSA_"):
            assert (found.family_label, found.key_size, found.quantum) == ("RSA", _bits(value), "vulnerable"), value
        elif value.startswith("KEM_ECDH_"):
            assert (found.family_label, found.primitive, found.key_size) == ("EC", "key-agree", _bits(value)), value
        elif value.startswith(("AES_", "GOOGLE_", "HMAC_")):
            assert found.primitive in SYMMETRIC and found.quantum is None, value
            assert found.key_size == (_bits(value) if value.startswith("AES_") else found.key_size), value
    assert A.gcp("GOOGLE_SYMMETRIC_ENCRYPTION").key_size == 256
    assert A.gcp(None) is None and A.gcp(5) is None and A.gcp("NOPE") is None


SYMMETRIC_KMIP = re.compile(r"^(DES|3DES|Blowfish|Camellia|CAST5|IDEA|MARS|RC\d|SKIPJACK|Twofish|One Time Pad|ChaCha20"
                            r"|Poly1305|SHA3-|HMAC-SHA3-|HMAC-MD5|SHAKE-|ARIA|SEED|SM3|SM4)")


KMIP_PQ_EXACT = {  # name -> (row, status, standard, stateful, components, nist_category)
    "XMSS": ("XMSS", "standard", "SP 800-208", True, (), None),
    "SPHINCS-256": ("SPHINCS-256", "pre-standard", None, False, (), None),  # no FIPS 205 credit
    "McEliece": ("Classic McEliece", "candidate", None, False, (), None),
    "McEliece-6960119": ("Classic McEliece", "candidate", None, False, (), None),
    "McEliece-8192128": ("Classic McEliece", "candidate", None, False, (), None),
    "X25519MLKEM768": ("X25519MLKEM768", "standard", "FIPS 203", False, ("X25519", "ML-KEM-768"), 3),
    "SECP256R1MLKEM768": ("SecP256r1MLKEM768", "standard", "FIPS 203", False, ("P-256", "ML-KEM-768"), 3),
}


def test_kmip_enumeration():
    """Every KMIP 3.0 Cryptographic Algorithm value; the scan node's own table (kmip_ttlv.ALGORITHM) agrees."""
    rows = _extract("kmip-3.0-algorithms.json")["algorithms"]
    assert len(rows) >= 93 and dict((n, v) for n, v in rows)["ML-DSA-65"] == 0x3D
    for name, value in rows:
        found = A.kmip(value)
        assert found is None or found.matched_by == "enum", name
        if SYMMETRIC_KMIP.match(name):
            assert found is None, name
        elif _pq_name(name):
            assert found.name == _pq_name(name) and found.quantum == "safe", (name, found)
        elif name in KMIP_PQ_EXACT:
            row, status, standard, stateful, components, category = KMIP_PQ_EXACT[name]
            assert (found.name, found.status, found.standard, found.stateful, found.components, found.nist_category) \
                == (row, status, standard, stateful, components, category), (name, found)
            if status != "standard":
                assert found.parameter_set is None, name
        else:  # classical keys and GOST/AES/HMAC: the identity the name resolves to
            assert _same(found._replace(oid=None), A.resolve(name)._replace(oid=None)), (name, found)
    assert {n for n, _v in rows} >= set(KMIP_PQ_EXACT)
    assert A.kmip(0x2E).quantum == "vulnerable" and A.kmip(0x5D).name == "SecP256r1MLKEM768"
    node = (REPO / "scan_node/zs_scan_node/kmip_ttlv.py").read_text()
    table = dict(re.findall(r'(\d+): "([^"]+)"', node[node.index("ALGORITHM = {"):node.index("STATE = {")]))
    spec = {v: n for n, v in rows}
    assert {int(k): v for k, v in table.items()} == {k: spec[k] for k in map(int, table)}
    assert A.kmip(None) is None and A.kmip("61") is None and A.kmip(True) is None


PKCS11_EXACT = {  # every CKK_* with a row; the HMAC types are read from their names below
    "CKK_RSA": "RSA", "CKK_DSA": "DSA", "CKK_DH": "DH", "CKK_X9_42_DH": "DH", "CKK_EC": "EC", "CKK_ECDSA": "EC",
    "CKK_EC_EDWARDS": "EdDSA", "CKK_EC_MONTGOMERY": "XDH", "CKK_AES": "AES",
    "CKK_GOSTR3410": "GOST R 34.10", "CKK_GOSTR3411": "GOST R 34.11", "CKK_GOST28147": "GOST 28147-89",
    "CKK_HSS": "HSS", "CKK_XMSS": "XMSS", "CKK_XMSSMT": "XMSS^MT", "CKK_ML_KEM": "ML-KEM", "CKK_ML_DSA": "ML-DSA",
    "CKK_SLH_DSA": "SLH-DSA",
}


def test_pkcs11_key_types_and_parameter_sets():
    doc = _extract("pkcs11-3.2-constants.json")
    ckk = {name: value for name, value in doc["key_types"]}
    assert {ckk[n] for n in ("CKK_HSS", "CKK_XMSS", "CKK_XMSSMT", "CKK_ML_KEM", "CKK_ML_DSA", "CKK_SLH_DSA")} \
        == set(range(0x46, 0x4C))  # PKCS#11 3.2 adds 0x46-0x4B
    for name, value in ckk.items():
        m = re.fullmatch(r"CKK_SHA_?(1|224|256|384|512)_HMAC", name)
        want = f"HMAC-SHA{m.group(1)}" if m else PKCS11_EXACT.get(name)  # anything else has no row
        found = A.pkcs11_key_type(value)
        assert (found.name if found else None) == want, (name, found)
        assert found is None or found.matched_by == "enum", name
    families = {"CKK_DSA": ("DSA", "vulnerable"), "CKK_DH": ("DH", "vulnerable"), "CKK_EC": ("EC", "vulnerable"),
                "CKK_EC_EDWARDS": ("EDDSA", "vulnerable"), "CKK_EC_MONTGOMERY": ("ECDH", "vulnerable"),
                "CKK_GOSTR3410": ("EC", "vulnerable"), "CKK_GOSTR3411": (None, None), "CKK_AES": (None, None),
                "CKK_ML_DSA": ("PQ", "safe"), "CKK_XMSS": ("PQ", "safe")}
    for name, family in families.items():
        found = A.pkcs11_key_type(ckk[name])
        assert (found.family_label, found.quantum) == family, name
    assert A.pkcs11_key_type(ckk["CKK_XMSS"]).stateful and A.pkcs11_key_type(ckk["CKK_HSS"]).stateful
    for name, value in doc["parameter_sets"]:
        group = "CKK_" + re.match(r"CKP_(ML_DSA|SLH_DSA|ML_KEM)_", name).group(1)
        found = A.pkcs11_key_type(ckk[group], value)
        assert found.name == _pq_name(name[4:]) == found.parameter_set, (name, found)
    assert A.pkcs11_key_type(ckk["CKK_ML_DSA"], 0x99).name == "ML-DSA"  # an undefined set: the family
    assert A.pkcs11_key_type(ckk["CKK_ML_DSA"], True).name == "ML-DSA"  # a bool is not CKP_ML_DSA_44 (1)
    assert A.pkcs11_key_type(ckk["CKK_ML_DSA"], "2").name == "ML-DSA"
    assert A.pkcs11_key_type(ckk["CKK_RSA"], 2).name == "RSA"  # parameter sets refine PQ types only
    assert A.pkcs11_key_type(0x80000000) is None and A.pkcs11_key_type("0x4a") is None


def _jose_alg_expected(name: str, desc: str) -> str | None:
    """The row a registered JWS/JWE alg names, read from its registry description."""
    if desc.startswith(("RSASSA", "RSAES", "RSA-OAEP")):
        return "RSA"
    m = re.match(r"ECDSA using (P-\d+|secp256k1)", desc)
    if m:
        return m.group(1)
    if name in ("EdDSA", "Ed25519", "Ed448") or "FIPS 204" in desc:
        return name
    return None  # HMAC, key wrap, dir, PBES2, enc, ECDH-ES (the crv names the key), HPKE suites, none


JOSE_KTY_FOR = {"RSA": "RSA", "EC": "EC", "ED25519": "OKP", "ED448": "OKP", "EDDSA": "OKP", "PQ": "AKP"}


def test_jose_keys():
    key_types = [r['"kty" Parameter Value'] for r in _rows("iana-jose-key-types.csv")]
    assert set(key_types) == {"EC", "RSA", "oct", "OKP", "AKP"}
    assert A.jose("EC").name == "EC" and A.jose("RSA").name == "RSA"
    for kty in ("oct", "OKP", "AKP"):
        assert A.jose(kty) is None, kty  # symmetric, or named only by its crv / alg
    for row in _rows("iana-jose-curves.csv"):
        kty = "EC" if row["Curve Name"].startswith(("P-", "secp")) else "OKP"
        assert A.jose(kty, crv=row["Curve Name"]).name == row["Curve Name"], row["Curve Name"]
        assert A.jose("RSA", crv=row["Curve Name"]).name == "RSA" and A.jose("oct", crv=row["Curve Name"]) is None
    for row in _rows("iana-jose-algs.csv"):
        name = row["Algorithm Name"]
        want = _jose_alg_expected(name, row["Algorithm Description"])
        assert A._JOSE_ALG.get(name) == want, name  # every registered alg, mapped or not
        if want is None:
            continue
        own = JOSE_KTY_FOR[A.resolve(want).family_label]
        found = A.jose(own, name)
        assert (found.name, found.matched_by) == (want, "enum"), name
        for kty in key_types:  # an alg of another family never renames the key: the key type answers
            if kty != own:
                other = A.jose(kty, name)
                assert (other.name if other else None) == A._JOSE_KTY.get(kty), (kty, name)
    for name in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "RS1", "RSA1_5", "RSA-OAEP-256"):
        assert A.jose("RSA", name).family_label == "RSA", name
    for name in ("EdDSA", "Ed25519", "Ed448"):
        assert A.jose("OKP", name).name == name, name
    # The review's cases: kty is REQUIRED and names the key; alg/crv are refinements of that family only.
    assert A.jose("RSA", "ML-DSA-65").name == "RSA" and A.jose("EC", "ML-DSA-65").name == "EC"
    assert A.jose("oct", "ES256") is None and A.jose("oct", "ML-DSA-65") is None
    assert A.jose("RSA", None, "Ed25519").name == "RSA" and A.jose("AKP", "RS256") is None
    # crv names the key before alg does
    assert A.jose("EC", "ES512", "P-256").name == "P-256" and A.jose("OKP", "Ed448", "Ed25519").name == "Ed25519"
    assert A.jose("AKP", "ML-DSA-65").parameter_set == "ML-DSA-65" and A.jose("oct", "HS256") is None
    assert A.jose("NOPE", "ML-DSA-65") is None and A.jose(None) is None and A.jose(b"EC") is None


def _build_algid():
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_algid_guards", REPO / "scripts/algid/build_algid.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)  # type: ignore[union-attr]
    return gen


def _json_edit(name: str, edit):
    def apply(data: dict) -> None:
        doc = json.loads(data[name])
        edit(doc)
        data[name] = json.dumps(doc).encode()
    return apply


def _csv_append(name: str, column: str, value: str):
    def apply(data: dict) -> None:
        import csv
        import io

        rows = list(csv.DictReader(io.StringIO(data[name].decode("utf-8"))))
        rows.append({**rows[-1], column: value})
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        data[name] = out.getvalue().encode("utf-8")
    return apply


def _curated(edit):
    return _json_edit("curated.json", edit)


@pytest.mark.parametrize("change, refusal", [
    (_json_edit("gcp-kms-algorithms.json", lambda d: d["algorithms"].append(["PQ_SIGN_ML_DSA_99", "new"])),
     "gcp: curated names differ"),
    (_json_edit("kmip-3.0-algorithms.json", lambda d: d["algorithms"].append(["ML-DSA-99", 0x5E])),
     "kmip: curated names differ"),
    (_json_edit("pkcs11-3.2-constants.json", lambda d: d["key_types"].append(["CKK_NEW_PQ", 0x4C])),
     "pkcs11.key_types: curated names differ"),
    (_json_edit("pkcs11-3.2-constants.json", lambda d: d["parameter_sets"].append(["CKP_ML_DSA_99", 0x99])),
     "PKCS#11 parameter sets differ"),
    (_curated(lambda c: c["pkcs11"]["key_types"].update(CKK_ECDSA="P-256")), "PKCS#11 value 0x3 maps to"),
    (_curated(lambda c: c["pkcs11"]["parameter_sets"]["CKK_ML_DSA"].update(CKP_ML_KEM_512="ML-KEM-512")),
     "listed under CKK_ML_DSA"),
    (_csv_append("iana-jose-curves.csv", "Curve Name", "brainpoolP256r1"), "jose.crv: curated names differ"),
    (_csv_append("iana-jose-algs.csv", "Algorithm Name", "SLH-DSA-SHA2-128s"), "jose.alg: curated names differ"),
    (_curated(lambda c: c["jose"]["alg"].update({"ML-DSA-99": "ML-DSA-87"})), "jose.alg: curated names differ"),
], ids=["gcp value", "kmip row", "pkcs11 CKK", "pkcs11 CKP", "CKK alias disagrees", "CKP group", "jose crv",
        "jose alg", "jose alg unregistered"])
def test_generator_refuses_an_unlisted_source_value(change, refusal):
    """The body's promise: a new enum value in any PR-1b source fails the build until curated.json lists it."""
    gen = _build_algid()
    data, _digest = gen.load_sources()
    gen.build(dict(data))  # the committed sources build
    changed = dict(data)
    change(changed)
    with pytest.raises(gen.SourceError, match=re.escape(refusal)):
        gen.build(changed)
