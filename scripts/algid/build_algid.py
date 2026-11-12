"""Generate algid_tables.py (the tables of algid, the one algorithm-identity module) from the captured sources.

    python3 scripts/algid/build_algid.py           # write algid_tables.py next to each of the three algid.py
    python3 scripts/algid/build_algid.py --check   # exit 1 if any copy differs from what the sources give
    python3 scripts/algid/build_algid.py --sync    # also copy the master algid.py over the two other copies

algid.py and algid_tables.py are vendored byte-identical in three places (the scan node, the backend and aibom
cannot import each other). algid.py is hand-written: edit the master, backend/utilities/cbom_sources/algid.py, only;
this script refuses to write while another copy differs from it, and --sync copies the master over the others.
algid_tables.py is generated whole, never edited. Every input file is listed in sources/SOURCES.json with its
sha256; a missing entry or a changed file is an error. Third-party HTML pages are not committed: sources/ holds
normalised extracts of them (extract_html.py), each with the raw page's sha256. Stdlib only.
"""
from __future__ import annotations

import csv
import difflib
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = Path(__file__).resolve().parent / "sources"
COPIES = (ROOT / "backend/utilities/cbom_sources/algid.py", ROOT / "scan_node/zs_scan_node/algid.py",
          ROOT / "aibom/src/aibom/cbom/algid.py")
MASTER = COPIES[0]
TABLES = tuple(p.with_name("algid_tables.py") for p in COPIES)
WIDTH = 88


class SourceError(Exception):
    pass


# --------------------------------------------------------------------------- sources
def load_sources() -> tuple[dict[str, bytes], str]:
    manifest_bytes = (SRC / "SOURCES.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    entries = {e["file"]: e for e in manifest["files"]}
    present = {p.name for p in SRC.iterdir() if p.is_file() and p.name != "SOURCES.json"}
    if present - set(entries):
        raise SourceError(f"files without a SOURCES.json entry: {sorted(present - set(entries))}")
    if set(entries) - present:
        raise SourceError(f"SOURCES.json lists missing files: {sorted(set(entries) - present)}")
    data = {}
    for name, entry in entries.items():
        raw = (SRC / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise SourceError(f"{name}: sha256 differs from SOURCES.json")
        data[name] = raw
    return data, hashlib.sha256(manifest_bytes).hexdigest()


def _csv(raw: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(raw.decode("utf-8").splitlines()))


_RFC = re.compile(r"\[RFC (\d+)\]")


def _status(reference: str, description: str = "") -> str:
    """The one status rule for every registry row (curated.json "status_rule"), first match wins:
    "obsolete" (any case) in the reference or description -> obsolete; a published "[RFC NNNN]" -> standard; an
    RFC-to-be "RFC-ietf-*" -> draft (coordinator decision: no credit for unpublished text); "draft-*" -> draft;
    anything else -> standard."""
    if "obsolete" in f"{reference} {description}".lower():
        return "obsolete"
    if _RFC.search(reference):
        return "standard"
    if "RFC-ietf-" in reference or "draft-" in reference:
        return "draft"
    return "standard"


def _rfc(reference: str) -> str | None:
    """'RFC NNNN' when the reference names a published RFC (the row's `standard`), else None."""
    m = _RFC.search(reference)
    return f"RFC {m.group(1)}" if m else None


def _digits(text: str) -> int | None:
    m = re.search(r"(\d{3,4})", text)
    return int(m.group(1)) if m else None


class Tables:
    def __init__(self, curated: dict) -> None:
        self.curated = curated
        self.algs: dict[str, tuple] = {}
        self.oid: dict[str, str] = {}
        self.tls_group: dict[int, str] = {}
        self.tls_sigscheme: dict[int, str] = {}
        self.ssh_kex: dict[str, str] = {}
        self.ike_ke: dict[int, str] = {}
        self.aws: dict[str, dict[str, str]] = {}
        self.aws_tls_policy: dict[str, dict[str, tuple[str, ...]]] = {}
        self.openssl_text: dict[str, str] = {}
        self.alias: dict[str, str] = {}
        self.grease: set[int] = set()
        self.gcp: dict[str, str] = {}
        self.kmip: dict[int, str] = {}
        self.pkcs11_key_types: dict[int, str] = {}
        self.pkcs11_parameter_sets: dict[int, dict[int, str]] = {}
        self.jose_key_types: tuple[str, ...] = ()
        self.jose_kty: dict[str, str] = {}
        self.jose_crv: dict[str, str] = {}
        self.jose_alg: dict[str, str] = {}

    def add(self, name: str, attrs: list | tuple) -> str:
        attrs = tuple(tuple(a) if isinstance(a, list) else a for a in attrs)
        if len(attrs) != 10 or len(name) > 64:
            raise SourceError(f"bad row {name!r}: {attrs}")
        old = self.algs.get(name)
        if old is not None and old != attrs:
            raise SourceError(f"conflicting rows for {name!r}: {old} vs {attrs}")
        self.algs[name] = attrs
        return name


def _cat(param: str | None, curated: dict) -> int | None:
    fips = curated["fips_algorithms"]
    if param and param in fips:
        return fips[param][5]
    m = re.match(r"SLH-DSA-(?:SHA2|SHAKE)-(\d{3})[sf]$", param or "")
    return curated["slh_dsa_categories"][m.group(1)] if m else None


def _pq(family: str, primitive: str, standard: str | None, status: str, param: str | None,
        construction: str, components: tuple = (), curated: dict | None = None) -> list:
    quantum = "hybrid" if construction in ("hybrid", "composite") else "safe"
    if status in ("pre-standard", "obsolete"):
        # neither a FIPS parameter set nor a standard is claimed for a round-3 or obsolete identity (OA-CB04-2/4)
        param = standard = None
    # a NIST category is claimed only for FIPS 203/204/205 (and FN-DSA) parameter sets, never for obsolete,
    # pre-standard or candidate identities (OA-CB04-2/4)
    category = _cat(param, curated or {}) if status in ("standard", "draft") else None
    return [family, primitive, standard, status, param, category, construction, quantum, None,
            list(components)]


def _classical(family: str | None, primitive: str | None, key_size: int | None = None,
               status: str = "standard") -> list:
    quantum = "vulnerable" if family else None
    return [family, primitive, None, status, None, None, "classical", quantum, key_size, []]


# --------------------------------------------------------------------------- namespaces
def build_curated_rows(t: Tables) -> None:
    c = t.curated
    for section in ("fips_algorithms", "other_pq", "classical_algorithms"):
        for name, attrs in c[section].items():
            if name.startswith("_"):
                continue
            if attrs[3] in ("pre-standard", "obsolete") and attrs[4] is not None:
                raise SourceError(f"{name}: a {attrs[3]} row carries parameter set {attrs[4]!r}")
            t.add(name, attrs)
    for oid, name in c["classical_oids"].items():
        if oid.startswith("_"):
            continue
        if name not in t.algs:
            raise SourceError(f"classical oid {oid} names unknown {name!r}")
        t.oid[oid] = name


def build_csor(t: Tables, extract: bytes) -> None:
    defs = json.loads(extract)["object_identifier_definitions"]
    arcs = {"nistAlgorithms": "2.16.840.1.101.3.4"}
    for name, body in defs:
        parts = body.split()
        if len(parts) == 2 and parts[0] in arcs and parts[1].isdigit():
            arcs[name] = f"{arcs[parts[0]]}.{parts[1]}"
    c = t.curated
    for ident, oid in arcs.items():
        if not oid.startswith(("2.16.840.1.101.3.4.3.", "2.16.840.1.101.3.4.4.")):
            continue
        m = re.fullmatch(r"id-ml-dsa-(\d+)", ident)
        if m:
            t.oid[oid] = f"ML-DSA-{m.group(1)}"
            continue
        m = re.fullmatch(r"id-alg-ml-kem-(\d+)", ident)
        if m:
            t.oid[oid] = f"ML-KEM-{m.group(1)}"
            continue
        m = re.fullmatch(r"id-slh-dsa-(sha2|shake)-(\d{3}[sf])", ident)
        if m:
            name = f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}"
            t.oid[oid] = t.add(name, _pq("PQ", "signature", "FIPS 205", "standard", name, "pure", curated=c))
            continue
        m = re.fullmatch(r"id-hash-ml-dsa-(\d+)-with-(sha\d+)", ident)
        if m:
            name = f"HashML-DSA-{m.group(1)}-with-{m.group(2).upper()}"
            param = f"ML-DSA-{m.group(1)}"
            t.oid[oid] = t.add(name, _pq("PQ", "signature", "FIPS 204", "standard", param, "pure", curated=c))
            continue
        m = re.fullmatch(r"id-hash-slh-dsa-(sha2|shake)-(\d{3}[sf])-with-(\w+)", ident)
        if m:
            param = f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}"
            name = f"Hash{param}-with-{m.group(3).upper()}"
            t.oid[oid] = t.add(name, _pq("PQ", "signature", "FIPS 205", "standard", param, "pure", curated=c))
            continue
        m = re.fullmatch(r"id-(dsa|ecdsa)-with-(sha[\d-]+)", ident)
        if m:
            fam = "DSA" if m.group(1) == "dsa" else "ECDSA"
            name = f"{m.group(1)}-with-{m.group(2).upper()}"
            t.oid[oid] = t.add(name, _classical(fam, "signature"))
            continue
        m = re.fullmatch(r"id-rsassa-pkcs1-v1-5-with-(sha3-\d+)", ident)
        if m:
            name = f"RSA-{m.group(1).upper()}"
            t.oid[oid] = t.add(name, _classical("RSA", "signature"))
            continue
        raise SourceError(f"CSOR identifier with no rule: {ident} {oid}")


_COMPOSITE = re.compile(r"(ML(?:DSA|KEM)\d+)-(.+)")


def _component(suffix: str, t: Tables) -> str:
    """The canonical row of a composite's classical part ("RSA2048-PSS-SHA256" -> "RSA-2048",
    "ECDSA-brainpoolP256r1-SHA512" -> "brainpoolP256r1"); the hash and padding stay in the composite's name."""
    m = re.match(r"RSA(\d{4})-", suffix)
    name = f"RSA-{m.group(1)}" if m else None
    m = re.match(r"(?:ECDSA|ECDH)-(P(\d{3})|brainpoolP\d{3}r1)-", suffix)
    if m:
        name = f"P-{m.group(2)}" if m.group(2) else m.group(1)
    m = re.match(r"(Ed25519|Ed448|X25519|X448)-", suffix)
    if m:
        name = m.group(1)
    if name is None or name not in t.algs:
        raise SourceError(f"composite component with no row: {suffix}")
    return name


def build_pkix(t: Tables, raw: bytes) -> None:
    for row in _csv(raw):
        dec, desc, ref = row["Decimal"], row["Description"], row["Reference"]
        if not dec.isdigit() or desc in ("Unassigned", "Reserved"):
            continue
        oid = f"1.3.6.1.5.5.7.6.{dec}"
        name = re.sub(r"^id-(alg-)?", "", desc)
        status = _status(ref, desc)
        m = _COMPOSITE.fullmatch(name)
        if m:
            kem = m.group(1).startswith("MLKEM")
            param = re.sub(r"ML(DSA|KEM)(\d+)", r"ML-\1-\2", m.group(1))
            attrs = _pq("PQ", "kem" if kem else "signature", _rfc(ref), status, param, "composite",
                        (param, _component(m.group(2), t)), t.curated)
            t.oid[oid] = t.add(name, attrs)
        elif name == "xmss-hashsig":
            t.oid[oid] = "XMSS"
        elif name == "xmssmt-hashsig":
            t.oid[oid] = "XMSS^MT"
        elif name.startswith(("dhPop", "dh-sig")):
            t.oid[oid] = t.add(name, _classical("DH", "signature", status=status))
        elif name.startswith(("ecdhPop", "eccsi")):
            t.oid[oid] = t.add(name, _classical("EC", "signature", status=status))
        elif name.startswith("RSASSA-PSS"):
            t.oid[oid] = t.add(name, _classical("RSA", "signature", status=status))
        elif name.startswith("ecdsa-with"):
            t.oid[oid] = t.add(name, _classical("ECDSA", "signature", status=status))
        else:  # des40, noSignature, unsigned, mtcProof: identifiers, not key algorithms (no family, no verdict)
            t.oid[oid] = t.add(name, _classical(None, "other", status=status))


def _group_attrs(desc: str, status: str) -> list | None:
    low = desc.lower()
    if low.startswith(("sect", "secp", "brainpool", "gc256", "gc512", "bign-", "arbitrary_explicit")):
        return _classical("EC", "key-agree", _digits(desc), status)
    if low == "curvesm2":
        return _classical("SM2", "key-agree", 256, status)
    if low in ("x25519", "x448"):
        return _classical(desc.upper(), "key-agree", 256 if low == "x25519" else 448, status)
    if low.startswith("ffdhe"):
        return _classical("DH", "key-agree", _digits(desc), status)
    return None


def build_tls_groups(t: Tables, raw: bytes) -> None:
    pq = t.curated["tls_pq_groups"]
    for row in _csv(raw):
        value, desc, ref = row["Value"], row["Description"], row["Reference"]
        if not value.isdigit():
            continue
        cp = int(value)
        if desc == "Reserved" and "RFC 8701" in ref:
            t.grease.add(cp)
            continue
        if desc.startswith(("Reserved", "Unassigned")):
            continue
        name = desc.replace(" (OBSOLETE)", "")
        status = _status(ref, desc)
        if name in pq:
            param, components = pq[name]
            construction = "hybrid" if components else "pure"
            attrs = _pq("PQ", "kem", "FIPS 203", status, param, construction, components, t.curated)
        else:
            attrs = _group_attrs(name, status)
            if attrs is None:
                raise SourceError(f"TLS group with no rule: {cp} {desc}")
        same = t.algs.get(name)
        if same is not None and (same[0], same[8]) == (attrs[0], attrs[8]):
            t.tls_group[cp] = name  # a named curve already curated (secp256k1, brainpool*): one identity
        else:
            t.tls_group[cp] = t.add(name, attrs)
    unused = set(k for k in pq if not k.startswith("_")) - set(t.tls_group.values())
    if unused:
        raise SourceError(f"curated tls_pq_groups not in the registry: {sorted(unused)}")


def _sigscheme_attrs(desc: str, ref: str, curated: dict) -> list:
    low = desc.lower()
    status = _status(ref, desc)
    m = re.fullmatch(r"mldsa(\d+)", low)
    if m:
        return _pq("PQ", "signature", "FIPS 204", status, f"ML-DSA-{m.group(1)}", "pure", (), curated)
    m = re.fullmatch(r"slhdsa_(sha2|shake)_(\d{3}[sf])", low)
    if m:
        param = f"SLH-DSA-{m.group(1).upper()}-{m.group(2)}"
        return _pq("PQ", "signature", "FIPS 205", status, param, "pure", (), curated)
    if low.startswith("rsa_"):
        return _classical("RSA", "signature", status=status)
    if low.startswith("ecdsa_"):
        return _classical("ECDSA", "signature", status=status)
    if low in ("ed25519", "ed448"):
        return _classical(desc.upper(), "signature", status=status)
    if low.startswith("sm2"):
        return _classical("SM2", "signature", status=status)
    if low.startswith(("gostr", "eccsi", "iso_", "bign-")):
        return _classical("EC", "signature", status=status)
    raise SourceError(f"TLS signature scheme with no rule: {desc}")


def build_tls_sigschemes(t: Tables, raw: bytes) -> None:
    for row in _csv(raw):
        value, desc, ref = row["Value"], row["Description"], row["Reference"]
        if "-" in value or desc.startswith(("Reserved", "Unassigned")):
            continue
        t.tls_sigscheme[int(value, 16)] = t.add(desc, _sigscheme_attrs(desc, ref, t.curated))


def _ssh_attrs(name: str, status: str) -> list | None:
    if name.startswith(("diffie-hellman-", "gss-group", "gss-gex")) or name.startswith("rsa"):
        if name.startswith("rsa"):
            return _classical("RSA", "key-agree", _digits(name), status)
        # RFC 4253 s8.1-8.2 (group1: Oakley group 2, 1024 bit; group14: 2048) and RFC 8268 s3 / RFC 3526
        size = {"group1": 1024, "group14": 2048, "group15": 3072, "group16": 4096, "group17": 6144,
                "group18": 8192}
        m = re.search(r"(group\d+)", name)
        return _classical("DH", "key-agree", size.get(m.group(1)) if m else None, status)
    if name.startswith(("ecdh-sha2-", "gss-nistp")):
        return _classical("ECDH", "key-agree", _digits(name.replace("sha2", "").replace("sha", "")), status)
    if name.startswith("ecmqv"):
        return _classical("EC", "key-agree", status=status)
    if "curve25519" in name:
        return _classical("X25519", "key-agree", 256, status)
    if "curve448" in name:
        return _classical("X448", "key-agree", 448, status)
    return None


def build_ssh_kex(t: Tables, raw: bytes, openssh: bytes) -> None:
    pq = t.curated["ssh_pq_kex"]
    for row in _csv(raw):
        name = row["Method Name"]
        if name in ("ext-info-s", "ext-info-c", "gss-"):
            continue  # extension signals and the reserved gss- prefix: not key exchanges
        status = _status(row["Reference"])
        if name in pq:
            param, components = pq[name]
            attrs = _pq("PQ", "kem", "FIPS 203" if param.startswith("ML-KEM") else None, status, param,
                        "hybrid" if components else "pure", components, t.curated)
        else:
            attrs = _ssh_attrs(name, status)
            if attrs is None:
                raise SourceError(f"SSH KEX with no rule: {name}")
        t.ssh_kex[name] = t.add(name, attrs)
    lines = openssh.decode().splitlines()
    for name in lines[1:]:  # line 1 is `ssh -V`
        name = name.strip()
        base = name.split("@", 1)[0]
        if name in t.ssh_kex:
            continue
        if base in t.ssh_kex:
            t.ssh_kex[name] = t.ssh_kex[base]
        else:
            raise SourceError(f"OpenSSH KEX name with no registry row: {name}")


def build_ike(t: Tables, raw: bytes) -> None:
    names = {int(k): v for k, v in t.curated["ike_ke_names"].items() if not k.startswith("_")}
    seen = set()
    for row in _csv(raw):
        num, desc = row["Number"], row["Name"]
        if not num.isdigit() or desc in ("NONE", "Reserved", "Unassigned"):
            continue
        n = int(num)
        if n not in names:
            raise SourceError(f"IKEv2 transform type 4 id {n} ({desc}) has no product name")
        seen.add(n)
        name, low = names[n], desc.lower()
        status = _status(row["Reference"], desc)
        m = re.fullmatch(r"ml-kem-(\d+)", low)
        if m:
            attrs = _pq("PQ", "kem", "FIPS 203", status, f"ML-KEM-{m.group(1)}", "pure", (), t.curated)
        elif "modp" in low:
            attrs = _classical("DH", "key-agree", _digits(desc), status)
        elif low.startswith("gost"):
            attrs = _classical("EC", "key-agree", int(desc.rsplit("_", 1)[1]), status)
        elif "ecp" in low or low.startswith("brainpool"):
            attrs = _classical("EC", "key-agree", _digits(desc), status)
        elif low in ("curve25519", "curve448"):
            attrs = _classical("X25519" if low == "curve25519" else "X448", "key-agree",
                               256 if low == "curve25519" else 448, status)
        else:
            raise SourceError(f"IKEv2 group with no rule: {n} {desc}")
        t.ike_ke[n] = t.add(name, attrs)
    if set(names) - seen:
        raise SourceError(f"ike_ke_names not in the registry: {sorted(set(names) - seen)}")


def build_aws(t: Tables, enums: bytes, elb_extract: bytes, apigw_extract: bytes) -> None:
    captured = json.loads(enums)["enums"]
    for key, mapping in t.curated["aws"].items():
        if key.startswith("_"):
            continue
        values = set(captured[key])
        if set(mapping) != values:
            raise SourceError(f"aws {key}: curated {sorted(set(mapping) ^ values)} differ from botocore")
        for value, name in mapping.items():
            if name not in t.algs:
                raise SourceError(f"aws {key} {value} names unknown {name!r}")
        names = list(mapping.values())
        shared = sorted({n for n in names if names.count(n) > 1})
        if shared:  # compare_key canonicalises enums: two values of one field must never compare equal
            raise SourceError(f"aws {key}: several values name {shared}")
        t.aws[key] = dict(mapping)
    quote = t.curated["aws_tls_policy"]["elbv2_quote"]
    elb = json.loads(elb_extract)
    if elb["group_sentence"] != quote:
        raise SourceError("the ELB extract's PQ group sentence differs from curated.json")
    groups = tuple(g for g in re.findall(r"(\w+MLKEM\d+)", quote))
    for g in groups:
        if g not in t.tls_group.values():
            raise SourceError(f"ELB group {g} is not an IANA TLS group")
    t.aws_tls_policy["elbv2"] = {n: groups for n in elb["pq_policy_names"]}
    api_names = set(json.loads(apigw_extract)["pq_policy_names"])
    api_names |= {v for v in captured["apigateway.SecurityPolicy"] if "_PQ_" in v}
    t.aws_tls_policy["apigateway"] = {n: () for n in sorted(api_names)}


def _mapped(t: Tables, section: str, curated: dict, names: list[str]) -> dict[str, str]:
    """{source name: row} for a curated section that must list every name the source defines (mapped or null)."""
    listed = {k: v for k, v in curated.items() if not k.startswith("_")}
    if set(listed) != set(names):
        raise SourceError(f"{section}: curated names differ from the source: {sorted(set(listed) ^ set(names))}")
    for name, row in listed.items():
        if row is not None and row not in t.algs:
            raise SourceError(f"{section} {name} names unknown {row!r}")
    return {k: v for k, v in listed.items() if v is not None}


def build_gcp(t: Tables, extract: bytes) -> None:
    values = [v for v, _desc in json.loads(extract)["algorithms"]]
    t.gcp = _mapped(t, "gcp", t.curated["gcp"], values)


def build_kmip(t: Tables, extract: bytes) -> None:
    rows = json.loads(extract)["algorithms"]
    mapped = _mapped(t, "kmip", t.curated["kmip"], [n for n, _v in rows])
    t.kmip = {value: mapped[name] for name, value in rows if name in mapped}


def build_pkcs11(t: Tables, extract: bytes) -> None:
    doc = json.loads(extract)
    key_types = {name: value for name, value in doc["key_types"]}
    c = t.curated["pkcs11"]
    mapped = _mapped(t, "pkcs11.key_types", c["key_types"], list(key_types))
    for name, row in mapped.items():
        old = t.pkcs11_key_types.get(key_types[name])
        if old is not None and old != row:  # CKK_ECDSA is CKK_EC: aliases must agree
            raise SourceError(f"PKCS#11 value {key_types[name]:#x} maps to {old!r} and {row!r}")
        t.pkcs11_key_types[key_types[name]] = row
    params = {name: value for name, value in doc["parameter_sets"]}
    for ckk, sets in c["parameter_sets"].items():
        out: dict[int, str] = {}
        for ckp, row in sets.items():
            if ckp not in params or row not in t.algs:
                raise SourceError(f"PKCS#11 parameter set {ckp} -> {row!r}: not in the header or not a row")
            out[params[ckp]] = row
        t.pkcs11_parameter_sets[key_types[ckk]] = out


def build_jose(t: Tables, key_types: bytes, curves: bytes, algs: bytes) -> None:
    c = t.curated["jose"]
    kty = [r['"kty" Parameter Value'] for r in _csv(key_types)]
    t.jose_key_types = tuple(kty)
    t.jose_kty = _mapped(t, "jose.kty", c["kty"], kty)
    t.jose_crv = _mapped(t, "jose.crv", c["crv"], [r["Curve Name"] for r in _csv(curves)])
    registered = {r["Algorithm Name"] for r in _csv(algs)}
    if set(c["alg"]) - registered:
        raise SourceError(f"jose.alg not in the registry: {sorted(set(c['alg']) - registered)}")
    t.jose_alg = _mapped(t, "jose.alg", c["alg"], list(c["alg"]))


def build_openssl_text(t: Tables, *captures: bytes) -> None:
    for raw in captures:
        for row in json.loads(raw)["rows"]:
            for text, oid in ((row["public_key_text"], row["spki_oid"]), (row["signature_text"], row["sig_oid"])):
                if not text or re.fullmatch(r"\d+(\.\d+)+", text):
                    continue  # OpenSSL printed the dotted OID: the oid table answers it
                name = t.oid.get(oid)
                if name is None:
                    raise SourceError(f"OpenSSL text {text!r}: OID {oid} not in the oid table")
                old = t.openssl_text.get(text)
                if old is not None and old != name:
                    raise SourceError(f"OpenSSL text {text!r} maps to {old!r} and {name!r}")
                t.openssl_text[text] = name


def norm(text: str) -> str:
    """algid._norm: Unicode NFKC, every non-alphanumeric character removed, case-folded."""
    return re.sub(r"[\W_]+", "", unicodedata.normalize("NFKC", text)).casefold()


def build_aliases(t: Tables) -> None:
    for canonical, spellings in t.curated["aliases"].items():
        if canonical.startswith("_"):
            continue
        if canonical not in t.algs:
            raise SourceError(f"alias target {canonical!r} is not a row")
        for s in spellings:
            key = norm(s)
            if key in t.alias and t.alias[key] != canonical:
                raise SourceError(f"alias {s!r} maps to {t.alias[key]!r} and {canonical!r}")
            t.alias[key] = canonical
    for name in t.algs:  # every row is also reachable by its own normalised name (curated aliases win)
        t.alias.setdefault(norm(name), name)
    # registry and OpenSSL spellings too, so a lookup never depends on letter case or separators
    for table in (t.ssh_kex, t.openssl_text):
        for spelling, name in table.items():
            t.alias.setdefault(norm(spelling), name)


def build(data: dict[str, bytes]) -> Tables:
    t = Tables(json.loads(data["curated.json"]))
    build_curated_rows(t)
    build_csor(t, data["nist-csor-oids.json"])
    build_pkix(t, data["iana-pkix-alg.csv"])
    build_tls_groups(t, data["iana-tls-groups.csv"])
    build_tls_sigschemes(t, data["iana-tls-sigschemes.csv"])
    build_ssh_kex(t, data["iana-ssh-kex.csv"], data["openssh-kex-aliases.txt"])
    build_ike(t, data["iana-ikev2-t4.csv"])
    build_aws(t, data["botocore-enums.json"], data["aws-elb-pq-policies.json"],
              data["aws-apigw-pq-policies.json"])
    build_openssl_text(t, data["openssl-3.0-text.json"], data["openssl-3.5-text.json"])
    build_gcp(t, data["gcp-kms-algorithms.json"])
    build_kmip(t, data["kmip-3.0-algorithms.json"])
    build_pkcs11(t, data["pkcs11-3.2-constants.json"])
    build_jose(t, data["iana-jose-key-types.csv"], data["iana-jose-curves.csv"], data["iana-jose-algs.csv"])
    build_aliases(t)
    for oid, name in t.oid.items():
        if name not in t.algs:
            raise SourceError(f"oid {oid} names unknown row {name!r}")
    for name, attrs in t.algs.items():
        missing = [c for c in attrs[9] if c not in t.algs]
        if missing:
            raise SourceError(f"{name}: components {missing} are not rows")
    return t


# --------------------------------------------------------------------------- emit
def _lit(value) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, tuple):
        inner = ", ".join(_lit(v) for v in value)
        return f"({inner},)" if len(value) == 1 else f"({inner})"
    if value is None:
        return "None"
    return repr(value)


def _entry(key: str, value: str, indent: int = 4) -> list[str]:
    pad = " " * indent
    line = f"{pad}{key}: {value},"
    if len(line) <= WIDTH:
        return [line]
    if value.startswith("(") and value.endswith(")"):
        items = _split_tuple(value[1:-1])
        out = [f"{pad}{key}: ("]
        cur = pad + "    "
        for item in items:
            piece = item + ","
            if len(cur) + len(piece) + 1 > WIDTH and cur.strip():
                out.append(cur.rstrip())
                cur = pad + "    "
            cur += piece + " "
        out.append(cur.rstrip())
        out.append(f"{pad}),")
        if all(len(x) <= WIDTH for x in out):
            return out
    out = [f"{pad}{key}:", f"{pad}    {value},"]
    if any(len(x) > WIDTH for x in out):
        raise SourceError(f"cannot fit {key} in {WIDTH} columns")
    return out


def _split_tuple(body: str) -> list[str]:
    items, depth, cur, quote = [], 0, "", False
    for ch in body:
        if ch == '"' and (not cur or cur[-1] != "\\"):
            quote = not quote
        if not quote and ch in "([":
            depth += 1
        if not quote and ch in ")]":
            depth -= 1
        if ch == "," and depth == 0 and not quote:
            items.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur.strip())
    return items


def _seq(name: str, values: list, fmt=_lit, per_line: int = 8) -> list[str]:
    out = [f"{name} = ("]
    for i in range(0, len(values), per_line):
        out.append("    " + ", ".join(fmt(v) for v in values[i:i + per_line]) + ",")
    out.append(")")
    return out


def _hex(v: int) -> str:
    return f"0x{v:04X}"


HEADER = '''"""GENERATED by scripts/algid/build_algid.py from scripts/algid/sources: do not edit.

The tables algid.py reads, vendored byte-identical next to each algid.py copy.
Change a source (or curated.json) and run build_algid.py; a backend test fails when
a copy differs from what the sources give. Every table is read-only.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any
'''


def _mapping(name: str, annotation: str, items: list[tuple[str, str]], indent: int = 0) -> list[str]:
    pad = " " * indent
    head = f"{pad}{name}: {annotation} = MappingProxyType(" if annotation else f"{pad}{name}: MappingProxyType("
    out = [head + "{"]
    for key, value in items:
        out += _entry(key, value, indent + 4)
    out.append(pad + "})")
    return out


def emit(t: Tables, digest: str) -> str:
    c = t.curated
    lines = HEADER.rstrip("\n").split("\n") + ["", f'SOURCES_SHA256 = "{digest}"', "",
             "# canonical name -> (family_label, primitive, standard, status, parameter_set,",
             "#                    nist_category, construction, quantum, key_size, components)"]
    lines += _mapping("ALGS", "Mapping[str, tuple[Any, ...]]",
                      [(_lit(n), _lit(t.algs[n])) for n in sorted(t.algs)])
    oids = sorted(t.oid, key=lambda o: [int(x) for x in o.split(".")])
    lines += [""] + _mapping("OIDS", "Mapping[str, str]", [(_lit(o), _lit(t.oid[o])) for o in oids])
    lines += [""] + _mapping("TLS_GROUPS", "Mapping[int, str]",
                             [(_hex(cp), _lit(t.tls_group[cp])) for cp in sorted(t.tls_group)])
    lines += [""] + _mapping("TLS_SIGSCHEMES", "Mapping[int, str]",
                             [(_hex(cp), _lit(t.tls_sigscheme[cp])) for cp in sorted(t.tls_sigscheme)])
    lines += [""] + _mapping("SSH_KEX", "Mapping[str, str]",
                             [(_lit(n), _lit(t.ssh_kex[n])) for n in sorted(t.ssh_kex)])
    lines += [""] + _mapping("IKE_KE", "Mapping[int, str]",
                             [(str(n), _lit(t.ike_ke[n])) for n in sorted(t.ike_ke)])
    lines += ["", "AWS: Mapping[str, Mapping[str, str]] = MappingProxyType({"]
    for key in sorted(t.aws):
        lines.append(f"    {_lit(key)}: MappingProxyType({{")
        for value in sorted(t.aws[key]):
            lines += _entry(_lit(value), _lit(t.aws[key][value]), 8)
        lines.append("    }),")
    lines += ["})", "", "AWS_TLS_POLICY: Mapping[str, Mapping[str, tuple[str, ...]]] = MappingProxyType({"]
    for service in sorted(t.aws_tls_policy):
        lines.append(f"    {_lit(service)}: MappingProxyType({{")
        for name in sorted(t.aws_tls_policy[service]):
            lines += _entry(_lit(name), _lit(t.aws_tls_policy[service][name]), 8)
        lines.append("    }),")
    lines += ["})", ""]
    lines += _mapping("OPENSSL_TEXT", "Mapping[str, str]",
                      [(_lit(x), _lit(t.openssl_text[x])) for x in sorted(t.openssl_text)])
    lines += [""] + _mapping("ALIASES", "Mapping[str, str]",
                             [(_lit(k), _lit(t.alias[k])) for k in sorted(t.alias)])
    lines += [""] + _mapping("GCP", "Mapping[str, str]", [(_lit(k), _lit(t.gcp[k])) for k in sorted(t.gcp)])
    lines += [""] + _mapping("KMIP", "Mapping[int, str]", [(_hex(k), _lit(t.kmip[k])) for k in sorted(t.kmip)])
    lines += [""] + _mapping("PKCS11_KEY_TYPES", "Mapping[int, str]",
                             [(_hex(k), _lit(t.pkcs11_key_types[k])) for k in sorted(t.pkcs11_key_types)])
    lines += ["", "PKCS11_PARAMETER_SETS: Mapping[int, Mapping[int, str]] = MappingProxyType({"]
    for ckk in sorted(t.pkcs11_parameter_sets):
        lines.append(f"    {_hex(ckk)}: MappingProxyType({{")
        for ckp in sorted(t.pkcs11_parameter_sets[ckk]):
            lines += _entry(_hex(ckp), _lit(t.pkcs11_parameter_sets[ckk][ckp]), 8)
        lines.append("    }),")
    lines += ["})", ""]
    lines += _seq("JOSE_KEY_TYPES", list(t.jose_key_types))
    for name, table in (("JOSE_KTY", t.jose_kty), ("JOSE_CRV", t.jose_crv), ("JOSE_ALG", t.jose_alg)):
        lines += [""] + _mapping(name, "Mapping[str, str]", [(_lit(k), _lit(table[k])) for k in sorted(table)])
    lines += ["", "OID_PREFIXES: tuple[tuple[str, str, str | None], ...] = ("]
    for prefix, spec in c["oid_prefixes"].items():
        if not prefix.startswith("_"):
            lines.append(f"    ({_lit(prefix)}, {_lit(spec[0])}, {_lit(spec[1])}),")
    lines += [")", ""]
    x509 = c["code_lane_x509"]
    lines += _mapping("CODE_LANE_X509_NAMES", "Mapping[str, str]",
                      [(_lit(o), _lit(n)) for o, n in x509["names"].items()])
    lines += [""] + _mapping("CODE_LANE_X509_KEYS", "Mapping[str, str]",
                             [(_lit(o), _lit(n)) for o, n in x509["keys"].items()])
    lines += [""] + _seq("GREASE", sorted(t.grease), _hex)
    markers = c["markers"]
    lines += [""] + _seq("PQ_MARKERS", markers["pq"], per_line=6)
    lines += [""] + _seq("PRE_STANDARD_MARKERS", markers["pre_standard"], per_line=6)
    lines += [""] + _seq("CLASSICAL_MARKERS", markers["classical"], per_line=6)
    p = c["prober"]
    lines += ["", "# DA s5's pinned lists govern over s0's wording \"every IANA TLS 1.3 group\":",
              "# the offer stops at 42, so bign-curve384v1/512v1 (43/44) are not offered",
              "# (coordinator decision, 2026-11-12)."]
    lines += _seq("TLS13_OFFER_GROUPS", p["TLS13_OFFER_GROUPS"], _hex)
    lines += [""] + _seq("PQ_PROBE_GROUPS", p["PQ_PROBE_GROUPS"], _hex)
    lines += [""] + _seq("TLS13_SIGSCHEMES", p["TLS13_SIGSCHEMES"], _hex)
    lines += ["", "S_CLIENT_GROUPS_35 = ("]
    rest = p["S_CLIENT_GROUPS_35"]
    while rest:
        # cut after the last ':' that fits, else at the width (pieces are concatenated literals)
        cut = len(rest) if len(rest) <= 72 else (rest.rfind(":", 0, 72) + 1 or 72)
        lines.append(f"    {_lit(rest[:cut])}")
        rest = rest[cut:]
    lines += [")", ""]
    lines += _seq("TLS_CLASSICAL_SIGSCHEME_NAMES", p["TLS_CLASSICAL_SIGSCHEME_NAMES"], per_line=2)
    for line in lines:
        if len(line) > WIDTH:
            raise SourceError(f"generated line over {WIDTH} columns: {line}")
    return "\n".join(lines) + "\n"


def _differs(path: Path, text: str) -> bool:
    return not path.exists() or path.read_text(encoding="utf-8") != text


def main(argv: list[str]) -> int:
    data, digest = load_sources()
    tables = emit(build(data), digest)
    master = MASTER.read_text(encoding="utf-8")
    drifted = [p for p in COPIES[1:] if _differs(p, master)]
    if "--check" in argv:
        bad = [str(p.relative_to(ROOT)) for p in TABLES if _differs(p, tables)]
        bad += [str(p.relative_to(ROOT)) for p in drifted]
        if bad:
            print("algid: out of date: " + ", ".join(bad), file=sys.stderr)
            return 1
        print("algid: all copies match the sources and the master")
        return 0
    if drifted and "--sync" not in argv:
        for p in drifted:
            old = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
            diff = list(difflib.unified_diff(master.splitlines(), old, str(MASTER.relative_to(ROOT)),
                                             str(p.relative_to(ROOT)), lineterm=""))
            print("\n".join(diff[:60]), file=sys.stderr)
        print("algid: a copy of algid.py differs from the master (backend/utilities/cbom_sources/algid.py). "
              "Edit the master only; --sync copies it over the others (and discards their edits).",
              file=sys.stderr)
        return 1
    for p in TABLES:
        p.write_text(tables, encoding="utf-8")
    for p in drifted:
        p.write_text(master, encoding="utf-8")
    print(f"algid: wrote {len(TABLES)} copies of algid_tables.py ({len(tables.splitlines())} lines)"
          + (f"; synced {len(drifted)} algid.py from the master" if drifted else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
