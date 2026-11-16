"""Import an uploaded CycloneDX CBOM into crypto-asset components (the "Analyze CBOM file" scan).

The uploaded document is only an INPUT: its components become ``CryptoAssetComponent`` nodes with the same ``crypto:``
properties the repository scanners emit, and the regular flagging, PQC grading, scoring and compliance scanners judge
them. Nothing the file claims about its own risk (strength, quantum level, findings) is trusted; those properties are
recomputed. Pure and offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from aibom.cbom.rules import (
    ALGORITHM_NORMALIZE,
    LITERAL_ALGO_ALIASES,
    PQC_FIPS_NAME,
    PQC_PARAM_SETS,
    algo_info,
)
from aibom.cbom.weakness import _base_key
from aibom.model.component import CryptoAssetComponent

MAX_COMPONENTS = 20_000
MAX_DEPTH = 8
_ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}
_MODES = {"gcm", "cbc", "ecb", "ctr", "cfb", "ofb", "xts", "ccm"}
_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf",
               "key-agree", "kem", "ae", "combiner", "other", "unknown"}
# Values the engine computes itself; never copied from the uploaded file.
_RECOMPUTED = {"crypto:strength", "crypto:quantumVulnerable", "crypto:nistQuantumSecurityLevel",
               "crypto:securityStrengthBits", "crypto:pqcMigrationTarget", "crypto:pqcMigrationRoadmap",
               "crypto:hybrid"}
_PQC_RE = re.compile(r"^(mlkem|kyber|mldsa|dilithium|slhdsa|sphincs|falcon)(\d+)?")


@dataclass
class IngestStats:
    components_total: int = 0
    crypto_assets: int = 0
    imported: int = 0
    skipped_not_crypto: int = 0
    skipped_invalid: int = 0
    duplicates: int = 0
    # components a ZeroShield run export marks as parts of certificates
    # (``zs:part_of``): their signature algorithm, public key and key algorithm,
    # read into the certificates that reference them, never assets of their own
    certificate_parts: int = 0
    truncated: bool = False
    spec_version: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def _d(value: Any) -> dict[str, Any]:
    """The value when it is a JSON object, else an empty one: a malformed entry is read as empty, never raised."""
    return value if isinstance(value, dict) else {}


def _l(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")[:80] or "asset"


def _walk(components: Any, depth: int = 0):
    if not isinstance(components, list) or depth > MAX_DEPTH:
        return
    for comp in components:
        if isinstance(comp, dict):
            yield comp
            yield from _walk(comp.get("components"), depth + 1)


def _int(value: Any) -> int | None:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if 0 < n < 1_000_000 else None


_CLASSICAL_KEX = re.compile(r"x25519|x448|secp(?:256|384|521)r1|prime256v1|p(?:256|384|521)|ecdh|ecdhe")
_HYBRID_PQ = re.compile(r"(mlkem|kyber)(512|768|1024)?")
_CURVE = re.compile(r"^(?:secp(256|384|521)r1|prime256v1|p(256|384|521)|nistp(256|384|521))$")
# Dilithium round-3 security levels -> ML-DSA parameter sets (FIPS 204)
_DILITHIUM_LEVEL = {"2": "44", "3": "65", "5": "87"}


def _signature_scheme(flat: str) -> str | None:
    """For a signature-algorithm name ('sha256WithRSAEncryption', 'ecdsa-with-SHA1', 'SHA1withRSA'): a broken digest
    (MD2/MD4/MD5/SHA-1) is what makes it weak, so that is returned; with a sound digest the public-key algorithm decides
    (quantum-vulnerable), so that is returned instead."""
    m = re.match(r"^(md[245]|sha(?:1|224|256|384|512))with(rsa|ecdsa|dsa)", flat) or \
        re.match(r"^(rsa|ecdsa|dsa)with(md[245]|sha(?:1|224|256|384|512))", flat)
    if not m:
        m2 = re.match(r"^(ecdsa|dsa|rsa)(?:with)?(sha(?:1|224|256|384|512))$", flat)  # ecdsa-with-SHA1 -> ecdsawithsha1
        if not m2:
            return None
        pk, digest = m2.group(1), m2.group(2)
    elif m.group(1).startswith(("md", "sha")):
        digest, pk = m.group(1), m.group(2)
    else:
        pk, digest = m.group(1), m.group(2)
    if digest in ("md2", "md4", "md5", "sha1"):
        return LITERAL_ALGO_ALIASES.get(digest) or digest
    return LITERAL_ALGO_ALIASES.get(pk) or pk


def resolve_algorithm(name: str, key_size: int | None = None) -> tuple[str | None, int | None, str | None, str | None]:
    """(canonical key, key size, mode, PQC parameter set) for an algorithm name such as 'AES-256-GCM', 'RSA',
    'sha1WithRSAEncryption', 'ML-KEM-768' or 'X25519MLKEM768'. key_size may carry the file's parameterSetIdentifier.
    The key is None for a name the rule base does not know (it is then reported as unknown, never as safe)."""
    text = str(name or "").strip()
    low = text.lower()
    parts = [p for p in re.split(r"[-_/\s.()]+", low) if p]
    mode = next((p.upper() for p in parts if p in _MODES), None)
    flat = re.sub(r"[^a-z0-9]", "", low)
    # hybrid key exchange: a classical group and ML-KEM together (X25519MLKEM768, secp256r1_mlkem768, x25519_kyber768)
    hyb = _HYBRID_PQ.search(flat)
    if hyb and _CLASSICAL_KEX.search(flat.replace(hyb.group(0), " ")):
        param = hyb.group(2) or (str(key_size) if key_size and str(key_size) in PQC_PARAM_SETS.get("hybrid", ()) else None)
        return "hybrid", None, None, param
    if flat.startswith("fndsa"):  # FN-DSA is FIPS 206's name for Falcon
        flat = "falcon" + flat[5:]
    pqc = _PQC_RE.match(flat)
    if pqc:
        key = LITERAL_ALGO_ALIASES[pqc.group(1) if pqc.group(1) != "sphincs" else "sphincs"]
        digits = re.findall(r"\d+", flat[len(pqc.group(1)):])
        if key == "dilithium" and digits and digits[0] in _DILITHIUM_LEVEL:
            digits = [_DILITHIUM_LEVEL[digits[0]]]
        if key == "sphincs+":  # SLH-DSA-SHA2-128s: the security level, not the digest's digits
            digits = re.findall(r"(?<!\d)(128|192|256)[sf]?(?!\d)", low)
        if key_size is not None:
            digits.append(str(key_size))
        param = next((d for d in digits if d in PQC_PARAM_SETS.get(key, ())), None)
        return key, None, None, param
    key = _base_key(text)
    if key is None:
        key = _signature_scheme(flat)
    if key is None and re.search(r"3des|tripledes|tdea|des-?ede|desede", low):
        key = "3des"
    if key is None and (flat.startswith("rsaencryption") or flat in ("rsassapss", "rsapss", "rsaesoaep", "rsaoaep")):
        key = "rsa"
    curve = next((p for p in parts + [flat] if _CURVE.match(p)), None)
    if key is None and curve:
        key = "ecdsa"
    if key is None and (parts[:1] and parts[0] in ("dh", "dhe", "diffie", "diffiehellman") or flat.startswith(("ffdhe", "modp"))):
        key = "dh"
    if key is None:
        candidates = parts + [a + b for a, b in zip(parts, parts[1:])]
        for cand in candidates:
            if cand in LITERAL_ALGO_ALIASES:
                key = LITERAL_ALGO_ALIASES[cand]
                break
            m = re.match(r"^(rsa|aes|sha|sha2|sha3)(\d{3,4})$", cand)
            if m:
                key = LITERAL_ALGO_ALIASES.get(m.group(1).replace("sha2", "sha") + m.group(2))
                if key:
                    break
    if key is None:
        return None, key_size, mode, None
    size = key_size
    if size is None:
        if key.startswith("rsa"):
            # only a number written right after RSA is a modulus size: RSA-OAEP-256 and RSA-PSS-SHA256 name a digest
            m = re.search(r"rsa[-_ ]?(\d{3,5})(?!\d)", low)
            size = int(m.group(1)) if m and int(m.group(1)) >= 512 else None
        elif key == "dh":
            m = re.search(r"(\d{3,5})(?!\d)", low)
            size = int(m.group(1)) if m and int(m.group(1)) >= 512 else None
        elif key in ("ecdsa", "ecdh") and curve:
            size = None  # P-256 names a curve; its bits are not an RSA-style key size
        else:
            nums = [int(n) for n in re.findall(r"(?<![a-z])(\d{3,5})(?!\d)", low)]
            size = next((n for n in nums if n in (128, 192, 256, 512, 1024, 2048, 3072, 4096, 7680, 8192)), None)
    if key == "rsa" and size and algo_info(f"rsa-{size}"):
        key = f"rsa-{size}"
    if key == "aes" and size in (128, 192, 256):
        key = f"aes-{size}"
    return key, size, mode, None


def _display(key: str, size: int | None, mode: str | None, param: str | None) -> str:
    if param and key in PQC_FIPS_NAME:
        return f"{PQC_FIPS_NAME[key]}-{param}"
    # Sized RSA / AES are already folded into the key (rsa-2048, aes-128); other sizes stay in crypto:keySize so the
    # display name keeps the canonical spelling the weakness corpus looks up (3DES-CBC, not 3DES-168-CBC).
    base = ALGORITHM_NORMALIZE.get(key, key.upper())
    if mode and mode not in base.upper().split("-"):
        base = f"{base}-{mode}"
    return base


def _algorithm_props(name: str, algo: dict[str, Any], props: dict[str, str]) -> tuple[str, dict[str, str]]:
    size = _int(algo.get("parameterSetIdentifier")) or _int(props.get("crypto:keySize"))
    key, size, mode, param = resolve_algorithm(name, size)
    mode = (str(algo.get("mode") or "").upper() or mode) if str(algo.get("mode") or "").lower() in _MODES else mode
    out = dict(props)
    out["crypto:assetType"] = "algorithm"
    if key:
        info = algo_info(key) or {}
        out["crypto:primitive"] = info.get("primitive") or "other"
        out["crypto:strength"] = info.get("strength", "unknown")
        out["crypto:quantumVulnerable"] = str(bool(info.get("quantum_vulnerable", False))).lower()
        if param:
            out["crypto:parameterSet"] = param
        if key == "hybrid":
            out["crypto:hybrid"] = "true"
        display = name if key == "hybrid" else _display(key, size, mode, param)
    else:
        primitive = str(algo.get("primitive") or "").lower()
        if primitive in _PRIMITIVES:
            out["crypto:declaredPrimitive"] = primitive
        out["crypto:primitive"] = "unknown"  # the rule base cannot judge it, so it is not reported as safe
        out["crypto:strength"] = "unknown"
        display = name
    if size and not param:
        out["crypto:keySize"] = str(size)
    if mode:
        out["crypto:mode"] = mode
    if algo.get("curve"):
        out["crypto:curve"] = str(algo["curve"])[:64]
    elif key in ("ecdsa", "ecdh") and _CURVE.match(re.sub(r"[^a-z0-9]", "", name.lower())):
        out["crypto:curve"] = name[:64]  # a curve name such as P-256 is the curve, not a key size
    return display, out


def _protocol_props(name: str, proto: dict[str, Any], props: dict[str, str]) -> dict[str, str]:
    out = dict(props)
    out["crypto:assetType"] = "protocol"
    ptype = str(proto.get("type") or props.get("crypto:protocolType") or "").lower()
    if not ptype:
        low = name.lower()
        ptype = next((t for t in ("tls", "ssh", "ipsec", "ike", "dtls") if t in low), "other")
    version = str(proto.get("version") or props.get("crypto:protocolVersion") or "").strip()
    if not version:
        m = re.search(r"(\d+(?:\.\d+)?)", name)
        version = m.group(1) if m else ""
    out["crypto:protocolType"] = ptype
    if version:
        out["crypto:protocolVersion"] = version[:20]
    suites = [str(s.get("name")) for s in _l(proto.get("cipherSuites")) if isinstance(s, dict) and s.get("name")]
    if suites:
        out["crypto:cipherSuite"] = ",".join(suites[:200])
    weak = False
    if ptype in ("tls", "dtls", "ssl") and version:
        v = version.lower().replace(" ", "").replace("_", ".")
        bare = re.sub(r"^(tls|dtls|ssl)v?", "", v)
        weak = v.startswith("ssl") or "ssl" in name.lower() or bare in ("1", "1.0", "1.1", "10", "11", "2", "3", "3.0")
    elif ptype == "ssh" and version:
        weak = version.startswith("1")
    elif ptype in ("ike", "ipsec") and version:
        weak = re.sub(r"^(ike)?v?", "", version.lower()) in ("1", "1.0")
    out["crypto:strength"] = "weak" if weak else ("strong" if version else "unknown")
    return out


def _certificate_props(cert: dict[str, Any], props: dict[str, str], refs: dict[str, dict]) -> dict[str, str]:
    out = dict(props)
    out["crypto:assetType"] = "certificate"
    for src, dst in (("subjectName", "crypto:subjectName"), ("issuerName", "crypto:issuerName"),
                     ("notValidBefore", "crypto:notValidBefore"), ("notValidAfter", "crypto:notValidAfter")):
        if cert.get(src):
            out[dst] = str(cert[src])[:300]
    sig = refs.get(str(cert.get("signatureAlgorithmRef") or ""))
    if sig is not None and not out.get("crypto:signatureAlgorithm"):
        out["crypto:signatureAlgorithm"] = str(sig.get("name") or "")[:80]
    pub = refs.get(str(cert.get("subjectPublicKeyRef") or ""))
    if pub is not None:
        pub_crypto = _d(pub.get("cryptoProperties"))
        material = _d(pub_crypto.get("relatedCryptoMaterialProperties"))
        # CycloneDX 1.6: the subject's public key (related-crypto-material),
        # whose algorithmRef names its algorithm
        key_comp = pub
        if pub_crypto.get("assetType") == "related-crypto-material":
            key_comp = refs.get(str(material.get("algorithmRef") or "")) or {}
        algo = _d(_d(key_comp.get("cryptoProperties")).get("algorithmProperties"))
        hint = _int(material.get("size")) or _int(algo.get("parameterSetIdentifier"))
        key, size = None, None
        # the key algorithm's own name ("RSA"), else the key's label ("EC-secp384r1"),
        # else its curve: "EC" alone names no algorithm the rule base knows, its curve does
        for name in (key_comp.get("name"), pub.get("name"), algo.get("curve")):
            key, size, _mode, _param = resolve_algorithm(str(name or ""), hint)
            if key:
                break
        size = _int(material.get("size")) or size
        if key and not out.get("crypto:publicKeyAlgorithm"):
            out["crypto:publicKeyAlgorithm"] = key.split("-")[0].upper()
        if size and not out.get("crypto:keySize"):
            out["crypto:keySize"] = str(size)
        if algo.get("curve") and not out.get("crypto:curve"):
            out["crypto:curve"] = str(algo["curve"])[:64]
    if out.get("crypto:subjectName") and out.get("crypto:subjectName") == out.get("crypto:issuerName"):
        out.setdefault("crypto:selfSigned", "true")
    return out


def _material_props(mat: dict[str, Any], props: dict[str, str], refs: dict[str, dict]) -> dict[str, str]:
    out = dict(props)
    out["crypto:assetType"] = "related-crypto-material"
    if mat.get("type"):
        out["crypto:materialKind"] = str(mat["type"])[:40]
    size = _int(mat.get("size"))
    if size:
        out["crypto:keySize"] = str(size)
    algo = refs.get(str(mat.get("algorithmRef") or ""))
    if algo is not None:
        out["crypto:algorithm"] = str(algo.get("name") or "")[:80]
    return out


def _older_than_16(version: str) -> bool:
    try:
        major, minor = (int(x) for x in version.split(".")[:2])
    except ValueError:
        return False
    return (major, minor) < (1, 6)


def _is_certificate_part(comp: dict[str, Any]) -> bool:
    """A ZeroShield run export's certificate part (``zs:part_of`` = ``certificate``)."""
    return any(
        isinstance(p, dict)
        and p.get("name") == "zs:part_of"
        and p.get("value") == "certificate"
        for p in _l(comp.get("properties"))
    )


def components_from_cyclonedx(doc: Any) -> tuple[list[CryptoAssetComponent], IngestStats]:
    """Crypto-asset components from a CycloneDX document; non-crypto and malformed entries are counted, not raised."""
    stats = IngestStats()
    if not isinstance(doc, dict):
        stats.notes.append("The file is not a CycloneDX JSON object.")
        return [], stats
    stats.spec_version = str(doc.get("specVersion") or "") or None
    if doc.get("bomFormat") not in (None, "CycloneDX"):
        stats.notes.append(f"bomFormat is {doc.get('bomFormat')!r}, not CycloneDX.")
    every = list(_walk(doc.get("components")))
    stats.components_total = len(every)
    refs = {str(c.get("bom-ref")): c for c in every if isinstance(c.get("bom-ref"), (str, int)) and c.get("bom-ref")}
    out: list[CryptoAssetComponent] = []
    seen: set[str] = set()
    next_n: dict[str, int] = {}
    for comp in every:
        if comp.get("type") != "cryptographic-asset":
            stats.skipped_not_crypto += 1
            continue
        # read through the certificates' refs below, not an asset of its own
        if _is_certificate_part(comp):
            stats.certificate_parts += 1
            continue
        stats.crypto_assets += 1
        if len(out) >= MAX_COMPONENTS:
            stats.truncated = True
            continue
        name = str(comp.get("name") or "").strip()[:200]
        crypto = _d(comp.get("cryptoProperties"))
        asset_type = crypto.get("assetType")
        if not name or not isinstance(asset_type, str) or asset_type not in _ASSET_TYPES:
            stats.skipped_invalid += 1
            continue
        props: dict[str, str] = {}
        for p in _l(comp.get("properties")):
            if isinstance(p, dict) and isinstance(p.get("name"), str) and p.get("value") is not None:
                key = p["name"]
                if key.startswith(("crypto:", "discovery:")) and key not in _RECOMPUTED:
                    props[key] = str(p["value"])[:500]
        occ = _l(_d(comp.get("evidence")).get("occurrences"))
        location = next((str(o.get("location")) for o in occ if isinstance(o, dict) and o.get("location")), None)
        if location and not props.get("discovery:source"):
            props["discovery:source"] = location[:500]
        props["discovery:origin"] = "uploaded-cbom"
        display = name
        if asset_type == "algorithm":
            display, props = _algorithm_props(name, _d(crypto.get("algorithmProperties")), props)
        elif asset_type == "protocol":
            props = _protocol_props(name, _d(crypto.get("protocolProperties")), props)
        elif asset_type == "certificate":
            props = _certificate_props(_d(crypto.get("certificateProperties")), props, refs)
        else:
            props = _material_props(_d(crypto.get("relatedCryptoMaterialProperties")), props, refs)
        base = f"upload-{asset_type[:4]}-{_slug(comp.get('bom-ref') or name)}"
        ref = base
        if ref in seen:  # a repeated bom-ref: number the copies (linear, however many repeat)
            stats.duplicates += 1
            n = next_n.get(base, 1)
            while ref in seen:
                n += 1
                ref = f"{base}-{n}"
            next_n[base] = n
        seen.add(ref)
        out.append(CryptoAssetComponent(bom_ref=ref, name=display, properties=props))
    stats.imported = len(out)
    if stats.crypto_assets == 0:
        if stats.spec_version and _older_than_16(stats.spec_version):
            stats.notes.append(f"CycloneDX {stats.spec_version} has no cryptographic-asset type; export a 1.6 CBOM.")
        else:
            stats.notes.append("The file has no cryptographic-asset components.")
    if stats.truncated:
        stats.notes.append(f"Only the first {MAX_COMPONENTS} cryptographic assets were analysed.")
    if stats.certificate_parts:
        stats.notes.append(
            f"{stats.certificate_parts} component(s) describe parts of certificates "
            "(signature algorithm, public key, key algorithm); they were read into the "
            "certificates that reference them, not judged as assets of their own."
        )
    return out, stats


__all__ = ["IngestStats", "MAX_COMPONENTS", "components_from_cyclonedx", "resolve_algorithm"]
