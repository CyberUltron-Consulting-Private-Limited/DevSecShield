"""Algorithm identity: one answer to "which algorithm is this, is it quantum-safe?".

Identifiers come in many shapes: dotted OIDs (X.509, PKCS#8), IANA TLS group and
signature-scheme codepoints, SSH key-exchange names, IKEv2 transform ids, cloud API
enums and the names OpenSSL prints. ``resolve`` maps each one to an ``Identity``: a
canonical name, the family label the CBOM rules use, the FIPS 203/204/205 parameter
set and NIST category, the construction (pure, hybrid, composite, classical), the
status and the quantum verdict.

This file and its tables (algid_tables.py) are vendored BYTE-IDENTICAL into the scan
node (scan_node/zs_scan_node/), the backend (backend/utilities/cbom_sources/) and the
code lane (aibom/src/aibom/cbom/), because those packages cannot import each other; a
backend test fails when the copies differ. algid_tables.py is written by
scripts/algid/build_algid.py from the captured registries in scripts/algid/sources:
change a source and regenerate, never edit a table by hand. This file is hand-written:
edit the backend copy only, then run ``build_algid.py --sync``. Stdlib only. The tables
are read-only. ``resolve`` keeps one bounded LRU memo of str lookups (CB-04 ST-9),
cleared when a table it reads is rebound, so it never answers from an older table.

``status`` follows one rule for every registry row (curated.json "status_rule"): a
published RFC is ``standard``; an RFC-to-be (``RFC-ietf-*``) or an Internet-Draft is
``draft``; "obsolete" in the registry is ``obsolete``. Curated rows state theirs
(``pre-standard`` round-3 names, ``candidate`` NIST round-4 KEMs). Credit is only ever
given for ``standard`` (CB-16).
"""

from __future__ import annotations

import functools
import re
import unicodedata
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, NamedTuple

from . import algid_tables as _t


class Identity(NamedTuple):
    """What an identifier names (``name`` is None for marker/fallback/prefix hits)."""

    name: str | None
    # PQ RSA EC ECDSA ECDH ED25519 ED448 EDDSA X25519 X448 DSA DH SM2, or None
    family_label: str | None
    primitive: str | None  # CycloneDX 1.6: signature, kem, key-agree, pke, ...
    oid: str | None
    standard: str | None  # FIPS 204, SP 800-208, RFC 10073, ... (published only)
    status: str | None  # standard, draft, obsolete, pre-standard, candidate
    # a FIPS 203/204/205 set (or FN-DSA's); None for pre-standard and obsolete names
    parameter_set: str | None
    nist_category: int | None  # FIPS 203/204/205 and FN-DSA parameter sets only
    construction: str | None  # pure, hybrid, composite, classical
    quantum: str | None  # vulnerable, safe, hybrid; None: no public-key verdict
    key_size: int | None  # curve bits (EC, SM2, GOST), RSA modulus; None for PQ
    # canonical algid names (rows); a composite's hash and padding stay in its name
    components: tuple[str, ...]
    stateful: bool  # LMS, HSS, XMSS, XMSS^MT
    matched_by: str  # oid codepoint enum name alias marker fallback oid-prefix


SOURCES_SHA256: str = _t.SOURCES_SHA256
_ALGS: Mapping[str, tuple[Any, ...]] = _t.ALGS
_OIDS: Mapping[str, str] = _t.OIDS
_TLS_GROUPS: Mapping[int, str] = _t.TLS_GROUPS
_TLS_SIGSCHEMES: Mapping[int, str] = _t.TLS_SIGSCHEMES
_SSH_KEX: Mapping[str, str] = _t.SSH_KEX
_IKE_KE: Mapping[int, str] = _t.IKE_KE
_IKE_KE_NAMES: Mapping[int, str] = _t.IKE_KE_NAMES
_AWS: Mapping[str, Mapping[str, str]] = _t.AWS
_AWS_TLS_POLICY: Mapping[str, Mapping[str, tuple[str, ...]]] = _t.AWS_TLS_POLICY
_OPENSSL_TEXT: Mapping[str, str] = _t.OPENSSL_TEXT
_ALIASES: Mapping[str, str] = _t.ALIASES
_X509_NAMES: Mapping[str, str] = _t.CODE_LANE_X509_NAMES
_X509_KEYS: Mapping[str, str] = _t.CODE_LANE_X509_KEYS
_GCP: Mapping[str, str] = _t.GCP
_KMIP: Mapping[int, str] = _t.KMIP
_PKCS11_KEY_TYPES: Mapping[int, str] = _t.PKCS11_KEY_TYPES
_PKCS11_PARAMETER_SETS: Mapping[int, Mapping[int, str]] = _t.PKCS11_PARAMETER_SETS
_JOSE_KEY_TYPES: tuple[str, ...] = _t.JOSE_KEY_TYPES
_JOSE_KTY: Mapping[str, str] = _t.JOSE_KTY
_JOSE_CRV: Mapping[str, str] = _t.JOSE_CRV
_JOSE_ALG: Mapping[str, str] = _t.JOSE_ALG
# The families a crv or alg may name for each JWK key type (RFC 7518 s6, RFC 8037,
# RFC 9964); oct (symmetric) has none.
_JOSE_FAMILIES: Mapping[str, frozenset[str]] = MappingProxyType({
    "RSA": frozenset({"RSA"}),
    "EC": frozenset({"EC", "ECDSA"}),
    "OKP": frozenset({"ED25519", "ED448", "X25519", "X448", "EDDSA"}),
    "AKP": frozenset({"PQ"}),
})
_OID_PREFIXES: tuple[tuple[str, str, str | None], ...] = _t.OID_PREFIXES
_GREASE: tuple[int, ...] = _t.GREASE
_PQ_MARKERS: tuple[str, ...] = _t.PQ_MARKERS
_PRE_STANDARD_MARKERS: tuple[str, ...] = _t.PRE_STANDARD_MARKERS
_CLASSICAL_MARKERS: tuple[str, ...] = _t.CLASSICAL_MARKERS
# Prober lists (DA s5). DA s5's pinned lists govern over s0's wording "every IANA TLS
# 1.3 group": TLS13_OFFER_GROUPS stops at 42 (no bign 43/44), by coordinator decision.
TLS13_OFFER_GROUPS: tuple[int, ...] = _t.TLS13_OFFER_GROUPS
PQ_PROBE_GROUPS: tuple[int, ...] = _t.PQ_PROBE_GROUPS
TLS13_SIGSCHEMES: tuple[int, ...] = _t.TLS13_SIGSCHEMES
S_CLIENT_GROUPS_35: str = _t.S_CLIENT_GROUPS_35
TLS_CLASSICAL_SIGSCHEME_NAMES: tuple[str, ...] = _t.TLS_CLASSICAL_SIGSCHEME_NAMES

_REVERSE_OID: Mapping[str, str] = MappingProxyType(
    {name: oid for oid, name in reversed(list(_OIDS.items()))}
)

NAMESPACES = ("tls_group", "tls_sigscheme", "ssh_kex", "ike_ke", "openssl_text", "name")
_SENTINELS = frozenset(
    {"", "<null>", "(none)", "none", "null", "unknown", "unknown oid"}
)
_OID_RE = re.compile(r"^[0-2](\.(0|[1-9][0-9]*))+$")
_SEPARATORS = re.compile(r"[\W_]+")
_STATEFUL = frozenset({"LMS", "HSS", "XMSS", "XMSS^MT"})
# Markers short enough to sit inside ordinary words ("realms", "bikes", "SHA1 with
# SSH"): each must start a token and be followed in it by nothing, digits, or a
# NIST level (oqs-provider's "bikel1", "hqc128").
_TOKEN_MARKERS = frozenset({"LMS", "HSS", "HQC", "BIKE"})
_TOKEN_TAIL = re.compile(r"(?:L?\d.*)?")
_KEM_MARKERS = frozenset(
    {"MLKEM", "KYBER", "FRODO", "HQC", "MCELIECE", "BIKE", "XWING", "SNTRUP"}
)
_QV_FAMILIES = frozenset(
    {"RSA", "DSA", "DH", "ECDSA", "ECDH", "EC", "ED25519", "ED448", "EDDSA"}
    | {"X25519", "X448", "SM2"}
)
# A DSA token that is part of a PQ name (ML-DSA, SLH-DSA, FN-DSA, HashML-DSA) or of
# ECDSA/EdDSA, whatever separates the letters: never the classical DSA family.
_NOT_DSA = re.compile(r"(ML|SLH|FN|HASHML|EC|ED)DSA")
_OPENSSL_VERSION = re.compile(r"^OpenSSL (\d+)\.(\d+)")


def _bare(
    family: str | None,
    primitive: str | None,
    status: str | None,
    construction: str | None,
    quantum: str | None,
    stateful: bool,
    matched_by: str,
    oid: str | None = None,
    name: str | None = None,
) -> Identity:
    return Identity(
        name, family, primitive, oid, None, status, None, None, construction,
        quantum, None, (), stateful, matched_by,
    )


# RFC 8701 GREASE codepoints in a TLS group list: a sentinel, never an algorithm.
GREASE = _bare(None, None, None, None, None, False, "codepoint", name="GREASE")


def _norm(text: str) -> str:
    """Unicode NFKC, every non-alphanumeric character removed, case-folded: the key of
    the alias table, so a lookup never depends on letter case or on which dash or space
    a source used (an ML-DSA name typed with non-breaking hyphens is still ML-DSA)."""
    return _SEPARATORS.sub("", unicodedata.normalize("NFKC", text)).casefold()


def _identity(name: str, matched_by: str, oid: str | None = None) -> Identity:
    a = _ALGS[name]
    return Identity(
        name, a[0], a[1], oid or _REVERSE_OID.get(name), a[2], a[3], a[4], a[5],
        a[6], a[7], a[8], tuple(a[9]), name in _STATEFUL, matched_by,
    )


def _by_oid(oid: str) -> Identity | None:
    name = _OIDS.get(oid)
    if name is not None:
        return _identity(name, "oid", oid)
    for prefix, hint_text, primitive in _OID_PREFIXES:
        if oid.startswith(prefix) and hint_text == "composite-prototype":
            return _bare(
                "PQ", primitive, "pre-standard", "composite", "hybrid", False,
                "oid-prefix", oid,
            )
    return None


def _starts_token(marker: str, tokens: list[str]) -> bool:
    return any(
        tok.startswith(marker) and _TOKEN_TAIL.fullmatch(tok, len(marker))
        for tok in tokens
    )


def _marker(text: str) -> Identity | None:
    """A PQ marker in the text. LMS, HSS, HQC and BIKE must start a token and be
    followed in it only by digits or a level ("LMS_SHA256_M32_H10", "HSS/LMS",
    "hqc128", "p256_bikel1"), so "SHA1 with SSH", "realms" or "bikes" never read as
    post-quantum. Every other marker, XMSS included, may sit anywhere in the text
    with its separators removed ("SHA256withXMSS", "X25519MLKEM768")."""
    compact = _norm(text).upper()
    tokens = _SEPARATORS.split(unicodedata.normalize("NFKC", text).upper())
    found = [
        m for m in _PQ_MARKERS
        if (_starts_token(m, tokens) if m in _TOKEN_MARKERS else m in compact)
    ]
    if not found:
        return None
    kem = any(m in _KEM_MARKERS for m in found)
    classical = any(c in compact for c in _CLASSICAL_MARKERS) or "XWING" in found
    construction = ("hybrid" if kem else "composite") if classical else "pure"
    pre = any(m in _PRE_STANDARD_MARKERS for m in found)
    stateful = any(m in found for m in ("LMS", "HSS", "XMSS"))
    return _bare(
        "PQ", "kem" if kem else "signature", "pre-standard" if pre else None,
        construction, "hybrid" if classical else "safe", stateful, "marker",
    )


def _fallback(text: str) -> Identity | None:
    """classify.family's classical rules before algid, with a token-bounded DSA."""
    up = unicodedata.normalize("NFKC", text).upper().replace("_", "-")
    compact = _SEPARATORS.sub("", up)
    family: str | None = None
    for name in ("ED25519", "ED448", "X25519", "X448", "EDDSA", "ECDSA", "ECDH"):
        if name in up:
            family = name
            break
    if family is None and "DSA" in up and "DSA" in _NOT_DSA.sub("", compact):
        family = "DSA"
    for name in ("RSA", "SM2"):
        if family is None and name in up:
            family = name
    if family is None and up.startswith(
        ("EC", "ID-EC", "PRIME256", "SECP", "P-256", "P-384", "P-521", "NIST")
    ):
        family = "EC"
    if family is None and (
        up in ("DH", "DHE", "FFDHE") or up.startswith(("DH-", "FFDHE", "DIFFIE"))
    ):
        family = "DH"
    if family is None:
        return None
    quantum = "vulnerable" if family in _QV_FAMILIES else None
    return _bare(family, None, None, "classical", quantum, False, "fallback")


def resolve(value: object, namespace: str | None = None) -> Identity | None:
    """The identity of ``value``, or None when it names nothing known.

    Only ``str`` values (and ``int`` codepoints with a codepoint namespace) are
    identifiers; anything else (bytes, lists, None, bools) gives None. A dotted OID is
    looked up in the OID table. With ``namespace`` the lookup is exact in that namespace
    only (strict, no fallback). Otherwise: the name/alias table (NFKC, separators
    removed, case-folded, so letter case and dashes never change the answer), the PQ
    marker scan, then the classical fallback. Sentinels ("<NULL>", "(NONE)",
    "Unknown OID", "") give None.
    """
    if namespace is not None and namespace not in NAMESPACES:
        raise ValueError(f"unknown namespace {namespace!r}")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if namespace == "tls_group":
            return tls_group(value)
        if namespace == "tls_sigscheme":
            return tls_sigscheme(value)
        if namespace == "ike_ke":
            return ike_ke(value)
        return None
    if not isinstance(value, str):
        return None
    if len(value) > _MEMO_MAX_TEXT:
        return _resolve_text(value, namespace)
    global _memo_tables
    tables = _lookup_tables()
    if tables != _memo_tables:  # a table was rebound in this process
        _resolve_memo.cache_clear()
        _memo_tables = tables
    return _resolve_memo(value, namespace)


def _resolve_text(value: str, namespace: str | None) -> Identity | None:
    text = value.strip()
    if text.casefold() in _SENTINELS:
        return None
    if _OID_RE.match(text):
        return _by_oid(text)
    if namespace is not None:
        return _strict(text, namespace)
    return _named(text) or _marker(text) or _fallback(text)


# The memo (CB-04 ST-9): an LRU of at most 4,096 str lookups, never an unbounded dict
# (identifiers come from scan nodes), and none for text longer than 256 characters.
# An Identity is immutable, so one cached answer can be shared. Every table a str
# lookup reads is compared by identity on each call; when one was rebound (a test, a
# reload) the memo is cleared first, so it never serves an older table's answer.
_MEMO_MAX_TEXT = 256
_resolve_memo = functools.lru_cache(maxsize=4096)(_resolve_text)


def _lookup_tables() -> tuple[object, ...]:
    return (
        _ALGS, _OIDS, _ALIASES, _REVERSE_OID, _OID_PREFIXES, _PQ_MARKERS,
        _PRE_STANDARD_MARKERS, _CLASSICAL_MARKERS, _KEM_MARKERS, _TOKEN_MARKERS,
        _STATEFUL, _QV_FAMILIES, _SENTINELS, _NOT_DSA, _OPENSSL_TEXT, _SSH_KEX,
        _IKE_KE, _IKE_KE_NAMES, _TLS_GROUPS, _TLS_SIGSCHEMES,
    )


def _named(text: str) -> Identity | None:
    name = _ALIASES.get(_norm(text))
    if name is None:
        return None
    return _identity(name, "name" if name == text else "alias")


def _strict(text: str, namespace: str) -> Identity | None:
    if namespace == "openssl_text":
        name = _OPENSSL_TEXT.get(text)
        return _identity(name, "name") if name else None
    if namespace == "ssh_kex":
        return ssh_kex(text)
    if namespace == "name":
        return _named(text)
    if namespace == "ike_ke":  # the product spelling (ML-KEM-768) names the binding row
        for transform_id, spelling in _IKE_KE_NAMES.items():
            if spelling == text:
                return _identity(_IKE_KE[transform_id], "name")
    tables = {
        "tls_group": _TLS_GROUPS,
        "tls_sigscheme": _TLS_SIGSCHEMES,
        "ike_ke": _IKE_KE,
    }
    found = text in tables[namespace].values()
    return _identity(text, "name") if found else None


def _codepoint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def tls_group(codepoint: int) -> Identity | None:
    """IANA TLS Supported Groups codepoint (RFC 8701 GREASE gives ``GREASE``)."""
    if not _codepoint(codepoint):
        return None
    if codepoint in _GREASE:
        return GREASE
    name = _TLS_GROUPS.get(codepoint)
    return _identity(name, "codepoint") if name else None


def tls_sigscheme(codepoint: int) -> Identity | None:
    """IANA TLS SignatureScheme codepoint."""
    if not _codepoint(codepoint):
        return None
    name = _TLS_SIGSCHEMES.get(codepoint)
    return _identity(name, "codepoint") if name else None


def ike_ke(transform_id: int) -> Identity | None:
    """IKEv2 Transform Type 4 id. Rows are named with the product's spellings
    (MODP-2048...), except the ML-KEM bindings 35-37 (ml-kem-NNN, draft), whose
    product spelling is the FIPS 203 algorithm row: ``ike_name`` gives what the
    product emits."""
    if not _codepoint(transform_id):
        return None
    name = _IKE_KE.get(transform_id)
    return _identity(name, "codepoint") if name else None


def ike_name(transform_id: int) -> str | None:
    """The name the product emits for an IKEv2 Transform Type 4 id, exactly as
    ikeprobe.GROUPS and appliance_parsers do today ("MODP-2048", "ML-KEM-768")."""
    if not _codepoint(transform_id):
        return None
    return _IKE_KE_NAMES.get(transform_id)


def ssh_kex(method: str) -> Identity | None:
    """SSH key-exchange method, including OpenSSH @openssh.com / @libssh.org
    spellings and the registry's wildcard families (ecdh-sha2-*, gss-*)."""
    if not isinstance(method, str):
        return None
    name = _SSH_KEX.get(method)
    if name is not None:
        return _identity(name, "name")
    best = ""
    for pattern in _SSH_KEX:
        if not pattern.endswith("*") or len(pattern) <= len(best):
            continue
        if method.startswith(pattern[:-1]):
            best = pattern
    return _identity(_SSH_KEX[best], "name") if best else None


def _enum_key(value: str) -> str:
    return value.strip().upper().replace("-", "_")


def aws(service: str, field: str, value: object) -> Identity | None:
    """An AWS API enum value, e.g. aws("acm-pca", "KeyAlgorithm", "ML_DSA_65"). Case,
    '-' and '_' are equivalent ("RSA-2048" is "RSA_2048")."""
    table = _AWS.get(f"{service}.{field}")
    if table is None or not isinstance(value, str):
        return None
    want = _enum_key(value)
    for enum_value, name in table.items():
        if _enum_key(enum_value) == want:
            return _identity(name, "enum")
    return None


def aws_tls_policy(service: str, name: object) -> tuple[str, ...] | None:
    """The hybrid groups a named AWS TLS policy offers: a tuple (empty when AWS
    documents the policy as post-quantum without naming groups), or None for a policy
    with no post-quantum key exchange."""
    table = _AWS_TLS_POLICY.get(service)
    if table is None or not isinstance(name, str):
        return None
    return table.get(name)


def gcp(value: object) -> Identity | None:
    """A Cloud KMS CryptoKeyVersionAlgorithm value, e.g. "KEM_XWING" or
    "PQ_SIGN_ML_DSA_65" (case-insensitive). The identity is the key's: the signing
    scheme and digest an enum names stay in the enum."""
    if not isinstance(value, str):
        return None
    name = _GCP.get(value.strip().upper())
    return _identity(name, "enum") if name else None


def kmip(value: int) -> Identity | None:
    """A KMIP Cryptographic Algorithm enumeration value (KMIP 3.0: 0x3D is ML-DSA-65).
    Symmetric ciphers, hashes and MACs with no algid row give None."""
    if not _codepoint(value):
        return None
    name = _KMIP.get(value)
    return _identity(name, "enum") if name else None


def pkcs11_key_type(key_type: int, parameter_set: int | None = None) -> Identity | None:
    """A PKCS#11 CKA_KEY_TYPE (CKK_*), refined by CKA_PARAMETER_SET (CKP_*) for ML-DSA,
    SLH-DSA and ML-KEM keys: pkcs11_key_type(0x4A, 2) is ML-DSA-65, and 0x4A alone (or
    with a parameter set PKCS#11 3.2 does not define) is the ML-DSA family."""
    if not _codepoint(key_type):
        return None
    name = _PKCS11_KEY_TYPES.get(key_type)
    if name is None:
        return None
    sets = _PKCS11_PARAMETER_SETS.get(key_type) or {}
    if isinstance(parameter_set, int) and not isinstance(parameter_set, bool):
        name = sets.get(parameter_set, name)
    return _identity(name, "enum")


def jose(kty: object, alg: object = None, crv: object = None) -> Identity | None:
    """A JSON Web Key's algorithm. ``kty`` (REQUIRED, RFC 7517 s4.1) must be a
    registered key type and decides the family; ``crv`` (EC, OKP), else ``alg``
    (OPTIONAL, only the intended use), refines it when its family fits the key type:
    an AKP key (RFC 9964) is named by its alg, ML-DSA-44/65/87. A crv or alg of another
    family is ignored (an RSA key with alg ML-DSA-65 is RSA), so the key type alone
    answers: EC, RSA, or None for a symmetric ``oct`` key and an OKP/AKP key."""
    if not isinstance(kty, str) or kty not in _JOSE_KEY_TYPES:
        return None
    fits = _JOSE_FAMILIES.get(kty, frozenset())
    for table, member in ((_JOSE_CRV, crv), (_JOSE_ALG, alg)):
        name = table.get(member) if isinstance(member, str) else None
        if name and _ALGS[name][0] in fits:
            return _identity(name, "enum")
    name = _JOSE_KTY.get(kty)
    return _identity(name, "enum") if name else None


def openssl_text(text: str) -> Identity | None:
    """The algorithm text OpenSSL 3.0 or 3.5 prints in ``x509 -text`` (strict)."""
    return resolve(text, "openssl_text")


def hint(value: object) -> str | None:
    """Why an OID is unknown: "oqs-arc" or "composite-prototype" for known arcs."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not _OID_RE.match(text) or text in _OIDS:
        return None
    for prefix, hint_text, _primitive in _OID_PREFIXES:
        if text.startswith(prefix):
            return hint_text
    return None


def is_sentinel(value: object) -> bool:
    """True for the placeholder texts tools print where there is no algorithm
    ("<NULL>", "(NONE)", "Unknown OID", "none", ""): absent, not unknown."""
    return isinstance(value, str) and value.strip().casefold() in _SENTINELS


def family_label(value: object) -> str | None:
    found = resolve(value)
    return found.family_label if found else None


def quantum_vulnerable(value: object) -> bool | None:
    """True for quantum-vulnerable public-key algorithms, False for PQ (pure, hybrid,
    composite), None when the value carries no public-key verdict."""
    found = resolve(value)
    if found is None:
        return None
    return {"vulnerable": True, "safe": False, "hybrid": False}.get(found.quantum or "")


def compare_key(value: object) -> object:
    """The canonical name when ``value`` is an identifier (a dotted OID or a cloud enum
    value), else ``value`` unchanged: an OID and its name compare equal, any other
    string compares as stored. The generator refuses two enum values of one field that
    name the same row, so two different enum values never compare equal."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if _OID_RE.match(text):
        found = _by_oid(text)
        return found.name if found and found.name else value
    for table in _AWS.values():
        if text in table:
            return table[text]
    return value


def code_lane_x509_name(oid: str) -> str:
    """The code lane's string for a certificate algorithm OID: its historic strings
    unchanged (bom-refs use them), else the canonical name, else the OID."""
    return _X509_NAMES.get(oid) or _OIDS.get(oid) or oid


def code_lane_x509_key(oid: str) -> str | None:
    """The code lane's key-type label for a private-key AlgorithmIdentifier OID."""
    return _X509_KEYS.get(oid) or _OIDS.get(oid)


def openssl_major_minor(version_text: str) -> tuple[int, int] | None:
    """(major, minor) from ``openssl version`` output; None for LibreSSL or other."""
    if not isinstance(version_text, str):
        return None
    m = _OPENSSL_VERSION.match(version_text)
    return (int(m.group(1)), int(m.group(2))) if m else None


# ------------------------------------------------------------------- DER readers
# They return OIDs only, and never return or log key bytes. Anything that is not
# bytes or bytearray gives None.
def _tlv(der: bytes, i: int, end: int) -> tuple[int, int, int] | None:
    """(tag, body start, body end) of the element at ``i``; None when malformed."""
    if i + 2 > end:
        return None
    tag, length, j = der[i], der[i + 1], i + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or j + n > end:
            return None
        length, j = int.from_bytes(der[j : j + n], "big"), j + n
    if j + length > end:
        return None
    return tag, j, j + length


def _elements(
    der: bytes, start: int, end: int
) -> list[tuple[int, int, int, int]] | None:
    """(tag, element start, body start, body end) of each child in [start, end)."""
    out, i = [], start
    while i < end:
        item = _tlv(der, i, end)
        if item is None:
            return None
        out.append((item[0], i, item[1], item[2]))
        i = item[2]
    return out


def _oid_text(body: bytes) -> str | None:
    """Dotted text of an OBJECT IDENTIFIER body (X.690 8.19). The first subidentifier
    is a base-128 number like the others (2.999 is 0x88 0x37); a subidentifier that
    starts with 0x80 is not minimal and gives None."""
    if not body or body[-1] & 0x80:
        return None
    values, val, start = [], 0, True
    for b in body:
        if start and b == 0x80:
            return None
        val = (val << 7) | (b & 0x7F)
        start = not b & 0x80
        if start:
            values.append(val)
            val = 0
    first = values[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(p) for p in head + values[1:])


def _alg_id(der: bytes, start: int, end: int) -> tuple[str, str | None] | None:
    kids = _elements(der, start, end)
    if not kids or kids[0][0] != 0x06:
        return None
    oid = _oid_text(der[kids[0][2] : kids[0][3]])
    if oid is None:
        return None
    params: str | None = None
    if len(kids) > 1 and kids[1][0] == 0x06:
        params = _oid_text(der[kids[1][2] : kids[1][3]])
    elif len(kids) > 1 and kids[1][0] == 0x30:
        params = "explicit"
    return oid, params


def _der(value: object) -> bytes | None:
    return bytes(value) if isinstance(value, (bytes, bytearray)) and value else None


def _top_children(der: bytes) -> list[tuple[int, int, int, int]] | None:
    top = _tlv(der, 0, len(der))
    if top is None or top[0] != 0x30:
        return None
    return _elements(der, top[1], top[2])


def spki_alg(der: bytes) -> tuple[str, str | None] | None:
    """(algorithm OID, parameters OID | "explicit" | None) of a SubjectPublicKeyInfo."""
    data = _der(der)
    kids = _top_children(data) if data else None
    if not data or not kids or len(kids) < 2:
        return None
    if kids[0][0] != 0x30 or kids[1][0] != 0x03:
        return None
    return _alg_id(data, kids[0][2], kids[0][3])


def pkcs8_alg(der: bytes) -> str | None:
    """The algorithm OID of an unencrypted PKCS#8 PrivateKeyInfo / OneAsymmetricKey."""
    data = _der(der)
    kids = _top_children(data) if data else None
    if not data or not kids or len(kids) < 3:
        return None
    if kids[0][0] != 0x02 or kids[1][0] != 0x30 or kids[2][0] != 0x04:
        return None
    found = _alg_id(data, kids[1][2], kids[1][3])
    return found[0] if found else None


def tbs_spki_alg(tbs_der: bytes) -> tuple[str, str | None] | None:
    """``spki_alg`` of the SubjectPublicKeyInfo inside a TBSCertificate."""
    data = _der(tbs_der)
    kids = _top_children(data) if data else None
    if kids and kids[0][0] == 0xA0:  # [0] EXPLICIT version
        kids = kids[1:]
    if not data or not kids or len(kids) < 6:
        return None
    _tag, begin, _body, end = kids[5]
    return spki_alg(data[begin:end])


_memo_tables: tuple[object, ...] = _lookup_tables()
