"""Standards status per asset (CB-16): FIPS 203/204/205, NSA CNSA 2.0, SP 800-131A.

ONE module, two byte-identical copies (a test compares their bytes):
``backend/utilities/cbom_sources/standards.py`` (Sources runs, judged by the server's
classifier) and ``aibom/src/aibom/cbom/standards.py`` (the code lane), so the same
algorithm gets the same statuses in both lanes.  Algorithm identity comes from
``algid`` (the copy beside each file; the single source for post-quantum names,
parameter sets and NIST categories), never from a table here.

``grade(parts)`` judges an asset from its parts, each ``(role, identifier, key_size)``:

* ``key``: a public-key (or symmetric) algorithm with its size (a certificate's or
  key's algorithm, a KMS key spec);
* ``signature``: a signature algorithm name (``sha256WithRSAEncryption``); its hash
  is what is graded here;
* ``cipher``: a cipher or TLS cipher suite (the symmetric cipher and, for CNSA 2.0,
  the suite's hash);
* ``group``: a key-exchange group (``secp384r1``, a hybrid group).

Each standard's asset status is the worst over the parts (statuses in ``RANK``,
worst first), with the reasons that decided it.  ``unknown`` is never shown as a
pass: a key whose size was not read is not "acceptable".
"""

from __future__ import annotations

import re
from typing import Any

from . import algid

STANDARDS: tuple[tuple[str, str], ...] = (
    ("fips_203_204_205", "FIPS 203/204/205"),
    ("cnsa_2_0", "NSA CNSA 2.0"),
    ("sp800_131a", "NIST SP 800-131A"),
)
LABELS = dict(STANDARDS)
# statuses per standard, worst first
RANK: dict[str, tuple[str, ...]] = {
    "fips_203_204_205": ("not_approved", "unknown", "approved", "not_applicable"),
    "cnsa_2_0": ("not_compliant", "unknown", "compliant", "not_applicable"),
    "sp800_131a": (
        "disallowed",
        "not_approved",
        "unknown",
        "acceptable",
        "not_applicable",
    ),
}
VERSION = "std-1"

_FIPS_PQ = ("FIPS 203", "FIPS 204", "FIPS 205")
_TRANSITION = (
    "quantum-vulnerable public-key algorithm: CNSA 2.0 allows it only during the "
    "transition (National "
    "Security Systems use quantum-resistant algorithms only by 2035)"
)
_IR8547_112 = (
    "112-bit security: acceptable today; NIST IR 8547 (draft) deprecates 112-bit "
    "public-key algorithms "
    "after 2030 and disallows quantum-vulnerable ones after 2035"
)
_IR8547_128 = (
    "acceptable today; NIST IR 8547 (draft) disallows quantum-vulnerable public-key "
    "algorithms after 2035"
)
_CNSA_SUITE = (
    "CNSA 2.0 accepts only the category-5 FIPS 203 key-establishment set, the "
    "category-5 FIPS 204 "
    "signature set and SP 800-208 stateful hash-based signatures"
)

_AES = re.compile(r"AES[-_ ]?(128|192|256)", re.I)
_DES = re.compile(
    r"(^|[^A-Z])(3DES|DES|TDEA|TRIPLE[-_ ]?DES|DES[-_]?EDE3?|DES[-_]?CBC3?)([^A-Z]|$)",
    re.I,
)
_BROKEN = re.compile(
    r"(^|[^A-Z])(RC4|ARCFOUR|RC2|BLOWFISH|NULL|EXPORT|MD5|MD4|MD2)([^A-Z0-9]|$)", re.I
)
_NOT_FIPS_CIPHER = re.compile(r"CHACHA20|CAMELLIA|ARIA|SEED|IDEA|GOST|SM4", re.I)
_SHA = re.compile(
    r"SHA[-_ ]?(1|224|256|384|512)(?!\d)|SHA3[-_ ]?(224|256|384|512)", re.I
)
_SUITE_HASH = re.compile(r"SHA(256|384|512)?$|_SHA(256|384|512)?$", re.I)


def _verdict(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {"status": status, "reason": reason, **extra}


def _hash_bits(text: str) -> int | str | None:
    """The hash a name carries: ``"md5"`` (MD5/MD4/MD2), 1 (SHA-1), or the SHA-2/SHA-3
    output bits."""
    if re.search(r"MD[245]", text, re.I):
        return "md5"
    m = _SHA.search(text)
    if not m:
        return None
    return int(m.group(1) or m.group(2))


def _symmetric(
    text: str, size: int | None, suite: bool
) -> dict[str, dict[str, Any]] | None:
    """Ciphers (and, for a TLS suite, its hash for CNSA 2.0); None when the text names
    no known cipher."""
    out: dict[str, dict[str, Any]] = {}
    broken, other = _BROKEN.search(text), _NOT_FIPS_CIPHER.search(text)
    if broken:
        name = broken.group(2).upper()
        out["sp800_131a"] = _verdict(
            "disallowed", f"{name} is not an approved algorithm (SP 800-131A)"
        )
        out["cnsa_2_0"] = _verdict(
            "not_compliant", f"{name} is not a CNSA 2.0 algorithm"
        )
    elif _DES.search(text):
        out["sp800_131a"] = _verdict(
            "disallowed",
            "Triple DES (TDEA) encryption is disallowed after 2023 "
            "(SP 800-131A Rev. 2)",
        )
        out["cnsa_2_0"] = _verdict(
            "not_compliant", "Triple DES is not a CNSA 2.0 algorithm (AES-256 only)"
        )
    elif _AES.search(text) or (
        re.search(r"(^|[^A-Z])AES", text, re.I) and size in (128, 192, 256)
    ):
        m = _AES.search(text)
        bits = int(m.group(1)) if m else int(size or 0)
        out["sp800_131a"] = _verdict(
            "acceptable", f"AES-{bits} is approved (SP 800-131A)"
        )
        out["cnsa_2_0"] = (
            _verdict("compliant", "AES-256")
            if bits == 256
            else _verdict("not_compliant", f"AES-{bits}: CNSA 2.0 requires AES-256")
        )
    elif other:
        name = other.group(0).upper()
        out["sp800_131a"] = _verdict(
            "not_approved", f"{name} is not a NIST-approved cipher"
        )
        out["cnsa_2_0"] = _verdict(
            "not_compliant", f"{name} is not a CNSA 2.0 algorithm (AES-256 only)"
        )
    else:
        return None
    if suite and out["cnsa_2_0"]["status"] == "compliant":
        tail = _SUITE_HASH.search(text.upper())
        found = [int(g) for g in (tail.groups() if tail else ()) if g]
        sha = found[0] if found else (1 if tail else None)
        if sha is not None and sha < 384:
            out["cnsa_2_0"] = _verdict(
                "not_compliant",
                f"the suite's hash is SHA-{sha}: CNSA 2.0 requires SHA-384 or SHA-512",
            )
    out["fips_203_204_205"] = _verdict("not_applicable", "no post-quantum algorithm")
    return out


def _hash(text: str, signature: bool) -> dict[str, dict[str, Any]] | None:
    bits = _hash_bits(text)
    if bits is None:
        return None
    what = "signatures" if signature else "hashing"
    if bits == "md5":
        sp = _verdict("disallowed", f"MD5 {what} are disallowed (SP 800-131A)")
        cnsa = _verdict("not_compliant", "MD5 is not a CNSA 2.0 algorithm")
    elif bits == 1:
        sp = (
            _verdict(
                "disallowed",
                "SHA-1 is disallowed for signature generation (SP 800-131A Rev. 2)",
            )
            if signature
            else _verdict(
                "acceptable",
                "SHA-1 is allowed only outside digital signatures (SP 800-131A Rev. 2)",
            )
        )
        cnsa = _verdict("not_compliant", "SHA-1: CNSA 2.0 requires SHA-384 or SHA-512")
    else:
        sp = _verdict("acceptable", f"SHA-{bits} is approved (SP 800-131A)")
        cnsa = (
            _verdict("compliant", f"SHA-{bits}")
            if isinstance(bits, int) and bits >= 384
            else _verdict(
                "not_compliant", f"SHA-{bits}: CNSA 2.0 requires SHA-384 or SHA-512"
            )
        )
    return {
        "sp800_131a": sp,
        "cnsa_2_0": cnsa,
        "fips_203_204_205": _verdict("not_applicable", "no post-quantum algorithm"),
    }


def _post_quantum(ident: algid.Identity) -> dict[str, dict[str, Any]]:
    name = ident.parameter_set or ident.name or "post-quantum algorithm"
    hybrid = ident.construction == "hybrid"
    if ident.standard in _FIPS_PQ and ident.nist_category:
        fips = _verdict(
            "approved",
            f"{name}: {ident.standard} category {ident.nist_category}"
            + (" (hybrid with a classical algorithm)" if hybrid else ""),
            standard=ident.standard,
            category=ident.nist_category,
        )
    elif ident.standard:
        fips = _verdict(
            "not_applicable",
            f"{ident.name or name}: {ident.standard}, not FIPS 203/204/205",
        )
    else:
        fips = _verdict(
            "not_approved",
            f"{ident.name or name}: a pre-standard or draft algorithm, not a FIPS "
            "203/204/205 parameter set",
        )
    top = ident.nist_category == 5 and (
        (ident.standard == "FIPS 203" and ident.primitive == "kem")
        or (ident.standard == "FIPS 204" and ident.primitive == "signature")
    )
    if ident.stateful and ident.standard:
        cnsa = _verdict(
            "compliant",
            f"{ident.name or name}: SP 800-208 stateful hash-based signature",
        )
    elif top:
        cnsa = _verdict(
            "compliant",
            f"{name}: the CNSA 2.0 parameter set" + (" (hybrid)" if hybrid else ""),
        )
    else:
        cnsa = _verdict("not_compliant", f"{name}: {_CNSA_SUITE}")
    sp = (
        _verdict(
            "acceptable",
            f"{ident.name or name}: published NIST standard ({ident.standard})",
        )
        if ident.standard
        else _verdict(
            "not_approved", f"{ident.name or name}: not a published NIST standard"
        )
    )
    return {"fips_203_204_205": fips, "cnsa_2_0": cnsa, "sp800_131a": sp}


def _classical(
    ident: algid.Identity, size: int | None, role: str
) -> dict[str, dict[str, Any]]:
    family = ident.family_label or ""
    bits = size if isinstance(size, int) and size > 0 else ident.key_size
    label = ident.name or family
    if family == "DSA" and role != "group":
        sp = _verdict(
            "disallowed",
            "DSA signature generation was removed in FIPS 186-5 (verification only)",
        )
    elif family in ("RSA", "DH", "DSA"):
        if not bits:
            sp = _verdict("unknown", f"{label}: the key size was not read")
        elif bits < 2048:
            sp = _verdict(
                "disallowed", f"{label}-{bits}: below 112-bit security (SP 800-131A)"
            )
        else:
            sp = _verdict(
                "acceptable",
                f"{label}-{bits}: " + (_IR8547_112 if bits < 3072 else _IR8547_128),
            )
    elif family in ("EC", "ECDSA", "ECDH"):
        if not bits:
            sp = _verdict("unknown", f"{label}: the curve size was not read")
        elif bits < 224:
            sp = _verdict(
                "disallowed",
                f"{label} {bits}-bit curve: below 112-bit security (SP 800-131A)",
            )
        else:
            sp = _verdict(
                "acceptable",
                f"{label} {bits}-bit curve: "
                + (_IR8547_112 if bits < 256 else _IR8547_128),
            )
    elif family in ("ED25519", "ED448", "EDDSA"):
        sp = _verdict("acceptable", f"{label}: approved in FIPS 186-5; " + _IR8547_128)
    elif family in ("X25519", "X448"):
        sp = _verdict(
            "unknown",
            f"{label}: key agreement outside the SP 800-131A tables (not graded)",
        )
    else:
        sp = _verdict(
            "not_approved",
            f"{label or 'algorithm'}: not a NIST-approved public-key algorithm",
        )
    return {
        "sp800_131a": sp,
        "cnsa_2_0": _verdict("not_compliant", f"{label}: {_TRANSITION}"),
        "fips_203_204_205": _verdict("not_applicable", "no post-quantum algorithm"),
    }


def _unknown(text: str) -> dict[str, dict[str, Any]]:
    why = f"{text[:80]}: the algorithm could not be identified"
    return {key: _verdict("unknown", why) for key, _label in STANDARDS}


def judge(
    role: str, identifier: Any, key_size: Any = None
) -> dict[str, dict[str, Any]] | None:
    """Every standard's verdict on one part, or None when it names nothing to judge."""
    text = str(identifier or "").strip()
    if not text:
        return None
    size = (
        key_size
        if isinstance(key_size, int) and not isinstance(key_size, bool)
        else None
    )
    if role == "cipher":
        return _symmetric(text, size, suite=True)
    if role == "signature":
        ident = algid.resolve(text)
        if ident is not None and ident.family_label == "PQ":
            return _post_quantum(ident)
        return _hash(text, signature=True)
    ident = algid.resolve(text)
    if ident is not None and ident.family_label == "PQ":
        return _post_quantum(ident)
    if ident is not None and ident.quantum == "vulnerable":
        return _classical(ident, size, role)
    return (
        _symmetric(
            text, size if size else (ident.key_size if ident else None), suite=False
        )
        or _hash(text, signature=False)
        or _unknown(text)
    )


def grade(parts: list[tuple[str, Any, Any]]) -> dict[str, dict[str, Any]] | None:
    """Each standard's status for an asset made of ``parts`` (the worst part decides),
    or None when no part names an algorithm.  FIPS 203/204/205 carries the standards
    and the lowest category of its approved parts."""
    judged = [v for v in (judge(role, ident, size) for role, ident, size in parts) if v]
    if not judged:
        return None
    out: dict[str, dict[str, Any]] = {}
    for key, _label in STANDARDS:
        order = RANK[key]
        verdicts = [v[key] for v in judged]
        worst = min(verdicts, key=lambda v: order.index(v["status"]))["status"]
        reasons = list(
            dict.fromkeys(v["reason"] for v in verdicts if v["status"] == worst)
        )
        row: dict[str, Any] = {"status": worst, "reasons": reasons}
        if key == "fips_203_204_205" and worst == "approved":
            approved = [v for v in verdicts if v["status"] == "approved"]
            row["standard"] = ", ".join(sorted({v["standard"] for v in approved}))
            row["category"] = min(v["category"] for v in approved)
        out[key] = row
    return out


def rows(graded: dict[str, dict[str, Any]] | None) -> list[dict[str, Any]]:
    """The statuses in ``STANDARDS`` order, each with its id and label (drawer rows)."""
    if not graded:
        return []
    return [
        {"id": key, "label": label, **graded[key]}
        for key, label in STANDARDS
        if key in graded
    ]


def export_value(row: dict[str, Any]) -> str:
    """One standard's status as an export value (``approved (FIPS 203 category 3)``)."""
    if row.get("status") == "approved" and row.get("standard"):
        return f"approved ({row['standard']} category {row['category']})"
    return str(row.get("status"))


# CB-16: the CNSA 2.0 and FIPS 140-3 requirement predicates, shared by both lanes.  The
# code lane's framework checks (``aibom.cbom.compliance``) call them per algorithm asset
# (falling back to their graph facts where these say None); the Sources lane judges each
# collection's assets with them (``cbom_sources.frameworks``).  True: the part fails the
# requirement; False: it meets it; None: the requirement does not apply to this part, or
# the part could not be graded.
REQUIREMENTS: dict[str, tuple[str, str]] = {
    "CNSA-1": (
        "cnsa_2_0",
        "CNSA 2.0 symmetric + hashing: AES-256 and SHA-384/512 only",
    ),
    # the code lane's title names the parameter sets; post-quantum names live in algid only
    "CNSA-2": (
        "cnsa_2_0",
        "Quantum-resistant algorithms at the CNSA 2.0 parameter set",
    ),
    "FIPS-1": ("fips_140_3", "Only FIPS-approved security functions in use"),
    "FIPS-2": ("fips_140_3", "Approved key sizes (asymmetric ≥ 2048-bit)"),
    "FIPS-3": ("fips_140_3", "No disallowed algorithm or ECB mode (SP 800-131A)"),
}
_MODULUS_FAMILIES = ("RSA", "DH", "DSA")


def _part_kind(role: str, text: str, size: int | None) -> str | None:
    """What a part is, for the requirement predicates: ``post_quantum``,
    ``classical`` (a quantum-vulnerable public key), ``symmetric``, ``hash``,
    ``signature_hash`` (the hash of a signature), or None (not identified)."""
    if role == "cipher":
        return "symmetric" if _symmetric(text, size, suite=True) else None
    ident = algid.resolve(text)
    if ident is not None and ident.family_label == "PQ":
        return "post_quantum"
    if role == "signature":
        return "signature_hash" if _hash_bits(text) is not None else None
    if ident is not None and ident.quantum == "vulnerable":
        return "classical"
    bits = size if size else (ident.key_size if ident else None)
    if _symmetric(text, bits, suite=False) is not None:
        return "symmetric"
    if _hash_bits(text) is not None:
        return "hash"
    return None


def framework_checks(
    role: str, identifier: Any, key_size: Any = None
) -> dict[str, bool | None]:
    """Each requirement of ``REQUIREMENTS`` on one part (see the block comment above).

    * CNSA-1: a symmetric cipher or a hash (not a signature's hash) is AES-256 or
      SHA-384/512;
    * CNSA-2: a post-quantum algorithm is a CNSA 2.0 parameter set (a name that does not
      say its parameter set is not graded);
    * FIPS-1: an approved security function (SP 800-131A not "not approved" nor
      "disallowed"; a bare SHA-1 is not graded: only a signature's SHA-1 is disallowed);
    * FIPS-2: an RSA / DH / DSA key of at least 2048 bits (its size read);
    * FIPS-3: no SP 800-131A "disallowed" algorithm (ECB mode is the caller's: a
      name does not carry the mode).
    """
    out: dict[str, bool | None] = dict.fromkeys(REQUIREMENTS)
    text = str(identifier or "").strip()
    verdict = judge(role, identifier, key_size)
    if not text or verdict is None:
        return out
    size = (
        key_size
        if isinstance(key_size, int) and not isinstance(key_size, bool)
        else None
    )
    kind = _part_kind(role, text, size)
    ident = algid.resolve(text)
    cnsa, sp = verdict["cnsa_2_0"]["status"], verdict["sp800_131a"]["status"]
    if kind in ("symmetric", "hash") and cnsa in ("compliant", "not_compliant"):
        out["CNSA-1"] = cnsa == "not_compliant"
    if kind == "post_quantum":
        graded = ident is not None and (
            bool(ident.nist_category) or (ident.stateful and bool(ident.standard))
        )
        if not graded:  # a name that does not say its parameter set: not graded here
            return out
        out["CNSA-2"] = cnsa == "not_compliant"
    if kind == "classical":
        # an approved function whatever its size (the size is FIPS-2's), except DSA
        family = (ident.family_label if ident else "") or ""
        bits = size if size else (ident.key_size if ident else None)
        if sp in ("disallowed", "not_approved", "acceptable"):
            dsa = family == "DSA" and sp == "disallowed"
            out["FIPS-1"] = sp == "not_approved" or dsa
            out["FIPS-3"] = sp == "disallowed"
        if family in _MODULUS_FAMILIES and bits:
            out["FIPS-2"] = bits < 2048
        return out
    if kind == "hash" and _hash_bits(text) == 1:
        # SHA-1 on its own: SP 800-131A disallows it for signatures only, so its use
        # decides, which a bare hash name does not say (the caller's own rule applies)
        return out
    if sp in ("disallowed", "not_approved", "acceptable"):
        out["FIPS-1"] = sp != "acceptable"
        out["FIPS-3"] = sp == "disallowed"
    return out
