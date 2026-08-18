"""CBOM compliance mapping (C7) — crypto-regulatory frameworks, tri-state.

A peer of the AIBOM compliance lane (:mod:`aibom.compliance`). It REUSES that
lane's tri-state machinery — the ``Requirement`` / ``CheckResult`` contract, the
``register_check`` / ``register_applicability`` registries, the verdict
constructors, and the framework runner :func:`aibom.compliance.engine.run_framework`
(coverage = ``pass / (pass + fail)``, NA excluded; applicability → ``out_of_scope``;
an uploaded attestation flips ``not_bom_evidenceable`` → ``pass_with_evidence``) —
so the same locked verdict vocabulary covers crypto findings, never reinvented.

What is NEW here is the crypto **graph** the checks query and the frameworks they
anchor to:

* **NIST SP 1800-38B** (``nist_1800_38b``) — Migration to Post-Quantum
  Cryptography readiness;
* **NIST SP 800-57** (``nist_800_57``) — key & certificate management;
* **OMB M-23-02** (``omb_m_23_02``) — the federal cryptographic-inventory mandate;
* optional **EU CRA** (``eu_cra``) and **EU DORA** (``eu_dora``).

HARD RULE (``aibom/contract/lanes`` + CLAUDE.md #4): a check reads the GRAPH —
``crypto_asset`` components and their ``crypto:`` namespaced properties (assetType,
strength, primitive, keySize, mode, quantumVulnerable, selfSigned, materialKind,
nistQuantumSecurityLevel, pqcMigrationTarget) — and decides applicability / pass /
fail from that. A check NEVER reads ``result.flags`` (flags are the scoring echo,
parallel to the authoritative graph facts).

The "is this asset weak?" question reuses :func:`aibom.cbom.weakness.weak_finding`,
which is a PURE function of a component's ``crypto:`` properties + display name
(it reads no flags) — so compliance never drifts from the inventory's own notion
of weakness while staying strictly graph-evidenced.
"""

from __future__ import annotations

import re
from typing import Any

from aibom.cbom.strength import canonical_algorithm_family, is_approved_algorithm
from aibom.cbom.weakness import WEAK_PROTOCOL, weak_finding
from aibom.compliance.base import (
    ADVISORY_DISCLAIMER,
    FAIL,
    PASS,
    CheckResult,
    Requirement,
    register_applicability,
    register_check,
    register_manual,
)
from aibom.compliance.engine import run_framework
from aibom.model.component import AIComponent
from aibom.model.result import ScanResult

# Canonical CBOM framework keys (must match ``Requirement.framework``).
CBOM_FRAMEWORKS = [
    "nist_1800_38b",
    "nist_800_57",
    "omb_m_23_02",
    "eu_cra",
    "eu_dora",
    "pci_dss_4",
    "fips_140_3",
    "bsi_tr_02102",
    "nist_1800_38c",
    "cnsa_2_0",
    "rbi_free_ai_protection",
    "cert_in_cbom",
    "sebi_cscrf_cbom",
]

# --------------------------------------------------------------------------- #
# Crypto GRAPH helpers (read-only; NO flags). Checks compose these.
# --------------------------------------------------------------------------- #


def crypto_assets(r: ScanResult) -> list[AIComponent]:
    return [c for c in r.components if c.kind == "crypto_asset"]


def _of_type(r: ScanResult, asset_type: str) -> list[AIComponent]:
    return [
        c
        for c in crypto_assets(r)
        if (c.properties or {}).get("crypto:assetType") == asset_type
    ]


def algorithms(r: ScanResult) -> list[AIComponent]:
    return _of_type(r, "algorithm")


def certificates(r: ScanResult) -> list[AIComponent]:
    return _of_type(r, "certificate")


def protocols(r: ScanResult) -> list[AIComponent]:
    return _of_type(r, "protocol")


def related_material(r: ScanResult) -> list[AIComponent]:
    return _of_type(r, "related-crypto-material")


def quantum_vulnerable(r: ScanResult) -> list[AIComponent]:
    """Algorithm assets the inventory marked broken by a quantum computer."""
    return [
        c
        for c in algorithms(r)
        if (c.properties or {}).get("crypto:quantumVulnerable") == "true"
    ]


# Weakness reuses the pure C5 predicate (graph-only; reads properties + name,
# never flags). An algorithm is weak iff ``weak_finding`` returns any weakness
# code; a protocol is weak iff it returns ``WEAK_PROTOCOL``. The orthogonal
# key-size / ECB-mode dimensions are queried directly (see ``undersized_keys`` /
# ``ecb_modes``) because ``weak_finding`` emits only one code per asset.
def _weakness_code(c: AIComponent) -> str | None:
    finding = weak_finding(c)
    return finding[0] if finding else None


def weak_algorithms(r: ScanResult) -> list[AIComponent]:
    return [c for c in algorithms(r) if _weakness_code(c) is not None]


#: Minimum acceptable asymmetric key size (bits) — NIST SP 800-57 / 800-131A.
_MIN_ASYMMETRIC_BITS = 2048


def undersized_keys(
    r: ScanResult, min_bits: int = _MIN_ASYMMETRIC_BITS
) -> list[AIComponent]:
    """Asymmetric algorithm assets whose modulus is below ``min_bits``.

    Queried straight off the graph (``crypto:primitive`` + ``crypto:keySize``),
    not via ``weak_finding`` — that predicate emits ONE code per asset and the
    deprecated-corpus match (e.g. RSA-1024 → ``WEAK_ALGORITHM``) would mask the
    orthogonal key-size dimension this check measures.

    The floor is parameterized (C8): NIST SP 800-57 / FIPS 140-3 use the default
    2048-bit RSA floor; a stricter framework passes a higher ``min_bits``. Only
    an integer ``crypto:keySize`` is measured — an EC asset carries its curve in
    ``crypto:curve`` (keySize unset), so raising the floor never false-flags a
    curve whose comparable strength this modulus check does not model (that is
    the strength-graded :func:`under_strength`'s job).
    """
    out: list[AIComponent] = []
    for c in algorithms(r):
        props = c.properties or {}
        if props.get("crypto:primitive") not in ("pke", "signature", "key-agree"):
            continue
        # A PQC / stateful-hash asset carries its parameter set in keySize, not an
        # IF/DL modulus — the classical modulus floor must not false-flag it.
        if canonical_algorithm_family(c) in _PQC_FAMILIES:
            continue
        raw = props.get("crypto:keySize")
        if raw and raw.isdigit() and int(raw) < min_bits:
            out.append(c)
    return out


def under_strength(r: ScanResult, min_bits: int) -> list[AIComponent]:
    """Algorithm assets graded below ``min_bits`` of comparable strength (C15/C8).

    Reads the C15 graph fact ``crypto:securityStrengthBits`` (SP 800-57 Table 2
    comparable strength), so it is family-normalized: RSA-2048 → 112, P-256 →
    128, 3DES → 112, MD5 → 64. This is the correct floor for a *security-level*
    requirement (PCI "strong cryptography" ≥ 112-bit, BSI TR-02102-1 ≥ 120-bit)
    because the number already folds modulus / curve / primitive into one axis —
    an ungraded asset (``securityStrengthBits`` absent) is skipped, never
    counted as a fail the inventory cannot substantiate.
    """
    out: list[AIComponent] = []
    for c in algorithms(r):
        raw = (c.properties or {}).get("crypto:securityStrengthBits")
        if raw and raw.isdigit() and int(raw) < min_bits:
            out.append(c)
    return out


#: Canonical family tokens (from C15's ``canonical_algorithm_family``) that name a
#: quantum-safe / PQC mechanism — the positive readiness signal QR-3 / crypto-
#: agility checks query alongside the ``crypto:hybrid`` graph fact.
_PQC_FAMILIES = frozenset(
    {"ml-kem", "ml-dsa", "slh-dsa", "falcon", "lms", "hss", "xmss", "hybrid"}
)


def quantum_safe_mechanisms(r: ScanResult) -> list[AIComponent]:
    """Algorithm assets that are a PQC / hybrid (quantum-safe) mechanism.

    A positive crypto-agility signal read straight off the graph: an asset marked
    ``crypto:hybrid=true`` (a classical+PQC key-agreement) or whose canonical
    family is a NIST/stateful-hash PQC scheme. Never reads flags.
    """
    out: list[AIComponent] = []
    for c in algorithms(r):
        if (c.properties or {}).get("crypto:hybrid") == "true":
            out.append(c)
            continue
        if canonical_algorithm_family(c) in _PQC_FAMILIES:
            out.append(c)
    return out


# --------------------------------------------------------------------------- #
# CNSA 2.0 (C14): the NSA Commercial National Security Algorithm Suite 2.0 is a
# PARAMETER-LEVEL allowlist for National Security Systems — stricter than the
# family-level FIPS/BSI allowlist (C15). It approves AES-256, SHA-384/512,
# ML-KEM-1024, ML-DSA-87, and the SP 800-208 stateful-hash signatures (LMS/XMSS)
# for firmware/software signing. Everything else that is quantum-safe-capable
# but under-parameterized (ML-KEM-512/768, ML-DSA-44/65) or outside the suite
# (SLH-DSA, FALCON, ChaCha20, AES-128/192, SHA-256) is non-compliant. Classical
# quantum-vulnerable public-key crypto is NOT a suite violation — it is the
# transition state CNSA-3 tracks. These queries read only the graph facts C7
# stamped (nistQuantumSecurityLevel + primitive + parameterSet + hybrid) + C15's
# canonical family; they never read flags.
# --------------------------------------------------------------------------- #

#: CNSA 2.0 security-strength category floors (C7 nistQuantumSecurityLevel). The
#: suite mandates the Category-5 (256-bit) member of the symmetric + quantum-safe
#: families and Category-4+ (SHA-384/512) hashing.
_CNSA_SYMMETRIC_LEVEL = 5  # AES-256 only
_CNSA_HASH_LEVEL = 4  # SHA-384 / SHA-512
_CNSA_PQC_LEVEL = 5  # ML-KEM-1024 / ML-DSA-87

#: SP 800-208 stateful-hash signatures CNSA 2.0 approves for firmware/software
#: signing regardless of a NIST-category grade (their strength rides the tree/hash
#: parameters, not a single securityStrengthBits number).
_CNSA_STATEFUL_HASH = frozenset({"lms", "xmss", "hss"})


def _qsl(c: AIComponent) -> int | None:
    """The asset's C7 ``nistQuantumSecurityLevel`` as an int, or None if ungraded."""
    raw = (c.properties or {}).get("crypto:nistQuantumSecurityLevel")
    if raw is not None and str(raw).isdigit():
        return int(raw)
    return None


def cnsa_symmetric_hash_noncompliant(r: ScanResult) -> list[AIComponent]:
    """Symmetric ciphers / hashes below the CNSA 2.0 floor (AES-256, SHA-384/512).

    Graded straight off the C7 ``nistQuantumSecurityLevel`` + ``crypto:primitive``:
    a block/stream cipher must be AES at Category 5 (AES-256); a hash must be
    Category 4+ (SHA-384/512 — SHA-256 at Category 2 fails). An ungraded asset
    (no level stamped, e.g. an AES whose key size the source never revealed) is
    skipped — never counted as a fail the inventory cannot substantiate.
    """
    out: list[AIComponent] = []
    for c in algorithms(r):
        prim = (c.properties or {}).get("crypto:primitive")
        lvl = _qsl(c)
        if lvl is None:
            continue
        if prim in ("block-cipher", "stream-cipher"):
            if canonical_algorithm_family(c) != "aes" or lvl < _CNSA_SYMMETRIC_LEVEL:
                out.append(c)
        elif prim == "hash" and lvl < _CNSA_HASH_LEVEL:
            out.append(c)
    return out


def cnsa_underparameterized_quantum_safe(r: ScanResult) -> list[AIComponent]:
    """Quantum-safe assets not at the CNSA 2.0 parameter set.

    Queries the quantum-safe / hybrid mechanisms (:func:`quantum_safe_mechanisms`)
    and rejects any that are not the CNSA-mandated parameter: ML-KEM must be 1024
    (Category 5), ML-DSA must be 87 (Category 5); LMS/XMSS/HSS are approved as
    SP 800-208 stateful-hash signing; every other quantum-safe scheme (SLH-DSA,
    FALCON) is outside the CNSA 2.0 suite. A hybrid key-agreement is judged on its
    ML-KEM component's grade (its ``nistQuantumSecurityLevel``).
    """
    out: list[AIComponent] = []
    for c in quantum_safe_mechanisms(r):
        fam = canonical_algorithm_family(c)
        if fam in _CNSA_STATEFUL_HASH:
            continue
        pset = (c.properties or {}).get("crypto:parameterSet")
        lvl = _qsl(c)
        if fam in ("ml-kem", "hybrid"):
            if pset == "1024" or lvl == _CNSA_PQC_LEVEL:
                continue
        elif fam == "ml-dsa" and (pset == "87" or lvl == _CNSA_PQC_LEVEL):
            continue
        out.append(c)
    return out


def ecb_modes(r: ScanResult) -> list[AIComponent]:
    """Algorithm assets using the ECB cipher mode (read straight off the graph)."""
    return [
        c
        for c in algorithms(r)
        if (c.properties or {}).get("crypto:mode", "").upper() == "ECB"
    ]


def weak_protocols(r: ScanResult) -> list[AIComponent]:
    return [c for c in protocols(r) if _weakness_code(c) == WEAK_PROTOCOL]


def self_signed_certs(r: ScanResult) -> list[AIComponent]:
    return [
        c
        for c in certificates(r)
        if (c.properties or {}).get("crypto:selfSigned") == "true"
    ]


# --------------------------------------------------------------------------- #
# Crypto-policy cross-reference (C11): the environment's own policy artifacts
# (java.security / openssl.cnf) list DISABLED algorithms; a *disabled-but-used*
# algorithm — one the runtime forbids yet the code still uses — is a policy
# violation. The disabled set rides as a ``crypto:disabledAlgorithms`` property
# on the policy ``protocol`` asset the C11 scanner emits (a graph fact, not a
# flag), so this stays strictly graph-evidenced.
# --------------------------------------------------------------------------- #

#: Cipher-mode suffixes appended to an algorithm display name (``AES-256-GCM``);
#: stripped to recover the base algorithm before matching against the policy.
_POLICY_MODE_SUFFIXES = ("-GCM", "-CBC", "-ECB", "-CTR", "-CFB", "-OFB", "-XTS", "-CCM")


def _canon_alg(token: str) -> str:
    """Fold an algorithm token to a comparison key: lowercase, alnum-only.

    ``SHA-1`` -> ``sha1``, ``3DES_EDE_CBC`` -> ``3desedecbc``, ``RC4`` -> ``rc4``.
    """
    return re.sub(r"[^a-z0-9]", "", token.lower())


def policy_disabled_algorithms(r: ScanResult) -> set[str]:
    """Blanket-disabled algorithm families declared by the crypto-policy assets.

    Only UNCONDITIONED single tokens (``RC4``, ``DES``, ``SSLv3``, ``MD5``)
    become a family disable. Conditioned entries (``RSA keySize < 1024``,
    ``SHA1 jdkCA & usage TLSServer``) carry a numeric/usage predicate this
    static cross-check does not evaluate, so they are conservatively skipped —
    never producing a false disabled-but-used positive.
    """
    disabled: set[str] = set()
    for p in protocols(r):
        raw = (p.properties or {}).get("crypto:disabledAlgorithms")
        if not raw:
            continue
        for entry in raw.split(","):
            e = entry.strip()
            if not e or " " in e or any(c in e for c in "&<>"):
                continue
            key = _canon_alg(e)
            if len(key) >= 3:
                disabled.add(key)
    return disabled


def _used_algorithm_key(c: AIComponent) -> str:
    name = c.name.upper()
    for suffix in _POLICY_MODE_SUFFIXES:
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return _canon_alg(name)


def disabled_but_used(r: ScanResult) -> list[AIComponent]:
    """Algorithm assets in use that the environment crypto policy disables.

    An algorithm matches a disabled family when its canonical base name equals a
    disabled token, or begins with one followed by a key-size digit (so a bare
    ``RSA`` disable catches ``RSA-2048`` while ``DES`` never matches ``3DES``).
    """
    disabled = policy_disabled_algorithms(r)
    if not disabled:
        return []
    out: list[AIComponent] = []
    for c in algorithms(r):
        key = _used_algorithm_key(c)
        if not key:
            continue
        if key in disabled or any(
            key.startswith(d) and (len(key) == len(d) or key[len(d)].isdigit())
            for d in disabled
        ):
            out.append(c)
    return out


def hardcoded_key_material(r: ScanResult) -> list[AIComponent]:
    """Private / secret key material embedded in the repo (a custody failure)."""
    return [
        c
        for c in related_material(r)
        if (c.properties or {}).get("crypto:materialKind")
        in ("private-key", "secret-key")
    ]


def _refs(components: list[AIComponent]) -> list[str]:
    return [c.bom_ref for c in components]


# --------------------------------------------------------------------------- #
# Applicability: every CBOM framework applies iff the artifact contains crypto.
# A repo with no cryptographic assets -> all requirements out_of_scope.
# --------------------------------------------------------------------------- #

_NO_CRYPTO = "no cryptographic assets detected; crypto frameworks do not apply"


def _has_crypto(r: ScanResult) -> bool:
    return bool(crypto_assets(r))


for _fw in CBOM_FRAMEWORKS:
    register_applicability(_fw, _has_crypto, _NO_CRYPTO)

# CERT-In CBOM Table 9 + §8.4.1 (side-effect register_check / register_manual).
# Keep out of aibom.compliance.__init__ — CBOM runner owns the import.
from aibom.compliance.cert_in import crypto as _cert_in_crypto  # noqa: E402,F401
# SEBI CSCRF CBOM Box Item 7 + PR.DS (side-effect registration).
from aibom.compliance.sebi_cscrf import crypto as _sebi_cscrf_crypto  # noqa: E402,F401


def _req(rid: str, framework: str, title: str, source: str) -> Requirement:
    return Requirement(rid, framework, title, source)


# --------------------------------------------------------------------------- #
# NIST SP 1800-38B — Migration to Post-Quantum Cryptography (readiness).
# --------------------------------------------------------------------------- #

_FW_PQC = "nist_1800_38b"
_S_PQC = "NIST SP 1800-38B"

R_PQC1 = _req(
    "PQC-1", _FW_PQC, "No quantum-vulnerable public-key cryptography in use", _S_PQC
)
R_PQC2 = _req(
    "PQC-2", _FW_PQC, "Quantum-vulnerable assets graded (nistQuantumSecurityLevel)",
    _S_PQC,
)
R_PQC3 = _req(
    "PQC-3",
    _FW_PQC,
    "NIST PQC migration target identified per quantum-vulnerable asset",
    _S_PQC,
)
R_PQC4 = _req("PQC-4", _FW_PQC, "Crypto-agile / hybrid deployment architecture", _S_PQC)


@register_check(R_PQC1)
def _pqc1(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable public-key algorithms in use")
    return FAIL(
        f"{len(qv)} quantum-vulnerable public-key algorithm(s) in use "
        f"(broken by Shor's algorithm; NIST deprecates RSA/ECC after 2030)",
        _refs(qv),
    )


@register_check(R_PQC2)
def _pqc2(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable assets to grade")
    ungraded = [
        c
        for c in qv
        if (c.properties or {}).get("crypto:nistQuantumSecurityLevel") is None
    ]
    if ungraded:
        return FAIL(
            f"{len(ungraded)} quantum-vulnerable asset(s) lack a "
            f"nistQuantumSecurityLevel grade",
            _refs(ungraded),
        )
    return PASS(
        "every quantum-vulnerable asset carries a nistQuantumSecurityLevel", _refs(qv)
    )


@register_check(R_PQC3)
def _pqc3(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable assets to migrate")
    missing = [
        c
        for c in qv
        if not (c.properties or {}).get("crypto:pqcMigrationTarget")
    ]
    if missing:
        return FAIL(
            f"{len(missing)} quantum-vulnerable asset(s) have no PQC migration target",
            _refs(missing),
        )
    return PASS(
        "every quantum-vulnerable asset names a NIST PQC migration target "
        "(ML-KEM / ML-DSA / SLH-DSA)",
        _refs(qv),
    )


register_manual(
    R_PQC4,
    "a crypto-agile / hybrid (classical+PQC) deployment architecture is design "
    "evidence not visible in a crypto inventory",
)


# --------------------------------------------------------------------------- #
# NIST SP 800-57 — key & certificate management.
# --------------------------------------------------------------------------- #

_FW_KM = "nist_800_57"
_S_KM = "NIST SP 800-57 Pt.1 / SP 800-131A"

R_KM1 = _req("KM-1", _FW_KM, "No broken or deprecated algorithms", _S_KM)
R_KM2 = _req("KM-2", _FW_KM, "Asymmetric keys meet the 2048-bit floor", _S_KM)
R_KM3 = _req("KM-3", _FW_KM, "No hardcoded private / secret key material", _S_KM)
R_KM4 = _req("KM-4", _FW_KM, "Certificates are CA-issued (not self-signed)", _S_KM)
R_KM5 = _req("KM-5", _FW_KM, "Authenticated cipher modes (no ECB)", _S_KM)
R_KM6 = _req("KM-6", _FW_KM, "Key rotation + HSM-backed custody policy", _S_KM)
R_KM7 = _req(
    "KM-7",
    _FW_KM,
    "No algorithm in use is disabled by the environment crypto policy",
    _S_KM,
)


@register_check(R_KM1)
def _km1(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = weak_algorithms(r)
    if weak:
        return FAIL(
            f"{len(weak)} broken/deprecated algorithm(s) in use "
            f"(superseded per NIST SP 800-131A)",
            _refs(weak),
        )
    return PASS("all algorithms in use are NIST-approved", _refs(algorithms(r)))


@register_check(R_KM2)
def _km2(r: ScanResult, req: Requirement) -> CheckResult:
    small = undersized_keys(r)
    if small:
        return FAIL(
            f"{len(small)} asymmetric key(s) below the 2048-bit floor (SP 800-57)",
            _refs(small),
        )
    return PASS("no undersized asymmetric keys detected")


@register_check(R_KM3)
def _km3(r: ScanResult, req: Requirement) -> CheckResult:
    hardcoded = hardcoded_key_material(r)
    if hardcoded:
        return FAIL(
            f"{len(hardcoded)} hardcoded private/secret key(s) embedded in the repo "
            f"(keys must be HSM/KMS-custodied, never in source)",
            _refs(hardcoded),
        )
    return PASS("no hardcoded private/secret key material detected")


@register_check(R_KM4)
def _km4(r: ScanResult, req: Requirement) -> CheckResult:
    certs = certificates(r)
    if not certs:
        return PASS("no certificates inventoried")
    selfsigned = self_signed_certs(r)
    if selfsigned:
        return FAIL(
            f"{len(selfsigned)} self-signed certificate(s) — not issued by a "
            f"trusted CA",
            _refs(selfsigned),
        )
    return PASS("all certificates are CA-issued", _refs(certs))


@register_check(R_KM5)
def _km5(r: ScanResult, req: Requirement) -> CheckResult:
    ecb = ecb_modes(r)
    if ecb:
        return FAIL(
            f"{len(ecb)} cipher(s) using ECB mode (leaks plaintext structure; use "
            f"an authenticated mode — GCM/CCM)",
            _refs(ecb),
        )
    return PASS("no ECB cipher modes detected")


register_manual(
    R_KM6,
    "key rotation cadence + HSM/KMS custody is operational-policy evidence not "
    "modelled in a crypto inventory",
)


@register_check(R_KM7)
def _km7(r: ScanResult, req: Requirement) -> CheckResult:
    disabled = policy_disabled_algorithms(r)
    if not disabled:
        return PASS(
            "no crypto-policy artifact (java.security / openssl.cnf) disables an "
            "algorithm family; no disabled-but-used violation to evaluate"
        )
    violations = disabled_but_used(r)
    if violations:
        return FAIL(
            f"{len(violations)} algorithm(s) in use are explicitly disabled by the "
            f"environment crypto policy (java.security "
            f"jdk.tls/certpath.disabledAlgorithms) — disabled-but-used",
            _refs(violations),
        )
    return PASS(
        f"the crypto policy disables {len(disabled)} algorithm family/ies; none "
        f"are used in the inventoried code",
        _refs(algorithms(r)),
    )


# --------------------------------------------------------------------------- #
# OMB M-23-02 — federal cryptographic-inventory mandate. The BOM IS the
# inventory; quantum-vulnerable systems must be identified + prioritized.
# --------------------------------------------------------------------------- #

_FW_OMB = "omb_m_23_02"
_S_OMB = "OMB M-23-02"

R_OMB1 = _req(
    "OMB-1", _FW_OMB, "Cryptographic inventory enumerates algorithm primitives", _S_OMB
)
R_OMB2 = _req(
    "OMB-2", _FW_OMB, "Quantum-vulnerable systems identified + prioritized", _S_OMB
)
R_OMB3 = _req("OMB-3", _FW_OMB, "Agency PQC migration plan submitted to OMB", _S_OMB)


@register_check(R_OMB1)
def _omb1(r: ScanResult, req: Requirement) -> CheckResult:
    algos = algorithms(r)
    if not algos:
        return FAIL("no cryptographic algorithms inventoried")
    unidentified = [
        c
        for c in algos
        if (c.properties or {}).get("crypto:primitive", "unknown") == "unknown"
    ]
    if unidentified:
        return FAIL(
            f"{len(unidentified)} inventoried algorithm(s) with an unidentified "
            f"primitive",
            _refs(unidentified),
        )
    return PASS(
        f"cryptographic inventory enumerates {len(algos)} algorithm(s) with "
        f"identified primitives",
        _refs(algos),
    )


@register_check(R_OMB2)
def _omb2(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable systems to prioritize")
    unprioritized = [
        c
        for c in qv
        if not (c.properties or {}).get("crypto:pqcMigrationTarget")
    ]
    if unprioritized:
        return FAIL(
            f"{len(unprioritized)} quantum-vulnerable system(s) not prioritized with "
            f"a migration target",
            _refs(unprioritized),
        )
    return PASS(
        f"{len(qv)} quantum-vulnerable system(s) identified + prioritized with a "
        f"migration target",
        _refs(qv),
    )


register_manual(
    R_OMB3,
    "submission of the agency-wide PQC migration plan to OMB is a process artifact "
    "outside a crypto inventory",
)


# --------------------------------------------------------------------------- #
# EU Cyber Resilience Act (optional) — secure-by-design; Annex I bans known
# vulnerable cryptography and hardcoded secrets in products.
# --------------------------------------------------------------------------- #

_FW_CRA = "eu_cra"
_S_CRA = "EU CRA Annex I"

R_CRA1 = _req(
    "CRA-1", _FW_CRA, "No known-vulnerable cryptography in the product", _S_CRA
)
R_CRA2 = _req("CRA-2", _FW_CRA, "No hardcoded keys / secrets in the product", _S_CRA)
R_CRA3 = _req("CRA-3", _FW_CRA, "Coordinated vulnerability disclosure + SBOM", _S_CRA)


@register_check(R_CRA1)
def _cra1(r: ScanResult, req: Requirement) -> CheckResult:
    weak = weak_algorithms(r) + weak_protocols(r)
    if weak:
        return FAIL(
            f"{len(weak)} known-vulnerable cryptographic asset(s) (weak algorithm "
            f"or protocol) in the product",
            _refs(weak),
        )
    return PASS("no known-vulnerable cryptography detected")


@register_check(R_CRA2)
def _cra2(r: ScanResult, req: Requirement) -> CheckResult:
    hardcoded = hardcoded_key_material(r)
    if hardcoded:
        return FAIL(
            f"{len(hardcoded)} hardcoded key/secret(s) shipped in the product",
            _refs(hardcoded),
        )
    return PASS("no hardcoded keys/secrets detected")


register_manual(
    R_CRA3,
    "coordinated vulnerability disclosure process + SBOM provision are "
    "organizational obligations not visible in a crypto inventory",
)


# --------------------------------------------------------------------------- #
# EU DORA (optional) — ICT operational resilience; encryption of data in transit.
# --------------------------------------------------------------------------- #

_FW_DORA = "eu_dora"
_S_DORA = "EU DORA (Reg. 2022/2554) Art.9"

R_DORA1 = _req("DORA-1", _FW_DORA, "Strong transport encryption (TLS 1.2+)", _S_DORA)
R_DORA2 = _req("DORA-2", _FW_DORA, "Approved cryptographic algorithms only", _S_DORA)
R_DORA3 = _req("DORA-3", _FW_DORA, "ICT third-party risk + encryption policy", _S_DORA)


@register_check(R_DORA1)
def _dora1(r: ScanResult, req: Requirement) -> CheckResult:
    if not protocols(r):
        return PASS("no transport protocols inventoried")
    weak = weak_protocols(r)
    if weak:
        return FAIL(
            f"{len(weak)} weak transport protocol(s) (TLS < 1.2 / SSL; RFC 8996)",
            _refs(weak),
        )
    return PASS("all transport protocols negotiate TLS 1.2+", _refs(protocols(r)))


@register_check(R_DORA2)
def _dora2(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = weak_algorithms(r)
    if weak:
        return FAIL(
            f"{len(weak)} non-approved cryptographic algorithm(s) in use",
            _refs(weak),
        )
    return PASS("all algorithms in use are approved", _refs(algorithms(r)))


register_manual(
    R_DORA3,
    "ICT third-party risk register + the encryption policy itself are governance "
    "documents outside a crypto inventory",
)


# --------------------------------------------------------------------------- #
# Allowlist inversion (C8/C15): the FIPS / BSI approved-algorithm frameworks pass
# iff every classifiable algorithm asset is on the framework's allowlist. A
# ``False`` from is_approved_algorithm (C15) is a compliance failure; ``None``
# (unclassifiable family / non-algorithm) is skipped — never counted as a fail.
# --------------------------------------------------------------------------- #


def non_approved_algorithms(r: ScanResult, framework: str) -> list[AIComponent]:
    return [
        c for c in algorithms(r) if is_approved_algorithm(framework, c) is False
    ]


# --------------------------------------------------------------------------- #
# PCI-DSS 4.0.1 — "strong cryptography" for stored + transmitted account data.
# PCI defines strong cryptography as NIST-approved with ≥ 112-bit effective key
# strength; early TLS/SSL is disallowed for open-network transmission.
# --------------------------------------------------------------------------- #

_FW_PCI = "pci_dss_4"
_S_PCI = "PCI-DSS v4.0.1 Req.3/4"

#: PCI "strong cryptography" effective-strength floor (bits).
_PCI_STRENGTH_FLOOR = 112

R_PCI1 = _req(
    "PCI-1", _FW_PCI, "Strong cryptography only (≥ 112-bit effective strength)", _S_PCI
)
R_PCI2 = _req(
    "PCI-2",
    _FW_PCI,
    "Strong cryptography over open networks (no early TLS/SSL)",
    _S_PCI,
)
R_PCI3 = _req(
    "PCI-3", _FW_PCI, "No hardcoded key material (Req 3.6/3.7 key management)", _S_PCI
)
R_PCI4 = _req(
    "PCI-4", _FW_PCI, "Key-management lifecycle: dual control + split knowledge", _S_PCI
)


@register_check(R_PCI1)
def _pci1(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = under_strength(r, _PCI_STRENGTH_FLOOR)
    if weak:
        return FAIL(
            f"{len(weak)} algorithm(s) below PCI 'strong cryptography' "
            f"({_PCI_STRENGTH_FLOOR}-bit effective strength; PCI-DSS 4.0 Glossary)",
            _refs(weak),
        )
    return PASS(
        f"all algorithms meet the {_PCI_STRENGTH_FLOOR}-bit strong-crypto floor",
        _refs(algorithms(r)),
    )


@register_check(R_PCI2)
def _pci2(r: ScanResult, req: Requirement) -> CheckResult:
    if not protocols(r):
        return PASS("no transport protocols inventoried")
    weak = weak_protocols(r)
    if weak:
        return FAIL(
            f"{len(weak)} weak transport protocol(s) (early TLS/SSL disallowed for "
            f"open-network transmission of account data; PCI-DSS 4.0 Req 4.2.1)",
            _refs(weak),
        )
    return PASS("all transport protocols use strong cryptography", _refs(protocols(r)))


@register_check(R_PCI3)
def _pci3(r: ScanResult, req: Requirement) -> CheckResult:
    hardcoded = hardcoded_key_material(r)
    if hardcoded:
        return FAIL(
            f"{len(hardcoded)} hardcoded key/secret(s) in source (PCI-DSS 4.0 Req 3.7 "
            f"requires keys stored in the fewest possible locations, never in code)",
            _refs(hardcoded),
        )
    return PASS("no hardcoded key material detected")


register_manual(
    R_PCI4,
    "cryptographic key-management lifecycle (dual control, split knowledge, "
    "documented key-custodian procedures; PCI-DSS 4.0 Req 3.7) is operational "
    "evidence not visible in a crypto inventory",
)


# --------------------------------------------------------------------------- #
# FIPS 140-3 — only FIPS-approved security functions (SP 800-140C), approved key
# sizes (SP 800-131A), no disallowed algorithm/mode. The approved-algorithm
# ALLOWLIST is C15 data; this framework inverts it.
# --------------------------------------------------------------------------- #

_FW_FIPS = "fips_140_3"
_S_FIPS = "FIPS 140-3 / SP 800-140C / SP 800-131A"

R_FIPS1 = _req(
    "FIPS-1", _FW_FIPS, "Only FIPS-approved security functions in use", _S_FIPS
)
R_FIPS2 = _req(
    "FIPS-2", _FW_FIPS, "Approved key sizes (asymmetric ≥ 2048-bit)", _S_FIPS
)
R_FIPS3 = _req(
    "FIPS-3", _FW_FIPS, "No disallowed algorithm or ECB mode (SP 800-131A)", _S_FIPS
)
R_FIPS4 = _req(
    "FIPS-4", _FW_FIPS, "CMVP-validated cryptographic module (certificate)", _S_FIPS
)


@register_check(R_FIPS1)
def _fips1(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    unapproved = non_approved_algorithms(r, _FW_FIPS)
    if unapproved:
        return FAIL(
            f"{len(unapproved)} algorithm(s) not FIPS-approved security functions "
            f"(SP 800-140C allowlist; e.g. DES/3DES/RC4/MD5/plain-DSA/ChaCha20/FALCON)",
            _refs(unapproved),
        )
    return PASS(
        "all algorithms are FIPS-approved security functions", _refs(algorithms(r))
    )


@register_check(R_FIPS2)
def _fips2(r: ScanResult, req: Requirement) -> CheckResult:
    small = undersized_keys(r, _MIN_ASYMMETRIC_BITS)
    if small:
        return FAIL(
            f"{len(small)} asymmetric key(s) below the FIPS 2048-bit floor "
            f"(SP 800-131A)",
            _refs(small),
        )
    return PASS("no undersized asymmetric keys detected")


@register_check(R_FIPS3)
def _fips3(r: ScanResult, req: Requirement) -> CheckResult:
    bad = weak_algorithms(r) + ecb_modes(r)
    if bad:
        return FAIL(
            f"{len(bad)} disallowed algorithm/mode in use (deprecated primitive or "
            f"ECB mode; SP 800-131A)",
            _refs(bad),
        )
    return PASS("no disallowed algorithms or ECB modes detected")


register_manual(
    R_FIPS4,
    "a CMVP module-validation certificate (the algorithm running inside a "
    "FIPS-validated boundary) is process/attestation evidence not derivable from "
    "source",
)


# --------------------------------------------------------------------------- #
# BSI TR-02102-1 — German federal crypto recommendations: stricter than FIPS. The
# approved-mechanism allowlist is C15 data (AES-only symmetric, no ChaCha20/FALCON)
# and the effective-strength floor is 120-bit (RSA ≥ 3000, EC ≥ 250 comparable).
# --------------------------------------------------------------------------- #

_FW_BSI = "bsi_tr_02102"
_S_BSI = "BSI TR-02102-1"

#: BSI TR-02102-1 effective-strength floor (bits) — stricter than FIPS/NIST. The
#: RSA ≥ 3000 / EC ≥ 250 modulus floors collapse to this single comparable-
#: strength axis (RSA-3072 → 128-bit, P-256 → 128-bit; RSA-2048 → 112-bit fails).
_BSI_STRENGTH_FLOOR = 120

R_BSI1 = _req("BSI-1", _FW_BSI, "Only BSI-approved mechanisms in use", _S_BSI)
R_BSI2 = _req(
    "BSI-2", _FW_BSI, "≥ 120-bit effective strength (RSA ≥ 3000, EC ≥ 250)", _S_BSI
)
R_BSI3 = _req("BSI-3", _FW_BSI, "No weak algorithm or ECB mode", _S_BSI)
R_BSI4 = _req(
    "BSI-4", _FW_BSI, "Key lifecycle: defined crypto-periods + key renewal", _S_BSI
)


@register_check(R_BSI1)
def _bsi1(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    unapproved = non_approved_algorithms(r, _FW_BSI)
    if unapproved:
        return FAIL(
            f"{len(unapproved)} algorithm(s) not a BSI TR-02102-1 approved mechanism "
            f"(AES-only symmetric; no ChaCha20/FALCON/deprecated primitives)",
            _refs(unapproved),
        )
    return PASS("all algorithms are BSI-approved mechanisms", _refs(algorithms(r)))


@register_check(R_BSI2)
def _bsi2(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = under_strength(r, _BSI_STRENGTH_FLOOR)
    if weak:
        return FAIL(
            f"{len(weak)} algorithm(s) below the BSI {_BSI_STRENGTH_FLOOR}-bit "
            f"effective-strength floor (RSA ≥ 3000 / EC ≥ 250; TR-02102-1)",
            _refs(weak),
        )
    return PASS(
        f"all algorithms meet the BSI {_BSI_STRENGTH_FLOOR}-bit floor",
        _refs(algorithms(r)),
    )


@register_check(R_BSI3)
def _bsi3(r: ScanResult, req: Requirement) -> CheckResult:
    bad = weak_algorithms(r) + ecb_modes(r)
    if bad:
        return FAIL(
            f"{len(bad)} weak algorithm/mode in use (deprecated primitive or ECB)",
            _refs(bad),
        )
    return PASS("no weak algorithms or ECB modes detected")


register_manual(
    R_BSI4,
    "defined cryptographic key-periods + renewal cadence (BSI TR-02102-1 §keys) is "
    "operational key-lifecycle policy not modelled in a crypto inventory",
)


# --------------------------------------------------------------------------- #
# NIST SP 1800-38C — Quantum-Readiness: discovery + migration. A crypto inventory
# IS the discovery deliverable (QR-1/QR-2); crypto-agility is the readiness signal
# (QR-3); PQC interoperability/performance testing is the process step (QR-4).
# --------------------------------------------------------------------------- #

_FW_QR = "nist_1800_38c"
_S_QR = "NIST SP 1800-38C"

R_QR1 = _req(
    "QR-1", _FW_QR, "Cryptographic discovery: every algorithm primitive identified",
    _S_QR,
)
R_QR2 = _req(
    "QR-2", _FW_QR, "Quantum-vulnerable assets discovered + risk-graded", _S_QR
)
R_QR3 = _req(
    "QR-3", _FW_QR, "Crypto-agility: quantum-safe / hybrid mechanism adopted", _S_QR
)
R_QR4 = _req(
    "QR-4", _FW_QR, "PQC interoperability + performance testing in the environment",
    _S_QR,
)


@register_check(R_QR1)
def _qr1(r: ScanResult, req: Requirement) -> CheckResult:
    algos = algorithms(r)
    if not algos:
        return FAIL("no cryptographic algorithms discovered")
    unidentified = [
        c
        for c in algos
        if (c.properties or {}).get("crypto:primitive", "unknown") == "unknown"
    ]
    if unidentified:
        return FAIL(
            f"{len(unidentified)} discovered algorithm(s) with an unidentified "
            f"primitive (discovery incomplete)",
            _refs(unidentified),
        )
    return PASS(
        f"cryptographic discovery identified the primitive of {len(algos)} "
        f"algorithm(s)",
        _refs(algos),
    )


@register_check(R_QR2)
def _qr2(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable assets discovered")
    ungraded = [
        c
        for c in qv
        if (c.properties or {}).get("crypto:nistQuantumSecurityLevel") is None
    ]
    if ungraded:
        return FAIL(
            f"{len(ungraded)} quantum-vulnerable asset(s) discovered but not "
            f"risk-graded (nistQuantumSecurityLevel)",
            _refs(ungraded),
        )
    return PASS(
        f"{len(qv)} quantum-vulnerable asset(s) discovered + risk-graded", _refs(qv)
    )


@register_check(R_QR3)
def _qr3(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable cryptography requiring migration")
    adopted = quantum_safe_mechanisms(r)
    if adopted:
        return PASS(
            f"{len(adopted)} quantum-safe / hybrid mechanism(s) adopted while "
            f"{len(qv)} quantum-vulnerable asset(s) migrate (crypto-agility)",
            _refs(adopted),
        )
    return FAIL(
        f"{len(qv)} quantum-vulnerable asset(s) in use with no quantum-safe / hybrid "
        f"mechanism adopted (no crypto-agility; ML-KEM/ML-DSA/SLH-DSA/hybrid)",
        _refs(qv),
    )


register_manual(
    R_QR4,
    "interoperability + performance testing of PQC (or hybrid) in the target "
    "environment is a validation activity outside a static crypto inventory",
)


# --------------------------------------------------------------------------- #
# CNSA 2.0 — NSA Commercial National Security Algorithm Suite 2.0 (National
# Security Systems). A parameter-level quantum-readiness allowlist: AES-256,
# SHA-384/512, ML-KEM-1024, ML-DSA-87, and SP 800-208 stateful-hash (LMS/XMSS)
# for firmware signing. Classical quantum-vulnerable crypto is permitted through
# the CNSA 2.0 transition window (exclusive PQC by 2035) but must be identified
# for migration — that is CNSA-3's transition-state tracker, not a suite ban.
# --------------------------------------------------------------------------- #

_FW_CNSA = "cnsa_2_0"
_S_CNSA = "NSA CNSA 2.0"

R_CNSA1 = _req(
    "CNSA-1",
    _FW_CNSA,
    "CNSA 2.0 symmetric + hashing: AES-256 and SHA-384/512 only",
    _S_CNSA,
)
R_CNSA2 = _req(
    "CNSA-2",
    _FW_CNSA,
    "Quantum-resistant algorithms at the CNSA 2.0 parameter set "
    "(ML-KEM-1024 / ML-DSA-87 / LMS / XMSS)",
    _S_CNSA,
)
R_CNSA3 = _req(
    "CNSA-3",
    _FW_CNSA,
    "Quantum-vulnerable public-key cryptography identified for CNSA 2.0 migration",
    _S_CNSA,
)
R_CNSA4 = _req(
    "CNSA-4",
    _FW_CNSA,
    "CNSA 2.0 NSS transition-timeline milestones met",
    _S_CNSA,
)


@register_check(R_CNSA1)
def _cnsa1(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    bad = cnsa_symmetric_hash_noncompliant(r)
    if bad:
        return FAIL(
            f"{len(bad)} symmetric/hash algorithm(s) below the CNSA 2.0 floor "
            f"(NSS requires AES-256 and SHA-384/512; e.g. AES-128/192, SHA-256)",
            _refs(bad),
        )
    return PASS(
        "all symmetric ciphers + hashes meet the CNSA 2.0 floor (AES-256, "
        "SHA-384/512)",
        _refs(algorithms(r)),
    )


@register_check(R_CNSA2)
def _cnsa2(r: ScanResult, req: Requirement) -> CheckResult:
    safe = quantum_safe_mechanisms(r)
    if not safe:
        return PASS("no quantum-resistant algorithms adopted yet to evaluate")
    under = cnsa_underparameterized_quantum_safe(r)
    if under:
        return FAIL(
            f"{len(under)} quantum-resistant algorithm(s) not at the CNSA 2.0 "
            f"parameter set (NSS mandates ML-KEM-1024 / ML-DSA-87 / LMS / XMSS; "
            f"e.g. ML-KEM-512/768, ML-DSA-44/65, SLH-DSA, FALCON)",
            _refs(under),
        )
    return PASS(
        f"all {len(safe)} quantum-resistant algorithm(s) use a CNSA 2.0 "
        f"parameter set",
        _refs(safe),
    )


@register_check(R_CNSA3)
def _cnsa3(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS(
            "no quantum-vulnerable public-key cryptography — no CNSA 2.0 migration "
            "pending"
        )
    missing = [
        c for c in qv if not (c.properties or {}).get("crypto:pqcMigrationTarget")
    ]
    if missing:
        return FAIL(
            f"{len(missing)} quantum-vulnerable public-key asset(s) not identified "
            f"with a CNSA 2.0 PQC migration target (NSS must migrate off RSA/ECC "
            f"before the 2035 exclusive-PQC deadline)",
            _refs(missing),
        )
    return PASS(
        f"{len(qv)} quantum-vulnerable public-key asset(s) identified + assigned a "
        f"CNSA 2.0 migration target (classical use permitted through the CNSA 2.0 "
        f"transition window; exclusive PQC by 2035)",
        _refs(qv),
    )


register_manual(
    R_CNSA4,
    "CNSA 2.0 NSS transition-timeline attestation (software/firmware signing by "
    "2030, default across NSS by 2033, exclusive by 2035) is a program milestone "
    "outside a static crypto inventory",
)


# --------------------------------------------------------------------------- #
# RBI FREE-AI — Protection pillar (Rec 19 + Annexure IV Cyber Security Framework).
# --------------------------------------------------------------------------- #

_FW_RBI = "rbi_free_ai_protection"
_S_RBI = "RBI FREE-AI Rec 19 / RBI Cyber Security Framework (2016)"

R_RBI1 = _req(
    "FREEAI-PROT-1",
    _FW_RBI,
    "No broken or deprecated cryptographic algorithms",
    _S_RBI,
)
R_RBI2 = _req(
    "FREEAI-PROT-2",
    _FW_RBI,
    "Transport security: no weak TLS / protocol versions",
    _S_RBI,
)
R_RBI3 = _req(
    "FREEAI-PROT-3",
    _FW_RBI,
    "No hardcoded private / secret key material",
    _S_RBI,
)
R_RBI4 = _req(
    "FREEAI-PROT-4",
    _FW_RBI,
    "Asymmetric keys meet the 2048-bit floor",
    _S_RBI,
)
R_RBI5 = _req(
    "FREEAI-PROT-5",
    _FW_RBI,
    "Security strength meets DPDP-aligned 112-bit floor",
    _S_RBI,
)
R_RBI6 = _req(
    "FREEAI-PROT-6",
    _FW_RBI,
    "Quantum-vulnerable PKI graded with migration target",
    _S_RBI,
)
R_RBI7 = _req(
    "FREEAI-PROT-7",
    _FW_RBI,
    "AI-specific cybersecurity incident response protocols",
    _S_RBI,
)
R_RBI8 = _req(
    "FREEAI-PROT-8",
    _FW_RBI,
    "Structured adversarial / red-team testing program",
    _S_RBI,
)


@register_check(R_RBI1)
def _rbi_prot1(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = weak_algorithms(r)
    if weak:
        return FAIL(
            f"{len(weak)} broken/deprecated algorithm(s) in use",
            _refs(weak),
        )
    return PASS("no weak cryptographic algorithms detected", _refs(algorithms(r)))


@register_check(R_RBI2)
def _rbi_prot2(r: ScanResult, req: Requirement) -> CheckResult:
    weak = weak_protocols(r)
    if weak:
        return FAIL(
            f"{len(weak)} weak transport protocol(s) in use (TLS < 1.2 / IKEv1)",
            _refs(weak),
        )
    return PASS("no weak transport protocols detected")


@register_check(R_RBI3)
def _rbi_prot3(r: ScanResult, req: Requirement) -> CheckResult:
    hardcoded = hardcoded_key_material(r)
    if hardcoded:
        return FAIL(
            f"{len(hardcoded)} hardcoded private/secret key(s) in source",
            _refs(hardcoded),
        )
    return PASS("no hardcoded key material detected")


@register_check(R_RBI4)
def _rbi_prot4(r: ScanResult, req: Requirement) -> CheckResult:
    small = undersized_keys(r)
    if small:
        return FAIL(
            f"{len(small)} asymmetric key(s) below the 2048-bit floor",
            _refs(small),
        )
    return PASS("no undersized asymmetric keys detected")


@register_check(R_RBI5)
def _rbi_prot5(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = under_strength(r, 112)
    if weak:
        return FAIL(
            f"{len(weak)} algorithm(s) below 112-bit security strength (DPDP proxy)",
            _refs(weak),
        )
    return PASS("all algorithms meet the 112-bit strength floor")


@register_check(R_RBI6)
def _rbi_prot6(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable public-key cryptography in use")
    missing = [
        c
        for c in qv
        if not (c.properties or {}).get("crypto:pqcMigrationTarget")
    ]
    if missing:
        return FAIL(
            f"{len(missing)} quantum-vulnerable asset(s) lack a PQC migration target",
            _refs(missing),
        )
    return PASS(
        "every quantum-vulnerable asset names a migration target",
        _refs(qv),
    )


register_manual(
    R_RBI7,
    "AI-specific cybersecurity incident monitoring and response protocols are "
    "operational evidence not visible in a crypto inventory",
)
register_manual(
    R_RBI8,
    "structured red teaming / adversarial testing cadence is process evidence",
)


# --------------------------------------------------------------------------- #
# Runner — assemble ``ScanResult.compliance`` for the CBOM frameworks.
# --------------------------------------------------------------------------- #


def run_cbom_compliance(
    result: ScanResult,
    evidence: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run every CBOM framework, write ``result.compliance`` in place, return it.

    Mirrors :func:`aibom.compliance.engine.run_all` but over the crypto
    frameworks. ``evidence`` is an optional
    ``{framework: {requirement_id: attestation}}`` map of uploaded attestations
    that flip ``not_bom_evidenceable`` requirements to ``pass_with_evidence``.
    """
    evidence = evidence or {}
    report: dict[str, Any] = {
        fw: run_framework(result, fw, evidence.get(fw)) for fw in CBOM_FRAMEWORKS
    }
    report["disclaimer"] = ADVISORY_DISCLAIMER
    result.compliance = report
    return report


__all__ = [
    "CBOM_FRAMEWORKS",
    "run_cbom_compliance",
    "crypto_assets",
    "algorithms",
    "certificates",
    "protocols",
    "related_material",
    "quantum_vulnerable",
    "weak_algorithms",
    "weak_protocols",
    "self_signed_certs",
    "hardcoded_key_material",
    "policy_disabled_algorithms",
    "disabled_but_used",
    "undersized_keys",
    "under_strength",
    "quantum_safe_mechanisms",
    "non_approved_algorithms",
    "cnsa_symmetric_hash_noncompliant",
    "cnsa_underparameterized_quantum_safe",
]
