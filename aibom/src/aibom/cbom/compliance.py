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

from typing import Any

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


def undersized_keys(r: ScanResult) -> list[AIComponent]:
    """Asymmetric algorithm assets below the 2048-bit floor.

    Queried straight off the graph (``crypto:primitive`` + ``crypto:keySize``),
    not via ``weak_finding`` — that predicate emits ONE code per asset and the
    deprecated-corpus match (e.g. RSA-1024 → ``WEAK_ALGORITHM``) would mask the
    orthogonal key-size dimension this check measures.
    """
    out: list[AIComponent] = []
    for c in algorithms(r):
        props = c.properties or {}
        if props.get("crypto:primitive") not in ("pke", "signature", "key-agree"):
            continue
        raw = props.get("crypto:keySize")
        if raw and raw.isdigit() and int(raw) < _MIN_ASYMMETRIC_BITS:
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
]
