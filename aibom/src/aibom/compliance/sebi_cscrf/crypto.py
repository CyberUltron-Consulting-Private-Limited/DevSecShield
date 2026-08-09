"""SEBI CSCRF CBOM lane — Box Item 7 + PR.DS + GV.SC.S5(d).

Registered under ``sebi_cscrf_cbom``. Imported only from
:mod:`aibom.cbom.compliance` — never from :mod:`aibom.compliance.__init__`.

Checks read GRAPH ``crypto:`` properties only (never ``result.flags``).
Box 7 is readiness (migration targets / grading), not a classical-PKI ban.
"""

from __future__ import annotations

from aibom.cbom.compliance import (
    algorithms,
    crypto_assets,
    quantum_vulnerable,
    under_strength,
    undersized_keys,
    weak_algorithms,
    weak_protocols,
)
from aibom.compliance.base import (
    FAIL,
    PASS,
    CheckResult,
    Requirement,
    register_applicability,
    register_check,
    register_manual,
)
from aibom.compliance.sebi_cscrf.common import SEBI_DISCLAIMER, load_ledger
from aibom.model.component import AIComponent
from aibom.model.result import ScanResult

_FW = "sebi_cscrf_cbom"
_SRC = "SEBI CSCRF CIR/2024/113"


def _refs(comps: list[AIComponent]) -> list[str]:
    return [c.bom_ref for c in comps if c.bom_ref]


register_applicability(
    _FW,
    lambda r: bool(crypto_assets(r)),
    "no cryptographic assets detected; SEBI CSCRF CBOM controls do not apply",
)


def _req(rid: str, title: str, source: str) -> Requirement:
    return Requirement(rid, _FW, title, source)


# ── Autos ───────────────────────────────────────────────────────────────────

R_QC1 = _req(
    "CSCRF-QC-1",
    "Cryptographic asset inventory present",
    f"{_SRC} Box Item 7 #1",
)
R_QC2 = _req(
    "CSCRF-QC-2",
    "Quantum-vulnerable assets have PQC migration targets",
    f"{_SRC} Box Item 7 #1/#2",
)
R_QC9 = _req(
    "CSCRF-QC-9",
    "PQC readiness grading present on quantum-vulnerable assets",
    f"{_SRC} Box Item 7 #4",
)
R_DS1 = _req(
    "CSCRF-DS-1",
    "No weak transport protocols",
    f"{_SRC} PR.DS.S1",
)
R_DS2 = _req(
    "CSCRF-DS-2",
    "Asymmetric keys meet 2048-bit floor",
    f"{_SRC} PR.DS.S1–S3",
)
R_DS6 = _req(
    "CSCRF-DS-6",
    "No broken or deprecated algorithms",
    f"{_SRC} PR.DS strong algorithms",
)
R_DS7 = _req(
    "CSCRF-DS-7",
    "Classical security strength at least 112 bits",
    f"{_SRC} PR.DS strong algorithms",
)
R_SC1 = _req(
    "CSCRF-SC-1",
    "Encryption used evidenced in crypto BOM",
    f"{_SRC} GV.SC.S5(d)",
)


@register_check(R_QC1)
def _qc1(r: ScanResult, req: Requirement) -> CheckResult:
    assets = crypto_assets(r)
    if not assets:
        return PASS("no crypto assets (applicability should OOS)")
    algos = algorithms(r)
    unknown = [
        c
        for c in algos
        if (c.properties or {}).get("crypto:primitive", "").lower() in {"", "unknown"}
    ]
    if not algos and not assets:
        return FAIL("no inventoriable cryptographic assets", [])
    if unknown:
        return FAIL(
            f"{len(unknown)} algorithm(s) lack a known primitive",
            _refs(unknown),
        )
    return PASS(
        f"{len(assets)} cryptographic asset(s) inventoried",
        _refs(assets),
    )


@register_check(R_QC2)
def _qc2(r: ScanResult, req: Requirement) -> CheckResult:
    qv = quantum_vulnerable(r)
    if not qv:
        return PASS("no quantum-vulnerable assets requiring migration targets")
    missing = [
        c for c in qv if not (c.properties or {}).get("crypto:pqcMigrationTarget")
    ]
    if missing:
        return FAIL(
            f"{len(missing)} quantum-vulnerable asset(s) lack pqcMigrationTarget",
            _refs(missing),
        )
    return PASS(
        "every quantum-vulnerable asset names a PQC migration target",
        _refs(qv),
    )


@register_check(R_QC9)
def _qc9(r: ScanResult, req: Requirement) -> CheckResult:
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
            f"{len(ungraded)} quantum-vulnerable asset(s) lack "
            f"nistQuantumSecurityLevel",
            _refs(ungraded),
        )
    return PASS(
        "every quantum-vulnerable asset carries nistQuantumSecurityLevel",
        _refs(qv),
    )


@register_check(R_DS1)
def _ds1(r: ScanResult, req: Requirement) -> CheckResult:
    weak = weak_protocols(r)
    if weak:
        return FAIL(
            f"{len(weak)} weak transport protocol(s) in use",
            _refs(weak),
        )
    return PASS("no weak transport protocols detected")


@register_check(R_DS2)
def _ds2(r: ScanResult, req: Requirement) -> CheckResult:
    small = undersized_keys(r)
    if small:
        return FAIL(
            f"{len(small)} asymmetric key(s) below the 2048-bit floor",
            _refs(small),
        )
    return PASS("no undersized asymmetric keys detected")


@register_check(R_DS6)
def _ds6(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = weak_algorithms(r)
    if weak:
        return FAIL(
            f"{len(weak)} broken/deprecated algorithm(s) in use",
            _refs(weak),
        )
    return PASS("no weak cryptographic algorithms detected", _refs(algorithms(r)))


@register_check(R_DS7)
def _ds7(r: ScanResult, req: Requirement) -> CheckResult:
    if not algorithms(r):
        return PASS("no cryptographic algorithms inventoried")
    weak = under_strength(r, 112)
    if weak:
        return FAIL(
            f"{len(weak)} algorithm(s) below 112-bit security strength",
            _refs(weak),
        )
    return PASS("all graded algorithms meet the 112-bit strength floor")


@register_check(R_SC1)
def _sc1(r: ScanResult, req: Requirement) -> CheckResult:
    """GV.SC.S5(d) — encryption used evidenced by inventoriable crypto assets."""
    assets = crypto_assets(r)
    if assets:
        return PASS(
            f"encryption-relevant crypto inventory present ({len(assets)} asset(s))",
            _refs(assets),
        )
    return FAIL("no encryption-relevant cryptographic assets in CBOM", [])


def _register_manuals() -> None:
    doc = load_ledger()
    for raw in doc.get("requirements") or []:
        if raw.get("lane") != "cbom" or raw.get("mode") != "manual":
            continue
        rid = str(raw["id"])
        req = Requirement(
            id=rid,
            framework=_FW,
            title=str(raw["title"]),
            source=str(raw.get("pdf") or _SRC),
        )
        register_manual(
            req,
            f"{SEBI_DISCLAIMER} Process attestation for {rid} "
            f"(organizational / infra evidence not visible in a crypto BOM).",
        )


_register_manuals()

# Guard: ledger auto IDs must match registered autos (drift detection at import).
_EXPECTED_AUTO = {
    "CSCRF-QC-1",
    "CSCRF-QC-2",
    "CSCRF-QC-9",
    "CSCRF-DS-1",
    "CSCRF-DS-2",
    "CSCRF-DS-6",
    "CSCRF-DS-7",
    "CSCRF-SC-1",
}
_LEDGER_AUTO = {
    str(r["id"])
    for r in (load_ledger().get("requirements") or [])
    if r.get("lane") == "cbom" and r.get("mode") == "auto"
}
if _LEDGER_AUTO != _EXPECTED_AUTO:
    raise RuntimeError(
        f"sebi_cscrf_cbom auto ID drift: "
        f"only_code={_EXPECTED_AUTO - _LEDGER_AUTO} "
        f"only_ledger={_LEDGER_AUTO - _EXPECTED_AUTO}"
    )
