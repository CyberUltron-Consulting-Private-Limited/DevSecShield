"""CBOM policy gate for the hosted CI path (``POST /cicd/cbom/scan``).

A customer's pipeline uploads its tree with the team's CI/CD key; the answer tells it whether to fail. The policy is
the code-scan CLI's: ``aibom cbom`` exits 1 when a finding code is in ``aibom.cbom.gate.FAIL_CODES`` (weak algorithm,
ECB, weak key, hard-coded key, static IV, reused nonce, weak RNG, weak padding, disabled certificate verification,
a vulnerable crypto library). Quantum-vulnerable and custom-crypto findings are reported and do not fail.

The backend image does not ship the aibom package, so the code set is copied here;
backend/tests/test_cicd_cbom_gate.py keeps it equal to the engine's. The verdict is decided from the run-object rows
the hosted scan returns (each row's ``finding_codes``), which carry every flag the CLI gate reads.

Fail closed: when no run-object arrived (the poll window ended) or the one that arrived cannot be read, the verdict
is ``no_result`` (each case with its own reason) and ``gate_failed`` is true, so a pipeline never passes a tree nobody
judged.
"""
from __future__ import annotations

from typing import Any

POLICY = "cbom-code-high"  # the CLI gate's set; named so a later policy change is visible in stored verdicts

# == aibom.cbom.gate.FAIL_CODES
FAIL_CODES = frozenset(
    {
        "WEAK_ALGORITHM",
        "WEAK_CIPHER_MODE",
        "WEAK_KEY_SIZE",
        "HARDCODED_KEY",
        "STATIC_IV",
        "REUSED_NONCE",
        "WEAK_RNG",
        "WEAK_PADDING",
        "TLS_VERIFICATION_DISABLED",
        "VULNERABLE_CRYPTO_LIBRARY",
    }
)

MAX_LISTED = 50  # failing findings listed in the answer (all are counted)

PASS, FAIL, NO_RESULT = "pass", "fail", "no_result"


def _line(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def evaluate(run: Any) -> dict[str, Any]:
    """The gate verdict for one hosted CBOM run-object (JSON-safe; stored on the CI log as returned)."""
    gate: dict[str, Any] = {
        "policy": POLICY,
        "verdict": NO_RESULT,
        "fail_codes": sorted(FAIL_CODES),
        "failing_count": 0,
        "failing": [],
        "truncated": False,
        "reason": "",
    }
    rows = run.get("results") if isinstance(run, dict) else None
    if not isinstance(rows, list):
        if run is None:  # poll_for_results gave up: running the job again can help
            gate["reason"] = ("No CBOM result arrived within the time limit, so the tree was not judged; the gate fails "
                              "closed. Run the job again; the scan is listed on the CI/CD page.")
        else:  # a result arrived but has no list of rows: running again will not help
            gate["reason"] = ("The CBOM result could not be read (it has no list of findings), so the tree was not "
                              "judged; the gate fails closed. Contact DevSecShield support with the scan's log id.")
        return gate
    failing: list[dict[str, Any]] = []
    codes_seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        codes = row.get("finding_codes")
        if not isinstance(codes, list):
            continue
        hit = sorted({code for code in codes if isinstance(code, str) and code in FAIL_CODES})
        if not hit:
            continue
        codes_seen.update(hit)
        failing.append({
            "codes": hit,
            "title": _text(row.get("title")),
            "location": _text(row.get("location")),
            "line": _line(row.get("line")),
            "impact": row.get("impact") if isinstance(row.get("impact"), str) else None,
        })
    gate["failing_count"] = len(failing)
    gate["failing"] = failing[:MAX_LISTED]
    gate["truncated"] = len(failing) > MAX_LISTED
    if failing:
        gate["verdict"] = FAIL
        gate["reason"] = (f"{len(failing)} high crypto finding(s): {', '.join(sorted(codes_seen))}. "
                          "The policy fails on these codes; quantum-vulnerable findings are reported only.")
    else:
        gate["verdict"] = PASS
        gate["reason"] = "No high crypto finding."
    return gate


def gate_failed(gate: dict[str, Any]) -> bool:
    """True unless the verdict is an explicit pass (fail closed)."""
    return gate.get("verdict") != PASS
