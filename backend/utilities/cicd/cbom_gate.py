"""CBOM policy gate for the hosted CI path (``POST /cicd/cbom/scan``).

A customer's pipeline uploads its tree with the team's CI/CD key; the answer tells it whether to fail. The verdict is
decided by the CBOM gate policy of the integration, else of the team, else the default
(``gate_policy.DEFAULT_POLICY``: NIST SP 800-131A Rev. 2 key sizes and banned algorithms, the code-scan CLI's high
finding codes, quantum-vulnerable and deprecated algorithms reported as warnings). The policy format, its validation
and the per-rule evaluation live in ``gate_policy.py``, vendored byte-identical into the ``aibom cbom`` offline gate.

The verdict is decided from the run-object rows the hosted scan returns (``finding_codes``, ``title``, ``primitive``,
``key_size``, ``curve``, ``quantum_vulnerable``); every failing finding lists each rule it broke.

Fail closed: when no run-object arrived (the poll window ended) or the one that arrived cannot be read, the verdict
is ``no_result`` (each case with its own reason) and ``gate_failed`` is true, so a pipeline never passes a tree nobody
judged.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from backend.utilities.cicd import gate_policy as GP

POLICY = GP.DEFAULT_POLICY["name"]  # the name a verdict carries when no team policy is set

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


def _cap(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return entries[:MAX_LISTED]


def evaluate(run: Any, policy: dict[str, Any] | None = None, *, source: str = "default", version: int | None = None,
             today: _dt.date | None = None) -> dict[str, Any]:
    """The gate verdict for one hosted CBOM run-object (JSON-safe; stored on the CI log as returned).

    ``policy`` is a validated policy (``gate_policy.validate_policy``); None uses the default. ``source`` says where it
    came from (``default``, ``team``, ``integration`` or ``file``) and ``version`` its stored version."""
    active = policy if policy is not None else GP.DEFAULT_POLICY
    gate: dict[str, Any] = {
        "policy": active["name"],
        "policy_source": source if policy is not None else "default",
        "policy_version": version,
        "policy_digest": GP.policy_digest(active),
        "verdict": NO_RESULT,
        "fail_codes": list(active["block_codes"]),
        "failing_count": 0,
        "failing": [],
        "truncated": False,
        "rules_failed": {},
        "warning_count": 0,
        "warnings": [],
        "waived_count": 0,
        "waived": [],
        "expired_exceptions": [],
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
    judged = GP.evaluate_rows(rows, active, today=today)
    failing, warnings, waived = judged["failing"], judged["warnings"], judged["waived"]
    gate.update({
        "failing_count": len(failing), "failing": _cap(failing), "truncated": len(failing) > MAX_LISTED,
        "rules_failed": judged["rules_failed"],
        "warning_count": len(warnings), "warnings": _cap(warnings),
        "waived_count": len(waived), "waived": _cap(waived),
        "expired_exceptions": judged["expired_exceptions"],
    })
    extra = []
    if warnings:
        extra.append(f"{len(warnings)} warning(s) reported")
    if waived:
        extra.append(f"{len(waived)} finding(s) waived by an exception")
    if judged["expired_exceptions"]:
        extra.append(f"{len(judged['expired_exceptions'])} exception(s) expired")
    tail = f" ({'; '.join(extra)})" if extra else ""
    if failing:
        codes = sorted({code for entry in failing for code in entry["codes"]})
        rules = ", ".join(f"{rule} x{count}" for rule, count in judged["rules_failed"].items())
        gate["verdict"] = FAIL
        gate["reason"] = (f"{len(failing)} finding(s) blocked by the CBOM policy \"{active['name']}\": {rules}"
                          + (f" (codes: {', '.join(codes)})" if codes else "") + f".{tail}")
    else:
        gate["verdict"] = PASS
        gate["reason"] = f"Nothing the CBOM policy \"{active['name']}\" blocks{tail}."
    return gate


def summary_line(gate: dict[str, Any]) -> str:
    """The verdict on one grep-safe line (no quotes or backslashes): the templates without jq print it."""
    return GP.summary_line(gate)


def gate_failed(gate: dict[str, Any]) -> bool:
    """True unless the verdict is an explicit pass (fail closed)."""
    return gate.get("verdict") != PASS
