"""One display rule for CBOM code-scan rows, applied when rows are read.

Scans stored before this release typed a vulnerable library, a disabled TLS verification or an unencrypted data
store as ``algorithm_type="other"`` and ``crypto_strength="strong"``, so the Weak KPI, the strength chart, the
PDF and the findings table disagreed with their own High findings. The engine now writes ``library`` /
``configuration`` and ``weak``; this helper gives OLD rows the same values from their finding codes, so every
view of an old scan agrees with a new one. It never changes a row that already carries the new values.
"""
from __future__ import annotations

from typing import Any

# The row TYPE a code gives, as the engine's adapter writes it (aibom/integrations/cbom_devsecshield.py
# _LIBRARY_TYPE_CODES / _CONFIG_TYPE_CODES): a library row, or a configuration (posture) row.
LIBRARY_CODES = frozenset({"VULNERABLE_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE", "EOL_CRYPTO_LIBRARY"})
CONFIG_CODES = frozenset({"TLS_VERIFICATION_DISABLED", "UNENCRYPTED_AT_REST", "AT_REST_ENCRYPTION_WEAK",
                          "UNENCRYPTED_IN_TRANSIT", "PLAINTEXT_LISTENER", "KNOWN_TLS_VULNERABILITY",
                          "DOWNGRADE_PROTECTION_MISSING", "KMS_KEY_ROTATION_DISABLED", "KMS_KEY_DELETION_UNPROTECTED",
                          "KMS_KEY_POLICY_PUBLIC", "PROVIDER_MANAGED_KEY", "EOL_BASE_IMAGE"})
# The codes that make a library or configuration row WEAK, as the engine marks them (aibom/cbom/normalize.py
# CONFIG_WEAKNESS_CODES, plus CUSTOM_CRYPTO). A provider-managed key, a key-management setting, an end-of-life base
# image or a library inside a CVE range is a finding, not a weak algorithm.
WEAK_EXTRA_CODES = frozenset({"VULNERABLE_CRYPTO_LIBRARY", "TLS_VERIFICATION_DISABLED", "UNENCRYPTED_AT_REST",
                              "AT_REST_ENCRYPTION_WEAK", "UNENCRYPTED_IN_TRANSIT", "PLAINTEXT_LISTENER",
                              "KNOWN_TLS_VULNERABILITY", "DOWNGRADE_PROTECTION_MISSING", "CUSTOM_CRYPTO"})


def display_row(row: dict[str, Any]) -> dict[str, Any]:
    """A copy of ``row`` with type/strength/weak derived from its finding codes when the stored values predate it."""
    if not isinstance(row, dict):
        return row
    codes = {c for c in (row.get("finding_codes") or []) if isinstance(c, str)}
    if not codes & (WEAK_EXTRA_CODES | LIBRARY_CODES | CONFIG_CODES):
        return row
    out = dict(row)
    if str(out.get("algorithm_type") or "other").lower() in ("other", "", "unknown", "none"):
        if codes & LIBRARY_CODES:
            out["algorithm_type"] = "library"
        elif codes & CONFIG_CODES:
            out["algorithm_type"] = "configuration"
    if codes & WEAK_EXTRA_CODES:
        if str(out.get("crypto_strength") or "").lower() in ("strong", "", "unknown", "not-applicable", "quantum_safe"):
            out["crypto_strength"] = "weak"
        out["weak"] = True
    return out


def is_finding(row: dict[str, Any]) -> bool:
    """Whether a CBOM code-scan row is a FINDING (counted on dashboards, reports and tickets) or clean inventory.

    The engine now leaves a row with no finding code without an impact (an AES-GCM or Ed25519 a CBOM must list is
    not a Low finding). One rule, decided when rows are read, so stored scans are never rewritten:

    * a legacy row stored before ``finding_codes`` existed keeps its impact and counts as a finding;
    * a row with at least one finding code is a finding (QUANTUM_VULNERABLE included);
    * a row with an empty code list is a finding only when it is still marked weak or quantum-vulnerable.
    """
    if not isinstance(row, dict):
        return False
    if "finding_codes" not in row:
        return True
    if any(isinstance(c, str) and c for c in (row.get("finding_codes") or [])):
        return True
    return bool(row.get("weak") is True or row.get("quantum_vulnerable") is True)


__all__ = ["display_row", "is_finding", "WEAK_EXTRA_CODES"]
