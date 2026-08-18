"""DevSecShield native-scanner adapter for the CBOM (crypto) lane.

The crypto peer of :mod:`aibom.integrations.devsecshield`. It makes the
standalone CBOM engine a drop-in for DevSecShield's ``cbom`` scanner, so the
worker task body becomes a single call::

    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield
    return scan_crypto_to_devsecshield(repo_path, level=4, progress=_progress)

and the returned dict is exactly the run-object the platform stores in
``Scan.scan_data`` and serves back through ``GET …/scan/{id}``.

Design (mirrors the AIBOM adapter; lanes intact):

* **Engine internals unchanged.** It only *invokes* the engine
  (:func:`aibom.cbom.pipeline.scan_crypto` runs the scanners + scorer + the
  tri-state compliance) and *reshapes* the result via
  :func:`aibom.cbom.normalize.normalize_crypto`. It raises no flags and computes
  no scores.
* **Carries the new chart payload through.** ``cbom_distributions`` (the five
  ``CbomCryptoCharts`` series) + ``cbom_compliance`` (tri-state) + ``cbom_scores``
  survive verbatim — never flattened.
* **Stays backward-compatible with the existing host.** Each ``results[]`` row is
  enriched with the legacy keys the backend findings serializer
  (``backend/utilities/db/findings.py`` cbom branch) and the dashboard cbom
  branch (``backend/utilities/dashboard/scan.py``) already read —
  ``algorithm_name`` / ``algorithm_type`` / ``crypto_strength`` / ``quantum_safe``
  / ``suggested_fix`` / ``compliance_controls`` / ``owasp_top_10`` / ``snippet`` —
  so the pre-existing CBOM dashboard + findings pages stay populated. Flagged
  rows (weak / quantum-vulnerable / finding_codes) get deterministic OWASP A02
  + ISO 27001 A.10 / NIST SC maps; clean inventory stays ``{}``. The enrichment
  is purely derived from the normalized row's own fields (no engine re-walk /
  LLM), keeping the adapter deterministic and decoupled from the host.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

ProgressCb = Callable[[int, str], None]

# crypto-asset assetType -> the legacy dashboard ``algorithm_type`` bucket. The
# dashboard counts ``== "certificate"`` for its cert card and ``== "key"`` for its
# key card; algorithm assets bucket by their CycloneDX primitive.
_ASSET_TYPE_TO_LEGACY = {
    "certificate": "certificate",
    "related-crypto-material": "key",
    "protocol": "protocol",
}

# algorithm_type values that have NO quantum-readiness meaning — adapter sets
# ``quantum_safe`` to None (N/A). The dashboard EXCLUDES those rows from the
# quantum_readiness Safe/Vulnerable buckets (never counts them as "unknown").
_QUANTUM_NA_TYPES = frozenset({"certificate", "protocol", "key"})


def _legacy_algorithm_type(row: dict[str, Any]) -> str:
    """Map the normalized ``asset_type`` to the dashboard ``algorithm_type``."""
    asset_type = row.get("asset_type")
    if asset_type in _ASSET_TYPE_TO_LEGACY:
        return _ASSET_TYPE_TO_LEGACY[asset_type]
    if asset_type == "algorithm":
        return row.get("primitive") or "algorithm"
    return "other"


def _legacy_strength(row: dict[str, Any]) -> str:
    """Derive the 4-bucket ``crypto_strength`` the dashboard charts read.

    ``weak`` (a flagged weakness) > ``quantum_safe`` (a quantum-resistant
    algorithm) > ``strong`` (sound today, e.g. RSA-2048 — quantum exposure is
    tracked separately via ``quantum_safe``/the PQC card).
    """
    if row.get("weak"):
        return "weak"
    if row.get("asset_type") == "algorithm" and not row.get("quantum_vulnerable"):
        return "quantum_safe"
    return "strong"


def _legacy_quantum_safe(row: dict[str, Any]) -> bool | None:
    """``True``/``False`` for algorithm assets, ``None`` (N/A) otherwise."""
    if row.get("asset_type") != "algorithm":
        return None
    return not row.get("quantum_vulnerable")


def _suggested_fix(row: dict[str, Any]) -> str:
    """A concrete remediation derived from the row's risk signals."""
    target = row.get("pqc_migration_target")
    if row.get("quantum_safe_legacy") is False and target:
        return (
            "Plan migration to post-quantum cryptography "
            f"({target}); NIST deprecates quantum-vulnerable public-key "
            "cryptography after 2030 and disallows it after 2035."
        )
    if row.get("weak"):
        return (
            "Replace this weak cryptographic asset with a current, "
            "standards-approved algorithm and parameterization."
        )
    return (
        "Keep this cryptographic asset in the organization's crypto inventory "
        "and post-quantum migration plan."
    )


def _is_flagged_crypto(row: dict[str, Any]) -> bool:
    """True when the row carries a weakness, quantum, or finding-code signal."""
    if row.get("weak") or row.get("quantum_vulnerable"):
        return True
    codes = row.get("finding_codes") or []
    return bool(codes)


# Display labels must match frontend/lib/owasp-compliance-labels.ts so the
# dashboard aggregation key (the map VALUE) renders correctly on CbomResults.
_OWASP_A02 = {
    "CRYPTOGRAPHIC_FAILURES": "A02:2021 - Cryptographic Failures",
}
_COMPLIANCE_CRYPTO = {
    "ISO27001_A10_CRYPTOGRAPHY": "ISO 27001 - A.10 Cryptography",
    "NIST80053_SC": "NIST 800-53 - System and Communications Protection",
}


def _legacy_owasp(row: dict[str, Any]) -> dict[str, str]:
    """Map flagged crypto rows to OWASP A02; leave clean inventory empty."""
    if not _is_flagged_crypto(row):
        return {}
    return dict(_OWASP_A02)


def _legacy_compliance(row: dict[str, Any]) -> dict[str, str]:
    """Map flagged crypto rows to ISO 27001 A.10 + NIST SC; clean rows empty."""
    if not _is_flagged_crypto(row):
        return {}
    return dict(_COMPLIANCE_CRYPTO)


def _enrich(row: dict[str, Any]) -> dict[str, Any]:
    """Add the legacy host-dashboard / findings keys to a normalized row.

    Returns a new dict (does not mutate the normalizer output) so the run-object
    stays a pure function of the ScanResult.
    """
    out = dict(row)
    quantum_safe = _legacy_quantum_safe(row)
    out["quantum_safe_legacy"] = quantum_safe  # scratch for _suggested_fix
    out.update(
        {
            "algorithm_name": row.get("title"),
            "algorithm_type": _legacy_algorithm_type(row),
            "crypto_strength": _legacy_strength(row),
            "quantum_safe": quantum_safe,
            "suggested_fix": _suggested_fix(out),
            # Per-row maps feed the legacy CbomResults OWASP / Compliance cards
            # (backend dashboard aggregates the VALUES). Flagged rows get
            # deterministic A02 + crypto controls; clean inventory stays {}.
            "compliance_controls": _legacy_compliance(row),
            "owasp_top_10": _legacy_owasp(row),
            "snippet": "",
        }
    )
    out.pop("quantum_safe_legacy", None)
    return out


def normalize_to_devsecshield(
    result: Any, *, duration_of_scan: float
) -> dict[str, Any]:
    """Normalize a scored CBOM ``ScanResult`` -> the host run-object.

    Pure + deterministic for a given ``ScanResult`` (``duration_of_scan`` aside):
    wraps :func:`normalize_crypto` and enriches each finding row with the legacy
    host keys.
    """
    run = normalize_crypto(result, duration_of_scan=duration_of_scan)
    run["results"] = [_enrich(row) for row in run["results"]]
    return run


def scan_crypto_to_devsecshield(
    target: str | Path,
    *,
    level: int = 1,
    progress: ProgressCb | None = None,
) -> dict[str, Any]:
    """One-call entry for the worker: scan + normalize -> the CBOM run-object."""
    _report(progress, 10, "scanning repository for cryptographic assets")
    start = time.monotonic()
    result = scan_crypto(target, level=level)
    _report(progress, 80, "normalizing crypto findings")
    out = normalize_to_devsecshield(result, duration_of_scan=time.monotonic() - start)
    _report(progress, 100, "scan complete")
    return out


def _report(progress: ProgressCb | None, pct: int, message: str) -> None:
    """Best-effort progress callback; never lets reporting break a scan."""
    if progress is None:
        return
    with contextlib.suppress(Exception):  # progress must never fail the scan
        progress(pct, message)


__all__ = ["normalize_to_devsecshield", "scan_crypto_to_devsecshield"]
