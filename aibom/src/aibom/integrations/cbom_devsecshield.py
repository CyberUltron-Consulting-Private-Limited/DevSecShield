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
import logging
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aibom.cbom import crypto_kb
from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import analyze_cbom_document, scan_crypto
from aibom.cbom.posture.safeio import SKIP_DIRS  # the directories the engine never reads (for size estimates)
from aibom.cbom.redact import attach_snippets

log = logging.getLogger("aibom.cbom")

# Uploaded CBOM files larger than this are refused before parsing (the upload limit is 50 MB).
MAX_CBOM_BYTES = 50 * 1024 * 1024

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


_CONFIG_TYPE_CODES = frozenset({"TLS_VERIFICATION_DISABLED", "UNENCRYPTED_AT_REST", "AT_REST_ENCRYPTION_WEAK",
                                "UNENCRYPTED_IN_TRANSIT", "PLAINTEXT_LISTENER", "KNOWN_TLS_VULNERABILITY",
                                "DOWNGRADE_PROTECTION_MISSING", "KMS_KEY_ROTATION_DISABLED",
                                "KMS_KEY_DELETION_UNPROTECTED", "KMS_KEY_POLICY_PUBLIC",
                                "PROVIDER_MANAGED_KEY", "EOL_BASE_IMAGE"})


# a library row: a vulnerable, in-CVE-range or end-of-life crypto library (manifests, images, binaries, firmware)
_LIBRARY_TYPE_CODES = frozenset({"VULNERABLE_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE", "EOL_CRYPTO_LIBRARY"})


def _legacy_algorithm_type(row: dict[str, Any]) -> str:
    """Map the normalized ``asset_type`` to the dashboard ``algorithm_type``. Rows that are not crypto assets
    (a library from a manifest, a configuration fact) say so instead of "other"; these labels live on the row
    only, never in the CycloneDX ``assetType`` enum."""
    asset_type = row.get("asset_type")
    if asset_type in _ASSET_TYPE_TO_LEGACY:
        return _ASSET_TYPE_TO_LEGACY[asset_type]
    if asset_type == "algorithm":
        return row.get("primitive") or "algorithm"
    codes = set(row.get("finding_codes") or [])
    if codes & _LIBRARY_TYPE_CODES or row.get("role") == "library":
        return "library"
    if codes & _CONFIG_TYPE_CODES:
        return "configuration"
    return "other"


def _legacy_strength(row: dict[str, Any]) -> str:
    """Derive the 4-bucket ``crypto_strength`` the dashboard charts read.

    ``weak`` (a flagged weakness) > ``quantum_safe`` (a quantum-resistant
    algorithm) > ``strong`` (sound today, e.g. RSA-2048 — quantum exposure is
    tracked separately via ``quantum_safe``/the PQC card).
    """
    if row.get("weak"):
        return "weak"
    if row.get("asset_type") == "algorithm" and row.get("primitive") in (None, "", "unknown"):
        return "unknown"  # an algorithm the rule base does not know is not "safe"
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
    codes = [c for c in row.get("finding_codes") or [] if c != "QUANTUM_VULNERABLE"]
    if row.get("asset_type") == "algorithm" and row.get("primitive") in (None, "", "unknown") and not codes:
        return ("The rule base does not recognise this algorithm, so its strength was not judged; check it "
                "against NIST SP 800-131A and record it in the crypto inventory.")
    kb_fix = crypto_kb.summary_fix("code", codes, str(row.get("title") or ""))
    target = row.get("pqc_migration_target")
    if kb_fix:
        if row.get("quantum_safe_legacy") is False and target and "ML-KEM" not in kb_fix:
            return f"{kb_fix} Then plan its post-quantum migration ({target})."
        return kb_fix
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
    """OWASP Top 10:2021 for flagged rows from the knowledge base (per finding
    code, via OWASP's mapped-CWE lists); clean inventory stays empty."""
    if not _is_flagged_crypto(row):
        return {}
    mapped = crypto_kb.owasp_legacy("code", list(row.get("finding_codes") or []))
    return mapped or dict(_OWASP_A02)


def _legacy_compliance(row: dict[str, Any]) -> dict[str, str]:
    """ISO 27001 / NIST 800-53 control families for flagged rows; clean rows empty."""
    if not _is_flagged_crypto(row):
        return {}
    mapped = crypto_kb.controls_legacy("code", list(row.get("finding_codes") or []))
    return mapped or dict(_COMPLIANCE_CRYPTO)


def _evidence(row: dict[str, Any]) -> str:
    return " ".join(str(row.get(k) or "") for k in ("title", "description", "mode", "protocol_version"))


def _kb_refs(row: dict[str, Any]) -> dict[str, Any]:
    """Small, stored references into the knowledge base (CWE ids, CVE ids). The full explanation, remediation
    steps and proof commands are rendered from the knowledge base when the finding is read."""
    codes = list(row.get("finding_codes") or [])
    if not codes:
        return {"cwe": [], "cves": []}
    cwe: list[str] = []
    cves: list[str] = []
    for code in codes:
        entry = crypto_kb.entry("code", code) or {}
        cwe += [c for c in entry.get("cwe") or [] if c not in cwe]
        cves += [c["id"] for c in crypto_kb.cves_for("code", code, _evidence(row)) if c["id"] not in cves]
    return {"cwe": cwe, "cves": cves}


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
            **_kb_refs(row),
        }
    )
    out.pop("quantum_safe_legacy", None)
    return out


def _fill_fact_locations(rows: list[dict[str, Any]], result: Any) -> None:
    """Configuration-posture rows (TLS verification off, unencrypted data store ...) keep their file and line in
    the fact's own properties; copy them into ``location`` so every finding says where it is."""
    props_by_ref = {c.bom_ref: (c.properties or {}) for c in getattr(result, "components", []) or []}
    for row in rows:
        if row.get("location"):
            continue
        props = props_by_ref.get(row.get("bom_ref")) or {}
        path = props.get("crypto:factPath")
        if path:
            line = str(props.get("crypto:factLine") or "")
            row["location"] = path  # bare path, like every other row; the line has its own field
            if line.isdigit():
                row["line"] = int(line)
                row.setdefault("occurrences", [int(line)])
                row.setdefault("occurrence_count", 1)
            from aibom.cbom.occurrences import language_of
            lang = language_of(path)
            if lang:
                row.setdefault("language", lang)


def normalize_to_devsecshield(
    result: Any, *, duration_of_scan: float
) -> dict[str, Any]:
    """Normalize a scored CBOM ``ScanResult`` -> the host run-object.

    Pure + deterministic for a given ``ScanResult`` (``duration_of_scan`` aside):
    wraps :func:`normalize_crypto` and enriches each finding row with the legacy
    host keys.
    """
    run = normalize_crypto(result, duration_of_scan=duration_of_scan)
    _fill_fact_locations(run["results"], result)
    run["results"] = [_enrich(row) for row in run["results"]]
    run["kb_version"] = crypto_kb.version()
    return run


def scan_crypto_to_devsecshield(
    target: str | Path,
    *,
    level: int = 1,
    progress: ProgressCb | None = None,
    include_vendored: bool = False,
    scan_history: bool | None = None,
    scan_binaries: bool = False,
) -> dict[str, Any]:
    """One-call entry for the worker: scan + normalize -> the CBOM run-object.

    ``include_vendored`` is the scan option that also reads ``vendor/``, ``dist/``, ``build/`` and
    ``node_modules/`` (default off). ``scan_history`` reads key files that exist only in the tree's ``.git``
    history (None: when the history is complete, True: also a shallow clone, False: never). ``scan_binaries`` also
    reads container images, compiled binaries and firmware in the tree (default off)."""
    _report(progress, 10, "scanning repository for cryptographic assets")
    start = time.monotonic()
    result = scan_crypto(target, level=level, include_vendored=include_vendored, scan_history=scan_history,
                         scan_binaries=scan_binaries)
    _report(progress, 80, "normalizing crypto findings")
    out = normalize_to_devsecshield(result, duration_of_scan=time.monotonic() - start)
    # Code windows (redacted) are read here, while the checkout still exists, and only for this code-scan path:
    # uploaded CBOMs (analyze_cbom_file_to_devsecshield) carry attacker-chosen paths and never read files.
    stats = attach_snippets(out["results"], Path(target))
    _log_summary(out, stats)
    _report(progress, 100, "scan complete")
    return out


class CbomFileError(ValueError):
    """The uploaded CBOM file cannot be analysed (the message is safe to show the user)."""


def analyze_cbom_file_to_devsecshield(
    path: str | Path,
    *,
    progress: ProgressCb | None = None,
) -> dict[str, Any]:
    """Uploaded CycloneDX CBOM -> the same run-object a repository scan returns.

    The file's crypto assets are judged by the deterministic engine (flags, PQC
    grade, score, compliance, knowledge-base mapping); no language model and no
    network. ``cbom_input`` reports what was read, skipped or truncated.
    """
    import json

    file_path = Path(path)
    if file_path.stat().st_size > MAX_CBOM_BYTES:
        raise CbomFileError(f"The CBOM file is larger than {MAX_CBOM_BYTES // (1024 * 1024)} MB.")
    _report(progress, 10, "reading the CBOM file")
    try:
        doc = json.loads(file_path.read_text(encoding="utf-8-sig", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CbomFileError(f"The CBOM file is not valid JSON ({exc.__class__.__name__}).") from None
    except RecursionError:
        raise CbomFileError("The CBOM file is nested too deeply to read.") from None
    except ValueError:  # e.g. an integer with thousands of digits
        raise CbomFileError("The CBOM file contains a value that cannot be read (for example a huge number).") from None
    if not isinstance(doc, dict):
        raise CbomFileError("The CBOM file must be a CycloneDX JSON object.")
    start = time.monotonic()
    _report(progress, 30, "analysing cryptographic assets")
    result, stats = analyze_cbom_document(doc, level=4)
    _report(progress, 80, "normalizing crypto findings")
    out = normalize_to_devsecshield(result, duration_of_scan=time.monotonic() - start)
    # No code windows here: an uploaded file's paths are attacker-chosen, so nothing is ever read from disk.
    _log_summary(out, {"snippets": 0})
    out["cbom_input"] = stats
    _report(progress, 100, "analysis complete")
    return out


def _log_summary(run: dict[str, Any], snippet_stats: dict[str, int]) -> None:
    """One line per scan for air-gapped debugging: rows, codes, located lines, snippets and redactions."""
    with contextlib.suppress(Exception):  # logging must never fail a scan
        rows = run.get("results") or []
        codes = Counter(c for r in rows for c in (r.get("finding_codes") or []))
        located = sum(1 for r in rows if r.get("line"))
        log.info("cbom scan summary: rows=%d located=%d codes=%s snippets=%s kb=%s", len(rows), located,
                 dict(sorted(codes.items())), snippet_stats, run.get("kb_version"))


def _report(progress: ProgressCb | None, pct: int, message: str) -> None:
    """Best-effort progress callback; never lets reporting break a scan."""
    if progress is None:
        return
    with contextlib.suppress(Exception):  # progress must never fail the scan
        progress(pct, message)


__all__ = [
    "SKIP_DIRS",
    "CbomFileError",
    "analyze_cbom_file_to_devsecshield",
    "normalize_to_devsecshield",
    "scan_crypto_to_devsecshield",
]
