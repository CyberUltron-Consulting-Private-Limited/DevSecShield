"""Project a CBOM CI run-object into the same view a CBOM scan page renders."""

from types import SimpleNamespace

from backend.utilities.dashboard.bom_risk_score import cbom_finding_risk_score
from backend.utilities.dashboard.finding_metrics import get_issue_status_metrics
from backend.utilities.dashboard.remediation_metrics import get_remediation_metrics
from backend.utilities.dashboard.scan import generate_scan_dashboard
from backend.utilities.dashboard.scan_metadata import get_scan_metadata


def _display_row(row: dict) -> dict:
    copied = dict(row)
    algorithm_type = copied.get("algorithm_type")
    if not algorithm_type or str(algorithm_type).lower() in ("unknown", "none", "null"):
        copied["algorithm_type"] = copied.get("asset_type") or "other"
    strength = copied.get("crypto_strength")
    if not strength or str(strength).lower() in ("unknown", "none", "null"):
        copied["crypto_strength"] = "not-applicable"
    return copied


_KB_REMEDIATION_ROWS = 200  # each row now also builds a code fix and an exploit demo


def _kb_remediation(row: dict, index: int) -> dict | None:
    if index >= _KB_REMEDIATION_ROWS or not row.get("finding_codes"):
        return None
    from backend.utilities.cbom_sources.kb_remediation import remediation

    return remediation(row, "code")


def _finding(row: dict, index: int) -> dict:
    from backend.utilities.cbom_sources.cbom_rows import display_row

    shown = display_row(_display_row(row))
    return {
        "id": str(shown.get("bom_ref") or f"ci-{index}"),
        "bom_ref": shown.get("bom_ref") or None,
        "title": shown.get("title") or "",
        "description": shown.get("description") or "",
        "impact": shown.get("impact") or "low",  # findings only reach here; a legacy one without impact is Low
        "risk_score": cbom_finding_risk_score(shown),
        "status": "not_started",
        "compliance_controls": shown.get("compliance_controls") or [],
        "owasp_top_10": shown.get("owasp_top_10") or [],
        "suggested_fix": shown.get("suggested_fix") or "",
        "algorithm_name": shown.get("algorithm_name") or shown.get("title") or "",
        "algorithm_type": shown.get("algorithm_type") or "",
        "crypto_strength": shown.get("crypto_strength") or "",
        "key_size": shown.get("key_size"),
        "quantum_safe": shown.get("quantum_safe", False),
        "location": shown.get("location") or "",
        "snippet": shown.get("snippet") or "",
        # CI runs are not stored findings, so the remediation endpoint cannot look them up; the offline
        # knowledge-base remediation is built here for flagged rows instead (no AI, no network).
        "remediation": _kb_remediation(shown, index),
        "finding_codes": shown.get("finding_codes") or [],
        "cwe": shown.get("cwe") or [],
        "cves": shown.get("cves") or [],
        "asset_type": shown.get("asset_type"),
        "material_kind": shown.get("material_kind"),
        "container_format": shown.get("container_format"),
        "not_valid_after": shown.get("not_valid_after"),
        "self_signed": shown.get("self_signed"),
        "expired": shown.get("expired"),
        "line": shown.get("line"),
        "occurrences": shown.get("occurrences") or [],
        "occurrence_count": shown.get("occurrence_count"),
        "language": shown.get("language"),
        "snippet_start": shown.get("snippet_start"),
        "snippet_note": shown.get("snippet_note"),
        "weak": bool(shown.get("weak")),
    }


def project_cbom_ci_page(run: dict) -> dict | None:
    """Return data, dashboard, findings, and scan_metadata for CbomResults.

    CI logs are not Scan rows, so findings are not in the findings collection.
    The dashboard is built from the stored run-object and every finding is
    not started.
    """
    if not isinstance(run, dict):
        return None
    rows = run.get("results")
    if not isinstance(rows, list):
        return None
    if "cbom_json" not in run and "cbom_distributions" not in run:
        return None

    scan = SimpleNamespace(
        id=-1,
        scan_data=run,
        scan_metadata={"zip_file_used": True},
    )
    dashboard = generate_scan_dashboard(scan_type="cbom", scan_object=scan)
    # findings only (cbom_rows.is_finding): clean inventory rows are listed by the CycloneDX and the charts
    from backend.utilities.cbom_sources.cbom_rows import is_finding

    flagged = [(index, row) for index, row in enumerate(rows) if isinstance(row, dict) and is_finding(row)]
    stored = [
        {
            "finding_status": "not_started",
            "finding_data": row,
            "created_at": None,
        }
        for _index, row in flagged
    ]
    status = get_issue_status_metrics(stored)
    dashboard["remediation_metrics"] = get_remediation_metrics(stored)
    dashboard["remediation_actions_required"] = {
        "total_findings": len(stored),
        "total_fixed": status.get("fixed", 0),
        "total_in_progress": status.get("in_progress", 0),
        "total_not_started": status.get("not_started", 0),
        "total_ignored": status.get("ignored", 0),
    }
    findings = [_finding(row, index) for index, row in flagged]
    return {
        "data": [_display_row(row) for row in rows if isinstance(row, dict)],
        "dashboard": dashboard,
        "findings": findings,
        "scan_metadata": get_scan_metadata(scan_type="cbom", scan=scan),
    }
