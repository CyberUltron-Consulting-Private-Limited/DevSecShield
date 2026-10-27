"""Infrastructure & Cloud Encryption Posture (#5, CBOM-D05).

Reads a team view. A view with no posture block still renders the shell, empty
registers and the limits sentence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from reportlab.platypus import Flowable

from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView
from backend.utilities.pdf import cbom_posture_common as common
from backend.utilities.pdf import cbom_posture_text as text
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    kpi_strip,
    manual_form,
    section_heading,
    signoff_block,
)
from backend.utilities.pdf.report_branding import REPORT_META

DOCUMENT_NUMBER = 5
REPORT_KEY = "cbom_infra_posture"
_SIGNOFF = ("Prepared by", "Reviewed by", "Approved by")


def _facts(view: object) -> list[dict[str, Any]]:
    return common.facts_of(view)


def _at_rest_counts(view: object) -> dict[str, int]:
    raw = common.as_mapping(common.counts_of(view).get("at_rest"))
    if raw:
        return {key: common.as_int(raw.get(key)) for key in text.AT_REST_VERDICTS}
    totals = {key: 0 for key in text.AT_REST_VERDICTS}
    for fact in _facts(view):
        if common.kind_of(fact) not in text.AT_REST_KINDS or common.is_evidence_only(fact):
            continue
        verdict = common.layer_verdict(fact, "at_rest").upper()
        if verdict in totals:
            totals[verdict] += 1
    return totals


def _finding_counts(view: object) -> dict[str, int]:
    raw = common.as_mapping(common.counts_of(view).get("findings_by_code"))
    if raw:
        return {str(key): common.as_int(value) for key, value in raw.items()}
    totals: dict[str, int] = {}
    for fact in _facts(view):
        for code in common.as_rows(fact.get("finding_codes")):
            totals[str(code)] = totals.get(str(code), 0) + 1
    return totals


def _severity_counts(view: object) -> dict[str, int]:
    raw = common.as_mapping(common.counts_of(view).get("findings_by_severity"))
    if raw:
        return {band: common.as_int(raw.get(band)) for band in ("High", "Medium", "Low")}
    bands = {"High": 0, "Medium": 0, "Low": 0}
    for code, count in _finding_counts(view).items():
        band = text.FINDING_IMPACT.get(code, "Low")
        bands[band] = bands.get(band, 0) + count
    return bands


def _kms_summary(view: object) -> dict[str, int]:
    raw = common.as_mapping(common.counts_of(view).get("kms"))
    if raw:
        return {str(key): common.as_int(value) for key, value in raw.items()}
    buckets = {
        "keys": 0,
        "rotation_enabled": 0,
        "rotation_disabled": 0,
        "rotation_not_applicable": 0,
        "rotation_unknown": 0,
    }
    for fact in _facts(view):
        if common.kind_of(fact) != "kms_key":
            continue
        buckets["keys"] += 1
        rotation = str(fact.get("rotation") or "unknown").lower()
        slot = {
            "enabled": "rotation_enabled",
            "disabled": "rotation_disabled",
            "not_applicable": "rotation_not_applicable",
            "n/a": "rotation_not_applicable",
        }.get(rotation, "rotation_unknown")
        buckets[slot] += 1
    return buckets


def _fact_count(view: object) -> int:
    raw = common.counts_of(view).get("facts")
    if raw is not None:
        return common.as_int(raw)
    return len(_facts(view))


def _kpi(view: object, width: float) -> Flowable:
    at_rest = _at_rest_counts(view)
    severity = _severity_counts(view)
    kms = _kms_summary(view)
    enabled = kms.get("rotation_enabled", 0)
    disabled = kms.get("rotation_disabled", 0)
    share = f"{enabled}/{enabled + disabled}" if enabled + disabled else "n/a"
    assessed, total, _missing, _partial = common.coverage_numbers(view)
    cards = [
        ("Facts", common.kpi_text(view, _fact_count(view)), "Encryption facts assessed"),
        ("Encrypted (declared)", common.kpi_text(view, at_rest["ENCRYPTED_DECLARED"]), "At rest"),
        (
            "Encrypted (provider default)",
            common.kpi_text(view, at_rest["ENCRYPTED_PROVIDER_DEFAULT"]),
            "At rest",
        ),
        ("Not encrypted", common.kpi_text(view, at_rest["NOT_ENCRYPTED"]), "At rest"),
        ("Unknown", common.kpi_text(view, at_rest["UNKNOWN"]), "At rest, not evidenceable"),
        ("Findings High", common.kpi_text(view, severity["High"]), "By impact"),
        ("Findings Medium", common.kpi_text(view, severity["Medium"]), "By impact"),
        ("Findings Low", common.kpi_text(view, severity["Low"]), "By impact"),
        (
            "KMS keys",
            common.kpi_text(view, kms.get("keys", 0)),
            f"rotation {share}; not applicable {kms.get('rotation_not_applicable', 0)}; "
            f"unknown {kms.get('rotation_unknown', 0)}",
        ),
        ("Sources", common.kpi_text(view, f"{assessed}/{total}"), "assessed of current sources"),
    ]
    return kpi_strip(cards, width, max_per_row=5)


def _declared_rows(view: object) -> list[list[Any]]:
    raw = common.counts_of(view).get("declared_resources")
    rows: list[list[Any]] = []
    if isinstance(raw, Mapping):
        for key, count in raw.items():
            if isinstance(key, tuple) and len(key) >= 2:
                fmt, provider = key[0], key[1]
            else:
                fmt, _sep, provider = str(key).partition("|")
            rows.append([fmt, provider, common.as_int(count)])
    else:
        for item in common.as_rows(raw):
            mapped = common.as_mapping(item)
            rows.append(
                [mapped.get("format", ""), mapped.get("provider", ""), common.as_int(mapped.get("count"))]
            )
    rows.sort(key=lambda row: (str(row[0]).casefold(), str(row[1]).casefold()))
    return rows


def _coverage(view: object, styles: Styles, width: float) -> list[Flowable]:
    counts = common.counts_of(view)
    flow: list[Flowable] = [
        *section_heading("Coverage and method", styles),
        common.note(
            f"Out of scope resources: {common.as_int(counts.get('out_of_scope_resources'))}. "
            f"Disabled resources: {common.as_int(counts.get('disabled_resources'))}.",
            styles,
        ),
        *common.register(
            ("Format", "Provider", "Declared resources"),
            _declared_rows(view),
            (240, 240, 240),
            width,
            styles,
            view=view,
            cap_key="declared",
            noun="coverage rows",
        ),
    ]
    for line in common.data_file_lines(view):
        flow.append(common.note(line, styles))
    if not common.data_file_lines(view):
        flow.append(common.note("No reference data file was recorded.", styles))
    flow.extend(common.diagnostics_flow(view, styles, width))
    return flow


def _kms_rows(view: object) -> list[list[Any]]:
    rows = [fact for fact in _facts(view) if common.kind_of(fact) == "kms_key"]
    rows.sort(
        key=lambda fact: (
            0 if str(fact.get("exposure") or "").casefold() == "public" else 1,
            common.address_of(fact).casefold(),
        )
    )
    return [
        [
            common.address_of(fact),
            common.provider_of(fact),
            fact.get("specification") or "",
            fact.get("usage") or "",
            fact.get("protection") or "",
            fact.get("rotation") or "",
            fact.get("deletion_protection") or "",
            fact.get("exposure") or "",
            fact.get("resources_protected") or "",
            fact.get("source") or fact.get("source_label") or "",
            common.location_of(fact),
            "",
            "",
        ]
        for fact in rows
    ]


def _resource_rows(facts: Sequence[Mapping[str, Any]]) -> list[list[Any]]:
    return [
        [
            common.address_of(fact),
            fact.get("native_type") or "",
            text.verdict_label(common.layer_verdict(fact, "at_rest")),
            text.verdict_label(common.layer_verdict(fact, "transport")),
            fact.get("key_management") or "",
            fact.get("basis") or "",
            common.codes_cell(fact),
            common.location_of(fact),
            fact.get("path_context") or "",
        ]
        for fact in facts
    ]


def _resources(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [
        fact
        for fact in _facts(view)
        if common.kind_of(fact) in text.AT_REST_KINDS and not common.is_evidence_only(fact)
    ]
    facts.sort(
        key=lambda fact: (
            common.provider_of(fact).casefold(),
            common.kind_of(fact).casefold(),
            *common.impact_key(fact),
        )
    )
    headers = (
        "Resource",
        "Native type",
        "At rest",
        "Transport",
        "Key management",
        "Basis",
        "Finding codes",
        "Location",
        "Path context",
    )
    weights = (120, 80, 80, 80, 70, 90, 80, 70, 50)
    flow: list[Flowable] = [*section_heading("Resource encryption register", styles)]
    if not facts:
        flow.extend(common.register(headers, [], weights, width, styles))
        return flow
    group: list[Mapping[str, Any]] = []
    current = None
    for fact in facts:
        key = (common.provider_of(fact), common.kind_of(fact))
        if current is None:
            current = key
        if key != current:
            flow.append(common.note(f"{current[0]} / {current[1]}", styles))
            flow.extend(common.register(headers, _resource_rows(group), weights, width, styles))
            group = []
            current = key
        group.append(fact)
    if current is not None:
        flow.append(common.note(f"{current[0]} / {current[1]}", styles))
        flow.extend(
            common.register(
                headers,
                _resource_rows(group),
                weights,
                width,
                styles,
                view=view,
                cap_key="resources",
                noun="resources",
            )
        )
    return flow


def _managed_tls(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [
        fact
        for fact in _facts(view)
        if common.kind_of(fact) == "tls_endpoint"
        and str(fact.get("provider") or "") in text.MANAGED_TLS_PROVIDERS
        and not common.is_verification(fact)
    ]
    facts.sort(key=common.impact_key)
    rows = []
    for fact in facts:
        net = common.net_of(fact)
        rows.append(
            [
                common.endpoint_label(fact),
                fact.get("policy") or net.get("policy") or "",
                net.get("min") or fact.get("protocol_version") or "",
                fact.get("listener") or net.get("listener") or "",
                text.verdict_label(common.layer_verdict(fact, "transport") or fact.get("verdict")),
                common.codes_cell(fact),
                common.location_of(fact),
            ]
        )
    return [
        *section_heading("Managed TLS endpoints", styles),
        *common.register(
            (
                "Endpoint",
                "Policy",
                "Minimum version",
                "Listener",
                "Verdict",
                "Finding codes",
                "Location",
            ),
            rows,
            (140, 110, 80, 80, 100, 110, 100),
            width,
            styles,
            view=view,
            cap_key="managed_tls",
            noun="endpoints",
        ),
    ]


def _secrets(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [
        fact
        for fact in _facts(view)
        if common.kind_of(fact) in {"secret_store", "certificate_policy"}
    ]
    facts.sort(key=lambda fact: common.address_of(fact).casefold())
    rows = [
        [
            common.address_of(fact),
            common.kind_of(fact),
            fact.get("key_algorithm") or fact.get("specification") or "",
            fact.get("key_management") or "",
            fact.get("rotation") or "",
        ]
        for fact in facts
    ]
    return [
        *section_heading("Secrets and certificate provisioning", styles),
        *common.register(
            ("Resource", "Kind", "Key algorithm", "Key management", "Rotation on renewal"),
            rows,
            (180, 120, 140, 150, 130),
            width,
            styles,
            view=view,
            cap_key="secrets",
            noun="secrets",
        ),
    ]


def _findings(view: object, styles: Styles, width: float) -> list[Flowable]:
    counts = _finding_counts(view)
    present = [code for code in text.FINDING_CODES if counts.get(code)]
    present.extend(sorted(code for code in counts if code not in text.FINDING_CODES and counts[code]))
    rows = [
        [
            text.finding_label(code),
            counts[code],
            text.FINDING_IMPACT.get(code, ""),
            text.FINDING_ANCHORS.get(code, ""),
            text.finding_action(code),
        ]
        for code in present
    ]
    ranked = [fact for fact in _facts(view) if common.as_rows(fact.get("finding_codes"))]
    ranked.sort(
        key=lambda fact: (
            common.impact_key(fact)[0],
            -len(common.as_rows(fact.get("finding_codes"))),
            common.address_of(fact).casefold(),
        )
    )
    top = [
        [common.address_of(fact), common.location_of(fact), fact.get("impact") or "", common.codes_cell(fact)]
        for fact in ranked[:25]
    ]
    return [
        *section_heading("Findings", styles),
        *common.register(
            ("Label", "Count", "Impact", "Anchor", "Remediation"),
            rows,
            (140, 50, 60, 120, 350),
            width,
            styles,
            noun="findings",
        ),
        common.note("25 highest-impact resources", styles),
        *common.register(
            ("Resource", "Location", "Impact", "Finding codes"),
            top,
            (180, 180, 80, 280),
            width,
            styles,
            view=view,
            cap_key="finding_resources",
            noun="finding resources",
        ),
    ]


def build_story(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """Document body for deliverable #5."""
    return [
        common.note(REPORT_META[REPORT_KEY]["how_to_read"], styles),
        common.gap(),
        _kpi(view, width),
        common.gap(),
        *common.source_status_flow(view, styles, width),
        *_coverage(view, styles, width),
        *section_heading("KMS key register", styles),
        *common.register(
            (
                "Key",
                "Provider",
                "Specification",
                "Usage",
                "Protection",
                "Rotation",
                "Deletion protection",
                "Exposure",
                "Resources protected",
                "Source",
                "Location",
                "Key custodian",
                "HSM or KMS custody evidence",
            ),
            _kms_rows(view),
            (80, 50, 60, 50, 50, 50, 55, 50, 55, 55, 55, 55, 55),
            width,
            styles,
            manual=(11, 12),
            view=view,
            cap_key="kms",
            noun="keys",
        ),
        *_resources(view, styles, width),
        *_managed_tls(view, styles, width),
        *_secrets(view, styles, width),
        *_findings(view, styles, width),
        *common.unknown_flow(view, styles, width),
        *common.previously_seen_flow(view, styles, width),
        common.gap(),
        manual_form(
            "Cloud account, subscription and project inventory",
            ("Account or project", "Environment", "Owner"),
            4,
            width=width,
        ),
        common.gap(),
        manual_form(
            "Key custodian assignments",
            ("Key", "Custodian", "Evidence reference"),
            4,
            width=width,
        ),
        common.gap(),
        signoff_block(_SIGNOFF, title="Sign-off", width=width),
        common.gap(),
        *section_heading("Limits", styles, min_space=70),
        common.note(text.INFRA_LIMIT, styles),
        common.note(text.POSTURE_SCOPE_OF_METHOD, styles, limit=800),
    ]


def build_pdf(view: TeamCbomView) -> bytes:
    """Render deliverable #5. Returns PDF bytes."""
    return build_document(
        view=view,
        number=DOCUMENT_NUMBER,
        report_key=REPORT_KEY,
        title=REPORT_META[REPORT_KEY]["title"],
        landscape=True,
        body=lambda styles, width: build_story(view, styles, width),
        basis_extra=common.basis_lines(view),
        disclaimer_paragraphs=text.DISCLAIMER_PARAGRAPHS,
        extra_banners=common.banner_pairs(view),
    )


__all__ = ["DOCUMENT_NUMBER", "REPORT_KEY", "build_pdf", "build_story"]
