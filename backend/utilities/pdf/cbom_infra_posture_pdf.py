"""Infrastructure & Cloud Encryption Posture (SOW D6, CBOM-D06).

Reads a team view. A view with no posture block still renders the shell, empty
registers and the limits sentence.

Rule P: every number on the page comes from ``scope_facts`` (the facts this document is about: keys, key stores,
at-rest resources, cloud-managed TLS, secrets and private CAs), so a KPI card always equals the rows listed under
it.  Probed and server-config TLS endpoints belong to the Network, TLS and Crypto Protocol Assessment (SOW D7).
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

DOCUMENT_NUMBER = 6  # SOW Table 7: D6
REPORT_KEY = "cbom_infra_posture"
_SIGNOFF = ("Prepared by", "Reviewed by", "Approved by")


_KEY_KINDS = frozenset({"kms_key"})
_SECRET_KINDS = frozenset({"secret_store", "secret", "certificate_policy"})
_SEVERITY_BANDS = ("Critical", "High", "Medium", "Low")


def _facts(view: object) -> list[dict[str, Any]]:
    return common.facts_of(view)


def _is_managed_tls(fact: Mapping[str, Any]) -> bool:
    return (
        common.kind_of(fact) == "tls_endpoint"
        and str(fact.get("provider") or "") in text.MANAGED_TLS_PROVIDERS
        and not common.is_verification(fact)
    )


def _is_at_rest(fact: Mapping[str, Any]) -> bool:
    return common.kind_of(fact) in text.AT_REST_KINDS and not common.is_evidence_only(fact)


# (the view's posture fact tuple, its scope facts): one document reads the scope seven times; at 50k facts the
# conversion (``facts_of``) dominated the build.  Keyed by the tuple object itself (held here, so its id is never
# reused); a different view or a new fold misses the cache.
_SCOPE_CACHE: tuple[object, list[dict[str, Any]]] = ((), [])


def scope_facts(view: object) -> list[dict[str, Any]]:
    """The facts this document reports on, in view order.  Every KPI and register below reads this list (a fresh
    list each call; the fact dicts are shared and read only)."""
    global _SCOPE_CACHE
    raw = common.grab(common.posture_block(view), "facts", ())
    held, cached = _SCOPE_CACHE
    if raw is held and isinstance(raw, tuple) and raw:
        return list(cached)
    found = [
        fact
        for fact in _facts(view)
        if common.kind_of(fact) in _KEY_KINDS
        or common.kind_of(fact) == "key_store"
        or common.kind_of(fact) in _SECRET_KINDS
        or _is_at_rest(fact)
        or _is_managed_tls(fact)
    ]
    if isinstance(raw, tuple) and raw:
        _SCOPE_CACHE = (raw, found)
    return list(found)


def _at_rest_counts(facts: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    totals = {key: 0 for key in text.AT_REST_VERDICTS}
    for fact in facts:
        if not _is_at_rest(fact):
            continue
        verdict = common.layer_verdict(fact, "at_rest").upper() or "UNKNOWN"
        totals[verdict if verdict in totals else "UNKNOWN"] += 1
    return totals


def finding_rows(facts: Sequence[Mapping[str, Any]]) -> list[tuple[str, int, str]]:
    """``(code, occurrences, impact)`` over ``facts``: the findings table and the severity cards both read it."""
    counts: dict[str, int] = {}
    worst: dict[str, str] = {}
    rank = {band: index for index, band in enumerate(_SEVERITY_BANDS)}
    for fact in facts:
        impact = str(fact.get("impact") or "")
        for code in common.as_rows(fact.get("finding_codes")):
            key = str(code)
            counts[key] = counts.get(key, 0) + 1
            if impact in rank and rank[impact] < rank.get(worst.get(key, ""), 9):
                worst[key] = impact
    rows = [(code, counts[code], text.finding_impact(code, worst.get(code))) for code in counts]
    rows.sort(key=lambda row: (rank.get(row[2], 9), -row[1], text.finding_label(row[0]).casefold(), row[0]))
    return rows


def _severity_counts(rows: Sequence[tuple[str, int, str]]) -> dict[str, int]:
    bands = {band: 0 for band in _SEVERITY_BANDS}
    for _code, count, impact in rows:
        bands[impact] = bands.get(impact, 0) + count
    return bands


def _rotation(fact: Mapping[str, Any]) -> str:
    """The rotation word of a key: the fact's own, else the engine's ``signals`` / ``attrs`` (what the counts read)."""
    for raw in (
        fact.get("rotation"),
        common.as_mapping(fact.get("signals")).get("rotation"),
        common.attrs_of(fact).get("rotation"),
    ):
        word = str(raw or "").strip().casefold()
        if word in ("enabled", "true", "yes"):
            return "enabled"
        if word in ("disabled", "false", "no"):
            return "disabled"
        if word in ("not_applicable", "not applicable", "n/a", "na"):
            return "not_applicable"
    return "unknown"


def _kms_summary(facts: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    buckets = {
        "keys": 0,
        "rotation_enabled": 0,
        "rotation_disabled": 0,
        "rotation_not_applicable": 0,
        "rotation_unknown": 0,
    }
    for fact in facts:
        if common.kind_of(fact) not in _KEY_KINDS:
            continue
        buckets["keys"] += 1
        buckets[f"rotation_{_rotation(fact)}"] += 1
    return buckets


def _kpi(view: object, width: float) -> Flowable:
    facts = scope_facts(view)
    at_rest = _at_rest_counts(facts)
    severity = _severity_counts(finding_rows(facts))
    kms = _kms_summary(facts)
    enabled = kms["rotation_enabled"]
    disabled = kms["rotation_disabled"]
    share = f"{enabled}/{enabled + disabled}" if enabled + disabled else "n/a"
    assessed, total, _missing, _partial = common.coverage_numbers(view)
    cards = [
        ("Facts", common.kpi_text(view, len(facts)), "Encryption facts in this document"),
        ("Encrypted (declared)", common.kpi_text(view, at_rest["ENCRYPTED_DECLARED"]), "At rest"),
        (
            "Encrypted (provider default)",
            common.kpi_text(view, at_rest["ENCRYPTED_PROVIDER_DEFAULT"]),
            "At rest",
        ),
        ("Not encrypted", common.kpi_text(view, at_rest["NOT_ENCRYPTED"]), "At rest"),
        ("Unknown", common.kpi_text(view, at_rest["UNKNOWN"]), "At rest, not evidenceable"),
    ]
    if severity["Critical"]:
        cards.append(("Findings Critical", common.kpi_text(view, severity["Critical"]), "By impact"))
    cards += [
        ("Findings High", common.kpi_text(view, severity["High"]), "By impact"),
        ("Findings Medium", common.kpi_text(view, severity["Medium"]), "By impact"),
        ("Findings Low", common.kpi_text(view, severity["Low"]), "By impact"),
        (
            "KMS keys",
            common.kpi_text(view, kms["keys"]),
            f"rotation {share}; not applicable {kms['rotation_not_applicable']}; "
            f"unknown {kms['rotation_unknown']}",
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


_ROTATION_WORDS = {
    "enabled": "enabled",
    "disabled": "disabled",
    "not_applicable": "not applicable",
    "unknown": "not reported",
}


def _rotation_cell(fact: Mapping[str, Any]) -> str:
    word = _ROTATION_WORDS[_rotation(fact)]
    detail = str(fact.get("rotation_detail") or "").strip()
    if not detail or detail.casefold() == word:
        return word
    return f"{word} ({detail})"


def _source_cell(fact: Mapping[str, Any]) -> str:
    return str(fact.get("source") or fact.get("source_label") or "")


def _kms_rows(view: object) -> list[list[Any]]:
    rows = [fact for fact in scope_facts(view) if common.kind_of(fact) in _KEY_KINDS]
    rows.sort(
        key=lambda fact: (
            0 if str(fact.get("exposure") or "").casefold() == "public" else 1,
            common.impact_key(fact)[0],
            common.provider_of(fact).casefold(),
            common.address_of(fact).casefold(),
        )
    )
    return [
        [
            common.address_of(fact),
            common.provider_of(fact),
            fact.get("specification") or "",
            fact.get("algorithm") or "",
            fact.get("usage") or "",
            fact.get("protection") or "",
            fact.get("state") or "",
            _rotation_cell(fact),
            fact.get("deletion_protection") or "",
            common.codes_cell(fact),
            _source_cell(fact),
            common.location_of(fact),
            "",
            "",
        ]
        for fact in rows
    ]


_KMS_HEADERS = (
    "Key",
    "Provider",
    "Key type",
    "Algorithm and size",
    "Usage",
    "Protection",
    "State",
    "Rotation",
    "Deletion protection",
    "Finding codes",
    "Source",
    "Location",
    "Key custodian",
    "HSM or KMS custody evidence",
)


def _key_stores(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [fact for fact in scope_facts(view) if common.kind_of(fact) == "key_store"]
    facts.sort(key=lambda fact: (common.provider_of(fact).casefold(), common.address_of(fact).casefold()))
    rows = [
        [
            common.address_of(fact),
            common.provider_of(fact),
            fact.get("vendor") or "",
            fact.get("version") or "",
            fact.get("state") or "",
            "" if fact.get("objects") is None else fact.get("objects"),
            _source_cell(fact),
            common.location_of(fact),
        ]
        for fact in facts
    ]
    return [
        *section_heading("Key stores, HSMs and key managers", styles),
        common.note(text.KEY_STORE_NOTE, styles),
        *common.register(
            ("Key store", "Provider", "Product", "Library or protocol version", "State", "Objects", "Source",
             "Location"),
            rows,
            (130, 90, 110, 80, 70, 50, 110, 130),
            width,
            styles,
            view=view,
            cap_key="key_stores",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="key stores",
        ),
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
            fact.get("path_context") or _source_cell(fact),
        ]
        for fact in facts
    ]


def _resources(view: object, styles: Styles, width: float) -> list[Flowable]:
    """At-rest resources grouped by provider and kind.  One cap for the whole register (not per group): the
    ``REGISTER_ROW_CAP`` worst rows are printed and the note above says exactly how many are left out."""
    facts = [fact for fact in scope_facts(view) if _is_at_rest(fact)]
    total = len(facts)
    if total > text.REGISTER_ROW_CAP:
        facts = sorted(facts, key=common.impact_key)[: text.REGISTER_ROW_CAP]
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
        "Source or path context",
    )
    weights = (100, 70, 80, 70, 90, 90, 80, 90, 70)
    flow: list[Flowable] = [*section_heading("Resource encryption register", styles)]
    if not facts:
        flow.extend(common.register(headers, [], weights, width, styles))
        return flow
    if total > len(facts):
        flow.append(
            common.note(
                f"{total - len(facts)} further rows omitted: showing the {len(facts)} highest-impact of the "
                f"{total} resources (cap {text.REGISTER_ROW_CAP} rows). {text.FULL_LIST_POINTER}",
                styles,
            )
        )
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for fact in facts:
        groups.setdefault((common.provider_of(fact), common.kind_of(fact)), []).append(fact)
    for (provider, kind), group in groups.items():
        flow.append(common.note(f"{provider} / {kind}", styles))
        flow.extend(common.register(headers, _resource_rows(group), weights, width, styles))
    return flow


def _managed_tls(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [fact for fact in scope_facts(view) if _is_managed_tls(fact)]
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
                _source_cell(fact),
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
                "Source",
                "Location",
            ),
            rows,
            (120, 100, 70, 60, 90, 100, 100, 120),
            width,
            styles,
            view=view,
            cap_key="managed_tls",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="endpoints",
        ),
    ]


def _secrets(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = [fact for fact in scope_facts(view) if common.kind_of(fact) in _SECRET_KINDS]
    facts.sort(  # worst first, so a capped register keeps the findings
        key=lambda fact: (common.impact_key(fact)[0], common.kind_of(fact), common.address_of(fact).casefold())
    )
    rows = [
        [
            common.address_of(fact),
            fact.get("service") or fact.get("native_type") or common.kind_of(fact),
            common.provider_of(fact),
            fact.get("key_algorithm") or fact.get("specification") or "",
            fact.get("key_management") or "",
            _rotation_cell(fact),
            fact.get("expires") or "",
            common.codes_cell(fact),
            _source_cell(fact),
            common.location_of(fact),
        ]
        for fact in facts
    ]
    return [
        *section_heading("Secrets services and certificate provisioning", styles),
        *common.register(
            (
                "Resource",
                "Service",
                "Provider",
                "Key algorithm",
                "Key management (KMS key)",
                "Rotation",
                "Expires",
                "Finding codes",
                "Source",
                "Location",
            ),
            rows,
            (110, 80, 45, 60, 110, 70, 60, 80, 90, 110),
            width,
            styles,
            view=view,
            cap_key="secrets",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="secrets",
        ),
    ]


def _findings(view: object, styles: Styles, width: float) -> list[Flowable]:
    facts = scope_facts(view)
    rows = [
        [
            text.finding_label(code),
            count,
            impact,
            text.finding_anchor(code),
            text.finding_action(code),
        ]
        for code, count, impact in finding_rows(facts)
    ]
    ranked = [fact for fact in facts if common.as_rows(fact.get("finding_codes"))]
    ranked.sort(
        key=lambda fact: (
            common.impact_key(fact)[0],
            -len(common.as_rows(fact.get("finding_codes"))),
            common.address_of(fact).casefold(),
        )
    )
    top = [
        [
            common.address_of(fact),
            _source_cell(fact) or common.location_of(fact),
            fact.get("impact") or "",
            common.codes_cell(fact),
        ]
        for fact in ranked[:25]
    ]
    return [
        *section_heading("Findings", styles),
        common.note(text.INFRA_FINDINGS_NOTE, styles),
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
            ("Resource", "Source", "Impact", "Finding codes"),
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
    """Document body for SOW D6."""
    return [
        common.note(REPORT_META[REPORT_KEY]["how_to_read"], styles),
        common.gap(),
        _kpi(view, width),
        common.gap(),
        *common.source_status_flow(view, styles, width),
        *_coverage(view, styles, width),
        *section_heading("KMS key register", styles),
        *common.register(
            _KMS_HEADERS,
            _kms_rows(view),
            (72, 45, 55, 50, 50, 52, 48, 58, 50, 55, 58, 70, 42, 45),
            width,
            styles,
            manual=(12, 13),
            view=view,
            cap_key="kms",
            cap=text.REGISTER_ROW_CAP,
            more=text.FULL_LIST_POINTER,
            noun="keys",
        ),
        *_key_stores(view, styles, width),
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
        common.note(text.posture_scope_of_method(view), styles, limit=900),
    ]


def build_pdf(view: TeamCbomView, *, ctx: Any = None) -> bytes:
    """Render SOW D6. Returns PDF bytes."""
    return build_document(ctx=ctx, 
        view=view,
        number=DOCUMENT_NUMBER,
        report_key=REPORT_KEY,
        title=REPORT_META[REPORT_KEY]["title"],
        landscape=True,
        body=lambda styles, width: build_story(view, styles, width),
        basis_extra=common.basis_lines(view),
        disclaimer_paragraphs=text.disclaimer_paragraphs(view),
        extra_banners=common.banner_pairs(view),
    )


__all__ = ["DOCUMENT_NUMBER", "REPORT_KEY", "build_pdf", "build_story", "finding_rows", "scope_facts"]
