"""Shared readers for the three posture PDFs (WP10b).

``TeamCbomView`` may not have a ``posture`` field yet. ``posture_block`` then returns
``None`` and every register is empty. A present block may be a mapping or an object;
each fact may be either.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date, datetime
from typing import Any

from reportlab.platypus import Flowable, Paragraph, Spacer

from backend.utilities.pdf import cbom_posture_text as text
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    dense_table,
    pdf_text,
    section_heading,
)

MAX_ROWS = 2000
_IMPACT_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def grab(obj: object, key: str, default: object = None) -> object:
    if obj is None:
        return default
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def as_mapping(obj: object) -> dict[str, Any]:
    if isinstance(obj, Mapping):
        return dict(obj)
    data = getattr(obj, "__dict__", None)
    if isinstance(data, dict):
        return {key: value for key, value in data.items() if not str(key).startswith("_")}
    return {}


def as_rows(value: object) -> list[Any]:
    if value is None or isinstance(value, (str, bytes, Mapping)):
        return []
    try:
        return list(value)  # type: ignore[arg-type]
    except TypeError:
        return []


def as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def posture_block(view: object) -> object | None:
    return getattr(view, "posture", None)


def fact_map(item: object) -> dict[str, Any]:
    mapped = as_mapping(item)
    return mapped if mapped else {}


def facts_of(view: object) -> list[dict[str, Any]]:
    raw = grab(posture_block(view), "facts", ())
    if isinstance(raw, Mapping):
        raw = [raw]
    return [fact_map(item) for item in as_rows(raw)]


def _source_status(row: Mapping[str, Any]) -> str:
    raw = str(row.get("status") or "").strip().lower().replace(" ", "_")
    if raw in {"assessed", "partial", "not_assessed"}:
        return raw
    if row.get("partial") or as_rows(row.get("failed_lanes")):
        return "partial"
    if row.get("assessed") is True:
        return "assessed"
    return "not_assessed"


def sources_of(view: object) -> list[dict[str, Any]]:
    block = posture_block(view)
    raw = grab(block, "sources", None)
    if raw is None:
        rows = []
        for item in as_rows(getattr(view, "sources", ())):
            label = grab(item, "label", None) or grab(item, "key", "")
            rows.append(
                {
                    "label": label,
                    "status": "not_assessed",
                    "reason": "re-scan needed",
                    "fact_count": 0,
                }
            )
        return rows
    if isinstance(raw, Mapping):
        raw = [raw]
    return [as_mapping(item) for item in as_rows(raw)]


def coverage_numbers(view: object) -> tuple[int, int, int, int]:
    assessed = partial = not_assessed = 0
    for row in sources_of(view):
        status = _source_status(row)
        if status == "partial":
            partial += 1
            assessed += 1
        elif status == "assessed":
            assessed += 1
        else:
            not_assessed += 1
    total = assessed + not_assessed
    # partial is already inside assessed, so total is assessed + not_assessed.
    return assessed, total, not_assessed, partial


def fully_unassessed(view: object) -> bool:
    assessed, total, _not_assessed, _partial = coverage_numbers(view)
    return total > 0 and assessed == 0


def counts_of(view: object) -> dict[str, Any]:
    return as_mapping(grab(posture_block(view), "counts", {}))


def omitted_of(view: object) -> dict[str, Any]:
    return as_mapping(grab(posture_block(view), "omitted", {}))


def kind_of(fact: Mapping[str, Any]) -> str:
    return str(fact.get("kind") or "")


def provider_of(fact: Mapping[str, Any]) -> str:
    provider = str(fact.get("provider") or "")
    return "self-hosted" if provider == "self_hosted" else provider


def address_of(fact: Mapping[str, Any]) -> str:
    return str(fact.get("address") or fact.get("name") or fact.get("id") or "")


def location_of(fact: Mapping[str, Any]) -> str:
    return str(fact.get("location") or fact.get("path") or "")


def layer_verdict(fact: Mapping[str, Any], layer: str) -> str:
    direct = fact.get(layer)
    if isinstance(direct, Mapping):
        return str(direct.get("verdict") or "")
    if isinstance(direct, str) and direct:
        return direct
    layers = fact.get("layers")
    if isinstance(layers, Mapping):
        item = layers.get(layer)
        if isinstance(item, Mapping):
            return str(item.get("verdict") or "")
        if item:
            return str(item)
    return ""


def is_verification(fact: Mapping[str, Any]) -> bool:
    return str(fact.get("native_type") or "").startswith("verification:")


def is_evidence_only(fact: Mapping[str, Any]) -> bool:
    return bool(fact.get("evidence_only"))


def impact_key(fact: Mapping[str, Any]) -> tuple[int, str]:
    raw = str(fact.get("worst_impact") or fact.get("impact") or "")
    return (_IMPACT_RANK.get(raw.casefold(), 9), address_of(fact).casefold())


def codes_cell(fact: Mapping[str, Any]) -> str:
    own = [str(code) for code in as_rows(fact.get("finding_codes")) if code]
    extra = [
        str(code)
        for code in as_rows(fact.get("asset_finding_codes"))
        if code and str(code) not in own
    ]
    body = "; ".join(own)
    if extra:
        suffix = "; ".join(extra)
        return f"{body}; on assets: {suffix}" if body else f"on assets: {suffix}"
    return body


def net_of(fact: Mapping[str, Any]) -> dict[str, Any]:
    return as_mapping(fact.get("net"))


def attrs_of(fact: Mapping[str, Any]) -> dict[str, Any]:
    return as_mapping(fact.get("attrs"))


def declared_of(fact: Mapping[str, Any]) -> dict[str, Any]:
    declared = as_mapping(fact.get("declared"))
    if declared:
        return declared
    return {}


def linkage_cell(fact: Mapping[str, Any], key: str) -> str:
    declared = declared_of(fact)
    value = declared.get(key)
    if value in (None, ""):
        value = fact.get(f"declared_{key}")
    if value in (None, ""):
        return ""
    return f"declared: {value}"


def endpoint_label(fact: Mapping[str, Any]) -> str:
    net = net_of(fact)
    matched = net.get("matched") or fact.get("endpoint_matched")
    if matched:
        return str(matched)
    if net.get("endpoint"):
        return str(net["endpoint"])
    if net.get("listen"):
        return f"listen {net['listen']}"
    return address_of(fact)


def evidence_kind(fact: Mapping[str, Any]) -> str:
    net = net_of(fact)
    evidence = str(net.get("evidence") or fact.get("evidence") or "")
    if evidence.startswith("imported"):
        return evidence
    native = str(fact.get("native_type") or "")
    if str(fact.get("format") or "") == "import" or native in {"testssl", "sslyze", "nmap"}:
        return f"imported:{native or 'tool'}"
    return "static server"


def parse_day(value: object) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value or "")[:10]
    if len(text) == 10 and text[4] == "-" and text[7] == "-":
        try:
            return date(int(text[0:4]), int(text[5:7]), int(text[8:10]))
        except ValueError:
            return None
    return None


def data_tables(view: object) -> list[dict[str, Any]]:
    raw = grab(posture_block(view), "data_tables", ())
    return [as_mapping(item) for item in as_rows(raw)]


def data_file_lines(view: object) -> list[str]:
    lines = []
    for row in data_tables(view):
        name = row.get("name") or "reference"
        version = row.get("data_version") or "unknown"
        valid = row.get("valid_as_of") or "unknown"
        lines.append(f"Reference data {name}: version {version}, valid as of {valid}")
    return lines


def reference_stale(view: object) -> bool:
    as_of = getattr(view, "as_of", None)
    if not isinstance(as_of, date):
        generated = getattr(view, "generated_at", None)
        as_of = generated.date() if isinstance(generated, datetime) else None
    if not isinstance(as_of, date):
        return False
    oldest: date | None = parse_day(grab(posture_block(view), "oldest_valid_as_of"))
    for row in data_tables(view):
        day = parse_day(row.get("valid_as_of"))
        if day is not None and (oldest is None or day < oldest):
            oldest = day
    if oldest is None:
        return False
    return (as_of - oldest).days > 365


def basis_lines(view: object) -> list[str]:
    assessed, total, not_assessed, partial = coverage_numbers(view)
    lines = [
        text.coverage_line(assessed, total, not_assessed, partial),
        text.FACTS_SEPARATE,
        *data_file_lines(view),
    ]
    if reference_stale(view):
        lines.append(text.REFERENCE_STALE)
    return lines


def truncated_facts(view: object) -> int:
    block = posture_block(view)
    direct = grab(block, "truncated_facts", None)
    if direct is None:
        direct = grab(block, "truncated", 0)
    total = as_int(direct)
    for row in sources_of(view):
        total += as_int(row.get("truncated"))
    return total


def banner_pairs(view: object) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if fully_unassessed(view):
        pairs.append((text.BANNER_NOT_ASSESSED_TITLE, text.BANNER_NOT_ASSESSED_TEXT))
    dropped = truncated_facts(view)
    if dropped:
        pairs.append(
            (text.BANNER_TRUNCATED_TITLE, f"Posture data truncated: {dropped} facts not retained")
        )
    _assessed, _total, _missing, partial = coverage_numbers(view)
    if partial:
        pairs.append(
            (
                text.BANNER_PARTIAL_TITLE,
                f"Posture lanes failed in {partial} sources: results for those sources are partial",
            )
        )
    return pairs


def kpi_text(view: object, value: object) -> str:
    if fully_unassessed(view):
        return "n/a"
    return str(value)


def note(message: object, styles: Styles, *, limit: int = 700) -> Paragraph:
    return Paragraph(pdf_text(message, limit=limit), styles["body"])


def fit_widths(weights: Sequence[float], width: float) -> list[float]:
    total = float(sum(weights)) or 1.0
    scaled = [round(weight * width / total, 2) for weight in weights]
    scaled[-1] = round(width - sum(scaled[:-1]), 2)
    return scaled


def register(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    weights: Sequence[float],
    width: float,
    styles: Styles,
    *,
    manual: Sequence[int] = (),
    view: object = None,
    cap_key: str = "",
    noun: str = "rows",
) -> list[Flowable]:
    body = [list(row) for row in rows]
    dropped = as_int(omitted_of(view).get(cap_key)) if view is not None and cap_key else 0
    if len(body) > MAX_ROWS:
        dropped += len(body) - MAX_ROWS
        body = body[:MAX_ROWS]
    flow: list[Flowable] = []
    if dropped:
        flow.append(
            note(
                f"{dropped} further rows omitted: showing the first {len(body)} of the "
                f"{noun} (cap {MAX_ROWS} rows).",
                styles,
            )
        )
    flow.append(dense_table(headers, body, fit_widths(weights, width), manual_cols=manual))
    return flow


def source_status_flow(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    zero_labels = []
    for source in sources_of(view):
        status = _source_status(source)
        if status == "partial":
            lanes = ", ".join(str(name) for name in as_rows(source.get("failed_lanes")))
            shown = f"partial (lanes failed: {lanes})" if lanes else "partial"
        elif status == "assessed":
            shown = "assessed"
            if as_int(source.get("fact_count")) == 0 and not source.get("partial"):
                zero_labels.append(str(source.get("label") or source.get("key") or "source"))
        else:
            shown = "not assessed"
        reason = str(source.get("reason") or source.get("failed_latest") or "")
        if status != "assessed" and not reason:
            reason = "re-scan needed"
        rows.append([source.get("label") or source.get("key") or "", shown, reason])
    flow: list[Flowable] = [
        *section_heading("Source status", styles, min_space=120),
        *register(
            ("Source", "Status", "Reason"),
            rows,
            (240, 220, 260),
            width,
            styles,
            view=view,
            cap_key="sources",
            noun="sources",
        ),
    ]
    for label in zero_labels:
        flow.append(
            note(
                f"{label}: {text.ZERO_FACTS_NOTE}.",
                styles,
            )
        )
    return flow


def unknown_flow(view: object, styles: Styles, width: float) -> list[Flowable]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for fact in facts_of(view):
        verdicts = (
            layer_verdict(fact, "at_rest"),
            layer_verdict(fact, "transport"),
            str(fact.get("verdict") or ""),
        )
        if not fact.get("unknown_reason") and not any(item.upper() == "UNKNOWN" for item in verdicts):
            continue
        reason = str(fact.get("unknown_reason") or fact.get("reason") or "attribute_not_modeled")
        grouped.setdefault(reason, []).append(fact)
    flow: list[Flowable] = [*section_heading("Not evidenceable from BOM", styles)]
    if not grouped:
        flow.extend(
            register(("Reason", "Count", "What to check", "Examples"), [], (160, 50, 250, 260), width, styles)
        )
        return flow
    for reason in sorted(grouped):
        examples = sorted(grouped[reason], key=address_of)[:25]
        names = ", ".join(address_of(fact) for fact in examples if address_of(fact))
        flow.append(note(f"{text.unknown_label(reason)} ({len(grouped[reason])})", styles))
        flow.append(note(text.unknown_check(reason), styles))
        if names:
            flow.append(note(f"Examples: {names}", styles))
    flow.extend(
        register(
            ("Reason", "Count", "What to check manually", "Example resources"),
            [
                [
                    text.unknown_label(reason),
                    len(items),
                    text.unknown_check(reason),
                    ", ".join(address_of(fact) for fact in sorted(items, key=address_of)[:25]),
                ]
                for reason, items in sorted(grouped.items())
            ],
            (160, 50, 250, 260),
            width,
            styles,
            view=view,
            cap_key="unknown",
            noun="unknown facts",
        )
    )
    return flow


def previously_seen_flow(view: object, styles: Styles, width: float) -> list[Flowable]:
    raw = grab(posture_block(view), "previously_seen", ())
    rows = [fact_map(item) for item in as_rows(raw)]
    exact = grab(posture_block(view), "previously_seen_exact", True)
    exact = True if exact is None else bool(exact)
    total = grab(posture_block(view), "previously_seen_total", None)
    if total is None:
        total = len(rows) + as_int(omitted_of(view).get("previously_seen"))
    rows.sort(key=lambda fact: str(fact.get("last_seen") or ""), reverse=True)
    prefix = "at least " if not exact else ""
    flow: list[Flowable] = [
        *section_heading("Previously seen", styles),
        note(f"Previously seen total: {prefix}{total}.", styles),
    ]
    table_rows = [
        [
            address_of(fact) or fact.get("id"),
            kind_of(fact),
            fact.get("native_type") or "",
            location_of(fact),
            fact.get("last_verdict") or fact.get("verdict") or "",
            fact.get("last_seen") or "",
            fact.get("first_seen") or "",
            fact.get("scan_count") or "",
            fact.get("last_scan_id") or "",
            fact.get("source") or fact.get("source_label") or "",
        ]
        for fact in rows
    ]
    flow.extend(
        register(
            (
                "Resource",
                "Kind",
                "Native type",
                "Path",
                "Last verdict",
                "Last seen",
                "First seen",
                "Scans",
                "Last scan",
                "Source",
            ),
            table_rows,
            (90, 70, 70, 90, 70, 60, 60, 40, 50, 70),
            width,
            styles,
            view=view,
            cap_key="previously_seen",
            noun="previously seen facts",
        )
    )
    return flow


def diagnostics_flow(view: object, styles: Styles, width: float) -> list[Flowable]:
    totals = as_mapping(grab(posture_block(view), "diagnostic_totals", {}))
    total_rows = sorted((str(code), as_int(count)) for code, count in totals.items())
    details = [as_mapping(item) for item in as_rows(grab(posture_block(view), "diagnostics", ()))]
    details = sorted(
        details,
        key=lambda row: (
            str(row.get("source") or row.get("source_label") or ""),
            str(row.get("path") or ""),
            as_int(row.get("line")),
        ),
    )[:50]
    return [
        *section_heading("Diagnostics", styles),
        *register(
            ("Code", "Count"),
            total_rows,
            (420, 120),
            width,
            styles,
            noun="diagnostic codes",
        ),
        Spacer(1, 6),
        *register(
            ("Source", "Path", "Line", "Code"),
            [
                [
                    row.get("source") or row.get("source_label") or "",
                    row.get("path") or "",
                    row.get("line") or "",
                    row.get("code") or "",
                ]
                for row in details
            ],
            (140, 280, 50, 150),
            width,
            styles,
            view=view,
            cap_key="diagnostics",
            noun="diagnostics",
        ),
    ]


def gap() -> Spacer:
    return Spacer(1, 8)
