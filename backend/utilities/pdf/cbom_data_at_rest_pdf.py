"""Data-at-rest encryption assessment (#9, CBOM-D09).

Declared configuration only. The document states that stored data was not inspected.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from reportlab.platypus import Flowable

from backend.utilities.dashboard.cbom_team_rollup import ASSET_ALGORITHM, TeamCbomView
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

DOCUMENT_NUMBER = 9
REPORT_KEY = "cbom_data_at_rest"
_SIGNOFF = ("Prepared by", "Reviewed by", "Approved by")


def _stores(view: object) -> list[dict[str, Any]]:
    rows = [
        fact
        for fact in common.facts_of(view)
        if common.kind_of(fact) in text.DATA_STORE_KINDS and not common.is_evidence_only(fact)
    ]
    rows.sort(key=common.impact_key)
    return rows


def _by_kind(view: object, kind: str) -> list[dict[str, Any]]:
    return [fact for fact in common.facts_of(view) if common.kind_of(fact) == kind]


def _verdict_tally(facts: list[dict[str, Any]], layer: str) -> dict[str, int]:
    totals = {key: 0 for key in text.AT_REST_VERDICTS}
    for fact in facts:
        verdict = common.layer_verdict(fact, layer).upper() or str(fact.get("verdict") or "").upper()
        if verdict in totals:
            totals[verdict] += 1
    return totals


def _kpi(view: object, width: float) -> Flowable:
    stores = _stores(view)
    backups = _by_kind(view, "backup")
    secrets = _by_kind(view, "k8s_secrets_etcd")
    at_rest = _verdict_tally(stores, "at_rest")
    backup_verdicts = _verdict_tally(backups, "backup")
    if not any(backup_verdicts.values()):
        backup_verdicts = _verdict_tally(backups, "at_rest")
    if secrets:
        secret_text = ", ".join(
            text.verdict_label(common.layer_verdict(fact, "at_rest") or fact.get("verdict"))
            for fact in secrets
        )
    else:
        secret_text = "no cluster configuration declared"
    classified = sum(1 for fact in stores if common.linkage_cell(fact, "classification"))
    assessed, total, _missing, _partial = common.coverage_numbers(view)
    not_encrypted = at_rest["NOT_ENCRYPTED"]
    cards = [
        ("Data stores", common.kpi_text(view, len(stores)), f"not encrypted {not_encrypted}"),
        (
            "Encrypted (declared)",
            common.kpi_text(view, at_rest["ENCRYPTED_DECLARED"]),
            "At rest",
        ),
        ("Unknown stores", common.kpi_text(view, at_rest["UNKNOWN"]), "Not evidenceable"),
        ("Backups", common.kpi_text(view, len(backups)), f"not encrypted {backup_verdicts['NOT_ENCRYPTED']}"),
        ("Kubernetes secrets", common.kpi_text(view, len(secrets) or secret_text), secret_text),
        ("Classified", common.kpi_text(view, classified), "Stores with a declared classification"),
        ("Sources", common.kpi_text(view, f"{assessed}/{total}"), "assessed of current sources"),
    ]
    return kpi_strip(cards, width, max_per_row=4)


def _layers(fact: dict[str, Any]) -> str:
    parts = []
    for layer in ("application", "database", "volume", "service", "backup", "transport"):
        verdict = common.layer_verdict(fact, layer)
        if verdict:
            parts.append(f"{layer}: {text.verdict_label(verdict)}")
    if not parts and fact.get("verdict"):
        parts.append(text.verdict_label(fact.get("verdict")))
    return "; ".join(parts)


def _store_register(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _stores(view):
        rows.append(
            [
                common.address_of(fact),
                common.kind_of(fact),
                common.provider_of(fact),
                _layers(fact),
                fact.get("key_management") or "",
                common.linkage_cell(fact, "system"),
                common.linkage_cell(fact, "owner"),
                common.linkage_cell(fact, "owner_hint"),
                common.linkage_cell(fact, "classification"),
                common.linkage_cell(fact, "data_lifetime"),
                common.location_of(fact),
            ]
        )
    return [
        common.note(text.DECLARED_LEGEND, styles),
        *section_heading("Data store register", styles),
        *common.register(
            (
                "Store",
                "Kind",
                "Provider",
                "Layers",
                "Key management",
                "System",
                "Owner",
                "Owner hint",
                "Classification",
                "Data lifetime",
                "Location",
            ),
            rows,
            (90, 55, 55, 110, 70, 60, 55, 55, 60, 50, 60),
            width,
            styles,
            manual=(5, 6, 7, 8, 9),
            view=view,
            cap_key="stores",
            noun="stores",
        ),
    ]


def _backups(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _by_kind(view, "backup"):
        verdict = common.layer_verdict(fact, "backup") or common.layer_verdict(fact, "at_rest")
        rows.append(
            [
                common.address_of(fact),
                text.verdict_label(verdict),
                fact.get("key_management") or "",
                fact.get("inheritance") or fact.get("basis") or "",
                common.location_of(fact),
            ]
        )
    return [
        *section_heading("Backups and snapshots", styles),
        *common.register(
            ("Resource", "Backup verdict", "Key management", "Inheritance", "Location"),
            rows,
            (160, 140, 140, 140, 140),
            width,
            styles,
            view=view,
            cap_key="backups",
            noun="backups",
        ),
    ]


def _retention(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in common.facts_of(view):
        attrs = common.attrs_of(fact)
        if "backup_retention_days" not in attrs and "pitr" not in attrs:
            continue
        if common.is_evidence_only(fact):
            continue
        rows.append(
            [
                common.address_of(fact),
                common.kind_of(fact),
                attrs.get("backup_retention_days", ""),
                attrs.get("pitr", ""),
                common.location_of(fact),
            ]
        )
    rows.sort(key=lambda row: str(row[0]).casefold())
    flow: list[Flowable] = [*section_heading("Backup retention and point-in-time recovery", styles)]
    if not rows:
        flow.append(common.note(text.NO_RETENTION, styles))
        return flow
    flow.extend(
        common.register(
            ("Store", "Kind", "Retention in days", "Point-in-time recovery", "Location"),
            rows,
            (180, 90, 110, 140, 200),
            width,
            styles,
            view=view,
            cap_key="retention",
            noun="retention rows",
        )
    )
    return flow


def _k8s(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _by_kind(view, "k8s_secrets_etcd"):
        rows.append(
            [
                fact.get("first_provider") or common.provider_of(fact),
                text.verdict_label(common.layer_verdict(fact, "at_rest") or fact.get("verdict")),
                fact.get("custody") or "",
                fact.get("weakness") or "",
                common.location_of(fact),
            ]
        )
    return [
        *section_heading("Kubernetes secrets at rest", styles),
        *common.register(
            ("First provider", "Verdict", "Custody", "Weakness", "Location"),
            rows,
            (120, 150, 140, 150, 160),
            width,
            styles,
            view=view,
            cap_key="k8s_secrets",
            noun="cluster rows",
        ),
    ]


def _disk(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in common.facts_of(view):
        kind = common.kind_of(fact)
        attrs = common.attrs_of(fact)
        if kind == "disk_encryption" or common.is_evidence_only(fact) or attrs.get("crypttab") or attrs.get("directive"):
            rows.append(
                [
                    common.address_of(fact) or attrs.get("device") or "",
                    kind or attrs.get("engine") or "",
                    attrs.get("directive") or attrs.get("cipher") or fact.get("native_type") or "",
                    attrs.get("value_class") or attrs.get("key_source") or "",
                    common.location_of(fact),
                ]
            )
    return [
        *section_heading("Database-native and disk-level evidence", styles),
        common.note("Statement text is not printed. Only labels and line counts are shown.", styles),
        *common.register(
            ("Resource", "Kind or engine", "Directive or cipher", "Value class or key source", "Location"),
            rows,
            (140, 110, 160, 150, 160),
            width,
            styles,
            view=view,
            cap_key="disk",
            noun="disk rows",
        ),
    ]


def _capability(view: object, styles: Styles, width: float) -> list[Flowable]:
    libs = []
    for lib in common.as_rows(getattr(view, "libs", ())):
        name = common.grab(lib, "name", "")
        sources = common.as_rows(common.grab(lib, "current_source_keys", ()))
        if common.grab(lib, "current", True) is False and not sources:
            continue
        libs.append([name, len(sources) or common.as_int(common.grab(lib, "scan_count", 0)), "library"])
    families: Counter[str] = Counter()
    for asset in common.as_rows(getattr(view, "assets", ())):
        if str(common.grab(asset, "asset_type", "")) != ASSET_ALGORITHM:
            continue
        if common.grab(asset, "current", True) is False:
            continue
        title = str(common.grab(asset, "title", "") or common.grab(asset, "primitive", "") or "algorithm")
        families[title] += 1
    rows = libs + [[name, count, "algorithm"] for name, count in sorted(families.items())]
    return [
        *section_heading("Application-level encryption evidence", styles),
        common.note(text.CAPABILITY_EVIDENCE, styles),
        *common.register(
            ("Name", "Sources or occurrences", "Kind"),
            rows,
            (280, 220, 220),
            width,
            styles,
            noun="capability rows",
        ),
    ]


def _classification(view: object, styles: Styles, width: float) -> list[Flowable]:
    raw = common.counts_of(view).get("by_classification")
    pairs: list[tuple[str, int]] = []
    if isinstance(raw, dict) and raw:
        pairs = [(str(key), common.as_int(value)) for key, value in raw.items()]
    else:
        counter: Counter[str] = Counter()
        for fact in _stores(view):
            cell = common.linkage_cell(fact, "classification")
            if cell.startswith("declared: "):
                counter[cell[len("declared: ") :]] += 1
        pairs = list(counter.items())
    flow: list[Flowable] = [*section_heading("Classification roll-up", styles)]
    if not pairs:
        flow.append(common.note(text.NO_CLASSIFICATION, styles))
        return flow
    pairs.sort(key=lambda item: (-item[1], item[0].casefold()))
    shown, rest = pairs[:50], pairs[50:]
    if rest:
        shown.append(("other", sum(count for _label, count in rest)))
    flow.extend(
        common.register(
            ("Classification", "Stores"),
            shown,
            (480, 240),
            width,
            styles,
            noun="classifications",
        )
    )
    return flow


def build_story(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """Document body for deliverable #9."""
    return [
        common.note(REPORT_META[REPORT_KEY]["how_to_read"], styles),
        common.gap(),
        _kpi(view, width),
        common.gap(),
        *common.source_status_flow(view, styles, width),
        *_store_register(view, styles, width),
        *_backups(view, styles, width),
        *_retention(view, styles, width),
        *_k8s(view, styles, width),
        *_disk(view, styles, width),
        *_capability(view, styles, width),
        *_classification(view, styles, width),
        *common.unknown_flow(view, styles, width),
        *common.previously_seen_flow(view, styles, width),
        common.gap(),
        manual_form(
            "Regulated-data mapping",
            ("Store", "Regulated data", "Key-management evidence", "Retention schedule"),
            4,
            width=width,
        ),
        common.gap(),
        signoff_block(_SIGNOFF, title="Sign-off", width=width),
        common.gap(),
        *section_heading("Limits", styles, min_space=70),
        common.note(text.STORED_DATA_LIMIT, styles),
        common.note(text.STORED_DATA_STATEMENT, styles),
    ]


def build_pdf(view: TeamCbomView) -> bytes:
    """Render deliverable #9. Returns PDF bytes."""
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
