"""Network, TLS and crypto protocol assessment (#6, CBOM-D06).

Static declarations and imported result files only. The document states that the
platform did not probe any endpoint.
"""

from __future__ import annotations

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

DOCUMENT_NUMBER = 6
REPORT_KEY = "cbom_network_tls"
_SIGNOFF = ("Prepared by", "Reviewed by", "Approved by")
_OFFERED = {"offered": "offered", "not_offered": "not offered", "unknown": "unknown"}


def _endpoints(view: object) -> list[dict[str, Any]]:
    rows = [
        fact
        for fact in common.facts_of(view)
        if not common.is_verification(fact)
        and (
            common.kind_of(fact) == "tls_endpoint"
            or common.net_of(fact)
        )
    ]
    rows.sort(key=lambda fact: (common.endpoint_label(fact).casefold(), common.evidence_kind(fact)))
    return rows


def _protocol_word(net: dict[str, Any], key: str) -> str:
    protocols = net.get("protocols")
    if not isinstance(protocols, dict):
        return "unknown"
    raw = str(protocols.get(key) or "unknown").lower()
    return _OFFERED.get(raw, "unknown")


def _legacy(fact: dict[str, Any]) -> bool:
    net = common.net_of(fact)
    return any(_protocol_word(net, key) == "offered" for key in ("SSLv3", "1.0", "1.1"))


def _weak(fact: dict[str, Any]) -> bool:
    suites = common.net_of(fact).get("weak_suites")
    return bool(common.as_rows(suites))


def _kpi(view: object, width: float) -> Flowable:
    endpoints = _endpoints(view)
    legacy = sum(1 for fact in endpoints if _legacy(fact))
    weak = sum(1 for fact in endpoints if _weak(fact))
    certs = sum(1 for fact in endpoints if common.net_of(fact).get("certificate"))
    imports = [common.as_mapping(item) for item in common.as_rows(common.grab(common.posture_block(view), "imports", ()))]
    tools = sorted({str(item.get("tool") or "unknown") for item in imports})
    assessed, total, _missing, _partial = common.coverage_numbers(view)
    tool_text = ", ".join(f"{tool}" for tool in tools) if tools else "none"
    cards = [
        ("Endpoints", common.kpi_text(view, len(endpoints)), "Static and imported"),
        ("Legacy protocol", common.kpi_text(view, legacy), "SSLv3, TLS 1.0 or TLS 1.1 offered"),
        ("Weak suites", common.kpi_text(view, weak), "Endpoints with a weak suite"),
        ("Certificates", common.kpi_text(view, certs), "Seen on endpoints"),
        ("Import tools", common.kpi_text(view, len(tools)), tool_text),
        ("Sources", common.kpi_text(view, f"{assessed}/{total}"), "assessed of current sources"),
    ]
    return kpi_strip(cards, width, max_per_row=3)


def _mark(fact: dict[str, Any], label: str) -> str:
    if fact.get("discrepancy"):
        return f"{label} discrepancy"
    return label


def _kx(net: dict[str, Any]) -> str:
    kx = net.get("kx") if isinstance(net.get("kx"), dict) else {}
    bits = kx.get("dh_bits") or net.get("dh_bits") or ""
    curves = kx.get("curves") or net.get("curves") or []
    curve_text = ", ".join(str(item) for item in common.as_rows(curves))
    parts = []
    if bits:
        parts.append(f"DH {bits}")
    if curve_text:
        parts.append(curve_text)
    return "; ".join(parts)


def _cert_summary(net: dict[str, Any]) -> str:
    cert = common.as_mapping(net.get("certificate"))
    if not cert:
        return ""
    subject = cert.get("subject") or ""
    after = cert.get("not_after") or ""
    return f"{subject} until {after}".strip()


def _endpoint_register(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _endpoints(view):
        net = common.net_of(fact)
        weak_suites = common.as_rows(net.get("weak_suites"))
        rows.append(
            [
                _mark(fact, common.endpoint_label(fact)),
                common.evidence_kind(fact),
                f"{net.get('min') or ''} / {net.get('max') or ''}".strip(" /"),
                _protocol_word(net, "1.3"),
                len(weak_suites),
                _kx(net),
                net.get("fs") or "",
                net.get("hsts") or "",
                net.get("downgrade") or "",
                _cert_summary(net),
                common.codes_cell(fact),
                common.location_of(fact),
            ]
        )
    return [
        *section_heading("Endpoint register", styles),
        *common.register(
            (
                "Endpoint",
                "Evidence",
                "Min / max",
                "TLS 1.3",
                "Weak suites",
                "Key exchange",
                "FS",
                "HSTS",
                "Downgrade",
                "Certificate",
                "Finding codes",
                "Location",
            ),
            rows,
            (120, 68, 52, 48, 38, 64, 36, 62, 52, 66, 52, 52),
            width,
            styles,
            view=view,
            cap_key="endpoints",
            noun="endpoints",
        ),
    ]


def _matrix(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _endpoints(view):
        net = common.net_of(fact)
        rows.append(
            [common.endpoint_label(fact), *[_protocol_word(net, key) for key in text.PROTOCOL_KEYS]]
        )
    return [
        *section_heading("Protocol version matrix", styles),
        *common.register(
            ("Endpoint", *text.PROTOCOL_HEADERS),
            rows,
            (180, 90, 90, 90, 90, 90),
            width,
            styles,
            view=view,
            cap_key="protocols",
            noun="protocol rows",
        ),
    ]


def _weak_suites(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _endpoints(view):
        for suite in common.as_rows(common.net_of(fact).get("weak_suites")):
            mapped = common.as_mapping(suite) or {"suite": suite}
            reasons = mapped.get("reasons") or []
            reason_text = "; ".join(str(item) for item in common.as_rows(reasons))
            rows.append([common.endpoint_label(fact), mapped.get("suite") or "", reason_text])
    return [
        *section_heading("Weak cipher suites", styles),
        *common.register(
            ("Endpoint", "Suite", "Attack or rationale"),
            rows,
            (200, 220, 300),
            width,
            styles,
            view=view,
            cap_key="weak_suites",
            noun="weak suites",
        ),
    ]


def _certificates(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _endpoints(view):
        cert = common.as_mapping(common.net_of(fact).get("certificate"))
        if not cert:
            continue
        chain = str(cert.get("chain") or "not_reported").replace("_", " ")
        codes = cert.get("finding_codes") or []
        rows.append(
            [
                cert.get("subject") or "",
                cert.get("issuer") or "",
                f"{cert.get('not_before') or ''} to {cert.get('not_after') or ''}",
                cert.get("signature_algorithm") or "",
                cert.get("key_size") or "",
                chain,
                "; ".join(str(code) for code in common.as_rows(codes)),
            ]
        )
    return [
        *section_heading("Certificates on endpoints", styles),
        *common.register(
            ("Subject", "Issuer", "Validity", "Signature", "Key size", "Chain", "Finding codes"),
            rows,
            (130, 110, 120, 90, 50, 70, 150),
            width,
            styles,
            view=view,
            cap_key="endpoint_certs",
            noun="certificates",
        ),
    ]


def _unscored(item: str) -> bool:
    token = "".join(ch for ch in item.upper() if ch.isalnum())
    return token in text.UNSCORED_VULNERABILITIES


def _downgrade(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _endpoints(view):
        net = common.net_of(fact)
        if net.get("downgrade"):
            rows.append(
                [
                    common.endpoint_label(fact),
                    "TLS_FALLBACK_SCSV",
                    net.get("downgrade"),
                    common.evidence_kind(fact),
                    "",
                ]
            )
        vulns = net.get("vulnerabilities") or fact.get("vulnerabilities") or []
        for item in common.as_rows(vulns):
            mapped = common.as_mapping(item) or {"item": item}
            name = str(mapped.get("item") or mapped.get("name") or "")
            note = "reported, not scored" if _unscored(name) else ""
            rows.append(
                [
                    common.endpoint_label(fact),
                    name,
                    mapped.get("status") or "",
                    mapped.get("tool") or common.evidence_kind(fact),
                    note,
                ]
            )
    return [
        *section_heading("Downgrade and vulnerabilities", styles),
        *common.register(
            ("Endpoint", "Item", "Reported status", "Source tool", "Note"),
            rows,
            (160, 140, 120, 140, 160),
            width,
            styles,
            view=view,
            cap_key="vulnerabilities",
            noun="vulnerability rows",
        ),
    ]


def _ssh_and_db(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in common.facts_of(view):
        kind = common.kind_of(fact)
        if kind == "ssh_service" or (kind in text.DATABASE_KINDS and common.layer_verdict(fact, "transport")):
            net = common.net_of(fact)
            rows.append(
                [
                    common.address_of(fact),
                    kind,
                    text.verdict_label(common.layer_verdict(fact, "transport")),
                    net.get("min") or fact.get("protocol_floor") or "",
                    common.codes_cell(fact),
                    common.location_of(fact),
                ]
            )
    rows.sort(key=lambda row: (str(row[1]), str(row[0]).casefold()))
    return [
        *section_heading("SSH and database transport", styles),
        *common.register(
            ("Setting", "Kind", "Verdict", "Protocol floor", "Finding codes", "Location"),
            rows,
            (150, 90, 120, 90, 140, 130),
            width,
            styles,
            view=view,
            cap_key="ssh_db",
            noun="transport rows",
        ),
    ]


def _verification_disabled(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in common.facts_of(view):
        signals = common.as_mapping(fact.get("signals"))
        native = str(fact.get("native_type") or "")
        disabled = str(signals.get("verification") or "").lower() == "disabled"
        if not native.startswith("verification:") and not disabled:
            continue
        if native.startswith("verification:"):
            label = native
        else:
            label = str(common.attrs_of(fact).get("verification_setting") or "verification disabled")
        rows.append([common.location_of(fact), label, fact.get("path_context") or "", fact.get("line") or ""])
    rows.sort(key=lambda row: (str(row[0]), str(row[3])))
    return [
        *section_heading("Disabled certificate verification", styles),
        *common.register(
            ("Location", "Pattern", "Path context", "Line"),
            rows,
            (220, 200, 220, 80),
            width,
            styles,
            view=view,
            cap_key="verification",
            noun="verification rows",
        ),
    ]


def _imports(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for item in common.as_rows(common.grab(common.posture_block(view), "imports", ())):
        mapped = common.as_mapping(item)
        rows.append(
            [
                mapped.get("file") or mapped.get("path") or "",
                mapped.get("tool") or "",
                mapped.get("tool_version") or "",
                mapped.get("scan_start") or "",
                mapped.get("scan_end") or "",
                mapped.get("age_days") if mapped.get("age_days") is not None else "",
                mapped.get("endpoint_count") or "",
            ]
        )
    return [
        *section_heading("Import provenance", styles),
        *common.register(
            ("File", "Tool", "Tool version", "Scan start", "Scan end", "Age in days", "Endpoints"),
            rows,
            (160, 80, 80, 100, 100, 70, 70),
            width,
            styles,
            view=view,
            cap_key="imports",
            noun="import files",
        ),
    ]


def build_story(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """Document body for deliverable #6."""
    return [
        common.note(REPORT_META[REPORT_KEY]["how_to_read"], styles),
        common.gap(),
        _kpi(view, width),
        common.gap(),
        *common.source_status_flow(view, styles, width),
        *_endpoint_register(view, styles, width),
        *_matrix(view, styles, width),
        *_weak_suites(view, styles, width),
        *_certificates(view, styles, width),
        *_downgrade(view, styles, width),
        *_ssh_and_db(view, styles, width),
        *_verification_disabled(view, styles, width),
        *_imports(view, styles, width),
        *common.unknown_flow(view, styles, width),
        *common.previously_seen_flow(view, styles, width),
        common.gap(),
        manual_form(
            "Endpoint ownership",
            ("Endpoint", "Owner", "Exposure", "Compensating control", "Live verification reference"),
            4,
            width=width,
        ),
        common.gap(),
        signoff_block(_SIGNOFF, title="Sign-off", width=width),
        common.gap(),
        *section_heading("Limits", styles, min_space=70),
        common.note(text.ENDPOINT_LIMIT, styles),
    ]


def build_pdf(view: TeamCbomView) -> bytes:
    """Render deliverable #6. Returns PDF bytes."""
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
