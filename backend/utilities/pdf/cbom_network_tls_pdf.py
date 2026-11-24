"""Network, TLS and crypto protocol assessment (SOW D7, CBOM-D07).

Static declarations and imported result files (code-scan posture facts), and the evidence of the team's CBOM Sources
collections read straight from their rows (``cbom_sources.network_estate``): TLS endpoints de-duplicated by
``host:port`` with their full accepted-suite list, chain and an SSL Labs-style grade; SSH endpoints (host keys, key
exchange, ciphers, MACs); network appliance configuration (Cisco IOS / ASA, FortiOS, PAN-OS, F5); IKE / IPsec;
STARTTLS services; OPC UA endpoint security; Modbus/TCP (port open only, SOW 7.2). A source that was deleted is left
out (and the number of its rows is stated). The certificate count is ``cert_estate.unique_certificates`` (the D8
register's own list). The document says the platform did not probe any endpoint only when no collection in scope
probed one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from reportlab.platypus import Flowable

import backend.utilities.cbom_sources.network_estate as NE
from backend.utilities.cbom_sources.cert_estate import count_phrase, inputs_of, unique_certificates
from backend.utilities.dashboard.cbom_team_rollup import PostureFactAgg, PostureSourceAgg, TeamCbomView
from backend.utilities.pdf import cbom_posture_common as common
from backend.utilities.pdf import cbom_posture_text as text
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    kpi_strip,
    manual_form,
    signoff_block,
)
from backend.utilities.pdf.cbom_deliverable_common import section_heading as _section_heading
from backend.utilities.pdf.cbom_pdf_outline import Bookmark
from backend.utilities.pdf.report_branding import REPORT_META

DOCUMENT_NUMBER = 7  # SOW D7 (REPORT_META sow_id; the Document ID reads it)
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


@dataclass(frozen=True)
class _Model:
    """Everything the document prints from the Sources rows, computed once per document."""

    tls: tuple[NE.TlsEndpoint, ...] = ()
    ssh: tuple[NE.Observed, ...] = ()
    appliances: tuple[NE.Observed, ...] = ()
    ike: tuple[NE.Observed, ...] = ()
    opcua: tuple[NE.Observed, ...] = ()
    modbus: tuple[NE.Observed, ...] = ()
    deleted_rows: int = 0
    deleted_sources: tuple[str, ...] = ()
    certificates: int = 0
    certificates_served: int = 0


# Very large estates: a D7 table of probed evidence stops at D7_ROW_CAP rows and the per-endpoint suite appendix at
# SUITE_ENDPOINT_CAP endpoints (lowest grade first); the document says how many were left out and where the full
# lists are (each Sources run's CycloneDX export carries every endpoint's cipherSuites).
D7_ROW_CAP = 1000
SUITE_ENDPOINT_CAP = 300
_FULL_LIST = "the full list is in each Sources run's asset list and CycloneDX export (protocolProperties.cipherSuites)"
# lowest first: F, the trust (T) and name (M) grades, then E..A+; "-" (no TLS) last
_GRADE_ORDER = {letter: rank for rank, letter in enumerate(("F", "T", "M", "E", "D", "C", "B", "A-", "A", "A+", "-"))}


def section_heading(text: str, styles: Styles, *, min_space: float = 90) -> list[Flowable]:
    """The shared heading plus a level-0 bookmark, so every section is one click away in the PDF outline."""
    flow = _section_heading(text, styles, min_space=min_space)
    slug = re.sub(r"[^a-z0-9]+", "-", text.casefold()).strip("-")[:60]
    return [flow[0], Bookmark(text, f"d7-{slug}", 0, closed=True), *flow[1:]]


def _capped(rows: list[list[Any]], noun: str, styles: Styles,
            cap: int = D7_ROW_CAP) -> tuple[list[list[Any]], list[Flowable]]:
    if len(rows) <= cap:
        return rows, []
    return rows[:cap], [common.note(f"Showing {cap} of {len(rows)} {noun}; {_FULL_LIST}.", styles)]


def _table(headers: tuple[str, ...], rows: list[list[Any]], weights: tuple[float, ...], width: float, styles: Styles,
           noun: str) -> list[Flowable]:
    shown, notes = _capped(rows, noun, styles)
    return [*notes, *common.register(headers, shown, weights, width, styles, noun=noun)]


_SOURCES_RENDERED = frozenset({"tls_endpoint", "ssh_service"})  # kinds this document reads from the rows themselves


def _from_sources(item: Any) -> bool:
    """A probed Sources endpoint fact, which ``_scoped`` swaps for its de-duplicated ``network_estate`` endpoint.

    A setting the posture mapper read from a cloud account (a load balancer listener, a CDN or API domain: evidence
    ``collected:CBOM Sources``) is not a probed row; network_estate never re-adds it, so it stays as it is."""
    fact = common.fact_map(item)
    ident = str(common.grab(item, "fact_id", "") or fact.get("id") or "")
    evidence = str(fact.get("evidence") or common.net_of(fact).get("evidence") or "")
    if common.evidence_kind(fact).startswith("collected"):
        return False
    return (ident.startswith("sources:") or evidence.startswith("probed:")) and common.kind_of(fact) in _SOURCES_RENDERED


def _collected_tls(item: Any) -> bool:
    """A TLS listener, CDN distribution or API domain the posture mapper read from a cloud account."""
    fact = common.fact_map(item)
    return common.kind_of(fact) == "tls_endpoint" and common.evidence_kind(fact).startswith("collected")


def _fold_collected(facts: list[PostureFactAgg]) -> list[PostureFactAgg]:
    """One fact per collected listener: two sources that read the same cloud account (two roles) collect the same
    listener ARN.  Keyed by ``(native_type, location)``; the newest read wins and the other sources are recorded in
    ``also_seen``, as ``network_estate.tls_endpoints`` does for a probed ``host:port``.  Other facts are kept as they
    are, in their order."""
    groups: dict[tuple[str, str], list[PostureFactAgg]] = {}
    order: list[PostureFactAgg | tuple[str, str]] = []
    for item in facts:
        if not _collected_tls(item):
            order.append(item)
            continue
        fact = item.fact
        key = (str(fact.get("native_type") or ""), str(fact.get("location") or fact.get("address") or item.fact_id))
        if key not in groups:
            order.append(key)
        groups.setdefault(key, []).append(item)
    out: list[PostureFactAgg] = []
    for entry in order:
        if not isinstance(entry, tuple):
            out.append(entry)
            continue
        items = sorted(groups[entry], key=lambda f: (f.last_seen, f.last_scan_id, f.fact_id), reverse=True)
        head = items[0]
        own = str(head.fact.get("source") or head.source_key)
        also = tuple(dict.fromkeys(label for label in (str(f.fact.get("source") or f.source_key) for f in items[1:])
                                   if label != own))
        out.append(replace(head, fact={**head.fact, "also_seen": list(also)}) if also else head)
    return out


def _where(fact: dict[str, Any]) -> str:
    """The Location cell: a collected listener names its resource id and every source that read it."""
    where = common.location_of(fact)
    if not _collected_tls(fact) or not fact.get("source"):
        return where
    also = [str(label) for label in common.as_rows(fact.get("also_seen"))]
    seen = str(fact["source"]) + (f" (also: {', '.join(also)})" if also else "")
    return f"{where} · {seen}" if where else seen


def _read_here(item: Any) -> bool:
    """A fact one of this document's tables prints: a TLS endpoint or listener, SSH, or a database transport."""
    fact = common.fact_map(item)
    kind = common.kind_of(fact)
    return (kind in _SOURCES_RENDERED or bool(common.net_of(fact))
            or (kind in text.DATABASE_KINDS and bool(common.layer_verdict(fact, "transport"))))


def _scoped(view: TeamCbomView) -> tuple[TeamCbomView, _Model]:
    """The view this document prints: Sources endpoints de-duplicated (one fact per ``host:port``) in place of the
    per-collection probed facts, and sources that were deleted left out of the source table."""
    deleted_keys = {c.key for c in view.collections if not c.source_kind}
    estate = unique_certificates(view)
    if not inputs_of(view).rows:  # a hand-built view, or no Sources rows loaded: print the posture as it is
        return view, _Model(certificates=len(estate), certificates_served=estate.served,
                            deleted_sources=tuple(sorted(c.label for c in view.collections if not c.source_kind)))
    tls, d1 = NE.tls_endpoints(view)
    ssh, d2 = NE.ssh_endpoints(view)
    appliances, d3 = NE.appliance_configs(view)
    ike, d4 = NE.ike_endpoints(view)
    opcua, modbus, d5 = NE.ot_endpoints(view)
    posture = view.posture
    # a deleted source's facts are never current evidence (the rollup already leaves them out; this keeps D7 honest
    # for any view that still carries one), and a listener collected by two sources is printed once
    kept = _fold_collected([f for f in posture.facts if not _from_sources(f) and f.source_key not in deleted_keys])
    new = [PostureFactAgg(source_key=e.observed.item.collection.key, fact_id=f"sources-endpoint:{e.key}", current=True,
                          first_seen=e.observed.item.collection.observed_at,
                          last_seen=e.observed.item.collection.observed_at, scan_count=1,
                          last_scan_id=int(e.observed.item.collection.run_id),
                          fact=NE.tls_net(e, "probed:CBOM Sources"))
           for e in tls]
    # a Sources collection is in the source table when it holds evidence printed here: since the posture mapper, a
    # cloud account whose only settings are keys, storage or a private CA (D6 / D8 evidence) is in posture.sources too
    collection_keys = {c.key for c in view.collections}
    network_keys = {f.source_key for f in posture.facts if f.source_key in collection_keys and _read_here(f)}
    network_keys |= {str(k) for f in posture.facts if _read_here(f)  # a source whose read is printed as "also"
                     for k in common.as_rows(common.fact_map(f).get("also_seen_keys")) if str(k) in collection_keys}
    sources = [s for s in posture.sources
               if s.key not in deleted_keys and (s.key not in collection_keys or s.key in network_keys)]
    listed = {s.key for s in sources}
    for observed in [*(e.observed for e in tls), *ssh, *appliances, *ike, *opcua, *modbus]:
        coll = observed.item.collection
        if coll.key in listed:
            continue
        listed.add(coll.key)
        sources.append(PostureSourceAgg(key=coll.key, label=coll.label, state="assessed", reason=None,
                                        current_scan_id=int(coll.run_id), last_scanned=coll.observed_at,
                                        zero_facts=False, truncated=False, dropped=0, lanes=("sources_network",),
                                        failed_lanes=()))
    sources.sort(key=lambda row: (row.label.casefold(), row.key))
    scoped_posture = replace(posture, facts=tuple([*kept, *new]), sources=tuple(sources))
    model = _Model(tls=tuple(tls), ssh=tuple(ssh), appliances=tuple(appliances), ike=tuple(ike), opcua=tuple(opcua),
                   modbus=tuple(modbus), deleted_rows=d1 + d2 + d3 + d4 + d5,
                   deleted_sources=tuple(sorted(c.label for c in view.collections if not c.source_kind)),
                   certificates=len(estate), certificates_served=estate.served)
    return replace(view, posture=scoped_posture), model


def _kpi(view: object, model: _Model, width: float) -> Flowable:
    endpoints = _endpoints(view)
    legacy = sum(1 for fact in endpoints if _legacy(fact))
    weak = sum(1 for fact in endpoints if _weak(fact))
    imports = [common.as_mapping(item) for item in common.as_rows(common.grab(common.posture_block(view), "imports", ()))]
    tools = sorted({str(item.get("tool") or "unknown") for item in imports})
    assessed, total, _missing, _partial = common.coverage_numbers(view)
    tool_text = ", ".join(f"{tool}" for tool in tools) if tools else "none"
    graded = [e.grade.letter for e in model.tls if e.grade.letter != "-"]
    poor = sum(1 for letter in graded if letter in ("C", "D", "E", "F", "T", "M"))
    cards = [
        ("Endpoints", common.kpi_text(view, len(endpoints)), "Unique host:port, static, imported, probed"),
        ("Legacy protocol", common.kpi_text(view, legacy), "SSLv3, TLS 1.0 or TLS 1.1 offered"),
        ("Weak suites", common.kpi_text(view, weak), "Endpoints with a weak suite"),
        ("Grade C or worse", common.kpi_text(view, poor), f"of {len(graded)} graded TLS endpoints", "high"),
        ("Certificates", common.kpi_text(view, model.certificates),
         f"{count_phrase(model.certificates)} (D8); {model.certificates_served} served on endpoints"),
        ("SSH endpoints", common.kpi_text(view, len(model.ssh)), "Host keys, kex, ciphers, MACs"),
        ("Appliance settings", common.kpi_text(view, len(model.appliances)), "TLS, SSH, IKE, IPsec configuration"),
        ("IKE / OT", common.kpi_text(view, f"{len(model.ike)} / {len(model.opcua) + len(model.modbus)}"),
         "IKE gateways / OPC UA + Modbus"),
        ("Import tools", common.kpi_text(view, len(tools)), tool_text),
        ("Sources", common.kpi_text(view, f"{assessed}/{total}"), "assessed of current sources"),
    ]
    return kpi_strip(cards, width, max_per_row=5)


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
                net.get("grade") or "",
                len(weak_suites),
                _kx(net),
                net.get("fs") or "",
                net.get("hsts") or "",
                net.get("downgrade") or "",
                _cert_summary(net),
                common.codes_cell(fact),
                _where(fact),
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
                "Grade",
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
            (130, 60, 46, 34, 36, 30, 60, 56, 46, 46, 50, 64, 54),
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


def suite_label(name: Any) -> str:
    """A suite by its IANA registry name, with the name the collector stored beside it when that was an OpenSSL name
    (staging QA Q3-10: D7 mixed ``DES-CBC3-SHA`` and ``TLS_RSA_WITH_3DES_EDE_CBC_SHA``).  ``tls_suites`` is the one
    table of names; a name it does not hold is printed as stored."""
    import backend.utilities.cbom_sources.tls_suites as tls_suites

    text = str(name or "").strip()
    hit = tls_suites.lookup(text)
    if hit is None or hit.iana.upper() == text.upper():
        return text
    return f"{hit.iana} ({text})"


def _weak_suites(view: object, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for fact in _endpoints(view):
        for suite in common.as_rows(common.net_of(fact).get("weak_suites")):
            mapped = common.as_mapping(suite) or {"suite": suite}
            reasons = mapped.get("reasons") or []
            reason_text = "; ".join(str(item) for item in common.as_rows(reasons))
            rows.append([common.endpoint_label(fact), suite_label(mapped.get("suite")), reason_text])
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
        *section_heading("SSH and database transport (declared in code and configuration)", styles),
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


def _codes(codes: Any) -> str:
    return " ".join(str(c) for c in codes or ())


def _seen(observed: NE.Observed) -> str:
    also = f" (also: {', '.join(observed.also_seen)})" if observed.also_seen else ""
    return observed.source + also


def _grade_rubric(styles: Styles, width: float) -> list[Flowable]:
    return [
        *section_heading("TLS grade rubric", styles),
        common.note("Each probed TLS endpoint gets a letter computed only from what the probe observed, modelled on "
                    "the Qualys SSL Labs SSL Server Rating Guide. It is informative: it ranks endpoints for "
                    "remediation and does not replace a live verification.", styles),
        *common.register(("Part", "Rule"), [list(row) for row in NE.RUBRIC], (140, 580), width, styles,
                         noun="rubric rows"),
    ]


def _grades(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for e in model.tls:
        facts = e.observed.facts
        rows.append([
            e.key, e.service, e.grade.text, "" if e.grade.score is None else e.grade.score,
            "; ".join(e.grade.reasons), facts.get("negotiated_version") or "",
            suite_label(facts.get("negotiated_cipher")), ", ".join(e.groups),
            "complete" if not e.grade.provisional else "incomplete: " + "; ".join(e.not_read[:3]),
            _seen(e.observed),
        ])
    return [
        *section_heading("TLS endpoint grades", styles),
        *_table(("Endpoint", "Service", "Grade", "Score", "Caps and trust", "Negotiated", "Cipher",
                          "Groups", "Suite enumeration", "Source"), rows,
                         (90, 50, 50, 30, 130, 45, 100, 60, 90, 75), width, styles, "graded endpoints"),
    ]


def _suites(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    flow: list[Flowable] = [*section_heading("Accepted cipher suites by endpoint", styles),
                            common.note("Every suite the probe saw accepted, per protocol version. Each endpoint is a "
                                        "collapsed entry under 'Accepted cipher suites by endpoint' in the PDF "
                                        "bookmarks panel. 'Incomplete' means the probe's handshake budget ran out "
                                        "before every suite was tried.", styles)]
    rows_all = 0
    listed = sorted((e for e in model.tls if e.suites), key=lambda e: _GRADE_ORDER.get(e.grade.letter, 9))
    if len(listed) > SUITE_ENDPOINT_CAP:
        flow.append(common.note(f"Showing the {SUITE_ENDPOINT_CAP} lowest-graded of {len(listed)} endpoints; "
                                f"{_FULL_LIST}.", styles))
        listed = listed[:SUITE_ENDPOINT_CAP]
    for index, e in enumerate(listed):
        rows = []
        for version, names in e.suites.items():
            done = e.suites_complete.get(version)
            state = "complete" if done else ("incomplete" if done is False else "not reported")
            for position, name in enumerate(names):  # one suite per row: a long list is never cut
                rows.append([version if position == 0 else "", position + 1, suite_label(name),
                             state if position == 0 else ""])
                rows_all += 1
        flow.append(Bookmark(f"{e.key} ({e.grade.text})", f"d7-suites-{index}", 1, closed=True))
        flow.extend(common.register((f"{e.key} · version", "#", "Accepted suite (IANA name)", "Enumeration"),
                                    rows, (110, 30, 480, 100), width, styles, noun="suite rows"))
    if rows_all == 0:
        flow.extend(common.register(("Endpoint", "Version", "Accepted suites"), [], (150, 90, 480), width, styles))
    return flow


def _chains(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for e in model.tls:
        for cert in e.chain:
            rows.append([e.key, cert.index, cert.subject, cert.issuer, cert.not_after[:10], cert.key,
                         (cert.thumbprint[:16] + "\u2026") if cert.thumbprint else ""])
    return [
        *section_heading("Certificate chains presented", styles),
        *_table(("Endpoint", "#", "Subject", "Issuer", "Valid to", "Key", "SHA-256"), rows,
                         (100, 20, 170, 170, 60, 70, 90), width, styles, "chain certificates"),
    ]


def _ssh(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for o in model.ssh:
        algs = NE.ssh_algorithms(o)
        rows.append([o.key, o.facts.get("banner") or "", "\n".join(NE.ssh_host_keys(o)), ", ".join(algs["kex"]),
                     ", ".join(algs["ciphers"]), ", ".join(algs["macs"]), "yes" if NE.ssh_pq_kex(o) else "no",
                     _codes(o.codes), _seen(o)])
    return [
        *section_heading("SSH endpoints", styles),
        *_table(("Endpoint", "Banner", "Host keys", "Key exchange", "Ciphers", "MACs", "PQ kex",
                          "Finding codes", "Source"), rows, (70, 70, 120, 110, 90, 70, 30, 90, 70), width, styles,
                         "SSH endpoints"),
    ]


def _appliances(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for o in model.appliances:
        f = o.facts
        rows.append([f.get("appliance") or o.item.target or "", f.get("vendor_label") or f.get("vendor") or "",
                     NE.APPLIANCE_KINDS.get(str(f.get("kind") or ""), str(f.get("kind") or "")),
                     f.get("section") or "", NE.appliance_settings(o), _codes(o.codes), _seen(o)])
    return [
        *section_heading("Network appliance configuration (TLS, SSH, IKE, IPsec)", styles),
        *_table(("Appliance", "Vendor", "Setting", "Section", "Configured values", "Finding codes",
                          "Source"), rows, (70, 60, 60, 120, 220, 110, 80), width, styles, "appliance settings"),
    ]


def _ike(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    probed = []
    for o in model.ike:
        info = NE.ike_summary(o)
        probed.append([o.key, info["versions"], info["chosen"], info["weak"], info["aggressive"], info["pq"],
                       _codes(o.codes), _seen(o)])
    configured = [[o.facts.get("appliance") or "", o.facts.get("vendor_label") or "", o.facts.get("section") or "",
                   NE.appliance_settings(o), _codes(o.codes)]
                  for o in model.appliances if o.facts.get("kind") in ("ike_policy", "ipsec_policy")]
    return [
        *section_heading("IKE / IPsec proposals", styles),
        common.note("Probed: what an IKE gateway accepted when the scan node offered proposals (UDP 500 / 4500). "
                    "Configured: the proposals and transform sets in the appliance configuration.", styles),
        *_table(("Gateway", "Versions", "Chosen proposal", "Weak transforms accepted", "Aggressive mode",
                          "PQ (RFC 9370)", "Finding codes", "Source"), probed,
                         (80, 55, 140, 150, 50, 60, 100, 85), width, styles, "IKE gateways"),
        *_table(("Appliance", "Vendor", "Proposal / transform set", "Configured values", "Finding codes"),
                         configured, (80, 70, 170, 260, 140), width, styles, "configured proposals"),
    ]


def _starttls(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    rows = []
    for e in model.tls:
        if not e.starttls:
            continue
        net = NE.tls_net(e, "probed:CBOM Sources")["net"]
        rows.append([e.key, e.service.replace(NE.STARTTLS_PREFIX, "STARTTLS "), net.get("min") or "",
                     net.get("max") or "", e.grade.text, _codes(e.observed.codes), _seen(e.observed)])
    return [
        *section_heading("STARTTLS services", styles),
        *_table(("Endpoint", "Service", "Lowest TLS", "Highest TLS", "Grade", "Finding codes", "Source"),
                         rows, (110, 110, 60, 60, 60, 160, 160), width, styles, "STARTTLS services"),
    ]


def _ot(model: _Model, styles: Styles, width: float) -> list[Flowable]:
    opc = []
    for o in model.opcua:
        info = NE.opcua_summary(o)
        opc.append([o.key, info["application"], info["endpoints"], info["modes"], info["policies"], info["tokens"],
                    _codes(o.codes), _seen(o)])
    modbus = [[o.key, "port open (TCP connect only)", "none: Modbus/TCP has no encryption or authentication",
               _codes(o.codes), _seen(o)] for o in model.modbus]
    return [
        *section_heading("OPC UA endpoint security", styles),
        *_table(("Endpoint", "Application", "Endpoints", "Security modes", "Security policies",
                          "User tokens", "Finding codes", "Source"), opc,
                         (90, 100, 45, 90, 130, 90, 90, 85), width, styles, "OPC UA endpoints"),
        *section_heading("Modbus/TCP (port open only)", styles),
        common.note("SOW 7.2: Modbus devices are recorded from a TCP connect to the port only. No Modbus request (not "
                    "even a read) is sent, so nothing about the device is asserted beyond the open port.", styles),
        *_table(("Endpoint", "Evidence", "Transport security", "Finding codes", "Source"), modbus,
                         (120, 140, 220, 110, 130), width, styles, "Modbus endpoints"),
    ]


def _deleted_note(model: _Model, styles: Styles) -> list[Flowable]:
    if not model.deleted_sources and not model.deleted_rows:
        return []
    names = ", ".join(model.deleted_sources[:6]) + (f" and {len(model.deleted_sources) - 6} more"
                                                    if len(model.deleted_sources) > 6 else "")
    rows = f" ({model.deleted_rows} network row{'s' if model.deleted_rows != 1 else ''})" if model.deleted_rows else ""
    return [common.note(f"Left out: the latest collections of {len(model.deleted_sources)} deleted source"
                        f"{'s' if len(model.deleted_sources) != 1 else ''}{rows}: {names}. A deleted source is never "
                        "counted as current evidence.", styles)]


def build_story(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """Document body for deliverable D7."""
    return _story(*_scoped(view), styles, width)


def _story(view: TeamCbomView, model: _Model, styles: Styles, width: float) -> list[Flowable]:
    return [
        common.note(REPORT_META[REPORT_KEY]["how_to_read"], styles),
        common.gap(),
        _kpi(view, model, width),
        *_deleted_note(model, styles),
        common.gap(),
        *common.source_status_flow(view, styles, width),
        *_endpoint_register(view, styles, width),
        *_grades(model, styles, width),
        *_matrix(view, styles, width),
        *_weak_suites(view, styles, width),
        *_certificates(view, styles, width),
        *_chains(model, styles, width),
        *_downgrade(view, styles, width),
        *_ssh(model, styles, width),
        *_appliances(model, styles, width),
        *_ike(model, styles, width),
        *_starttls(model, styles, width),
        *_ot(model, styles, width),
        *_ssh_and_db(view, styles, width),
        *_verification_disabled(view, styles, width),
        *_imports(view, styles, width),
        *_grade_rubric(styles, width),
        *_suites(model, styles, width),
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
        common.note(text.endpoint_limit(view), styles),
    ]


def build_pdf(view: TeamCbomView, *, ctx: Any = None) -> bytes:
    """Render deliverable D7. Returns PDF bytes.  The Basis box, the banners and the body all read ONE scoped view,
    so the Basis box's "N of M current sources" is the Sources KPI's number."""
    scoped, model = _scoped(view)
    return build_document(ctx=ctx,
        view=view,
        number=DOCUMENT_NUMBER,
        report_key=REPORT_KEY,
        title=REPORT_META[REPORT_KEY]["title"],
        landscape=True,
        body=lambda styles, width: _story(scoped, model, styles, width),
        basis_extra=common.basis_lines(scoped),
        disclaimer_paragraphs=text.disclaimer_paragraphs(scoped),
        extra_banners=common.banner_pairs(scoped),
    )


__all__ = ["DOCUMENT_NUMBER", "REPORT_KEY", "build_pdf", "build_story"]
