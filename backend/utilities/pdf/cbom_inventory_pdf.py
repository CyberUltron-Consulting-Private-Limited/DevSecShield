"""The full cryptographic inventory of a CBOM code scan, as PDF tables (SOW D3).

The findings section lists only assets with a finding; SOW D3 asks the report itself to carry the inventory:
encryption calls with algorithm, mode and key size, KDF parameters, salt / IV / nonce literals, keys and
certificates, crypto libraries with their versions, and the container images the code ships on. Built from the
scan's CycloneDX document (``cbom_json``), the same file the download serves, so the report and the BOM agree.
A literal's value is never printed: only that it is static, its length and what it feeds.
"""

from __future__ import annotations

from typing import Any, Dict, List

from reportlab.lib.units import inch
from reportlab.platypus import CondPageBreak, Paragraph, Spacer

from backend.utilities.pdf.report_branding import escape_html, styled_data_table, wrap_at_separators

_CELL_PAD = 16  # styled_data_table's left + right cell padding, in points

# KDF / construction parameters printed under "Parameters", in order: property -> label.
_PARAMS = (
    ("crypto:construction", "built from"),
    ("crypto:keyMaterialBits", "key material bits"),
    ("crypto:curve", "curve"),
    ("crypto:parameterSet", "parameter set"),
    ("crypto:padding", "padding"),
    ("crypto:kdfPrf", "PRF"),
    ("crypto:iterations", "iterations"),
    ("crypto:kdfLength", "output bytes"),
    ("crypto:saltLength", "salt bytes"),
    ("crypto:scryptN", "N"),
    ("crypto:scryptR", "r"),
    ("crypto:scryptP", "p"),
    ("crypto:argon2Variant", "variant"),
    ("crypto:argon2TimeCost", "time cost"),
    ("crypto:argon2MemoryCost", "memory KiB"),
    ("crypto:argon2Parallelism", "parallelism"),
    # several calls in one file: the row shows the weakest call's set (the CycloneDX lists every call)
    ("crypto:kdfWeakestLine", "weakest of its calls, line"),
)
_MAX_ROWS = 400  # per table; the rest are counted (the CycloneDX download lists every asset)


def _props(comp: Dict[str, Any]) -> Dict[str, str]:
    return {str(p.get("name")): str(p.get("value")) for p in comp.get("properties") or [] if isinstance(p, dict)}


def _location(props: Dict[str, str]) -> str:
    src = props.get("discovery:source") or ""
    line = props.get("crypto:line") or props.get("discovery:line") or ""
    return f"{src}:{line}" if src and line.isdigit() else (src or "—")


def _library_versions(components: List[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for comp in components:
        props = _props(comp)
        if comp.get("type") == "library" and props.get("crypto:role") == "library":
            name = str(comp.get("name") or "")
            out[name.lower()] = f"{name}@{comp['version']}" if comp.get("version") else name
    return out


def _algorithm_rows(components: List[Dict[str, Any]], libs: Dict[str, str]) -> List[List[str]]:
    rows: List[List[str]] = []
    for comp in components:
        cp = comp.get("cryptoProperties") or {}
        if comp.get("type") != "cryptographic-asset" or cp.get("assetType") != "algorithm":
            continue
        props = _props(comp)
        ap = cp.get("algorithmProperties") or {}
        size = props.get("crypto:keySize") or ap.get("parameterSetIdentifier") or ""
        params = [f"{label} {props[key]}" for key, label in _PARAMS if props.get(key)]
        level = ap.get("nistQuantumSecurityLevel")
        library = libs.get((props.get("crypto:detectedBy") or "").lower()) or ", ".join(
            libs.get(x.strip().lower(), x.strip()) for x in (props.get("crypto:libraries") or "").split(",") if x
        )
        # no leading "—;" when the size is unknown: only the parts the scan knows
        detail = ([f"{size} bits" if size.isdigit() else size] if size else []) + params
        rows.append([
            str(comp.get("name") or ""),
            str(ap.get("primitive") or props.get("crypto:primitive") or "—"),
            str(ap.get("mode") or props.get("crypto:mode") or "—").upper(),
            "; ".join(detail) or "—",
            "—" if level is None else str(level),
            library or "—",
            _location(props),
        ])
    return sorted(rows, key=lambda r: (r[0].lower(), r[6]))


def _material_rows(components: List[Dict[str, Any]]) -> List[List[str]]:
    rows: List[List[str]] = []
    for comp in components:
        cp = comp.get("cryptoProperties") or {}
        kind = cp.get("assetType")
        if comp.get("type") != "cryptographic-asset" or kind not in ("related-crypto-material", "certificate",
                                                                    "protocol"):
            continue
        props = _props(comp)
        detail: List[str] = []
        if kind == "related-crypto-material":
            label = str((cp.get("relatedCryptoMaterialProperties") or {}).get("type") or "material")
            if props.get("crypto:staticSalt") == "true" or props.get("crypto:staticIv") == "true" \
                    or props.get("crypto:hardcoded") == "true":
                detail.append("hard-coded literal (value not shown)")
            if props.get("crypto:literalLength"):
                detail.append(f"{props['crypto:literalLength']} bytes")
            if props.get("crypto:usedBy"):
                detail.append(f"feeds {props['crypto:usedBy'].replace(',', ', ')}")
        elif kind == "certificate":
            label = "certificate"
            cert = cp.get("certificateProperties") or {}
            for key, text in (("subjectName", "subject"), ("issuerName", "issuer"), ("notValidAfter", "expires")):
                if cert.get(key):
                    detail.append(f"{text} {cert[key]}")
        else:
            label = "protocol"
            proto = cp.get("protocolProperties") or {}
            detail.append(" ".join(str(x) for x in (proto.get("type"), proto.get("version")) if x))
        rows.append([str(comp.get("name") or ""), label, "; ".join(d for d in detail if d) or "—", _location(props)])
    return sorted(rows, key=lambda r: (r[1], r[0].lower()))


def _library_rows(components: List[Dict[str, Any]]) -> List[List[str]]:
    """One row per library. A vulnerable pin the advisory lane lists as its own component (``cryptography@>=42``)
    and links to the code lane's row for the same package (``crypto:libraryRef`` -> pyca/cryptography) is printed
    on that row, not as a second library (review of #491 m6)."""
    libraries = [c for c in components if c.get("type") == "library" and _props(c).get("crypto:role") == "library"]
    refs = {str(c.get("bom-ref") or "") for c in libraries}
    pins: Dict[str, List[Dict[str, str]]] = {}
    for comp in libraries:
        target = _props(comp).get("crypto:libraryRef")
        if target and target in refs and target != comp.get("bom-ref"):
            pins.setdefault(target, []).append(_props(comp))
    rows: List[List[str]] = []
    for comp in libraries:
        props = _props(comp)
        if props.get("crypto:libraryRef") in pins:
            continue  # printed on the library row it is linked to
        advisories = [p for p in [props] + pins.get(str(comp.get("bom-ref") or ""), []) if p.get("crypto:advisory")]
        version = str(comp.get("version") or "")
        if version:
            basis = f"from {props.get('crypto:versionSource') or 'the manifest'}"
            if props.get("crypto:versionConstraint"):
                basis += f" (declared {props['crypto:versionConstraint']})"
        else:
            declared = props.get("crypto:versionConstraint") or props.get("crypto:version") or next(
                (p.get("crypto:version") for p in advisories if p.get("crypto:version")), None)
            basis = props.get("crypto:versionUnknownReason") or (f"declared {declared}" if declared else "—")
        for pin in advisories:
            basis += f"; {pin.get('crypto:version') or 'the declared version'} matches " \
                     f"{pin.get('crypto:advisoryCount') or 'known'} advisories"
        if props.get("crypto:versionVerified") == "false" and props.get("crypto:unverifiedAdvisoryCount"):
            # a range's lower bound is no installed version: listed, not a finding (staging QA Q2-09)
            basis += (f"; version unverified: the range's lower bound matches "
                      f"{props['crypto:unverifiedAdvisoryCount']} advisories (not counted)")
        rows.append([str(comp.get("name") or ""), version or "not known", basis, _location(props)])
    return sorted(rows, key=lambda r: r[0].lower())


def _image_rows(components: List[Dict[str, Any]]) -> List[List[str]]:
    rows: List[List[str]] = []
    for comp in components:
        if comp.get("type") != "container":
            continue
        props = _props(comp)
        rows.append([str(comp.get("name") or ""), str(comp.get("version") or "latest (implicit)"),
                     props.get("image:origin") or "—", _location(props)])
    return sorted(rows, key=lambda r: r[0].lower())


def _table(story: List[Any], title: str, note: str, headers: List[str], rows: List[List[str]],
           widths: List[float], styles: Dict[str, Any], wrap: Dict[int, str] | None = None) -> None:
    """One inventory table. ``wrap`` maps a column to the separators its cells may break after (paths at "/" and
    ":", primitives at "-"), so narrow columns never split a word."""
    if not rows:
        return
    story.append(Spacer(1, 0.12 * inch))
    story.append(CondPageBreak(1.4 * inch))  # the title never sits alone at the foot of a page
    story.append(Paragraph(escape_html(f"{title} ({len(rows)})"), styles["heading"]))
    if note:
        story.append(Paragraph(escape_html(note), styles["muted"]))
    shown = rows[:_MAX_ROWS]
    if wrap:
        cell = styles["table_cell"]
        shown = [[Paragraph(wrap_at_separators(str(v), cell, widths[i] - _CELL_PAD, wrap[i]), cell) if i in wrap
                  else v for i, v in enumerate(row)] for row in shown]
    story.append(styled_data_table(headers, shown, styles=styles, col_widths=widths))
    if len(rows) > len(shown):
        story.append(Paragraph(escape_html(f"{len(rows) - len(shown)} more in the CycloneDX download."),
                               styles["muted"]))


def append_cbom_inventory(story: List[Any], payload: Any, styles: Dict[str, Any]) -> bool:
    """Append the inventory tables; False (nothing appended) when the payload carries no CycloneDX document."""
    bom = payload.get("cbom_json") if isinstance(payload, dict) else None
    components = [c for c in (bom or {}).get("components") or [] if isinstance(c, dict)]
    if not components:
        return False
    libs = _library_versions(components)
    story.append(CondPageBreak(3.0 * inch))
    story.append(Paragraph("Cryptographic inventory", styles["title"]))
    story.append(Paragraph(
        "Every cryptographic asset the scan found, with or without a finding: the same assets as the CycloneDX "
        "download. NIST level is the post-quantum security category (0 = broken by a quantum computer).",
        styles["muted"]))
    path = "/:"
    _table(story, "Algorithms", "NIST: the post-quantum security category.", ["Algorithm", "Primitive", "Mode",
                                                                             "Key size and parameters", "NIST",
                                                                             "Library", "Location"],
           _algorithm_rows(components, libs),
           [1.0 * inch, 0.85 * inch, 0.55 * inch, 1.85 * inch, 0.5 * inch, 1.0 * inch, 1.35 * inch], styles,
           wrap={0: "-", 1: "-", 5: "/ @-", 6: path})
    _table(story, "Keys, certificates, protocols and crypto material",
           "Salt, IV, nonce and key literals are listed with their length and use; their values are not printed.",
           ["Asset", "Type", "Detail", "Location"], _material_rows(components),
           [1.9 * inch, 1.15 * inch, 2.6 * inch, 1.45 * inch], styles, wrap={0: " /-", 1: "-", 3: path})
    _table(story, "Crypto libraries", "Version from the tree's lockfiles and manifests, or why it is not known.",
           ["Library", "Version", "Basis", "Declared or imported in"], _library_rows(components),
           [1.5 * inch, 0.9 * inch, 3.15 * inch, 1.55 * inch], styles, wrap={0: "/ @-", 3: path})
    _table(story, "Container images", "Images named by Dockerfile FROM lines and Compose files (not pulled).",
           ["Image", "Tag or digest", "Named by", "Location"], _image_rows(components),
           [2.4 * inch, 1.6 * inch, 1.3 * inch, 1.8 * inch], styles, wrap={0: "/:.-", 1: ".-:", 3: path})
    return True


__all__ = ["append_cbom_inventory"]
