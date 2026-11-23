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

from backend.utilities.pdf.report_branding import escape_html, styled_data_table

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
        rows.append([
            str(comp.get("name") or ""),
            str(ap.get("primitive") or props.get("crypto:primitive") or "—"),
            str(ap.get("mode") or props.get("crypto:mode") or "—").upper(),
            (f"{size} bits" if size.isdigit() else size or "—") + (f"; {'; '.join(params)}" if params else ""),
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
    rows: List[List[str]] = []
    for comp in components:
        props = _props(comp)
        if comp.get("type") != "library" or props.get("crypto:role") != "library":
            continue
        version = str(comp.get("version") or "")
        if version:
            basis = f"from {props.get('crypto:versionSource') or 'the manifest'}"
            if props.get("crypto:versionConstraint"):
                basis += f" (declared {props['crypto:versionConstraint']})"
        else:
            declared = props.get("crypto:versionConstraint") or props.get("crypto:version")
            basis = props.get("crypto:versionUnknownReason") or (f"declared {declared}" if declared else "—")
            if props.get("crypto:advisory"):
                basis += f"; matches {props.get('crypto:advisoryCount') or 'known'} advisories"
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
           widths: List[float], styles: Dict[str, Any]) -> None:
    if not rows:
        return
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(escape_html(f"{title} ({len(rows)})"), styles["heading"]))
    if note:
        story.append(Paragraph(escape_html(note), styles["muted"]))
    shown = rows[:_MAX_ROWS]
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
    _table(story, "Algorithms", "", ["Algorithm", "Primitive", "Mode", "Key size and parameters", "NIST level",
                                     "Library", "Location"], _algorithm_rows(components, libs),
           [1.05 * inch, 0.75 * inch, 0.45 * inch, 1.7 * inch, 0.45 * inch, 0.95 * inch, 1.15 * inch], styles)
    _table(story, "Keys, certificates, protocols and crypto material",
           "Salt, IV, nonce and key literals are listed with their length and use; their values are not printed.",
           ["Asset", "Type", "Detail", "Location"], _material_rows(components),
           [1.7 * inch, 1.0 * inch, 2.7 * inch, 1.1 * inch], styles)
    _table(story, "Crypto libraries", "Version from the tree's lockfiles and manifests, or why it is not known.",
           ["Library", "Version", "Basis", "Declared or imported in"], _library_rows(components),
           [1.5 * inch, 0.8 * inch, 2.8 * inch, 1.4 * inch], styles)
    _table(story, "Container images", "Images named by Dockerfile FROM lines and Compose files (not pulled).",
           ["Image", "Tag or digest", "Named by", "Location"], _image_rows(components),
           [2.2 * inch, 1.5 * inch, 1.2 * inch, 1.6 * inch], styles)
    return True


__all__ = ["append_cbom_inventory"]
