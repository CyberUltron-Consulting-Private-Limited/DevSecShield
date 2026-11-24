"""CERT-In CBOM lane checks — Table 9 auto + §8.4.1 manuals (Phase 1).

Registered under framework key ``cert_in_cbom``. Imported by the CBOM runner
(:mod:`aibom.cbom.compliance`) for side-effect registration only —
:mod:`aibom.compliance.__init__` must NEVER import this module.

Checks read GRAPH ``crypto:`` properties only (never ``result.flags``).
OID unknown → NBE (F9). Process manuals → register_manual → NBE.
"""

from __future__ import annotations

from collections.abc import Callable

from aibom.compliance.base import (
    FAIL,
    NOT_EVIDENCEABLE,
    PASS,
    CheckResult,
    Requirement,
    register_check,
    register_manual,
)
from aibom.compliance.cert_in.common import CERTIN_DISCLAIMER, load_ledger
from aibom.compliance.cert_in.predicates import has_nonempty, prop
from aibom.model.component import AIComponent
from aibom.model.result import ScanResult

_FW = "cert_in_cbom"


def _crypto_assets(r: ScanResult) -> list[AIComponent]:
    return [c for c in r.components if c.kind == "crypto_asset"]


def _of_type(r: ScanResult, asset_type: str) -> list[AIComponent]:
    return [
        c
        for c in _crypto_assets(r)
        if (c.properties or {}).get("crypto:assetType") == asset_type
    ]


def _refs(comps: list[AIComponent]) -> list[str]:
    return [c.bom_ref for c in comps if c.bom_ref]


def _field_value(comp: AIComponent, field: str) -> str | None:
    """Resolve a Table-9 field off a component (name or crypto: prop)."""
    if field == "name":
        return str(comp.name).strip() if has_nonempty(comp.name) else None
    if field == "crypto:assetType":
        return prop(comp, "crypto:assetType")
    if field.startswith("crypto:"):
        return prop(comp, field)
    # unsupported / not emitted by inventory → None (NBE path)
    return None


# Per-requirement field extractors keyed by ledger id.
# field=None means the inventory never invents this fact → NBE when class present.
_FIELD_BY_ID: dict[str, tuple[str, str | None]] = {
    "T9-Algorithms-Name": ("algorithm", "name"),
    "T9-Algorithms-AssetType": ("algorithm", "crypto:assetType"),
    "T9-Algorithms-Primitive": ("algorithm", "crypto:primitive"),
    "T9-Algorithms-Mode": ("algorithm", "crypto:mode"),
    "T9-Algorithms-Crypto-Functions": ("algorithm", None),
    "T9-Algorithms-Classical-Security-Level": (
        "algorithm",
        "crypto:securityStrengthBits",
    ),
    "T9-Algorithms-OID": ("algorithm", "crypto:oid"),
    "T9-Algorithms-List": ("algorithm", None),
    "T9-Keys-Name": ("related-crypto-material", "name"),
    "T9-Keys-AssetType": ("related-crypto-material", "crypto:assetType"),
    "T9-Keys-Id": ("related-crypto-material", "crypto:id"),
    "T9-Keys-State": ("related-crypto-material", "crypto:state"),
    "T9-Keys-Size": ("related-crypto-material", "crypto:keySize"),
    "T9-Keys-Creation-Date": ("related-crypto-material", "crypto:creationDate"),
    "T9-Keys-Activation-Date": ("related-crypto-material", "crypto:activationDate"),
    "T9-Protocols-Name": ("protocol", "name"),
    "T9-Protocols-AssetType": ("protocol", "crypto:assetType"),
    "T9-Protocols-Version": ("protocol", "crypto:protocolVersion"),
    "T9-Protocols-Cipher-Suites": ("protocol", "crypto:cipherSuite"),
    "T9-Protocols-OID": ("protocol", "crypto:oid"),
    "T9-Certificates-Name": ("certificate", "name"),
    "T9-Certificates-AssetType": ("certificate", "crypto:assetType"),
    "T9-Certificates-Subject-Name": ("certificate", "crypto:subjectName"),
    "T9-Certificates-Issuer-Name": ("certificate", "crypto:issuerName"),
    "T9-Certificates-Not-Valid-Before": ("certificate", "crypto:notValidBefore"),
    "T9-Certificates-Not-Valid-After": ("certificate", "crypto:notValidAfter"),
    "T9-Certificates-Signature-Algorithm-Reference": (
        "certificate",
        "crypto:signatureAlgorithmRef",
    ),
    "T9-Certificates-Subject-Public-Key-Reference": (
        "certificate",
        "crypto:subjectPublicKeyRef",
    ),
    "T9-Certificates-Certificate-Format": ("certificate", "crypto:certificateFormat"),
    "T9-Certificates-Certificate-Extension": (
        "certificate",
        "crypto:certificateExtension",
    ),
}


def _has_mode(comp: AIComponent) -> bool:
    """A mode of operation applies to a block cipher (CycloneDX ``mode``: "the mode of
    operation in which the
    cryptographic algorithm (block cipher) is used"), or to an asset whose mode the scan
    read (AES-GCM). A hash, MAC,
    KDF, signature or stream cipher has none, so its missing mode is not a gap (staging
    QA Q2-04)."""
    return prop(comp, "crypto:primitive") == "block-cipher" or has_nonempty(
        prop(comp, "crypto:mode")
    )


# Requirements that apply only to some assets of their class, and what those are.
_APPLIES: dict[str, Callable[[AIComponent], bool]] = {"T9-Algorithms-Mode": _has_mode}
_APPLIES_TEXT = {
    "T9-Algorithms-Mode": "a mode of operation applies only to block-cipher algorithms"
}


def _make_auto_check(
    *,
    asset_type: str,
    field: str | None,
    missing: str,
    rid: str,
) -> Callable[[ScanResult, Requirement], CheckResult]:
    """Build a pure graph check for one Table-9 element."""

    def _check(r: ScanResult, req: Requirement) -> CheckResult:
        assets = _of_type(r, asset_type)
        if rid in _APPLIES:
            assets = [c for c in assets if _APPLIES[rid](c)]
            if not assets:
                return PASS(
                    f"{rid}: {_APPLIES_TEXT[rid]}; no such asset in the inventory"
                )
        if not assets:
            return PASS(
                f"no {asset_type} assets in inventory; {rid} vacuously satisfied"
            )

        # Field not inventable by the scanner → NBE (F9 / ledger nbe).
        if field is None:
            return NOT_EVIDENCEABLE(
                f"{rid}: fact not BOM-evidenceable from static crypto inventory "
                f"({CERTIN_DISCLAIMER})"
            )

        present: list[AIComponent] = []
        absent: list[AIComponent] = []
        for c in assets:
            if has_nonempty(_field_value(c, field)):
                present.append(c)
            else:
                absent.append(c)

        # OID / nbe-missing policy: known → pass; unknown → NBE (never invent).
        if missing == "nbe" or field == "crypto:oid" or rid.endswith("-OID"):
            if not absent:
                return PASS(
                    f"all {len(assets)} {asset_type} asset(s) carry {field}",
                    _refs(assets),
                )
            if present and absent:
                # Partial: still NBE for unknowns (do not fail-invent).
                return NOT_EVIDENCEABLE(
                    f"{rid}: {len(absent)}/{len(assets)} {asset_type} asset(s) lack "
                    f"{field}; unknown → not BOM-evidenceable ({CERTIN_DISCLAIMER})",
                    _refs(absent),
                )
            return NOT_EVIDENCEABLE(
                f"{rid}: {field} not present on {asset_type} assets; "
                f"unknown → not BOM-evidenceable ({CERTIN_DISCLAIMER})",
                _refs(assets),
            )

        # fail-missing: empty field on any in-class asset → FAIL.
        if absent:
            return FAIL(
                f"{rid}: {len(absent)}/{len(assets)} {asset_type} asset(s) lack {field}",
                _refs(absent),
            )
        return PASS(
            f"all {len(assets)} {asset_type} asset(s) carry {field}",
            _refs(assets),
        )

    _check.__name__ = f"_certin_{rid.replace('.', '_').replace('-', '_')}"
    _check.__qualname__ = _check.__name__
    return _check


# Process requirements the code scan's own outputs evidence: every CBOM code scan is
# emitted as a schema-validated
# CycloneDX 1.6 document (JSON, and XML on download), and its VEX (CycloneDX 1.6) is
# issued with it (GET .../vex and
# the evidence pack's vex.json) for every finding code and matched CVE. Not "not BOM-
# evidenceable": the BOM is the
# evidence.
_PRODUCT_EVIDENCED = {
    "8.4.1.5": "this CBOM is emitted in CycloneDX 1.6 (JSON and XML), validated "
    "against the CycloneDX schema",
    "8.4.1.6": "a CycloneDX 1.6 VEX is issued with this CBOM (the VEX download and the "
    "evidence pack's vex.json) for its finding codes and matched CVEs",
}


def _product_check(rid: str) -> Callable[[ScanResult, Requirement], CheckResult]:
    def _check(r: ScanResult, req: Requirement) -> CheckResult:
        return PASS(f"{rid}: {_PRODUCT_EVIDENCED[rid]} ({CERTIN_DISCLAIMER})")

    _check.__name__ = f"_certin_{rid.replace('.', '_')}_product"
    _check.__qualname__ = _check.__name__
    return _check


def _register_from_ledger() -> None:
    doc = load_ledger()
    for raw in doc.get("requirements") or []:
        rid = str(raw.get("id") or "")
        mode = str(raw.get("mode") or "")
        missing = str(raw.get("missing") or "fail")
        title = str(raw.get("title") or rid)
        source = str(raw.get("pdf") or "CERT-In TG v2.0")

        if rid in _PRODUCT_EVIDENCED:
            # the scan itself produces this evidence (staging QA N7): a CycloneDX 1.6
            # CBOM and its VEX
            req = Requirement(id=rid, framework=_FW, title=title, source=source)
            register_check(req)(_product_check(rid))
            continue

        if mode == "manual" and rid.startswith("8.4.1."):
            req = Requirement(
                id=rid,
                framework=_FW,
                title=title,
                source=source,
            )
            register_manual(
                req,
                f"{CERTIN_DISCLAIMER} Process attestation for {rid}: "
                f"{raw.get('description') or raw.get('evidence_hint') or 'organizational evidence'}.",
            )
            continue

        if mode != "auto" or not rid.startswith("T9-"):
            continue

        spec = _FIELD_BY_ID.get(rid)
        if spec is None:
            # Ledger row without a field map → conservative NBE check.
            asset_type, field = "algorithm", None
        else:
            asset_type, field = spec

        req = Requirement(
            id=rid,
            framework=_FW,
            title=title,
            source=source,
        )
        register_check(req)(
            _make_auto_check(
                asset_type=asset_type,
                field=field,
                missing=missing,
                rid=rid,
            )
        )


_register_from_ledger()
