"""The scan's CycloneDX document exactly as every route serves, packs, signs and verifies it, and its digest.

One builder (review 6032108510 M-3): ``GET /bom``, ``GET /vex``, ``POST /sign``, the evidence pack
(``routers/certin.py``) and the SBOM PDF's minimum-elements page (``pdf/sbom_sca_pdf._downloaded_bom``, reached from
``GET /export`` and the pack's ``report.pdf``) all call ``served_bom``, so the SHA-256 the PDF prints is the digest of
the document ``/bom`` serves and ``bom_signature.json`` names.

A PDF learns which scan it is of from ``SCAN_IDENTITY_KEY`` in its data (``pdf_identity``): the PDF builders take the
scan's stored data only, and the served document also carries the server-stamped ``zs:scan_id`` / ``zs:scan_type`` /
``zs:team_id`` and the scan's stable serial, which the stored data alone cannot give.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any

from backend.utilities.compliance.certin_attest import (
    _BOM_JSON_KEY,
    _stub_sbom_from_findings,
    bom_dict_from_scan_data,
)

SCAN_IDENTITY_KEY = "dss_served_bom_identity"
_SCAN_SERIAL_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/code-scan/bom")


def scan_serial(scan_type: str, scan_id: int) -> str:
    """The scan's stable serial when its stored BOM has none: uuid5 of the scan type and id, the same on every
    request (review 6029745818 N2)."""
    return f"urn:uuid:{uuid.uuid5(_SCAN_SERIAL_NS, f'{scan_type}:{scan_id}')}"


def served_bom(scan_type: str, scan_id: int, data: dict, team_id: int, *,
               subject_name: str | None = None) -> dict | None:
    """The scan's CycloneDX document exactly as every route serves, packs, signs and verifies it.

    * Serial (N2): a stored BOM without a ``serialNumber``, and the stub an SBOM scan without a stored BOM gets from its
      findings, are given the scan's stable serial (``scan_serial``) in a copy of ``data`` BEFORE
      ``bom_dict_from_scan_data`` runs, so the SBOM path (``sanitize_industry_sbom``, which writes a fresh uuid4 when
      there is none) keeps it: every download, pack, VEX and verify of the scan computes the same serial. A stored
      serial is kept as it is (drift and VEX BOM-Links name it). ``data`` is never changed.
    * Binding (N1): every ``zs:`` metadata property of the stored document is dropped (an SBOM or CBOM scan can store a
      user's uploaded file as it was uploaded) and the server stamps ``zs:scan_id``, ``zs:scan_type`` and
      ``zs:team_id`` (``bom_signing.stamp_subject``); ``/signature/verify`` binds a signed file to a scan by those
      three, never by its serial.
    * ``subject_name`` (``certin_attest.subject_name_for(scan.scan_metadata)``: owner/repo, never the worker's clone
      directory) is passed to ``bom_dict_from_scan_data``; every caller passes it, so all copies name the same subject.
    """
    from backend.utilities.cbom_sources import bom_signing as SIGN

    data = data if isinstance(data, dict) else {}
    key = _BOM_JSON_KEY.get(scan_type)
    stored = data.get(key) if key else None
    src = data
    if isinstance(stored, dict):
        if not (isinstance(stored.get("serialNumber"), str) and stored["serialNumber"]):
            src = {**data, key: {**stored, "serialNumber": scan_serial(scan_type, scan_id)}}
    elif scan_type == "sbom_sca" and key:
        findings = data.get("results") if isinstance(data.get("results"), list) else None
        src = {**data, key: {**_stub_sbom_from_findings(findings), "serialNumber": scan_serial(scan_type, scan_id)}}
    bom = bom_dict_from_scan_data(scan_type, src, subject_name=subject_name)
    if not isinstance(bom, dict):
        return None
    if not (isinstance(bom.get("serialNumber"), str) and bom["serialNumber"]):
        bom = {**bom, "serialNumber": scan_serial(scan_type, scan_id)}
    return SIGN.stamp_subject(bom, SIGN.scan_facts(scan_type, scan_id, team_id), drop_all_zs=True)


def bom_sha256(bom: dict[str, Any]) -> str:
    """SHA-256 of the document's canonical JSON (sorted keys, compact, the embedded JSF ``signature`` left out): the
    digest a stored ``bom_signature`` names (``cert_in/sign.canonical_bom_bytes``)."""
    from backend.utilities.compliance.cert_in.sign import canonical_bom_bytes

    return hashlib.sha256(canonical_bom_bytes(bom)).hexdigest()


def pdf_identity(scan_type: str, scan_id: int, team_id: int, subject_name: str | None) -> dict[str, Any]:
    """What a PDF's data carries under ``SCAN_IDENTITY_KEY`` so its BOM pages call ``served_bom`` for this scan."""
    return {"scan_type": scan_type, "scan_id": int(scan_id), "team_id": int(team_id), "subject_name": subject_name}


def served_bom_for_pdf(data: dict[str, Any], scan_type: str) -> dict | None | bool:
    """The served document for a PDF's data, or False when the data names no scan (the caller then builds it from
    the stored data alone, as a PDF of an unsaved result does)."""
    ident = data.get(SCAN_IDENTITY_KEY) if isinstance(data, dict) else None
    if not (isinstance(ident, dict) and ident.get("scan_type") == scan_type
            and isinstance(ident.get("scan_id"), int) and isinstance(ident.get("team_id"), int)):
        return False
    subject = ident.get("subject_name")
    return served_bom(scan_type, ident["scan_id"], data, ident["team_id"],
                      subject_name=subject if isinstance(subject, str) else None)


__all__ = ["SCAN_IDENTITY_KEY", "bom_sha256", "pdf_identity", "scan_serial", "served_bom", "served_bom_for_pdf"]
