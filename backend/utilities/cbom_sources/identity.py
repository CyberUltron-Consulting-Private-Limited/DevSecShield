"""Stable identities for CBOM assets: what makes "the same asset" across runs and scans.

Diffs, drift events, finding resolution and remediation assignments all compare by these keys, never by a row id.

* Source: ``CbomCollectionSource.source_uid`` (a random id that survives deletion). Every collect job snapshots it in
  ``params["source_uid"]``; jobs queued before that existed fall back to the source's current uid, then to its id.
* Node / cloud asset: the asset key the server computed (type | target | location | identity), except
  certificates, which are compared by (target, location, subject, issuer): a renewal changes the fingerprint (part of
  the asset key) but must show as "renewed", not as one certificate removed and another added. The location is kept
  because one host can serve two different certificates for the same subject (two ports, or a chain entry); it is
  stable across renewal (an endpoint and chain position, a file path, an ARN or a Kubernetes secret).
  - A certificate whose location is a cloud resource id (an ARN, an Azure resource or Key Vault id, a GCP resource
    name, an OCID: ``asset_keys.cloud_resource_id``) is identified by (target, location) alone: the id names exactly
    one certificate or CA, and the subject is free text the provider API formats (staging QA2 Q1-09: #481 changed the
    AWS Private CA subject from ``{"CommonName": ...}`` to ``CN=...`` and run #54 showed the same CA removed + added,
    its QUANTUM_VULNERABLE resolved and opened again). Not the fingerprint or serial: both change on renewal.
  - The subject and issuer of every other certificate are compared as normalised DNs (``canonical_dn``): a DN text
    is compared as before (lower case, whitespace collapsed), a subject a collector stored as an attribute map (AWS
    ``ASN1Subject`` JSON) as the RFC 4514 DN it denotes, so the old and new spellings are one identity.
  - ``legacy_node_identity`` is the identity before this rule; ``rekeyed_observations`` maps the stored keys it gave
    to the new ones (the estate store and the remediation assignments move along, ``identity_migration``).
* Code-scan row: (asset type, file, title, bom-ref without a trailing line marker). Misuse refs end in ``-l<line>``
  (``crypto_misuse_scan``) and IaC key-material rows name their location ``<file>:<line>`` (Terraform / Kubernetes
  key specs, SQL Server keys), so an unrelated edit above them would otherwise look like remove + add; both line
  markers are dropped. Engine fact ids no longer hash a line (Dockerfile base images, cryptsetup commands).
* Code-scan source: the team roll-up's ``source_key_for`` (``repo:<host><path>@<branch>``, ``zip:<title>``,
  ``file:<title>``), the same key every CBOM deliverable uses.

``stable_key`` turns (scope, source ref, identity) into a 40-hex-character key that is stored.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource

CERT_CDX = "certificate"
_LINE_SUFFIX = re.compile(r"-l\d+$")
_LOCATION_LINE = re.compile(r":\d+$")


def _norm(value: Any) -> str:
    return " ".join(str(value or "").split()).lower()


def stable_key(scope: str, source_ref: str, identity: str) -> str:
    return hashlib.sha256(f"{scope}|{source_ref}|{identity}".encode("utf-8", "replace")).hexdigest()[:40]


def job_source_ref(job: CbomCollectionJob, source: CbomCollectionSource | None) -> str:
    """The source uid a collect job belongs to (snapshot first; sources deleted before snapshots existed fall back
    to their id, which is never reused on PostgreSQL)."""
    snap = (job.params or {}).get("source_uid")
    if isinstance(snap, str) and snap:
        return snap
    if source is not None and source.source_uid:
        return source.source_uid
    if job.source_id is not None:
        return f"source-{job.source_id}"
    return f"deleted:{(job.params or {}).get('source_name') or job.id}"


def job_source_name(job: CbomCollectionJob, source: CbomCollectionSource | None) -> str:
    return (source.name if source is not None else None) or str((job.params or {}).get("source_name") or "Deleted source")


def is_certificate(row: CbomCollectedAsset) -> bool:
    return row.cdx_type == CERT_CDX or row.asset_type in ("certificate", "k8s_certificate")


def mapping_dn(value: Any) -> str | None:
    """The RFC 4514 DN an attribute map denotes (a dict, or the JSON text of one, as AWS returns ``ASN1Subject``;
    ``cert_estate.dn_from_mapping``, the AWS collector's own formatter), else None (a DN text, or anything else)."""
    mapping: Any = value if isinstance(value, Mapping) else None
    if mapping is None and isinstance(value, str) and value.lstrip().startswith("{"):
        try:
            mapping = json.loads(value)
        except ValueError:
            mapping = None
    if not isinstance(mapping, Mapping):
        return None
    from backend.utilities.cbom_sources.cert_estate import dn_from_mapping

    return dn_from_mapping(mapping) or None


def canonical_dn(value: Any) -> str:
    """A subject or issuer as compared: an attribute map becomes its RFC 4514 DN (``mapping_dn``); then lower case,
    whitespace collapsed. A DN text is unchanged by the first step, so its identity is as before."""
    return _norm(mapping_dn(value) or value)


def legacy_node_identity(row: CbomCollectedAsset) -> str:
    """The identity before staging QA2 Q1-09 (free-text subject and issuer, also for a cloud certificate): what the
    stored keys of earlier runs were made from. Only ``rekeyed_observations`` reads it."""
    facts = row.facts or {}
    if is_certificate(row) and (facts.get("subject") or facts.get("issuer")):
        return "|".join(("cert", _norm(row.target), _norm(row.location), _norm(facts.get("subject")),
                         _norm(facts.get("issuer"))))
    return "key|" + row.asset_key


def node_identity(row: CbomCollectedAsset) -> str:
    facts = row.facts or {}
    if is_certificate(row) and (facts.get("subject") or facts.get("issuer")):
        from backend.utilities.cbom_sources.asset_keys import cloud_resource_id

        if cloud_resource_id(row.location):  # the id names one certificate: the subject text never re-keys it
            return "|".join(("cert", _norm(row.target), _norm(row.location)))
        return "|".join(("cert", _norm(row.target), _norm(row.location), canonical_dn(facts.get("subject")),
                         canonical_dn(facts.get("issuer"))))
    return "key|" + row.asset_key


def rekeyed_observations(rows: Any, source_ref: str) -> dict[str, str]:
    """``{key before Q1-09: key now}`` (``stable_key("node", ...)``) for the rows of one source whose identity the
    rule changed; empty for everything else (every non-certificate row, every DN-text certificate off the cloud)."""
    out: dict[str, str] = {}
    for row in rows:
        if not is_certificate(row):
            continue
        old, new = legacy_node_identity(row), node_identity(row)
        if old != new:
            out[stable_key("node", source_ref, old)] = stable_key("node", source_ref, new)
    return out


def node_label(row: CbomCollectedAsset) -> str:
    name = row.name or row.algorithm or row.asset_type
    where = row.location if not row.target or row.location.startswith(row.target) else f"{row.target} {row.location}"
    return f"{name} · {where}"[:255]


def code_identity_parts(asset_type: str, location: str | None, title: str | None, bom_ref: str | None) -> str:
    ref = _LINE_SUFFIX.sub("", str(bom_ref or "").strip())
    where = _LOCATION_LINE.sub("", str(location or "").strip())
    return "|".join(_norm(v) for v in (asset_type, where, title or "(unnamed)", ref))


def code_identity(row: Mapping[str, Any]) -> str:
    """Line-independent identity of a code-scan row; the asset type and title are read exactly as the team roll-up
    reads them, so a roll-up asset (``asset_agg_identity``) and its row get the same identity. Pass the row as
    stored (scan results / Mongo ``finding_data``), never ``display_row``'s copy: that one retypes legacy library and
    configuration rows, and drift, the roll-up and the "fixed" marking must all key the same row the same way."""
    from backend.utilities.dashboard.cbom_team_rollup import _asset_type_of

    title = str(row.get("title") or "").strip() or str(row.get("algorithm_name") or "").strip() or None
    return code_identity_parts(_asset_type_of(row), str(row.get("location") or "").strip(), title, row.get("bom_ref"))


def asset_agg_identity(asset: Any) -> str:
    """Identity of a team roll-up ``AssetAgg`` (the PQC roadmap rows)."""
    return code_identity_parts(asset.asset_type, asset.location, asset.title, asset.bom_ref)


def code_label(row: Mapping[str, Any]) -> str:
    title = row.get("title") or row.get("algorithm_name") or "(unnamed)"
    return f"{title} · {row.get('location') or ''}"[:255]


def code_source_ref(scan_metadata: Mapping[str, Any] | None, title: str, scan_id: int) -> tuple[str, str]:
    """(key, label) of a code scan's source, exactly as the team roll-up and the deliverables name it."""
    from backend.utilities.dashboard.cbom_team_rollup import source_key_for

    key, label, _kind = source_key_for(scan_metadata, title, scan_id)
    return key, label


__all__ = ["canonical_dn", "mapping_dn", "code_identity", "code_label", "code_source_ref", "is_certificate", "job_source_name",
           "job_source_ref", "legacy_node_identity", "node_identity", "node_label", "rekeyed_observations", "stable_key"]
