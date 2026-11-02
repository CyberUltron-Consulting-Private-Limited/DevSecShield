"""Stable identities for CBOM assets: what makes "the same asset" across runs and scans.

Diffs, drift events, finding resolution and remediation assignments all compare by these keys, never by a row id.

* Source: ``CbomCollectionSource.source_uid`` (a random id that survives deletion). Every collect job snapshots it in
  ``params["source_uid"]``; jobs queued before that existed fall back to the source's current uid, then to its id.
* Node / cloud asset: the asset key the server computed (type | target | location | identity), except
  certificates, which are compared by (target, location, subject, issuer): a renewal changes the fingerprint (part of
  the asset key) but must show as "renewed", not as one certificate removed and another added. The location is kept
  because one host can serve two different certificates for the same subject (two ports, or a chain entry); it is
  stable across renewal (an endpoint and chain position, a file path, an ARN or a Kubernetes secret).
* Code-scan row: (asset type, file, title, bom-ref without a trailing line marker). Misuse refs end in ``-l<line>``
  (``crypto_misuse_scan``), so an unrelated edit above them would otherwise look like remove + add.
* Code-scan source: the team roll-up's ``source_key_for`` (``repo:<host><path>@<branch>``, ``zip:<title>``,
  ``file:<title>``), the same key every CBOM deliverable uses.

``stable_key`` turns (scope, source ref, identity) into a 40-hex-character key that is stored.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource

CERT_CDX = "certificate"
_LINE_SUFFIX = re.compile(r"-l\d+$")


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


def node_identity(row: CbomCollectedAsset) -> str:
    facts = row.facts or {}
    if is_certificate(row) and (facts.get("subject") or facts.get("issuer")):
        return "|".join(("cert", _norm(row.target), _norm(row.location), _norm(facts.get("subject")),
                         _norm(facts.get("issuer"))))
    return "key|" + row.asset_key


def node_label(row: CbomCollectedAsset) -> str:
    name = row.name or row.algorithm or row.asset_type
    where = row.location if not row.target or row.location.startswith(row.target) else f"{row.target} {row.location}"
    return f"{name} · {where}"[:255]


def code_identity_parts(asset_type: str, location: str | None, title: str | None, bom_ref: str | None) -> str:
    ref = _LINE_SUFFIX.sub("", str(bom_ref or "").strip())
    return "|".join(_norm(v) for v in (asset_type, location, title or "(unnamed)", ref))


def code_identity(row: Mapping[str, Any]) -> str:
    """Line-independent identity of a code-scan row; the asset type and title are read exactly as the team roll-up
    reads them, so a roll-up asset (``asset_agg_identity``) and its row get the same identity."""
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


__all__ = ["code_identity", "code_label", "code_source_ref", "is_certificate", "job_source_name", "job_source_ref",
           "node_identity", "node_label", "stable_key"]
