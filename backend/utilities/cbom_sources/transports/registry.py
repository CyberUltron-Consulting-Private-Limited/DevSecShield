"""Lookups other code relies on (contract sections 3 and 6), and the zs-collect release store.

* ``get_transport(session, team_id, transport_id) -> TransportRef | None``: the seam F1.2's policy engine imports; a
  transport of another team, a deleted one or an unknown id is None.
* ``usable_transport``: the row a job may run through (same team, not deleted, enabled, flag on), else why not.
* ``sources_using``: the fleet sources that point at a transport (a delete is refused while there are any).
* Releases: ``verify_manifest`` checks the Ed25519 signature of a release manifest against the release key
  (``zs-release-ed25519.pub``, the same file the scan node carries); ``import_release`` stores a verified one and can
  make it the active release; ``active_release`` is what every wrapper and claim uses.  A manifest that does not
  verify is never stored.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources.transports.flags import transports_enabled
from backend.utilities.cbom_sources.transports.models import CbomTransport, CbomZsCollectRelease

FLEET_KINDS = {"awx_hosts": "awx", "salt_hosts": "salt", "ssm_hosts": "ssm"}
PUBLIC_KEY_PATH = Path(__file__).with_name("zs-release-ed25519.pub")
MANIFEST_FORMAT = "zs-collect-manifest/1"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?$")
NAME_RE = re.compile(r"^zs-collect-(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?)-linux-(?P<arch>amd64|arm64)$")


@dataclass(frozen=True)
class TransportRef:
    id: int
    kind: str
    name: str
    enabled: bool


class ReleaseError(Exception):
    pass


def get_transport(session: Session, team_id: int, transport_id: int | None) -> TransportRef | None:
    row = _row(session, team_id, transport_id)
    return TransportRef(row.id, row.kind, row.name, bool(row.enabled)) if row is not None else None


def _row(session: Session, team_id: int, transport_id: Any) -> CbomTransport | None:
    if not isinstance(transport_id, int) or isinstance(transport_id, bool) or transport_id <= 0:
        return None
    row = session.get(CbomTransport, transport_id)
    if row is None or row.team_id != team_id or row.deleted_at is not None:
        return None
    return row


def usable_transport(session: Session, team_id: int, transport_id: Any,
                     kind: str | None = None) -> tuple[CbomTransport | None, str | None]:
    """(row, None) when a job may run through it, else (None, why not)."""
    if not transports_enabled():
        return None, "Transports are turned off in this deployment"
    row = _row(session, team_id, transport_id)
    if row is None:
        return None, "The transport of this source was deleted or does not exist"
    if kind is not None and row.kind != kind:
        return None, f"The transport of this source is a {row.kind} transport, not {kind}"
    if not row.enabled:
        return None, f"Transport {row.name} is disabled"
    return row, None


def sources_using(session: Session, team_id: int, transport_id: int) -> list[tuple[int, str]]:
    rows = session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id,
                                                            CbomCollectionSource.kind.in_(tuple(FLEET_KINDS)))).all()
    return [(s.id, s.name) for s in rows if (s.config or {}).get("transport_id") == transport_id]


# ----------------------------------------------------------------------------- releases
def public_key_pem() -> str:
    return PUBLIC_KEY_PATH.read_text()


def key_fingerprint(public_pem: str | None = None) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key((public_pem or public_key_pem()).encode())
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def verify_manifest(manifest_bytes: bytes, sig_b64: str, public_pem: str | None = None) -> dict:
    """The manifest when its signature is the release key's and its entries are well formed; else ReleaseError."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = serialization.load_pem_public_key((public_pem or public_key_pem()).encode())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ReleaseError("the release public key is not Ed25519")
    try:
        key.verify(base64.b64decode(str(sig_b64).strip(), validate=True), manifest_bytes)
    except (InvalidSignature, ValueError):
        raise ReleaseError("the manifest signature is not valid for the release key") from None
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError:
        raise ReleaseError("the manifest is not JSON") from None
    if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT \
            or not VERSION_RE.match(str(manifest.get("version"))):
        raise ReleaseError("not a zs-collect manifest")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ReleaseError("the manifest lists no binary")
    for entry in files:
        m = NAME_RE.match(str((entry or {}).get("name")))
        if not m or m.group("version") != manifest["version"] or entry.get("arch") != m.group("arch") \
                or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256"))):
            raise ReleaseError("malformed manifest entry")
    return manifest


def import_release(session: Session, manifest_bytes: bytes, sig_b64: str, *, activate: bool,
                   now: _dt.datetime) -> CbomZsCollectRelease:
    manifest = verify_manifest(manifest_bytes, sig_b64)
    sha = {f["arch"]: f["sha256"] for f in manifest["files"]}
    row = session.exec(select(CbomZsCollectRelease).where(CbomZsCollectRelease.version == manifest["version"])).first()
    if row is None:
        row = CbomZsCollectRelease(version=manifest["version"], manifest_raw="", manifest_sig="", key_fingerprint="",
                                   created_at=now)
        session.add(row)
    elif row.manifest_raw and row.manifest_raw.encode() != manifest_bytes:
        raise ReleaseError(f"release {manifest['version']} is already stored with a different manifest")
    row.manifest, row.manifest_raw, row.manifest_sig = manifest, manifest_bytes.decode(), str(sig_b64).strip()
    row.sha256_amd64, row.sha256_arm64 = sha.get("amd64"), sha.get("arm64")
    row.key_fingerprint, row.verified_at, row.last_updated = key_fingerprint(), now, now
    if activate:
        for other in session.exec(select(CbomZsCollectRelease).where(CbomZsCollectRelease.active == True)).all():  # noqa: E712
            other.active = False
        row.active = True
    session.flush()
    return row


def active_release(session: Session) -> CbomZsCollectRelease | None:
    """The active release, re-verified against the release key (a row edited in the database is not trusted)."""
    row = session.exec(select(CbomZsCollectRelease).where(CbomZsCollectRelease.active == True,  # noqa: E712
                                                          CbomZsCollectRelease.team_id.is_(None))).first()
    if row is None or not row.manifest_raw:
        return None
    try:
        manifest = verify_manifest(row.manifest_raw.encode(), row.manifest_sig)
    except ReleaseError:
        return None
    if {f["arch"]: f["sha256"] for f in manifest["files"]} != {k: v for k, v in (("amd64", row.sha256_amd64),
                                                                                ("arm64", row.sha256_arm64)) if v}:
        return None
    return row


def release_payload(row: CbomZsCollectRelease) -> dict[str, Any]:
    """What a claim carries: the version and the sha256 per architecture (``config.zs_collect``)."""
    return {"version": row.version,
            "sha256": {k: v for k, v in (("amd64", row.sha256_amd64), ("arm64", row.sha256_arm64)) if v}}
