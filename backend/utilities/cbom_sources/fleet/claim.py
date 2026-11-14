"""Claim plugin of F1.2 for F1.1's ``secret_refs.PLUGINS`` (contract section 3): a managed source names a typed
credential (``credential_id``) instead of storing a secret, and its secrets are added to the claim payload here.

Read-only: nothing is minted or written.  A credential that is missing, deleted or of another team gives no secrets
(the job then fails its login, and the next reconcile makes the targets unmanaged with the reason).
"""
from __future__ import annotations

from typing import Any

from sqlmodel import Session

from backend.utilities.cbom_sources.crypto import decrypt_secrets
from backend.utilities.cbom_sources.fleet.models import CbomCredential


def _credential(session: Session, source: Any) -> CbomCredential | None:
    cid = getattr(source, "credential_id", None)
    if not cid:
        return None
    cred = session.get(CbomCredential, cid)
    if cred is None or cred.team_id != source.team_id or cred.deleted_at is not None:
        return None
    return cred


def claim_extras(session: Session, source: Any, node: Any, now: Any, acc: dict) -> dict | None:
    if not getattr(source, "credential_id", None):
        return None
    cred = _credential(session, source)
    secrets = decrypt_secrets(cred.secret_encrypted) if cred is not None else {}
    return {"config": dict(acc.get("config") or {}), "secrets": {**dict(acc.get("secrets") or {}), **secrets}}


def version_input(session: Session, source: Any) -> str | None:
    if not getattr(source, "credential_id", None):
        return None
    cred = _credential(session, source)
    return f"cred:{source.credential_id}:{cred.row_version if cred is not None else 'gone'}"


def known_secrets(session: Session, source: Any) -> list[str]:
    cred = _credential(session, source)
    return [v for v in decrypt_secrets(cred.secret_encrypted).values() if v] if cred is not None else []
