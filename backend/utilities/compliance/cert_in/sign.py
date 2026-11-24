"""CERT-In BOM signing — HMAC-SHA256 over canonical JSON (stdlib only).

Kept for the ``bom_signature`` objects already issued (verified server-side).
Customer-verifiable signatures are ES256 with a published key:
``backend/utilities/cbom_sources/bom_signing.py`` (D11).

F4: signing lives inside the ``aibom`` package. Do **not** add ``cryptography``;
secret bytes are supplied by the caller (backend ``CERTIN_HMAC_SECRET``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "canonical_bom_bytes",
    "sign_bom",
    "verify_signature",
]

_ALG = "HMAC-SHA256"


def canonical_bom_bytes(bom: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON bytes (sorted keys, compact separators).

    A top-level JSF ``signature`` (the ES256 signature the BOM downloads now
    carry, ``backend/utilities/cbom_sources/bom_signing.py``) is not part of the
    signed content: it was added after this HMAC was made, so an HMAC issued for
    the stored BOM still verifies the signed download.
    """
    return json.dumps(
        {k: v for k, v in bom.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_bom(
    bom: dict[str, Any],
    *,
    secret: bytes,
    key_id: str = "certin-hmac-1",
) -> dict[str, Any]:
    """Return a detached signature object for ``bom``.

    Shape: ``{alg, key_id, digest, signature_b64, signed_at}``.
    """
    if not secret:
        raise ValueError("signing secret must be non-empty")
    payload = canonical_bom_bytes(bom)
    digest = hashlib.sha256(payload).hexdigest()
    mac = hmac.new(secret, payload, hashlib.sha256).digest()
    return {
        "alg": _ALG,
        "key_id": key_id,
        "digest": digest,
        "signature_b64": base64.b64encode(mac).decode("ascii"),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def verify_signature(
    bom: dict[str, Any],
    signature: dict[str, Any],
    *,
    secret: bytes,
) -> bool:
    """Return True iff ``signature`` authenticates ``bom`` under ``secret``."""
    if not secret or not isinstance(signature, dict):
        return False
    if signature.get("alg") != _ALG:
        return False
    try:
        expected = base64.b64decode(str(signature.get("signature_b64") or ""), validate=True)
    except Exception:
        return False
    payload = canonical_bom_bytes(bom)
    mac = hmac.new(secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return False
    # Optional digest check (defense-in-depth).
    digest = signature.get("digest")
    if digest is not None and digest != hashlib.sha256(payload).hexdigest():
        return False
    return True
