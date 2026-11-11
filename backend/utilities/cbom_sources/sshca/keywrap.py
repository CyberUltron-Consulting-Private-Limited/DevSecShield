"""CA private keys at rest (contract section 9: AWS KMS when one is configured, otherwise the deployment key).

``fernet``  the deployment's ``ENCRYPTION_KEY`` (``backend/utilities/db/encryption.py``).  The plaintext carries the
            team and the CA fingerprint, checked on unwrap, so a wrapped key copied onto another CA row or team is
            refused.
``aws_kms`` envelope encryption: ``GenerateDataKey`` (AES-256) under a KMS key from the deployment's allow-list
            ``CBOM_SSHCA_KMS_KEY_ARNS`` (comma-separated; the first one is the default for new CAs), with the
            EncryptionContext ``{zs:purpose, zs:team, zs:ca_fp}``; the CA key is sealed with AES-GCM using that context
            as associated data.  Only the KMS-encrypted data key, the nonce and the ciphertext are stored.  A team admin
            can only pick an ARN the deployment listed (no confused deputy over the backend's KMS permissions).

Unwrapped keys are cached in this worker for at most ``CACHE_SECONDS`` (contract: 10 minutes).  Nothing here logs
key material: errors carry the error class only.
"""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import threading
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.utilities.cbom_sources.sshca import certs as C

PURPOSE = "devsecshield-sshca"
CACHE_SECONDS = 600
KMS_ENV = "CBOM_SSHCA_KMS_KEY_ARNS"
_ARN = re.compile(r"^arn:aws(-cn|-us-gov)?:kms:([a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d):(\d{12}):(key|alias)/[A-Za-z0-9/_+=,.@:-]{1,256}$")


class WrapError(Exception):
    """``str(err)`` is safe to show."""


def allowed_kms_keys() -> list[str]:
    raw = os.environ.get(KMS_ENV, "")
    return [part.strip() for part in raw.split(",") if _ARN.match(part.strip())]


def default_wrap() -> tuple[str, str | None]:
    """("aws_kms", arn) when the deployment configured KMS keys, else ("fernet", None)."""
    keys = allowed_kms_keys()
    return ("aws_kms", keys[0]) if keys else ("fernet", None)


def kms_region(arn: str) -> str:
    match = _ARN.match(arn)
    if not match:
        raise WrapError("kms_key_ref is not a KMS key ARN")
    return match.group(2)


def _context(team_id: int, ca_fingerprint: str) -> dict[str, str]:
    return {"zs:purpose": PURPOSE, "zs:team": str(team_id), "zs:ca_fp": ca_fingerprint}


def _aad(context: dict[str, str]) -> bytes:
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()


# A factory so tests (moto) and the live proof can hand in their own client; production uses boto3's default chain.
_kms_factory: Callable[[str], Any] | None = None


def set_kms_client_factory(factory: Callable[[str], Any] | None) -> None:
    global _kms_factory
    _kms_factory = factory


def _kms(region: str):
    if _kms_factory is not None:
        return _kms_factory(region)
    import boto3

    return boto3.client("kms", region_name=region)


def wrap(private_pem: bytes, *, team_id: int, ca_fingerprint: str, key_wrap: str, kms_key_ref: str | None) -> str:
    if key_wrap == "fernet":
        from backend.utilities.db.encryption import encrypt_value

        doc = {"v": 1, "team": team_id, "fp": ca_fingerprint, "key": private_pem.decode()}
        return "fernet:" + encrypt_value(json.dumps(doc, separators=(",", ":")))
    if key_wrap == "aws_kms":
        if not kms_key_ref or kms_key_ref not in allowed_kms_keys():
            raise WrapError(f"kms_key_ref must be one of the KMS keys this deployment allows ({KMS_ENV})")
        context = _context(team_id, ca_fingerprint)
        try:
            out = _kms(kms_region(kms_key_ref)).generate_data_key(KeyId=kms_key_ref, KeySpec="AES_256",
                                                                   EncryptionContext=context)
        except Exception as exc:
            raise WrapError(f"AWS KMS refused to create a data key ({type(exc).__name__})") from None
        nonce = secrets.token_bytes(12)
        sealed = AESGCM(out["Plaintext"]).encrypt(nonce, private_pem, _aad(context))
        doc = {"v": 1, "key_ref": kms_key_ref, "edk": base64.b64encode(out["CiphertextBlob"]).decode(),
               "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(sealed).decode()}
        return "aws_kms:" + json.dumps(doc, separators=(",", ":"))
    raise WrapError("key_wrap must be fernet or aws_kms")


def unwrap(blob: str, *, team_id: int, ca_fingerprint: str) -> bytes:
    """The OpenSSH private key, or ``WrapError``.  Bound to (team, CA fingerprint)."""
    if not blob:
        raise WrapError("this CA has no private key")
    scheme, _, body = blob.partition(":")
    if scheme == "fernet":
        from backend.utilities.db.encryption import decrypt_value

        try:
            doc = json.loads(decrypt_value(body))
        except Exception:
            raise WrapError("the CA key could not be decrypted with this deployment's ENCRYPTION_KEY") from None
        if doc.get("team") != team_id or doc.get("fp") != ca_fingerprint:
            raise WrapError("the wrapped CA key belongs to another CA")
        return str(doc["key"]).encode()
    if scheme == "aws_kms":
        try:
            doc = json.loads(body)
            edk, nonce, sealed = (base64.b64decode(doc[k]) for k in ("edk", "nonce", "ct"))
            key_ref = str(doc["key_ref"])
        except Exception:
            raise WrapError("the wrapped CA key is damaged") from None
        context = _context(team_id, ca_fingerprint)
        try:
            out = _kms(kms_region(key_ref)).decrypt(CiphertextBlob=edk, KeyId=key_ref, EncryptionContext=context)
        except WrapError:
            raise
        except Exception as exc:
            raise WrapError(f"AWS KMS refused to unwrap the CA key ({type(exc).__name__})") from None
        try:
            return AESGCM(out["Plaintext"]).decrypt(nonce, sealed, _aad(context))
        except Exception:
            raise WrapError("the wrapped CA key does not belong to this CA") from None
    raise WrapError("unknown key wrap")


# ----------------------------------------------------------------------------- per-worker cache
_cache: dict[tuple[int, str], tuple[float, Any]] = {}
_cache_lock = threading.Lock()


def cached_private_key(ca_id: int, team_id: int, ca_fingerprint: str, blob: str):
    """The CA's private key object, unwrapped at most once per ``CACHE_SECONDS`` in this worker."""
    key = (ca_id, ca_fingerprint)
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    pem = unwrap(blob, team_id=team_id, ca_fingerprint=ca_fingerprint)
    try:
        private = C.private_from_openssh(pem)
    except Exception:
        raise WrapError("the unwrapped CA key could not be read") from None
    if C.fingerprint(C.public_line(private)) != ca_fingerprint:
        raise WrapError("the unwrapped CA key does not match the CA's public key")
    with _cache_lock:
        _cache[key] = (now + CACHE_SECONDS, private)
    return private


def forget(ca_id: int | None = None) -> None:
    """Drop cached keys (one CA when revoked, or all of them in tests)."""
    with _cache_lock:
        for key in [k for k in _cache if ca_id is None or k[0] == ca_id]:
            del _cache[key]
