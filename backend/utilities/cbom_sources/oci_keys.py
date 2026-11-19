"""OCI API signing keys: the key pair ZeroShield generates for an ``oci_tenancy`` source, and the public facts of a stored
key (fingerprint, public key PEM) the server writes into the source's config on every save.

The fingerprint is the one the OCI Console shows next to an API key: the MD5 digest of the DER SubjectPublicKeyInfo,
as colon-separated hex (``openssl rsa -pubout -outform DER | openssl md5 -c``).  Only the public half ever leaves the
server; the private key is stored encrypted like every other source secret and is never returned.
"""
from __future__ import annotations

import hashlib
from typing import Any

KEY_BITS = 2048  # OCI requires RSA 2048 or more; 2048 matches the Console's own "Generate API key pair"


def generate_private_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def load_private_key(pem: str) -> Any:
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(pem.encode(), password=None)


def public_facts(private_pem: str) -> tuple[str, str]:
    """(fingerprint, public key PEM) of a stored private key."""
    from cryptography.hazmat.primitives import serialization

    public = load_private_key(private_pem).public_key()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.md5(der, usedforsecurity=False).hexdigest()  # OCI's key fingerprint: MD5 by definition
    fingerprint = ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return fingerprint, pem


def prepare_secrets(cfg: dict[str, Any], current: dict[str, str], provided: dict[str, str], clear: list[str],
                    where_changed: bool) -> dict[str, str]:
    """The ``provided`` secrets for a save, with a generated key added when the source uses a generated key pair and
    none is kept: on create, when the caller cleared the key (replace it), or when the tenancy changed (stored
    credentials are cleared then).  An uploaded key is the caller's to send."""
    if cfg.get("key_origin") != "generated" or provided.get("api_signing_key"):
        return provided
    keeps = bool(current.get("api_signing_key")) and "api_signing_key" not in clear and not where_changed
    return provided if keeps else {**provided, "api_signing_key": generate_private_key_pem()}


def with_public_facts(cfg: Any, secrets: dict[str, str]) -> Any:
    """The validated ``OciConfig`` with ``fingerprint`` and ``public_key_pem`` taken from the stored key (never from the
    client), or both None without a key."""
    pem = secrets.get("api_signing_key")
    fingerprint, public = public_facts(pem) if pem else (None, None)
    return cfg.model_copy(update={"fingerprint": fingerprint, "public_key_pem": public})
