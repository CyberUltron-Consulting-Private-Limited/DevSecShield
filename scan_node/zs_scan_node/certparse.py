"""Certificate and public-key facts with ``cryptography``.  Only public material is ever parsed here."""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import re
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.x509.oid import ExtensionOID

from zs_scan_node.scrub import printable

PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def _iso(moment: _dt.datetime | None) -> str | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return moment.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def key_facts(key: Any) -> dict[str, Any]:
    if isinstance(key, rsa.RSAPublicKey):
        return {"key_alg": "RSA", "key_size": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"key_alg": "EC", "key_size": key.curve.key_size, "curve": key.curve.name}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"key_alg": "Ed25519", "key_size": 256}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"key_alg": "Ed448", "key_size": 456}
    if isinstance(key, dsa.DSAPublicKey):
        return {"key_alg": "DSA", "key_size": key.key_size}
    if isinstance(key, x25519.X25519PublicKey):
        return {"key_alg": "X25519", "key_size": 256}
    if isinstance(key, x448.X448PublicKey):
        return {"key_alg": "X448", "key_size": 448}
    return {"key_alg": type(key).__name__.replace("PublicKey", "") or "unknown", "key_size": None}


def _name(value: x509.Name) -> str:
    try:
        return printable(value.rfc4514_string(), 1024)
    except Exception:  # malformed names must not break collection
        return "<unparseable name>"


def cert_facts(cert: x509.Certificate, source: str) -> dict[str, Any]:
    facts: dict[str, Any] = {"source": source}
    facts["subject"] = _name(cert.subject)
    facts["issuer"] = _name(cert.issuer)
    facts["serial"] = format(cert.serial_number, "x")
    facts["not_before"] = _iso(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)
    facts["not_after"] = _iso(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
    try:
        oid = cert.signature_algorithm_oid
        facts["sig_alg"] = getattr(oid, "_name", None) or oid.dotted_string
    except Exception:
        facts["sig_alg"] = "unknown"
    try:
        facts.update(key_facts(cert.public_key()))
    except Exception:
        try:  # e.g. ML-DSA / unsupported algorithms: keep the OID
            facts["key_alg"] = cert.public_key_algorithm_oid.dotted_string  # type: ignore[attr-defined]
        except Exception:
            facts["key_alg"] = "unknown"
    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san = [printable(str(v), 253) for v in ext.get_values_for_type(x509.DNSName)]
        san += [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
    except Exception:
        pass
    facts["san"] = san[:50]
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        facts["is_ca"] = bool(bc.ca)
    except Exception:
        facts["is_ca"] = False
    facts["self_signed"] = cert.issuer == cert.subject
    facts["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
    return facts


def load_certs(data: bytes, limit: int = 100) -> list[x509.Certificate]:
    """PEM bundle (any number), DER, or base64 DER.  Never raises; unparseable input gives []."""
    out: list[x509.Certificate] = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        for match in PEM_CERT_RE.finditer(data):
            try:
                out.append(x509.load_pem_x509_certificate(match.group(0)))
            except Exception:
                continue
            if len(out) >= limit:
                break
        return out
    try:
        return [x509.load_der_x509_certificate(data)]
    except Exception:
        pass
    try:
        return [x509.load_der_x509_certificate(base64.b64decode(data, validate=True))]
    except Exception:
        return []


def public_key_facts_from_pem(text: str) -> dict[str, Any] | None:
    try:
        key = serialization.load_pem_public_key(text.encode())
    except Exception:
        return None
    facts = key_facts(key)
    try:
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        facts["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    except Exception:
        pass
    return facts


def jwk_facts(jwk: dict) -> dict[str, Any]:
    """Key size and algorithm of a JWK without x5c (RSA ``n`` or EC/OKP ``crv``)."""
    kty = jwk.get("kty")
    out: dict[str, Any] = {"kty": kty, "alg": jwk.get("alg"), "use": jwk.get("use"), "kid": jwk.get("kid")}
    if kty == "RSA" and isinstance(jwk.get("n"), str):
        n = jwk["n"] + "=" * (-len(jwk["n"]) % 4)
        try:
            out["key_size"] = int.from_bytes(base64.urlsafe_b64decode(n), "big").bit_length()
        except Exception:
            out["key_size"] = None
        out["key_alg"] = "RSA"
    elif kty in ("EC", "OKP"):
        crv = jwk.get("crv")
        out["curve"] = crv
        out["key_alg"] = "EC" if kty == "EC" else str(crv)
        out["key_size"] = {"P-256": 256, "P-384": 384, "P-521": 521, "Ed25519": 256, "Ed448": 456}.get(crv)
    return out
