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
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from zs_scan_node import algid
from zs_scan_node.scrub import printable

MAX_SAN = 50
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


def _common_name(value: x509.Name) -> str:
    try:
        attrs = value.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attrs[0].value) if attrs else ""
    except Exception:
        return ""


def _named_oid(dotted: str | None) -> str | None:
    """algid's name for an algorithm OID, or the dotted OID when algid does not know it."""
    if not dotted:
        return None
    found = algid.resolve(dotted)
    if found is not None and found.name:
        return found.name
    return dotted


def _public_key_oid(cert: x509.Certificate) -> str | None:
    """The SubjectPublicKeyInfo algorithm OID. cryptography names it on recent releases; older ones still
    expose the TBS certificate, which algid reads without loading the key."""
    try:
        dotted = cert.public_key_algorithm_oid.dotted_string  # type: ignore[attr-defined]
        if isinstance(dotted, str) and dotted:
            return dotted
    except Exception:
        pass
    try:
        found = algid.tbs_spki_alg(cert.tbs_certificate_bytes)
    except Exception:
        return None
    return found[0] if found else None


def cert_facts(cert: x509.Certificate, source: str) -> dict[str, Any]:
    facts: dict[str, Any] = {"source": source}
    facts["subject"] = _name(cert.subject)
    facts["issuer"] = _name(cert.issuer)
    facts["serial"] = format(cert.serial_number, "x")
    facts["not_before"] = _iso(getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before)
    facts["not_after"] = _iso(getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after)
    try:
        oid = cert.signature_algorithm_oid
        # cryptography sets ObjectIdentifier._name to "Unknown OID" for an OID it does not list. That
        # placeholder is truthy, so it used to hide ML-DSA-65 (2.16.840.1.101.3.4.3.18). A name it does
        # list stays as printed; a placeholder is resolved through algid, else kept as the dotted OID.
        label = getattr(oid, "_name", None)
        if isinstance(label, str) and label and not algid.is_sentinel(label):
            facts["sig_alg"] = label
        else:
            facts["sig_alg"] = _named_oid(oid.dotted_string) or "unknown"
    except Exception:
        facts["sig_alg"] = "unknown"
    try:
        facts.update(key_facts(cert.public_key()))
    except Exception:
        # ML-DSA and other keys cryptography cannot load: name them the way the IdP reader does (CB-04).
        dotted = _public_key_oid(cert)
        facts["key_alg"] = _named_oid(dotted) or "unknown"
        found = algid.resolve(dotted) if dotted else None
        if found is not None and found.key_size is not None:
            facts["key_size"] = found.key_size
        if dotted:
            facts["key_alg_oid"] = dotted
    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san = [printable(str(v), 253) for v in ext.get_values_for_type(x509.DNSName)]
        san += [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
    except Exception:
        pass
    # CB-17: the list stays capped at 50 names, with the real count beside it (never cut silently)
    facts["san"] = san[:MAX_SAN]
    facts["san_count"] = len(san)
    facts["san_truncated"] = len(san) > MAX_SAN
    cn = _common_name(cert.subject)
    facts["wildcard"] = any(n.startswith("*.") for n in san) or cn.startswith("*.")
    try:  # the issuer's certificate is published for download (an intermediate a server should send)
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        facts["aia_ca_issuers"] = any(d.access_method == AuthorityInformationAccessOID.CA_ISSUERS for d in aia)
    except Exception:
        facts["aia_ca_issuers"] = False
    try:
        spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
        facts["spki_sha256"] = hashlib.sha256(spki).hexdigest()
    except Exception:
        pass
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        facts["is_ca"] = bool(bc.ca)
    except Exception:
        facts["is_ca"] = False
    facts["self_signed"] = cert.issuer == cert.subject
    facts["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
    return facts


# ----------------------------------------------------------------------------- served chains (CB-17)
_ANCHORS: dict[str, set[str]] | None = None


def anchor_index(certs: list[x509.Certificate]) -> dict[str, set[str]]:
    """Self-signed certificates as {subject: {SPKI sha256}}: the roots a chain may end at."""
    out: dict[str, set[str]] = {}
    for cert in certs:
        try:
            if cert.issuer != cert.subject:
                continue
            spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
            out.setdefault(_name(cert.subject), set()).add(hashlib.sha256(spki).hexdigest())
        except Exception:
            continue
    return out


def facts_anchors(certs: list[dict[str, Any]]) -> dict[str, set[str]]:
    """The same index from certificate facts (``cert_facts`` output): the self-signed ones."""
    out: dict[str, set[str]] = {}
    for c in certs:
        if c.get("self_signed") and c.get("spki_sha256"):
            out.setdefault(str(c.get("subject")), set()).add(str(c["spki_sha256"]))
    return out


def merge_anchors(*indexes: dict[str, set[str]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for index in indexes:
        for subject, keys in index.items():
            out.setdefault(subject, set()).update(keys)
    return out


def node_anchors() -> dict[str, set[str]]:
    """The roots of the node's own trust store (the system CA bundle), read once.  Empty when there is none: then no
    issuer is "trusted" and a top-of-chain issuer is only ever "missing" (which the server judges with care)."""
    global _ANCHORS
    if _ANCHORS is None:
        import os
        import ssl

        paths = ssl.get_default_verify_paths()
        found: dict[str, set[str]] = {}
        for path in (paths.cafile, paths.openssl_cafile):
            if path and os.path.isfile(path):
                try:
                    with open(path, "rb") as fh:
                        found = anchor_index(load_certs(fh.read(4_000_000), 1000))
                except OSError:
                    found = {}
                if found:
                    break
        _ANCHORS = found
    return _ANCHORS


def chain_links(chain: list[dict[str, Any]], anchors: dict[str, set[str]] | None = None) -> list[dict[str, Any]]:
    """Annotate the certificate facts of one served chain (in the order served) in place, for the server's chain rules:

    * ``chain_top``: the last certificate the server sent;
    * ``chain_issuer``: how this certificate's issuer is reached: ``self`` (self-signed), ``sent`` (another served
      certificate has the issuer's name), ``trusted`` (a root of the node's trust store has it) or ``missing``;
    * ``chain_extra``: a CA certificate above the leaf whose subject and key are also a root (served, or in the node's
      trust store), i.e. a cross-sign clients that trust that root never need (the 2021 DST Root CA X3 case)."""
    anchors = node_anchors() if anchors is None else anchors
    served_roots = facts_anchors(chain)
    for i, c in enumerate(chain):
        c["chain_top"] = i == len(chain) - 1
        issuer = str(c.get("issuer"))
        if c.get("self_signed"):
            c["chain_issuer"] = "self"
        elif any(j != i and str(o.get("subject")) == issuer for j, o in enumerate(chain)):
            c["chain_issuer"] = "sent"
        elif issuer in anchors:
            c["chain_issuer"] = "trusted"
        else:
            c["chain_issuer"] = "missing"
        spki, subject = c.get("spki_sha256"), str(c.get("subject"))
        c["chain_extra"] = bool(i > 0 and c.get("is_ca") and not c.get("self_signed") and spki and (
            spki in served_roots.get(subject, set()) or spki in anchors.get(subject, set())))
    return chain


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
