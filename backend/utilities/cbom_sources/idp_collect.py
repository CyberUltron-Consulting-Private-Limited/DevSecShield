"""Identity-provider signing keys from public OIDC discovery/JWKS documents and SAML metadata.

Only public documents are read (no client secret is used or needed): the keys an IdP signs tokens
and assertions with are published for every relying party.  Fetches go through ``safe_fetch``.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from backend.utilities.cbom_sources.safe_fetch import FetchError, fetch

_NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": "http://www.w3.org/2000/09/xmldsig#"}
_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.I)
_DTD_REFUSED = "SAML metadata contains a DOCTYPE or ENTITY declaration and was not parsed"


def _refuse_dtd(body: bytes) -> None:
    """Refuse any DTD however the document is encoded: expat decodes UTF-16/UTF-8 itself, so a DOCTYPE hidden
    from a byte search (UTF-16) is still seen here, before ElementTree ever parses the document."""
    import xml.parsers.expat as expat

    def deny(*_args: Any) -> None:
        raise FetchError(_DTD_REFUSED)

    parser = expat.ParserCreate()
    parser.StartDoctypeDeclHandler = deny
    parser.EntityDeclHandler = deny
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(body, True)
    except expat.ExpatError as exc:
        raise FetchError("SAML metadata is not valid XML") from exc


def discovery_urls(cfg: dict[str, Any]) -> list[tuple[str, str]]:
    """(kind, url) pairs to read for this IdP configuration; kind is "oidc" or "saml"."""
    provider = cfg.get("provider")
    base = (cfg.get("base_url") or "").rstrip("/")
    if provider in ("oidc_discovery",):
        return [("oidc", cfg["metadata_url"])]
    if provider == "saml_metadata":
        return [("saml", cfg["metadata_url"])]
    if provider == "entra_id":
        tenant = cfg.get("tenant_id")
        return [("oidc", f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"),
                ("saml", f"https://login.microsoftonline.com/{tenant}/federationmetadata/2007-06/federationmetadata.xml")]
    if provider == "okta":
        return [("oidc", f"{base}/.well-known/openid-configuration")]
    if provider == "keycloak":
        realm = cfg.get("realm")
        return [("oidc", f"{base}/realms/{realm}/.well-known/openid-configuration"),
                ("saml", f"{base}/realms/{realm}/protocol/saml/descriptor")]
    if provider == "adfs":
        return [("oidc", f"{base}/adfs/.well-known/openid-configuration"),
                ("saml", f"{base}/FederationMetadata/2007-06/FederationMetadata.xml")]
    return []


def _b64url_int_bits(value: str) -> int | None:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return None
    number = int.from_bytes(raw, "big")
    return number.bit_length() if number else None


_CRV_BITS = {"P-256": 256, "P-384": 384, "P-521": 521, "Ed25519": 256, "Ed448": 448, "X25519": 256, "secp256k1": 256}


def cert_facts(der: bytes, source: str) -> tuple[str | None, int | None, dict[str, Any]]:
    """(key algorithm, key bits, facts) of a DER certificate, using the cryptography package."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        alg, bits, curve = "RSA", key.key_size, None
    elif isinstance(key, ec.EllipticCurvePublicKey):
        alg, bits, curve = "ECDSA", key.curve.key_size, key.curve.name
    elif isinstance(key, ed25519.Ed25519PublicKey):
        alg, bits, curve = "Ed25519", 256, None
    elif isinstance(key, ed448.Ed448PublicKey):
        alg, bits, curve = "Ed448", 456, None
    elif isinstance(key, dsa.DSAPublicKey):
        alg, bits, curve = "DSA", key.key_size, None
    else:
        alg, bits, curve = type(key).__name__, None, None
    try:
        sig = cert.signature_algorithm_oid._name  # e.g. sha256WithRSAEncryption
    except Exception:
        sig = None
    try:
        san = [str(v) for v in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
    except Exception:
        san = []
    try:
        is_ca = bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except Exception:
        is_ca = False
    not_before = cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    facts = {
        "subject": cert.subject.rfc4514_string()[:255], "issuer": cert.issuer.rfc4514_string()[:255],
        "serial": format(cert.serial_number, "x")[:64], "not_before": not_before, "not_after": not_after,
        "sig_alg": sig, "key_alg": alg, "key_size": bits, "curve": curve, "san": san[:50], "is_ca": is_ca,
        "self_signed": cert.subject == cert.issuer, "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
        "source": source,
    }
    return alg, bits, facts


def _oidc(url: str, label: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assets: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    doc = fetch(url)
    if doc.status != 200:
        raise FetchError(f"discovery document returned HTTP {doc.status}")
    try:
        meta = json.loads(doc.body)
    except ValueError as exc:
        raise FetchError("discovery document is not JSON") from exc
    if not isinstance(meta, dict) or not isinstance(meta.get("jwks_uri"), str):
        raise FetchError("discovery document has no jwks_uri")
    issuer = str(meta.get("issuer") or url)[:255]
    assets.append({"type": "identity_provider", "target": label, "location": url, "name": issuer, "protocol": "OIDC",
                   "facts": {"kind": "oidc", "issuer": issuer,
                             "id_token_signing_alg_values_supported": meta.get("id_token_signing_alg_values_supported"),
                             "token_endpoint_auth_methods_supported": meta.get("token_endpoint_auth_methods_supported"),
                             "jwks_uri": meta["jwks_uri"][:500]}})
    jwks = fetch(meta["jwks_uri"])
    try:
        keys = json.loads(jwks.body).get("keys") or []
    except (ValueError, AttributeError) as exc:
        raise FetchError("JWKS document is not valid JSON") from exc
    for key in keys[:200]:
        if not isinstance(key, dict):
            continue
        kty = str(key.get("kty") or "")
        bits = _b64url_int_bits(key["n"]) if kty == "RSA" and isinstance(key.get("n"), str) else _CRV_BITS.get(str(key.get("crv")))
        algorithm = {"RSA": "RSA", "EC": "ECDSA", "OKP": str(key.get("crv") or "EdDSA")}.get(kty, kty or None)
        kid = str(key.get("kid") or "")[:128]
        assets.append({"type": "signing_key", "target": label, "location": f"{meta['jwks_uri'][:400]}#{kid}",
                       "name": kid or algorithm, "algorithm": algorithm, "key_size": bits,
                       "facts": {"kid": kid, "kty": kty, "alg": key.get("alg"), "use": key.get("use"), "crv": key.get("crv"),
                                 "signature_alg": key.get("alg"), "identity": kid, "issuer": issuer}})
        for index, x5c in enumerate((key.get("x5c") or [])[:3]):
            try:
                alg, size, facts = cert_facts(base64.b64decode(x5c), "idp")
            except Exception:
                gaps.append({"type": "coverage", "target": label, "location": f"{meta['jwks_uri'][:400]}#{kid}/x5c{index}",
                             "facts": {"check": "x5c certificate", "status": "error", "detail": "certificate could not be parsed"}})
                continue
            assets.append({"type": "certificate", "target": label, "location": f"{meta['jwks_uri'][:400]}#{kid}/x5c{index}",
                           "name": facts["subject"], "algorithm": alg, "key_size": size, "facts": facts})
    return assets, gaps


def saml_assets_from_xml(body: bytes, location: str, label: str) -> list[dict[str, Any]]:
    """identity_provider + certificate + signing_key assets from a SAML metadata document.

    Documents with a DOCTYPE or ENTITY declaration are refused (no XXE / entity expansion)."""
    if _DTD.search(body):
        raise FetchError(_DTD_REFUSED)
    _refuse_dtd(body)
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise FetchError("SAML metadata is not valid XML") from exc
    assets: list[dict[str, Any]] = []
    signature = root.find("ds:Signature", _NS)
    method = signature.find("ds:SignedInfo/ds:SignatureMethod", _NS) if signature is not None else None
    sig_alg = method.get("Algorithm") if method is not None else None
    sig_short = sig_alg.rsplit("#", 1)[-1] if sig_alg else None  # ...xmldsig-more#rsa-sha256 -> rsa-sha256
    entity = root.get("entityID") or location
    assets.append({"type": "identity_provider", "target": label, "location": location, "name": entity[:255], "protocol": "SAML",
                   "facts": {"kind": "saml", "entity_id": entity[:255], "metadata_signed": signature is not None,
                             "metadata_signature_alg": sig_short}})
    seen = set()
    for descriptor in root.iter(f"{{{_NS['md']}}}KeyDescriptor"):
        use = descriptor.get("use") or "signing"
        for node in descriptor.iter(f"{{{_NS['ds']}}}X509Certificate"):
            text = re.sub(r"\s+", "", node.text or "")
            if not text or (use, text) in seen:
                continue
            seen.add((use, text))
            try:
                alg, size, facts = cert_facts(base64.b64decode(text), "idp")
            except Exception:
                assets.append({"type": "coverage", "target": label, "location": f"{location}#{use}",
                               "facts": {"check": "SAML certificate", "status": "error", "detail": "certificate could not be parsed"}})
                continue
            facts["use"] = use
            where = f"{location}#{use}-{facts['fingerprint_sha256'][:12]}"
            assets.append({"type": "certificate", "target": label, "location": where, "name": facts["subject"],
                           "algorithm": alg, "key_size": size, "facts": facts})
            if use == "signing":
                assets.append({"type": "signing_key", "target": label, "location": where, "name": facts["subject"],
                               "algorithm": alg, "key_size": size,
                               "facts": {"use": use, "signature_alg": sig_short, "identity": facts["fingerprint_sha256"],
                                         "not_after": facts["not_after"]}})
    return assets


def _saml(url: str, label: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    doc = fetch(url, accept="application/samlmetadata+xml, application/xml, text/xml")
    if doc.status != 200:
        raise FetchError(f"SAML metadata returned HTTP {doc.status}")
    assets = saml_assets_from_xml(doc.body, url, label)
    return [a for a in assets if a["type"] != "coverage"], [a for a in assets if a["type"] == "coverage"]


def collect_idp(cfg: dict[str, Any], label: str) -> dict[str, Any]:
    """Assets plus per-document target rows for one IdP source.  Never raises for a bad document."""
    started = _dt.datetime.utcnow()
    assets: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    for kind, url in discovery_urls(cfg):
        t0 = _dt.datetime.utcnow()
        try:
            found, gaps = (_oidc if kind == "oidc" else _saml)(url, label)
            assets += found + gaps
            targets.append({"target": url, "status": "ok", "error": None, "assets": len(found),
                            "duration_ms": int((_dt.datetime.utcnow() - t0).total_seconds() * 1000)})
        except FetchError as exc:
            # A provider without one of the two documents (e.g. Okta has no tenant SAML metadata) is not a failure
            # of the whole source; it is listed, never silent.
            targets.append({"target": url, "status": "error", "error": str(exc)[:256], "assets": 0,
                            "duration_ms": int((_dt.datetime.utcnow() - t0).total_seconds() * 1000)})
            assets.append({"type": "coverage", "target": label, "location": url,
                           "facts": {"check": f"{kind.upper()} metadata", "status": "error", "detail": str(exc)[:200]}})
    ok = sum(1 for t in targets if t["status"] == "ok")
    return {"assets": assets, "targets": targets,
            "counts": {"total": len(targets), "ok": ok, "failed": len(targets) - ok, "skipped": 0},
            "duration_s": int((_dt.datetime.utcnow() - started).total_seconds())}
