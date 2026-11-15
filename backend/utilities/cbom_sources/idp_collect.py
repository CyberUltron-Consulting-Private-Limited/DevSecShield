"""Identity-provider signing keys from public OIDC discovery/JWKS documents and SAML metadata.

Only public documents are read (no client secret is used or needed): the keys an IdP signs tokens
and assertions with are published for every relying party.  Fetches go through ``safe_fetch``; an IdP on a private
network is reachable only when the operator lists it in ``CBOM_IDP_ALLOWED_PRIVATE`` (API and cloud worker).

One certificate is often published in several places of one IdP (Entra ID and ADFS put their token-signing
certificate in the JWKS ``x5c`` AND in the federation metadata, often once for signing and once for encryption).
``merge_publications`` keeps ONE certificate row per DER SHA-256 (and one signing key per certificate) and lists
every place it was published in ``facts.published_in``; the first place (the JWKS, read first) names the row.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from backend.utilities.cbom_sources import algid
from backend.utilities.cbom_sources.safe_fetch import FetchError, FetchTimeout, fetch, idp_private_allowlist

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
    key_oid = None
    try:
        key = cert.public_key()
    except Exception:  # a key type cryptography cannot load (post-quantum, composites): named by its OID via algid (CB-04)
        key = None
        try:
            key_oid = cert.public_key_algorithm_oid.dotted_string
        except Exception:
            key_oid = None
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
    elif key is not None:
        alg, bits, curve = type(key).__name__, None, None
    else:
        ident = algid.resolve(key_oid) if key_oid else None
        alg, bits, curve = (ident.name if ident is not None and ident.name else key_oid or "unknown"), (
            ident.key_size if ident is not None else None), None
    # the signature algorithm by its OID through algid (never cryptography's private _name, which an unknown
    # algorithm leaves unset); the dotted OID when algid does not know it
    try:
        sig_oid = cert.signature_algorithm_oid.dotted_string
        sig_ident = algid.resolve(sig_oid)
        sig = sig_ident.name if sig_ident is not None and sig_ident.name else sig_oid
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
    if key_oid:
        facts["key_alg_oid"] = key_oid
    return alg, bits, facts


_MAX_PUBLICATIONS = 20


def _parse_error(exc: Exception) -> str:
    """What the certificate parser said, short enough for a coverage row (never the certificate itself)."""
    text = " ".join(str(exc).split())[:120]
    return f"certificate could not be parsed: {type(exc).__name__}{': ' + text if text else ''}"


def _jwk_use(value: Any) -> str:
    return {"sig": "signing", "enc": "encryption"}.get(str(value or "sig"), str(value)[:32])


def _oidc(url: str, label: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assets: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    doc = fetch(url, private_allowlist=idp_private_allowlist())
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
    jwks = fetch(meta["jwks_uri"], private_allowlist=idp_private_allowlist())
    try:
        keys = json.loads(jwks.body).get("keys") or []
    except (ValueError, AttributeError) as exc:
        raise FetchError("JWKS document is not valid JSON") from exc
    for key in keys[:200]:
        if not isinstance(key, dict):
            continue
        kty = str(key.get("kty") or "")
        bits = _b64url_int_bits(key["n"]) if kty == "RSA" and isinstance(key.get("n"), str) else _CRV_BITS.get(str(key.get("crv")))
        algorithm = {"RSA": "RSA", "EC": "ECDSA", "OKP": str(key.get("crv") or "EdDSA")}.get(kty)
        if algorithm is None:  # AKP (RFC 9964: a post-quantum key named by alg) and any other registered key type
            ident = algid.jose(kty, key.get("alg"), key.get("crv"))
            algorithm = ident.name if ident is not None and ident.name else (kty or None)
            bits = ident.key_size if ident is not None else bits
        kid = str(key.get("kid") or "")[:128]
        key_where = f"{meta['jwks_uri'][:400]}#{kid}"
        signing = {"type": "signing_key", "target": label, "location": key_where,
                   "name": kid or algorithm, "algorithm": algorithm, "key_size": bits,
                   "facts": {"kid": kid, "kty": kty, "alg": key.get("alg"), "use": key.get("use"), "crv": key.get("crv"),
                             "signature_alg": key.get("alg"), "identity": kid, "issuer": issuer,
                             "published_in": [{"document": "jwks", "location": key_where, "use": _jwk_use(key.get("use"))}]}}
        assets.append(signing)
        for index, x5c in enumerate((key.get("x5c") or [])[:3]):
            where = f"{key_where}/x5c{index}"
            try:
                alg, size, facts = cert_facts(base64.b64decode(x5c), "idp")
            except Exception as exc:
                gaps.append({"type": "coverage", "target": label, "location": where,
                             "facts": {"check": "x5c certificate", "status": "error", "detail": _parse_error(exc)}})
                continue
            # x5c[0] is the key's own certificate; the rest is its chain
            facts["published_in"] = [{"document": "jwks", "location": where,
                                      "use": _jwk_use(key.get("use")) if index == 0 else "chain"}]
            if index == 0:
                signing["facts"].update(certificate_sha256=facts["fingerprint_sha256"], not_after=facts["not_after"])
            assets.append({"type": "certificate", "target": label, "location": where,
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
                alg, size, facts = cert_facts(base64.b64decode(text, validate=True), "idp")
            except Exception as exc:
                assets.append({"type": "coverage", "target": label, "location": f"{location}#{use}",
                               "facts": {"check": "SAML certificate", "status": "error", "detail": _parse_error(exc)}})
                continue
            facts["use"] = use
            where = f"{location}#{use}-{facts['fingerprint_sha256'][:12]}"
            facts["published_in"] = [{"document": "saml", "location": where, "use": use}]
            assets.append({"type": "certificate", "target": label, "location": where, "name": facts["subject"],
                           "algorithm": alg, "key_size": size, "facts": facts})
            if use == "signing":
                assets.append({"type": "signing_key", "target": label, "location": where, "name": facts["subject"],
                               "algorithm": alg, "key_size": size,
                               "facts": {"use": use, "signature_alg": sig_short, "identity": facts["fingerprint_sha256"],
                                         "certificate_sha256": facts["fingerprint_sha256"], "not_after": facts["not_after"],
                                         "published_in": [{"document": "saml", "location": where, "use": use}]}})
    return assets


def _saml(url: str, label: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    doc = fetch(url, accept="application/samlmetadata+xml, application/xml, text/xml",
                private_allowlist=idp_private_allowlist())
    if doc.status != 200:
        raise FetchError(f"SAML metadata returned HTTP {doc.status}")
    assets = saml_assets_from_xml(doc.body, url, label)
    return [a for a in assets if a["type"] != "coverage"], [a for a in assets if a["type"] == "coverage"]


def merge_publications(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per certificate (DER SHA-256, the strongest cross-source certificate key after the serial) and one
    signing key per certificate within ONE IdP collection; the later copies' publication points join the first row's
    ``facts.published_in``.  Rows without a certificate identity (coverage, a JWK without ``x5c``) pass unchanged."""
    kept: dict[tuple[str, str], dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    for asset in assets:
        facts = asset.get("facts") or {}
        ident = facts.get("fingerprint_sha256") if asset["type"] == "certificate" else \
            facts.get("certificate_sha256") if asset["type"] == "signing_key" else None
        if not ident:
            out.append(asset)
            continue
        first = kept.get((asset["type"], ident))
        if first is None:
            kept[(asset["type"], ident)] = asset
            out.append(asset)
            continue
        places = first["facts"].setdefault("published_in", [])
        for place in facts.get("published_in") or []:
            if place not in places and len(places) < _MAX_PUBLICATIONS:
                places.append(place)
        for name in ("not_after", "signature_alg"):  # a JWK without "alg" takes the metadata's signature method
            if first["facts"].get(name) is None and facts.get(name) is not None:
                first["facts"][name] = facts[name]
    return out


def idp_test_verdict(out: dict[str, Any]) -> tuple[str, str]:
    """(test status, summary) of one ``collect_idp`` result.  A document read whose certificates could not be parsed
    is never "passed": partial when signing keys were still found, failed when none was (C10b)."""
    keys = sum(1 for a in out["assets"] if a["type"] == "signing_key")
    counts = out["counts"]
    ok, partial, total = int(counts.get("ok") or 0), int(counts.get("partial") or 0), int(counts.get("total") or 0)
    if not (ok or partial):
        return "failed", ("Could not read the metadata: " + "; ".join(t["error"] or "" for t in out["targets"]))[:400]
    summary = f"Read {ok + partial} of {total} metadata documents; {keys} signing key(s) found"
    unreadable = [t["error"] for t in out["targets"] if t["status"] == "partial" and t.get("error")]
    if unreadable:
        summary += "; " + "; ".join(unreadable)
    if ok == total:
        return "passed", summary
    return ("failed" if partial and not keys else "partial"), summary[:400]


def _count_after_merge(targets: list[dict[str, Any]], origin: dict[int, dict[str, Any]],
                       merged: list[dict[str, Any]]) -> None:
    """Each document's ``assets`` = the rows it adds to what is stored (after ``merge_publications``), so the documents'
    counts add up to the job's rows; the copies of rows an earlier document already published are its
    ``already_found`` (staging QA B6-4: the ADFS test said 6 + 6 for 3 keys and 3 certificates)."""
    kept = {id(a) for a in merged}
    for target in targets:
        target["assets"] = 0
    for key, target in origin.items():
        if key in kept:
            target["assets"] += 1
        else:
            target["already_found"] += 1


def collect_idp(cfg: dict[str, Any], label: str) -> dict[str, Any]:
    """Assets plus per-document target rows for one IdP source.  Never raises for a bad document.  A document read
    with certificates that could not be parsed is a ``partial`` target naming the parser's error."""
    started = _dt.datetime.utcnow()
    assets: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    origin: dict[int, dict[str, Any]] = {}  # id(asset) -> the target row of the document that published it
    for kind, url in discovery_urls(cfg):
        t0 = _dt.datetime.utcnow()
        try:
            found, gaps = (_oidc if kind == "oidc" else _saml)(url, label)
            assets += found + gaps
            errors = [g["facts"]["detail"] for g in gaps if (g.get("facts") or {}).get("status") == "error"]
            targets.append({"target": url, "status": "partial" if errors else "ok",
                            "error": (f"{len(errors)} certificate(s) {errors[0].removeprefix('certificate ')}"[:256]
                                      if errors else None),
                            "assets": len(found), "already_found": 0,
                            "duration_ms": int((_dt.datetime.utcnow() - t0).total_seconds() * 1000)})
            origin.update((id(a), targets[-1]) for a in found)
        except FetchError as exc:
            # A provider without one of the two documents (e.g. Okta has no tenant SAML metadata) is not a failure
            # of the whole source; it is listed, never silent.
            status = "timeout" if isinstance(exc, FetchTimeout) else "error"  # a timeout is never "not JSON" (C10a)
            targets.append({"target": url, "status": status, "error": str(exc)[:256], "assets": 0, "already_found": 0,
                            "duration_ms": int((_dt.datetime.utcnow() - t0).total_seconds() * 1000)})
            assets.append({"type": "coverage", "target": label, "location": url,
                           "facts": {"check": f"{kind.upper()} metadata", "status": status, "detail": str(exc)[:200]}})
    merged = merge_publications(assets)
    _count_after_merge(targets, origin, merged)
    ok = sum(1 for t in targets if t["status"] == "ok")
    partial = sum(1 for t in targets if t["status"] == "partial")
    return {"assets": merged, "targets": targets,
            "counts": {"total": len(targets), "ok": ok, "partial": partial, "failed": len(targets) - ok - partial,
                       "skipped": 0},
            "duration_s": int((_dt.datetime.utcnow() - started).total_seconds())}
