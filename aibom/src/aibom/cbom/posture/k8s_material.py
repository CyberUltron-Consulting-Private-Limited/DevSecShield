"""Key and certificate material inside Kubernetes Secrets and ConfigMaps.

A ``kind: Secret`` holds its values base64-encoded under ``data`` (``tls.key: LS0tLS1CRUdJTi…``) or as text under
``stringData``; a ConfigMap holds text under ``data``. A value that is a PEM private key committed to the repository
is a hard-coded key: it is decoded in memory only, its algorithm and size are read, and the inventory gets a
``private-key`` asset with ``crypto:hardcoded=true`` (the weakness lane raises HARDCODED_KEY) at the line of the
value. The key itself is never stored, logged or exported. A PEM certificate becomes a certificate asset with its
properties. A PEM block that cannot be parsed is reported as a ``key_material_unparsed`` diagnostic.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from aibom.cbom.posture.extract_compose import load_documents
from aibom.cbom.x509 import parse_certificate, parse_private_key
from aibom.model.component import CryptoAssetComponent

_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]{1,40})-----\s{0,4}([A-Za-z0-9+/=\s]{1,65536}?)\s{0,4}-----END \1-----")
_MAX_VALUE = 262_144  # a Secret value is at most 1 MiB in etcd; key material is far smaller


@dataclass(frozen=True, slots=True)
class MaterialNote:
    code: str
    path: str
    line: int


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def _values(doc: Mapping[str, object]) -> Iterator[tuple[str, str, int]]:
    """(key, text value, line) for every value of a Secret or ConfigMap."""
    kind = doc.get("kind")
    sections: list[tuple[str, bool]] = []
    if kind == "Secret":
        sections = [("data", True), ("stringData", False)]
    elif kind == "ConfigMap":
        sections = [("data", False)]
    for section, encoded in sections:
        body = doc.get(section)
        if not isinstance(body, Mapping):
            continue
        lines = getattr(body, "key_lines", {}) or {}
        default = getattr(body, "line", 1)
        for key, value in body.items():
            if not isinstance(key, str) or not isinstance(value, str) or len(value) > _MAX_VALUE:
                continue
            text = value
            if encoded:
                try:
                    text = base64.b64decode("".join(value.split()), validate=True).decode("utf-8", "ignore")
                except (binascii.Error, ValueError):
                    continue
            if "-----BEGIN" in text:
                yield key, text, int(lines.get(key, default) or default)


def secret_material(text: str, path: str) -> tuple[tuple[CryptoAssetComponent, ...], tuple[MaterialNote, ...]]:
    """Assets for the PEM private keys and certificates held in the Secrets / ConfigMaps of one manifest file."""
    assets: list[CryptoAssetComponent] = []
    notes: list[MaterialNote] = []
    seen: set[str] = set()
    for doc in load_documents(text):
        for item in doc if isinstance(doc, list) else [doc]:
            if not isinstance(item, Mapping):
                continue
            meta = item.get("metadata")
            name = meta.get("name") if isinstance(meta, Mapping) else None
            owner = name if isinstance(name, str) and name else str(item.get("kind"))
            for key, value, line in _values(item):
                for label, body in _PEM.findall(value):
                    asset = _asset(label.strip(), body, owner, key, path, line)
                    if asset is None:
                        notes.append(MaterialNote("key_material_unparsed", path, line))
                    elif asset.bom_ref not in seen:
                        seen.add(asset.bom_ref)
                        assets.append(asset)
    return tuple(assets), tuple(notes)


def _asset(label: str, body: str, owner: str, key: str, path: str, line: int) -> CryptoAssetComponent | None:
    try:
        der = base64.b64decode("".join(body.split()), validate=True)
    except (binascii.Error, ValueError):
        return None
    where = f"{path}:{line}"
    ref_tail = f"{_slug(path)}-{_slug(owner)}-{_slug(key)}"
    if label == "ENCRYPTED PRIVATE KEY":  # inventoried; usable only with its passphrase, so not a hard-coded key
        return CryptoAssetComponent(
            bom_ref=f"crypto-material-private-key-{ref_tail}",
            name=f"private-key ({owner}/{key})",
            properties={
                "crypto:assetType": "related-crypto-material",
                "crypto:materialKind": "private-key",
                "discovery:source": where,
            },
        )
    if "PRIVATE KEY" in label:
        info = parse_private_key(der, label)
        if info is None:
            return None
        props = {
            "crypto:assetType": "related-crypto-material",
            "crypto:materialKind": "private-key",
            "crypto:hardcoded": "true",
            "crypto:algorithm": info.algorithm,
            "discovery:source": where,
        }
        if info.key_size:
            props["crypto:keySize"] = str(info.key_size)
        if info.curve:
            props["crypto:curve"] = info.curve
        return CryptoAssetComponent(
            bom_ref=f"crypto-material-private-key-{ref_tail}",
            name=f"private-key ({owner}/{key})",
            properties=props,
        )
    if "CERTIFICATE" in label and "REQUEST" not in label:
        cert = parse_certificate(der)
        if cert is None:
            return None
        props = {
            "crypto:assetType": "certificate",
            "crypto:selfSigned": str(cert.self_signed).lower(),
            "discovery:source": where,
        }
        optional = {
            "crypto:subjectName": cert.subject_cn,
            "crypto:issuerName": cert.issuer_cn,
            "crypto:notValidBefore": cert.not_before,
            "crypto:notValidAfter": cert.not_after,
            "crypto:signatureAlgorithm": cert.signature_algorithm,
            "crypto:publicKeyAlgorithm": cert.public_key_algorithm,
            "crypto:keySize": str(cert.key_size) if cert.key_size else None,
            "crypto:curve": cert.curve,
            "crypto:isCertificateAuthority": None if cert.is_ca is None else str(cert.is_ca).lower(),
        }
        props.update({k: v for k, v in optional.items() if v})
        return CryptoAssetComponent(bom_ref=f"crypto-cert-{ref_tail}", name=f"{owner}/{key}", properties=props)
    return None


__all__ = ["MaterialNote", "secret_material"]
