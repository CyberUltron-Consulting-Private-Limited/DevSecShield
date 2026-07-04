"""CBOM scanner (C2): **certificates** + **related crypto material**.

The second of the four CycloneDX 1.6 crypto-asset lanes (after C1's *algorithm*
lane). It inventories:

* **certificates** — ``.pem`` / ``.crt`` / ``.cer`` / ``.der`` files (and inline
  ``-----BEGIN CERTIFICATE-----`` blocks), parsed with the dependency-free
  :mod:`aibom.cbom.x509` reader to capture validity (notBefore / **notAfter** —
  the expiry the story requires), subject, issuer, self-signed status, signature
  algorithm and public-key size;
* **related crypto material** — private / public keys (``.key`` files and
  inline PEM key blocks, including a hardcoded private key embedded in source),
  plus conservatively-detected hardcoded IV / salt / secret-key literals.

All crypto detail lives in ``crypto:`` namespaced ``properties`` (assetType,
materialKind, notValidBefore/After, subjectName, selfSigned, signatureAlgorithm,
keySize). Lane discipline: this EMITS components only — flagging an expired cert
or a weak signature is the scorer's job (C5/C8); the CycloneDX crypto-asset
serialization is C4.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import LANGUAGE_EXTENSIONS
from aibom.cbom.x509 import Certificate, parse_certificate
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

_IGNORE_DIRS = frozenset(
    {
        ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
        "dist", "build", ".next", ".nuxt", "target", "vendor", ".tox",
        ".mypy_cache", ".pytest_cache",
    }
)
_MAX_BYTES = 2_000_000

# Certificate / key container file extensions.
_CERT_EXTS = frozenset({".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p7b", ".p7c"})
_BINARY_CERT_EXTS = frozenset({".der", ".cer"})

# A PEM armored block: ``-----BEGIN <label>----- <b64> -----END <label>-----``.
_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+?)-----\s*(.*?)\s*-----END \1-----", re.DOTALL
)

# PEM label -> related-crypto-material kind (CycloneDX relatedCryptoMaterialType).
_PRIVATE_KEY_RE = re.compile(r"PRIVATE KEY")
_PUBLIC_KEY_RE = re.compile(r"PUBLIC KEY")
# Algorithm encoded in a key PEM label (``RSA PRIVATE KEY`` / ``EC PRIVATE KEY``).
_KEY_ALG_RE = re.compile(r"\b(RSA|EC|DSA|DH|ED25519)\b")

# Conservative hardcoded key-material literals: a key-material variable bound to a
# non-trivial bytes/hex literal. Narrow on purpose — IV/salt detection must not
# fire on prose or function parameters (only assigned literal material counts).
_MATERIAL_ASSIGN = re.compile(
    r"\b(?P<var>iv|salt|nonce|secret_key|secretkey|aes_key|enc_key|hmac_key)\s*=\s*"
    r"""(?P<lit>b?["'][0-9A-Za-z+/=_\-]{8,}["']|bytes\.fromhex\(\s*["'][0-9a-fA-F]{16,}["']\s*\))""",
    re.IGNORECASE,
)
_VAR_TO_MATERIAL = {
    "iv": "initialization-vector",
    "nonce": "initialization-vector",
    "salt": "salt",
    "secret_key": "secret-key",
    "secretkey": "secret-key",
    "aes_key": "secret-key",
    "enc_key": "secret-key",
    "hmac_key": "secret-key",
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def _iter_files(root: Path, exts: frozenset[str] | None):
    for p in sorted(root.rglob("*")):
        if any(part in _IGNORE_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        if exts is not None and p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _decode_cert(b64body: str) -> Certificate | None:
    try:
        return parse_certificate(base64.b64decode("".join(b64body.split())))
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None


@cbom_register
class CertificateMaterialScanner(Scanner):
    name = "crypto_certificate"
    order = 20
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        seen: set[str] = set()
        self._scan_cert_files(ctx, seen)
        self._scan_embedded_material(ctx, seen)

    # --- certificate / key container files -------------------------------- #

    def _scan_cert_files(self, ctx: ScanContext, seen: set[str]) -> None:
        for path in _iter_files(ctx.root, _CERT_EXTS):
            rel = path.relative_to(ctx.root).as_posix()
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if b"-----BEGIN" in raw:
                text = raw.decode("utf-8", "ignore")
                for label, body in _PEM_BLOCK.findall(text):
                    self._emit_pem(ctx, seen, label.strip().upper(), body, rel)
            elif path.suffix.lower() in _BINARY_CERT_EXTS:
                cert = parse_certificate(raw)
                if cert is not None:
                    self._emit_certificate(ctx, seen, cert, rel)

    def _emit_pem(
        self, ctx: ScanContext, seen: set[str], label: str, body: str, rel: str
    ) -> None:
        if "CERTIFICATE" in label and "REQUEST" not in label:
            cert = _decode_cert(body)
            if cert is not None:
                self._emit_certificate(ctx, seen, cert, rel)
        elif _PRIVATE_KEY_RE.search(label):
            self._emit_material(ctx, seen, "private-key", rel, _label_alg(label))
        elif _PUBLIC_KEY_RE.search(label):
            self._emit_material(ctx, seen, "public-key", rel, _label_alg(label))

    # --- embedded key material in source ---------------------------------- #

    def _scan_embedded_material(self, ctx: ScanContext, seen: set[str]) -> None:
        for path in _iter_files(ctx.root, None):
            if path.suffix.lower() in _CERT_EXTS:
                continue  # already handled as a cert/key file
            if path.suffix.lower() not in LANGUAGE_EXTENSIONS:
                continue
            rel = path.relative_to(ctx.root).as_posix()
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            # Inline PEM key blocks (e.g. a hardcoded private key string literal).
            for label, _body in _PEM_BLOCK.findall(text):
                up = label.strip().upper()
                if _PRIVATE_KEY_RE.search(up):
                    self._emit_material(ctx, seen, "private-key", rel, _label_alg(up))
                elif _PUBLIC_KEY_RE.search(up):
                    self._emit_material(ctx, seen, "public-key", rel, _label_alg(up))
            # Conservative hardcoded IV / salt / secret-key literals.
            for m in _MATERIAL_ASSIGN.finditer(text):
                kind = _VAR_TO_MATERIAL[m.group("var").lower()]
                self._emit_material(ctx, seen, kind, rel, None)

    # --- emit helpers ----------------------------------------------------- #

    def _emit_certificate(
        self, ctx: ScanContext, seen: set[str], cert: Certificate, rel: str
    ) -> None:
        ref = f"crypto-cert-{_slug(rel)}-{_slug(cert.subject_cn or 'cert')}"
        if ref in seen:
            return
        seen.add(ref)
        props: dict[str, str] = {
            "crypto:assetType": "certificate",
            "crypto:selfSigned": str(cert.self_signed).lower(),
            "discovery:source": rel,
        }
        if cert.subject_cn:
            props["crypto:subjectName"] = cert.subject_cn
        if cert.issuer_cn:
            props["crypto:issuerName"] = cert.issuer_cn
        if cert.not_before:
            props["crypto:notValidBefore"] = cert.not_before
        if cert.not_after:
            props["crypto:notValidAfter"] = cert.not_after
        if cert.signature_algorithm:
            props["crypto:signatureAlgorithm"] = cert.signature_algorithm
        if cert.public_key_algorithm:
            props["crypto:publicKeyAlgorithm"] = cert.public_key_algorithm
        if cert.key_size:
            props["crypto:keySize"] = str(cert.key_size)
        ctx.add_component(
            CryptoAssetComponent(bom_ref=ref, name=Path(rel).name, properties=props)
        )

    def _emit_material(
        self,
        ctx: ScanContext,
        seen: set[str],
        material_kind: str,
        rel: str,
        algorithm: str | None,
    ) -> None:
        ref = f"crypto-material-{material_kind}-{_slug(rel)}"
        if ref in seen:
            return
        seen.add(ref)
        props: dict[str, str] = {
            "crypto:assetType": "related-crypto-material",
            "crypto:materialKind": material_kind,
            "discovery:source": rel,
        }
        if algorithm:
            props["crypto:algorithm"] = algorithm
        name = f"{material_kind} ({Path(rel).name})"
        ctx.add_component(
            CryptoAssetComponent(bom_ref=ref, name=name, properties=props)
        )


def _label_alg(label: str) -> str | None:
    """Algorithm encoded in a key PEM label (``RSA PRIVATE KEY`` -> ``RSA``)."""
    m = _KEY_ALG_RE.search(label)
    return m.group(1).upper() if m else None


__all__ = ["CertificateMaterialScanner"]
