"""CBOM scanner (C2): **certificates** + **related crypto material**.

The second of the four CycloneDX 1.6 crypto-asset lanes (after C1's *algorithm*
lane). It inventories:

* **certificates** — ``.pem`` / ``.crt`` / ``.cer`` / ``.cert`` / ``.der`` /
  ``.ca-bundle`` files (and inline ``-----BEGIN CERTIFICATE-----`` blocks in
  source), parsed with the dependency-free :mod:`aibom.cbom.x509` reader to
  capture validity (notBefore / **notAfter** — the expiry the story requires),
  subject, issuer, self-signed status, signature algorithm and public-key size;
  non-PEM DER bodies on those extensions are also parsed;
* **related crypto material** — private / public keys (``.key`` files and
  inline PEM key blocks, including a hardcoded private key embedded in source),
  conservatively-detected hardcoded IV / salt / secret-key literals, and
  **opaque keystore containers** (``.jks`` / ``.p12`` / ``.pfx``) inventoried as
  ``credential`` material without password decryption (industry parity with
  cbomkit-theia — never invent passwords).

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

from aibom.cbom.files import FileWalk, file_walk
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import LANGUAGE_EXTENSIONS
from aibom.cbom.x509 import Certificate, parse_certificate
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

# Certificate / key container file extensions.
# ``.ca-bundle`` matches cbomkit-theia certificate-plugin enumeration (v1.1.2).
_CERT_EXTS = frozenset(
    {
        ".pem",
        ".crt",
        ".cer",
        ".cert",
        ".der",
        ".ca-bundle",
        ".key",
        ".pub",
        ".p7b",
        ".p7c",
        # ASCII-armored OpenPGP keys (``-----BEGIN PGP PUBLIC KEY BLOCK-----``).
        # Only armored blocks are read (no binary keyring parse); an ``.asc`` that
        # holds a PGP SIGNATURE / MESSAGE is not key material and emits nothing.
        ".gpg",
        ".asc",
    }
)
# When a container has no PEM armor, try DER parse on these (not .key/.pub —
# those are material-only and may contain non-cert DER).
_BINARY_CERT_EXTS = frozenset(
    {".der", ".cer", ".crt", ".cert", ".pem", ".ca-bundle"}
)

# Encrypted / opaque keystore containers. Inventoried as related-crypto-material
# (CycloneDX ``credential``) — NEVER password-parsed. Magic checks reduce FPs
# on randomly renamed binaries.
_KEYSTORE_EXTS = frozenset({".jks", ".p12", ".pfx"})
_JKS_MAGIC = bytes.fromhex("FEEDFEED")
_PKCS12_ASN1_SEQ = 0x30

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


def _iter_files(walk: FileWalk, exts: frozenset[str] | None) -> list[Path]:
    return walk.files(lambda p: exts is None or p.suffix.lower() in exts)


def _sources(walk: FileWalk, exts: frozenset[str]):
    """(rel, bytes, suffix, extra properties) of the key/certificate files on disk, then of those inside archives
    (``outer.zip!inner.pem``) and in git history (:meth:`FileWalk.virtual_files`)."""
    for path in _iter_files(walk, exts):
        raw = walk.read_bytes(path)
        if raw is not None:
            yield walk.rel(path), raw, path.suffix.lower(), None
    for vf in walk.virtual_files():
        if vf.suffix in exts:
            yield vf.rel, vf.data, vf.suffix, vf.props


def _annotate_virtual(ctx: ScanContext, before: int, extra: dict[str, str] | None) -> None:
    """Components found in an archive member / a history blob: where they came from, and line 1 (the occurrence
    pass cannot open a file that is not on disk under that path)."""
    if extra is None:
        return
    for comp in ctx.components[before:]:
        props = dict(comp.properties or {})
        props.update(extra)
        props.setdefault("crypto:line", "1")
        comp.properties = props


_HEX_RE = re.compile(rb"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})$")
_B64_RE = re.compile(rb"^[A-Za-z0-9+/_-]{22,44}={0,2}$")


def _raw_symmetric_key_bits(raw: bytes) -> int | None:
    """The size of a bare symmetric key held by a key file: 128/192/256 bits as hex, base64 or raw bytes."""
    body = raw.strip()
    if _HEX_RE.match(body) and len(set(body.lower())) >= 8:
        return len(body) * 4
    if _B64_RE.match(body):
        try:
            n = len(base64.b64decode(body + b"=" * (-len(body) % 4), altchars=b"-_" if b"-" in body or b"_" in body
                                     else None, validate=True))
        except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            n = 0
        if n in (16, 24, 32):
            return n * 8
    binary = sum(1 for b in raw if b < 0x20 or b > 0x7E) >= 2
    if len(raw) in (16, 24, 32) and binary and len(set(raw)) >= len(raw) // 2:
        return len(raw) * 8  # raw key bytes (no text encoding), mostly distinct
    return None


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
        # (bom_ref, subject_cn, issuer_cn, self_signed) of every discovered cert,
        # so the chain lane can link a leaf to a co-located issuer certificate.
        chain: list[tuple[str, str | None, str | None, bool]] = []
        self._scan_cert_files(ctx, seen, chain)
        self._scan_keystores(ctx, seen)
        self._scan_embedded_material(ctx, seen, chain)
        self._emit_chain_edges(ctx, chain)

    # --- certificate / key container files -------------------------------- #

    def _scan_cert_files(
        self, ctx: ScanContext, seen: set[str], chain: list
    ) -> None:
        for rel, raw, ext, extra in _sources(file_walk(ctx), _CERT_EXTS):
            before = len(ctx.components)
            if b"-----BEGIN" in raw:
                text = raw.decode("utf-8", "ignore")
                for label, body in _PEM_BLOCK.findall(text):
                    self._emit_pem(ctx, seen, chain, label.strip().upper(), body, rel)
            elif ext in _BINARY_CERT_EXTS:
                # DER / raw X.509 without PEM armor (common for .crt/.cer/.der;
                # also rare DER-as-.pem). TOTAL — parse_certificate returns None
                # on garbage so a non-cert .pem body cannot crash the scan.
                cert = parse_certificate(raw)
                if cert is not None:
                    self._emit_certificate(ctx, seen, chain, cert, rel)
            elif ext in (".gpg", ".pgp") and raw[:1] and raw[0] & 0x80:
                # binary (unarmored) OpenPGP keyring / exported key: the key packets themselves
                for kind, info in _openpgp_binary_keys(raw):
                    extra_pgp = {"crypto:containerFormat": "openpgp"}
                    if info[1]:
                        extra_pgp["crypto:keySize"] = str(info[1])
                    self._emit_material(ctx, seen, kind, rel, info[0], extra=extra_pgp)
                    break  # one row per file and kind, like an armored block
            elif ext == ".key":
                bits = _raw_symmetric_key_bits(raw)
                if bits:  # a bare 128/192/256-bit key (hex, base64 or raw bytes) in a key file
                    self._emit_material(ctx, seen, "secret-key", rel, None, extra={"crypto:keySize": str(bits)})
            _annotate_virtual(ctx, before, extra)

    # --- opaque keystore containers (no password parse) ------------------- #

    def _scan_keystores(self, ctx: ScanContext, seen: set[str]) -> None:
        """Inventory ``.jks`` / ``.p12`` / ``.pfx`` as opaque credentials.

        Research decision (see fixture ``SOURCE.md`` + LEDGER): cbomkit-theia's
        certificates plugin does **not** decrypt PKCS#12/JKS; OpenSSL
        ``PKCS12_parse`` requires a password. We never invent passwords — emit
        related-crypto-material with ``materialKind=credential`` + container
        format props so the chart can show keystore presence without fake
        ``notValidAfter`` claims.
        """
        for rel, raw, ext, extra in _sources(file_walk(ctx), _KEYSTORE_EXTS):
            if not raw:
                continue
            before = len(ctx.components)
            self._emit_keystore(ctx, seen, rel, raw, ext)
            _annotate_virtual(ctx, before, extra)

    def _emit_keystore(self, ctx: ScanContext, seen: set[str], rel: str, raw: bytes, ext: str) -> None:
        if ext == ".jks":
            if not raw.startswith(_JKS_MAGIC):
                return
            fmt = "jks"
        else:
            # PKCS#12 / PFX are ASN.1 DER; require SEQUENCE tag + length.
            if raw[0] != _PKCS12_ASN1_SEQ:
                return
            fmt = "pkcs12"
        self._emit_material(
            ctx,
            seen,
            "credential",
            rel,
            None,
            extra={
                "crypto:containerFormat": fmt,
                "crypto:parseStatus": "opaque",
                "crypto:parseNote": (
                    "keystore inventoried without password; "
                    "contents not decrypted"
                ),
            },
        )

    def _emit_pem(
        self,
        ctx: ScanContext,
        seen: set[str],
        chain: list,
        label: str,
        body: str,
        rel: str,
    ) -> None:
        if "CERTIFICATE" in label and "REQUEST" not in label:
            cert = _decode_cert(body)
            if cert is not None:
                self._emit_certificate(ctx, seen, chain, cert, rel)
        elif _PRIVATE_KEY_RE.search(label):
            self._emit_key_block(ctx, seen, "private-key", rel, label, body)
        elif _PUBLIC_KEY_RE.search(label):
            self._emit_key_block(ctx, seen, "public-key", rel, label, body)

    def _emit_key_block(
        self, ctx: ScanContext, seen: set[str], kind: str, rel: str, label: str, body: str
    ) -> None:
        """A PEM / OpenPGP armored key block -> private-/public-key material."""
        if not label.startswith("PGP "):
            self._emit_material(ctx, seen, kind, rel, _label_alg(label))
            return
        extra = {"crypto:containerFormat": "openpgp"}
        info = _openpgp_key_info(body)
        if info is not None and info[1]:
            extra["crypto:keySize"] = str(info[1])
        self._emit_material(ctx, seen, kind, rel, info[0] if info else None, extra=extra)

    # --- embedded key material in source ---------------------------------- #

    def _scan_embedded_material(
        self, ctx: ScanContext, seen: set[str], chain: list
    ) -> None:
        walk = file_walk(ctx)
        for path in _iter_files(walk, None):
            if path.suffix.lower() in _CERT_EXTS:
                continue  # already handled as a cert/key file
            if path.suffix.lower() not in LANGUAGE_EXTENSIONS:
                continue
            rel = walk.rel(path)
            text = walk.read_text(path)
            if text is None:
                continue
            # Inline PEM blocks (hardcoded private key OR embedded certificate).
            for label, body in _PEM_BLOCK.findall(text):
                up = label.strip().upper()
                if "CERTIFICATE" in up and "REQUEST" not in up:
                    cert = _decode_cert(body)
                    if cert is not None:
                        self._emit_certificate(ctx, seen, chain, cert, rel)
                elif _PRIVATE_KEY_RE.search(up):
                    self._emit_key_block(ctx, seen, "private-key", rel, up, body)
                elif _PUBLIC_KEY_RE.search(up):
                    self._emit_key_block(ctx, seen, "public-key", rel, up, body)
            # Conservative hardcoded IV / salt / secret-key literals.
            for m in _MATERIAL_ASSIGN.finditer(text):
                kind = _VAR_TO_MATERIAL[m.group("var").lower()]
                self._emit_material(ctx, seen, kind, rel, None)

    # --- emit helpers ----------------------------------------------------- #

    def _emit_certificate(
        self, ctx: ScanContext, seen: set[str], chain: list, cert: Certificate, rel: str
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
        if cert.curve:
            props["crypto:curve"] = cert.curve
        if cert.is_ca is not None:
            props["crypto:isCertificateAuthority"] = str(cert.is_ca).lower()
        ctx.add_component(
            CryptoAssetComponent(bom_ref=ref, name=Path(rel).name, properties=props)
        )
        chain.append((ref, cert.subject_cn, cert.issuer_cn, cert.self_signed))

    # --- certificate chain linking ---------------------------------------- #

    def _emit_chain_edges(self, ctx: ScanContext, chain: list) -> None:
        """Link each non-self-signed leaf to a co-located issuer certificate.

        A CA-signed certificate names its issuer by DN; when the issuer's own
        certificate is present in the same scan (its subject CN equals this
        cert's issuer CN), we record a ``signed_by`` edge so the CycloneDX
        dependency graph reflects the trust chain. Self-signed certificates are
        their own issuer and are skipped (no self-loop).
        """
        by_subject: dict[str, str] = {
            subject: ref for ref, subject, _issuer, _ss in chain if subject
        }
        for ref, _subject, issuer, self_signed in chain:
            if self_signed or not issuer:
                continue
            issuer_ref = by_subject.get(issuer)
            if issuer_ref and issuer_ref != ref:
                ctx.add_edge(ref, "signed_by", issuer_ref)

    def _emit_material(
        self,
        ctx: ScanContext,
        seen: set[str],
        material_kind: str,
        rel: str,
        algorithm: str | None,
        extra: dict[str, str] | None = None,
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
        if extra:
            props.update(extra)
        name = f"{material_kind} ({Path(rel).name})"
        ctx.add_component(
            CryptoAssetComponent(bom_ref=ref, name=name, properties=props)
        )


def _label_alg(label: str) -> str | None:
    """Algorithm encoded in a key PEM label (``RSA PRIVATE KEY`` -> ``RSA``)."""
    m = _KEY_ALG_RE.search(label)
    return m.group(1).upper() if m else None


# RFC 9580 public-key algorithm ids -> the names the rest of the CBOM uses.
_PGP_ALGORITHMS = {
    1: "RSA", 2: "RSA", 3: "RSA", 16: "ElGamal", 17: "DSA", 18: "ECDH",
    19: "ECDSA", 22: "EdDSA", 25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448",
}
# Algorithms whose first key-material MPI is the modulus / prime (its bit count is
# the key size); EC keys are sized by their curve instead.
_PGP_MODULUS_ALGORITHMS = frozenset({"RSA", "DSA", "ElGamal"})


def _openpgp_key_info(armored: str) -> tuple[str, int | None] | None:
    """(algorithm, key size) of the first key packet of an ASCII-armored OpenPGP
    key block (RFC 9580 s4-5), or None. TOTAL: garbage returns None."""
    b64: list[str] = []
    for raw in armored.splitlines():
        s = raw.strip()
        if not s or ":" in s:
            continue  # blank separator / armor header ("Version: ...")
        if s.startswith("="):
            break  # CRC-24 checksum line ends the data
        b64.append(s)
    joined = "".join(b64)[:4096]  # the first key packet is all that is read
    try:
        data = base64.b64decode(joined[: len(joined) // 4 * 4], validate=False)
    except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None
    return _openpgp_packet_info(data)


def _openpgp_binary_keys(data: bytes) -> list[tuple[str, tuple[str, int | None]]]:
    """(material kind, (algorithm, key size)) of the primary key packets of a binary (unarmored) OpenPGP keyring /
    exported key: RFC 9580 packets walked by their headers, secret (tag 5) and public (tag 6) keys kept."""
    out: list[tuple[str, tuple[str, int | None]]] = []
    pos = 0
    for _ in range(4096):  # packets; a keyring holds keys, user ids, signatures, subkeys
        if pos >= len(data) or not data[pos] & 0x80:
            break
        head = data[pos]
        if head & 0x40:
            tag = head & 0x3F
            first = data[pos + 1] if pos + 1 < len(data) else 0
            if first < 192:
                hdr, length = 2, first
            elif first < 224 and pos + 2 < len(data):
                hdr, length = 3, ((first - 192) << 8) + data[pos + 2] + 192
            elif first == 255 and pos + 5 < len(data):
                hdr, length = 6, int.from_bytes(data[pos + 2: pos + 6], "big")
            else:
                break  # partial lengths are not used for key packets
        else:
            tag = (head >> 2) & 0x0F
            ltype = head & 0x03
            if ltype == 3:
                break
            size = {0: 1, 1: 2, 2: 4}[ltype]
            hdr, length = 1 + size, int.from_bytes(data[pos + 1: pos + 1 + size], "big")
        if tag in (5, 6):
            info = _openpgp_packet_info(data[pos: pos + hdr + length])
            if info is not None:
                out.append(("private-key" if tag == 5 else "public-key", info))
        pos += hdr + length
    return out


def _openpgp_packet_info(data: bytes) -> tuple[str, int | None] | None:
    """(algorithm, key size) of the key packet at the start of ``data``, or None."""
    if len(data) < 9 or not data[0] & 0x80:
        return None
    if data[0] & 0x40:  # new-format packet header
        tag = data[0] & 0x3F
        first = data[1]
        header = 2 if first < 192 else 3 if first < 224 else 6 if first == 255 else 0
    else:  # legacy header: length type in the low two bits
        tag = (data[0] >> 2) & 0x0F
        header = {0: 2, 1: 3, 2: 5}.get(data[0] & 0x03, 0)
    if tag not in (5, 6) or not header:  # 5 = secret key, 6 = public key
        return None
    body = data[header:]
    version = body[0] if body else 0
    if version in (2, 3):
        offset = 7  # version, creation time, validity days
    elif version in (4, 5, 6):
        offset = 5  # version, creation time
    else:
        return None
    if len(body) <= offset:
        return None
    algorithm = _PGP_ALGORITHMS.get(body[offset])
    if algorithm is None:
        return None
    mpi = offset + 1 + (4 if version in (5, 6) else 0)  # v5/v6 add a key-material length
    bits = None
    if algorithm in _PGP_MODULUS_ALGORITHMS and len(body) >= mpi + 2:
        bits = (body[mpi] << 8) | body[mpi + 1]
    return algorithm, bits or None


__all__ = ["CertificateMaterialScanner"]
