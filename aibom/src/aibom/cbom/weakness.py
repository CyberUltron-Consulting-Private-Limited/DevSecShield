"""Weak-crypto detection (C5) — the predicate, reconciled from the worker.

Lane discipline: the C1/C2/C3 scanners INVENTORY crypto assets (each
``crypto_asset`` component carries ``crypto:strength`` / ``crypto:mode`` /
``crypto:keySize`` / protocol version); this module turns that inventory into a
**finding** — a ``(code, severity, message)`` triple — and the C5 scanner
(:mod:`aibom.cbom.scanners.weak_algorithm_scan`) raises it as a ``Flag``. The C8
scorer later WEIGHTS those flags. Nothing here scores or serializes.

The authoritative "what is weak" corpus is the worker ``cbom_agent``'s
``WEAK_ALGORITHMS`` table, ported into :mod:`aibom.cbom.rules`. A component is
weak-by-algorithm iff its canonical key is in that table — which faithfully
includes the *moderate*-strength-but-deprecated members (3DES, Blowfish) the
worker flagged with a High impact, so ``strength == "weak"`` alone is NOT the
test. Three orthogonal weaknesses are detected on top of the algorithm corpus:
an ECB cipher mode, a sub-2048-bit asymmetric key, and a weak protocol version
(TLS < 1.2 / SSL — the ``crypto:strength=="weak"`` signal C3 sets).

All weak-crypto findings are SARIF ``error`` (== High impact), matching the
acceptance criterion "weak crypto -> high".
"""

from __future__ import annotations

from datetime import date

from aibom.cbom.rules import ALGORITHM_NORMALIZE, WEAK_ALGORITHMS
from aibom.model.component import AIComponent

# Flag codes this lane emits (the set the C8 scorer weights and the charts read).
WEAK_ALGORITHM = "WEAK_ALGORITHM"
WEAK_CIPHER_MODE = "WEAK_CIPHER_MODE"
WEAK_KEY_SIZE = "WEAK_KEY_SIZE"
WEAK_PROTOCOL = "WEAK_PROTOCOL"
# An X.509 certificate past its notValidAfter date (C8: "expired cert -> high").
EXPIRED_CERTIFICATE = "EXPIRED_CERTIFICATE"
# C4 certificate-depth weaknesses (distinct from the algorithm-asset codes above
# so the scorer/charts can attribute them to the certificate lane):
#   * a certificate signed with a broken digest (MD2/MD4/MD5/SHA-1) — forgeable;
#   * a certificate whose public key is below the asymmetric floor;
#   * a self-signed *leaf* (BasicConstraints CA:FALSE) — a production trust smell.
WEAK_CERTIFICATE_SIGNATURE = "WEAK_CERTIFICATE_SIGNATURE"
WEAK_CERTIFICATE_KEY = "WEAK_CERTIFICATE_KEY"
SELF_SIGNED_LEAF = "SELF_SIGNED_LEAF"
# C6 related-crypto-material misuse codes (source-derived; see
# :mod:`aibom.cbom.misuse` for detection). Each is a present-day break:
#   * WEAK_RNG      — key/IV/nonce/salt from a non-crypto PRNG (CWE-338);
#   * STATIC_IV     — a constant/predictable IV or nonce reaching a cipher (CWE-329);
#   * REUSED_NONCE  — the same static IV/nonce securing >1 encryption (CWE-323);
#   * HARDCODED_KEY — a symmetric key embedded as a source literal (CWE-321).
WEAK_RNG = "WEAK_RNG"
STATIC_IV = "STATIC_IV"
REUSED_NONCE = "REUSED_NONCE"
HARDCODED_KEY = "HARDCODED_KEY"

WEAK_CRYPTO_CODES = frozenset(
    {
        WEAK_ALGORITHM, WEAK_CIPHER_MODE, WEAK_KEY_SIZE, WEAK_PROTOCOL,
        WEAK_RNG, STATIC_IV, REUSED_NONCE, HARDCODED_KEY,
    }
)

_SEV = "error"  # SARIF error == High impact (mirrors the secret scanner).
_SEV_MED = "warning"  # SARIF warning == Medium impact (a smell, not a break).

# Broken message digests inside a certificate signatureAlgorithm name. A cert
# signed with any of these is forgeable via collision (chosen-prefix), so the
# whole certificate is untrustworthy regardless of its key strength.
_BROKEN_SIG_DIGESTS = ("md2", "md4", "md5", "sha1")

# Reverse of ALGORITHM_NORMALIZE: a display name (upper) -> canonical key. Built
# from the same table the scanner names assets with, so it never drifts. e.g.
# "3DES" -> "3des", "RSA-1024" -> "rsa-1024", "MD5" -> "md5".
_DISPLAY_TO_KEY: dict[str, str] = {
    disp.upper(): key for key, disp in ALGORITHM_NORMALIZE.items()
}

# Cipher-mode suffixes the scanner appends to a display name (e.g. "AES-256-GCM",
# "3DES-CBC"); stripped to recover the base algorithm display name.
_MODE_SUFFIXES = ("-GCM", "-CBC", "-ECB", "-CTR", "-CFB", "-OFB", "-XTS", "-CCM")

# Minimum acceptable asymmetric key size (bits). NIST SP 800-57 / 800-131A
# disallow RSA/DSA/DH below 2048.
_MIN_ASYMMETRIC_BITS = 2048

# Per-protocol-family rationale for a WEAK_PROTOCOL finding, so the message names
# the right deprecated version + migration target instead of a TLS-only string.
_WEAK_PROTOCOL_RATIONALE: dict[str, str] = {
    "tls": "TLS below 1.2 / SSL is deprecated (RFC 8996); negotiate TLS 1.2+ "
    "(prefer 1.3).",
    "ssh": "SSH protocol 1.x is cryptographically broken (CVE-2001-0361); use "
    "SSH-2.0 only.",
    "ipsec": "IKEv1 is deprecated (RFC 9395); migrate the tunnel to IKEv2.",
    "ike": "IKEv1 is deprecated (RFC 9395); migrate the tunnel to IKEv2.",
}
_WEAK_PROTOCOL_RATIONALE_DEFAULT = (
    "a deprecated protocol version is in use; migrate to the current, "
    "non-deprecated version."
)


def _base_key(name: str) -> str | None:
    """Recover the canonical algorithm key from a crypto_asset display name.

    Strips a trailing cipher-mode suffix, then maps the remainder back through
    the normalization table. Returns ``None`` when the name is not a known
    algorithm (e.g. a parametrized variant the table does not enumerate).
    """
    upper = name.upper()
    for suffix in _MODE_SUFFIXES:
        if upper.endswith(suffix):
            upper = upper[: -len(suffix)]
            break
    return _DISPLAY_TO_KEY.get(upper)


def _key_size(props: dict[str, str]) -> int | None:
    raw = props.get("crypto:keySize")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def weak_finding(component: AIComponent) -> tuple[str, str, str] | None:
    """Return ``(code, severity, message)`` if ``component`` is weak crypto, else None.

    Pure: depends only on the component's ``crypto:`` properties and display
    name. One finding per component (the most salient weakness wins).
    """
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    asset_type = props.get("crypto:assetType")
    name = component.name

    if asset_type == "protocol":
        if props.get("crypto:strength") == "weak":
            version = props.get("crypto:protocolVersion")
            ver = f" {version}" if version else ""
            rationale = _WEAK_PROTOCOL_RATIONALE.get(
                props.get("crypto:protocolType", ""),
                _WEAK_PROTOCOL_RATIONALE_DEFAULT,
            )
            return (
                WEAK_PROTOCOL,
                _SEV,
                f"Weak transport protocol {name}{ver}: {rationale}",
            )
        return None

    if asset_type != "algorithm":
        # Certificates / related-crypto-material are not algorithm-weakness
        # findings; C5 leaves them to their own (later) checks.
        return None

    # 1) Deprecated/broken algorithm by canonical corpus (covers MD5, SHA-1, DES,
    #    RC2, RC4, RSA-512/1024 — strength "weak" — AND 3DES/Blowfish, which the
    #    worker rates "moderate" strength but still deprecates).
    key = _base_key(name)
    if key is not None and key in WEAK_ALGORITHMS:
        return (
            WEAK_ALGORITHM,
            _SEV,
            f"Broken or deprecated algorithm {name}: superseded by modern "
            f"primitives (e.g. SHA-256/SHA-3, AES-GCM, RSA-3072+/ECDSA); "
            f"NIST SP 800-131A.",
        )

    # 2) ECB cipher mode — deterministic, leaks plaintext structure — even on an
    #    otherwise-strong cipher (e.g. AES-128-ECB).
    if props.get("crypto:mode", "").upper() == "ECB":
        return (
            WEAK_CIPHER_MODE,
            _SEV,
            f"Insecure ECB cipher mode on {name}: identical plaintext blocks "
            f"map to identical ciphertext; use an authenticated mode (GCM/CCM).",
        )

    # 3) Sub-2048-bit asymmetric key (a strong-named RSA/DSA/DH with a small key).
    if props.get("crypto:primitive") in ("pke", "signature", "key-agree"):
        bits = _key_size(props)
        if bits is not None and bits < _MIN_ASYMMETRIC_BITS:
            return (
                WEAK_KEY_SIZE,
                _SEV,
                f"Undersized asymmetric key on {name}: {bits}-bit is below the "
                f"{_MIN_ASYMMETRIC_BITS}-bit floor (NIST SP 800-57); use "
                f"RSA-3072+ or an elliptic-curve / PQC equivalent.",
            )

    # 4) Fallback: any asset the inventory already marked weak that the corpus
    #    lookup missed (a parametrized variant not in the normalization table).
    if props.get("crypto:strength") == "weak":
        return (
            WEAK_ALGORITHM,
            _SEV,
            f"Weak algorithm {name}: flagged by the crypto inventory as weak; "
            f"migrate to a modern primitive.",
        )

    return None


def material_misuse_findings(component: AIComponent) -> list[tuple[str, str, str]]:
    """Return every crypto-material misuse flag on a related-crypto-material asset (C6).

    Pure predicate over the ``crypto:`` misuse props the C6 misuse scanner
    (:mod:`aibom.cbom.scanners.crypto_misuse_scan`) emitted — never re-scans
    source. Returns an empty list for any non-material component, so the flag
    scanner can call it on every asset unconditionally. Misuses stack: material
    from a weak RNG that is also a static, reused IV raises all three.
    """
    if component.kind != "crypto_asset":
        return []
    props = component.properties or {}
    if props.get("crypto:assetType") != "related-crypto-material":
        return []
    kind = props.get("crypto:materialKind", "material")
    name = component.name
    findings: list[tuple[str, str, str]] = []

    if props.get("crypto:weakRng") == "true":
        src = props.get("crypto:generatedBy", "a non-cryptographic PRNG")
        findings.append(
            (
                WEAK_RNG,
                _SEV,
                f"Weak RNG for crypto material {name}: {src} is not a CSPRNG "
                f"(CWE-338); the {kind} is predictable. Use os.urandom / "
                f"secrets / crypto.randomBytes / a platform CSPRNG.",
            )
        )
    # A reused nonce is strictly worse than a merely-static one, so REUSED_NONCE
    # supersedes STATIC_IV on the same asset (no double IV finding).
    if props.get("crypto:reused") == "true":
        findings.append(
            (
                REUSED_NONCE,
                _SEV,
                f"Reused nonce/IV {name}: the same constant {kind} secures more "
                f"than one encryption (CWE-323) — catastrophic for GCM/CTR "
                f"(nonce reuse breaks confidentiality and integrity). Derive a "
                f"fresh random nonce per message.",
            )
        )
    elif props.get("crypto:staticIv") == "true":
        findings.append(
            (
                STATIC_IV,
                _SEV,
                f"Static IV/nonce {name}: a constant, predictable {kind} reaches "
                f"a cipher (CWE-329); it defeats CBC/CTR semantic security. Use a "
                f"fresh random IV per message.",
            )
        )
    if props.get("crypto:hardcoded") == "true" and kind in (
        "secret-key",
        "private-key",
        "key",
    ):
        findings.append(
            (
                HARDCODED_KEY,
                _SEV,
                f"Hardcoded key {name}: a symmetric/private key is embedded as a "
                f"source literal (CWE-321); anyone with the code has the key. "
                f"Load key material from a secret manager / KMS, never source.",
            )
        )
    return findings


def _sig_digest_is_broken(sig_alg: str) -> bool:
    """A certificate signatureAlgorithm built on a collision-broken digest."""
    low = sig_alg.lower()
    return any(d in low for d in _BROKEN_SIG_DIGESTS)


def certificate_findings(component: AIComponent) -> list[tuple[str, str, str]]:
    """Return every certificate-depth weakness on a certificate asset (C4).

    Pure, and orthogonal to :func:`cert_expiry_finding` — a certificate can be
    *both* expired and signed with SHA-1 with an undersized key, and every such
    finding is raised so the scorer stacks them (mirroring the weights file's
    "expired+weak cert" rationale). Returns an empty list for any non-certificate
    component, so the scanner can call it on every asset unconditionally.
    """
    if component.kind != "crypto_asset":
        return []
    props = component.properties or {}
    if props.get("crypto:assetType") != "certificate":
        return []
    name = component.name
    findings: list[tuple[str, str, str]] = []

    # 1) Broken signature digest (MD2/MD4/MD5/SHA-1) -> the cert is forgeable.
    sig_alg = props.get("crypto:signatureAlgorithm", "")
    if sig_alg and _sig_digest_is_broken(sig_alg):
        findings.append(
            (
                WEAK_CERTIFICATE_SIGNATURE,
                _SEV,
                f"Certificate {name} is signed with {sig_alg}: MD5/SHA-1 digests "
                f"are collision-broken (chosen-prefix), so the certificate can be "
                f"forged; reissue with a SHA-256+ signature.",
            )
        )

    # 2) Undersized public key. RSA/DSA below the 2048-bit floor (NIST SP 800-57);
    #    an EC curve below a 224-bit field (< 112-bit strength) is equally weak.
    bits = _key_size(props)
    if bits is not None:
        pk = props.get("crypto:publicKeyAlgorithm", "").lower()
        is_ec = pk.startswith("ec") or bool(props.get("crypto:curve"))
        floor = 224 if is_ec else _MIN_ASYMMETRIC_BITS
        if bits < floor:
            findings.append(
                (
                    WEAK_CERTIFICATE_KEY,
                    _SEV,
                    f"Certificate {name} has an undersized {bits}-bit public key "
                    f"(floor {floor}-bit, NIST SP 800-57); reissue with "
                    f"RSA-3072+ or a P-256+ / PQC key.",
                )
            )

    # 3) Self-signed leaf: a self-signed cert that is explicitly NOT a CA is an
    #    end-entity trusting itself — a production trust smell (a real root CA is
    #    self-signed but carries BasicConstraints CA:TRUE, so is not flagged).
    if (
        props.get("crypto:selfSigned") == "true"
        and props.get("crypto:isCertificateAuthority") == "false"
    ):
        findings.append(
            (
                SELF_SIGNED_LEAF,
                _SEV_MED,
                f"Self-signed leaf certificate {name} (BasicConstraints CA:FALSE): "
                f"an end-entity certificate acting as its own trust anchor; issue "
                f"it from a proper CA before relying on it in production.",
            )
        )
    return findings


def _cert_not_after_date(raw: str) -> date | None:
    """Parse a certificate ``crypto:notValidAfter`` value to a date.

    C2 captures it as an ISO-8601 ``YYYY-MM-DDThh:mm:ssZ`` string; only the
    date is needed for an expiry comparison. Returns ``None`` (never raises) on a
    malformed value, so a garbled cert can never crash the scan.
    """
    if not raw:
        return None
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return None


def cert_expiry_finding(
    component: AIComponent, today: date
) -> tuple[str, str, str] | None:
    """Return an ``EXPIRED_CERTIFICATE`` finding if the cert is past expiry, else None.

    Pure: depends only on the component's ``crypto:notValidAfter`` property and
    the supplied ``today`` reference date (the scanner passes ``date.today()``;
    tests pass a fixed date so the predicate stays deterministic). SARIF
    ``error`` (== High impact), matching the criterion "expired cert -> high".
    A certificate with no parseable expiry, or one still valid, is not flagged.
    """
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    if props.get("crypto:assetType") != "certificate":
        return None
    not_after = _cert_not_after_date(props.get("crypto:notValidAfter", ""))
    if not_after is None or not_after >= today:
        return None
    return (
        EXPIRED_CERTIFICATE,
        _SEV,
        f"Expired X.509 certificate {component.name}: notValidAfter "
        f"{not_after.isoformat()} is in the past; rotate/reissue and re-pin "
        f"trust anchors before relying on it.",
    )


__all__ = [
    "WEAK_ALGORITHM",
    "WEAK_CIPHER_MODE",
    "WEAK_KEY_SIZE",
    "WEAK_PROTOCOL",
    "EXPIRED_CERTIFICATE",
    "WEAK_CERTIFICATE_SIGNATURE",
    "WEAK_CERTIFICATE_KEY",
    "SELF_SIGNED_LEAF",
    "WEAK_RNG",
    "STATIC_IV",
    "REUSED_NONCE",
    "HARDCODED_KEY",
    "WEAK_CRYPTO_CODES",
    "weak_finding",
    "cert_expiry_finding",
    "certificate_findings",
    "material_misuse_findings",
]
