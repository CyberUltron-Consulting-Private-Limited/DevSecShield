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

import re
from datetime import date, timedelta

from aibom.cbom.rules import ALGORITHM_NORMALIZE, WEAK_ALGORITHMS
from aibom.model.component import AIComponent

# Flag codes this lane emits (the set the C8 scorer weights and the charts read).
WEAK_ALGORITHM = "WEAK_ALGORITHM"
WEAK_CIPHER_MODE = "WEAK_CIPHER_MODE"
WEAK_KEY_SIZE = "WEAK_KEY_SIZE"
WEAK_PROTOCOL = "WEAK_PROTOCOL"
# An X.509 certificate past its notValidAfter date (C8: "expired cert -> high").
EXPIRED_CERTIFICATE = "EXPIRED_CERTIFICATE"
# C4 certificate-weakness catalog: a collision-broken signature hash
# (MD2/MD4/MD5/SHA-1), an undersized RSA/DSA certificate key (< 2048), and a
# certificate approaching expiry (a warn band ahead of hard EXPIRED).
WEAK_CERT_SIGNATURE = "WEAK_CERT_SIGNATURE"
WEAK_CERT_KEY_SIZE = "WEAK_CERT_KEY_SIZE"
CERT_NEAR_EXPIRY = "CERT_NEAR_EXPIRY"

WEAK_CRYPTO_CODES = frozenset(
    {
        WEAK_ALGORITHM,
        WEAK_CIPHER_MODE,
        WEAK_KEY_SIZE,
        WEAK_PROTOCOL,
        WEAK_CERT_SIGNATURE,
        WEAK_CERT_KEY_SIZE,
    }
)

_SEV = "error"  # SARIF error == High impact (mirrors the secret scanner).
_SEV_WARN = "warning"  # SARIF warning == Medium impact (a migrate-soon band).

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

# Certificate signature hashes distrusted for collision resistance: MD2/MD4/MD5
# and SHA-1 (CA/Browser Forum SHA-1 sunset 2016; NIST SP 800-131A). Raw OIDs the
# x509 reader leaves unmapped (md2/md4-with-RSA) are matched explicitly; the rest
# are recognised by hash token inside the signatureAlgorithm name.
_WEAK_SIG_OIDS: dict[str, str] = {
    "1.2.840.113549.1.1.2": "MD2",  # md2WithRSAEncryption
    "1.2.840.113549.1.1.3": "MD4",  # md4WithRSAEncryption
    "1.2.840.113549.1.1.4": "MD5",  # md5WithRSAEncryption (also name-mapped)
    "1.3.14.3.2.29": "SHA-1",  # sha1WithRSA (legacy OIW OID)
}
# SHA-1 not followed by another digit (so "sha256"/"sha512" never match).
_SHA1_RE = re.compile(r"sha-?1(?![0-9])")

# Public-key algorithms whose certificate key size is graded against the 2048-bit
# asymmetric floor (EC/EdDSA are sized by curve, not modulus, so excluded here).
_MODULUS_PK_TOKENS = ("rsa", "dsa")

# Default near-expiry warn window (days). A cert expiring within this window but
# not yet past notValidAfter earns a Medium CERT_NEAR_EXPIRY (rotate-soon) band.
_NEAR_EXPIRY_DAYS = 30


def _weak_cert_hash(sig_alg: str) -> str | None:
    """Return the weak signature-hash display name (MD5/SHA-1/...) or None.

    Pure token/OID lookup over a certificate ``crypto:signatureAlgorithm`` value
    (either a human name like ``sha1WithRSAEncryption`` or a raw dotted OID).
    """
    s = sig_alg.strip().lower()
    if s in _WEAK_SIG_OIDS:
        return _WEAK_SIG_OIDS[s]
    if "md5" in s:
        return "MD5"
    if "md4" in s:
        return "MD4"
    if "md2" in s:
        return "MD2"
    if _SHA1_RE.search(s):
        return "SHA-1"
    return None


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
            return (
                WEAK_PROTOCOL,
                _SEV,
                f"Weak transport protocol {name}{ver}: TLS below 1.2 / SSL is "
                f"deprecated (RFC 8996); negotiate TLS 1.2+ (prefer 1.3).",
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


def cert_weakness_findings(
    component: AIComponent,
    today: date,
    near_expiry_days: int = _NEAR_EXPIRY_DAYS,
) -> list[tuple[str, str, str]]:
    """All certificate-weakness findings for one crypto asset (C4 catalog).

    Unlike the single-verdict :func:`weak_finding` (algorithm / protocol), a
    certificate can be weak on several orthogonal axes at once — a legacy cert can
    be BOTH SHA-1-signed AND RSA-1024 AND expiring — so this returns a list and
    the caller stacks the flags (the C8 scorer sums their weights per component).

    Findings (deterministic order): validity band first (EXPIRED_CERTIFICATE High,
    else CERT_NEAR_EXPIRY Medium when within ``near_expiry_days``), then a weak
    signature hash (High), then an undersized RSA/DSA key (High). Non-certificate
    assets return ``[]``. Pure: reads only ``crypto:`` properties + ``today``.
    """
    if component.kind != "crypto_asset":
        return []
    props = component.properties or {}
    if props.get("crypto:assetType") != "certificate":
        return []
    name = component.name
    findings: list[tuple[str, str, str]] = []

    # 1) Validity band — hard-expired (reuse the existing predicate) OR near-expiry.
    expired = cert_expiry_finding(component, today)
    if expired is not None:
        findings.append(expired)
    else:
        not_after = _cert_not_after_date(props.get("crypto:notValidAfter", ""))
        if (
            not_after is not None
            and not_after >= today
            and not_after < today + timedelta(days=near_expiry_days)
        ):
            days_left = (not_after - today).days
            findings.append(
                (
                    CERT_NEAR_EXPIRY,
                    _SEV_WARN,
                    f"Certificate {name} expires in {days_left} day(s) "
                    f"(notValidAfter {not_after.isoformat()}); schedule "
                    f"rotation before it lapses to avoid an outage.",
                )
            )

    # 2) Collision-broken signature hash (MD2/MD4/MD5/SHA-1).
    sig_alg = props.get("crypto:signatureAlgorithm", "")
    weak_hash = _weak_cert_hash(sig_alg) if sig_alg else None
    if weak_hash is not None:
        findings.append(
            (
                WEAK_CERT_SIGNATURE,
                _SEV,
                f"Certificate {name} is signed with {weak_hash} "
                f"({sig_alg}): a collision-broken hash (CA/Browser Forum SHA-1 "
                f"sunset; NIST SP 800-131A); reissue with SHA-256+.",
            )
        )

    # 3) Undersized RSA/DSA certificate key (< 2048), which WEAK_KEY_SIZE skips
    #    because it gates on assetType == "algorithm".
    pk_alg = props.get("crypto:publicKeyAlgorithm", "").lower()
    if any(tok in pk_alg for tok in _MODULUS_PK_TOKENS):
        bits = _key_size(props)
        if bits is not None and bits < _MIN_ASYMMETRIC_BITS:
            findings.append(
                (
                    WEAK_CERT_KEY_SIZE,
                    _SEV,
                    f"Certificate {name} has an undersized {bits}-bit key: "
                    f"below the {_MIN_ASYMMETRIC_BITS}-bit RSA/DSA floor "
                    f"(NIST SP 800-57); reissue with RSA-3072+ or ECDSA P-256.",
                )
            )

    return findings


__all__ = [
    "WEAK_ALGORITHM",
    "WEAK_CIPHER_MODE",
    "WEAK_KEY_SIZE",
    "WEAK_PROTOCOL",
    "EXPIRED_CERTIFICATE",
    "WEAK_CERT_SIGNATURE",
    "WEAK_CERT_KEY_SIZE",
    "CERT_NEAR_EXPIRY",
    "WEAK_CRYPTO_CODES",
    "weak_finding",
    "cert_expiry_finding",
    "cert_weakness_findings",
]
