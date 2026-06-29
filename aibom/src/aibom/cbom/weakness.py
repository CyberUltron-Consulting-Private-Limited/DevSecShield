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

WEAK_CRYPTO_CODES = frozenset(
    {WEAK_ALGORITHM, WEAK_CIPHER_MODE, WEAK_KEY_SIZE, WEAK_PROTOCOL}
)

_SEV = "error"  # SARIF error == High impact (mirrors the secret scanner).

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


__all__ = [
    "WEAK_ALGORITHM",
    "WEAK_CIPHER_MODE",
    "WEAK_KEY_SIZE",
    "WEAK_PROTOCOL",
    "EXPIRED_CERTIFICATE",
    "WEAK_CRYPTO_CODES",
    "weak_finding",
    "cert_expiry_finding",
]
